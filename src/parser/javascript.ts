// tree-sitter JS/JSX parser + import extractor.
import { readFileSync } from "node:fs";

import Parser from "tree-sitter";
import JavaScript from "tree-sitter-javascript";

import type { CallRef, ExportRef, ImportRef, ParsedModule, ParseOptions } from "./index.js";

// The JS grammar stays on the 0.23.x line so it remains compatible with tree-sitter 0.21.x
// and the pinned TypeScript grammar, which is the safest working combination in this runtime.
const REQUIRE_QUERY = '(call_expression function: (identifier) @fn arguments: (arguments (string) @path) (#eq? @fn "require"))';
const IMPORT_QUERY = '(import_statement source: (string) @source)';
const DYNAMIC_IMPORT_QUERY = `
  [
    (await_expression (call_expression function: (import) arguments: (arguments (string) @path)))
    (call_expression function: (import) arguments: (arguments (string) @path))
  ]
`;
const CALL_QUERY = '(call_expression function: [(member_expression) (identifier)] @callee)';
const EXPORT_QUERY = '(export_statement) @export';
// String contents count too: obj["template"]() reaches the function without naming it as an identifier.
const NAME_QUERY = "[(identifier) (property_identifier) (shorthand_property_identifier) (string_fragment)] @name";

const parser = new Parser();
parser.setLanguage(JavaScript);

function stripQuotes(text: string): string {
  return text.replace(/^['"`]|['"`]$/g, "");
}

function lineOf(node: Parser.SyntaxNode): number {
  return node.startPosition.row + 1;
}

// tree-sitter 0.21 throws "Invalid argument" when a string is not shorter than bufferSize (default 32768),
// so files of 32 KB or more were skipped and their imports and calls went missing from the graph.
export function parseSource(parser: Parser, sourceText: string): Parser.Tree {
  return parser.parse(sourceText, undefined, { bufferSize: sourceText.length + 1 });
}

function sameNode(left: Parser.SyntaxNode | null, right: Parser.SyntaxNode): boolean {
  return Boolean(left && left.startIndex === right.startIndex && left.endIndex === right.endIndex);
}

// export default function x() {}, module.exports = function x() {}: the app calls a default export by any name.
function isDefaultExport(declaration: Parser.SyntaxNode): boolean {
  const holder = declaration.parent;
  if (holder?.type === "export_statement") {
    return /^export\s+default\b/.test(holder.text);
  }

  return (
    holder?.type === "assignment_expression" &&
    sameNode(holder.childForFieldName("right"), declaration) &&
    /^(module\.exports|exports\.default)$/.test(holder.childForFieldName("left")?.text ?? "")
  );
}

// Declaring a name or exporting it under the same name: function x() {}, const x = ..., import { x },
// export { x }, { x: ... } keys, a.x = ..., a.x = x, module.exports = { x } or { x: x }, export default { x }.
// Anything else is a use: a call, an alias, an argument, a property read, and handing x out under another name
// (export { x as y }, import { x as y }, a.y = x, { y: x }, export default x, module.exports = x), since code that
// calls it by that name never mentions x.
function declaresOrExports(node: Parser.SyntaxNode): boolean {
  const parent = node.parent;
  if (!parent) {
    return false;
  }

  const alias = parent.childForFieldName("alias");
  if (sameNode(parent.childForFieldName("name"), node)) {
    return !alias ? !isDefaultExport(parent) : alias.text === node.text;
  }

  if (sameNode(alias, node) || (parent.type === "pair" && sameNode(parent.childForFieldName("key"), node))) {
    return true;
  }

  const assignment = parent.parent;
  if (parent.type === "member_expression" && assignment?.type === "assignment_expression") {
    return sameNode(parent.childForFieldName("property"), node) && sameNode(assignment.childForFieldName("left"), parent);
  }

  if (parent.type === "assignment_expression" && sameNode(parent.childForFieldName("right"), node)) {
    return parent.childForFieldName("left")?.childForFieldName("property")?.text === node.text;
  }

  if (parent.type === "pair" && parent.childForFieldName("key")?.text !== node.text) {
    return false;
  }

  const object = parent.type === "object" ? parent : parent.type === "pair" ? parent.parent : null;
  const holder = object?.type === "object" ? object.parent : null;
  return (
    holder?.type === "export_statement" ||
    (holder?.type === "assignment_expression" && /^(module\.)?exports$/.test(holder.childForFieldName("left")?.text ?? ""))
  );
}

// A bare module specifier: lodash, @scope/pkg, lodash/fp.
const SPECIFIER = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*(?:\/[\w.~@/-]*)?$/;

// A name declared here (a parameter, a variable, a function, the import itself) is a new binding, not a use.
function declares(node: Parser.SyntaxNode): boolean {
  const parent = node.parent;
  const is = (field: string): boolean => sameNode(parent?.childForFieldName(field) ?? null, node);
  switch (parent?.type) {
    case "formal_parameters":
    case "array_pattern":
    case "rest_pattern":
    case "catch_clause":
    case "import_clause":
    case "namespace_import":
    case "import_specifier":
    case "import_require_clause":
      return true;
    case "assignment_pattern":
    case "for_in_statement":
      return is("left");
    case "pair_pattern":
      return is("value");
    case "arrow_function":
      return is("parameter");
    case "required_parameter":
    case "optional_parameter":
      return is("pattern");
    case "variable_declarator":
    case "function_declaration":
    case "function_expression":
    case "generator_function":
    case "generator_function_declaration":
    case "class_declaration":
    case "class":
      return is("name");
    default:
      return false;
  }
}

// What code does with a module value (require("x"), import("x"), or a name bound to one): reads or calls a member by
// its name (_.map(), _["map"], _(x), const { map } = _), which the call graph sees; gives it another name (const lib
// = _), which is followed; or anything else, which hands the whole module to code the graph does not follow
// (Object.assign({}, _), app.locals.lib = _, render(_), export default _) or reads a member through a computed name
// (_[name]).
function moduleUse(node: Parser.SyntaxNode): "named" | "opaque" | Parser.SyntaxNode {
  const parent = node.parent;
  switch (parent?.type) {
    case undefined:
    case "member_expression":
    case "call_expression":
    case "expression_statement":
    case "unary_expression":
    case "type_query":
    case "nested_type_identifier":
    case "nested_identifier":
      return "named";
    case "subscript_expression":
      return sameNode(parent.childForFieldName("object"), node) && parent.childForFieldName("index")?.type === "string" ? "named" : "opaque";
    case "await_expression":
    case "parenthesized_expression":
    case "as_expression":
    case "satisfies_expression":
    case "non_null_expression":
    case "type_assertion":
      return moduleUse(parent);
    case "binary_expression":
      return ["||", "&&", "??"].includes(parent.childForFieldName("operator")?.text ?? "") ? "opaque" : "named";
    case "variable_declarator":
    case "assignment_expression": {
      const target = parent.childForFieldName(parent.type === "variable_declarator" ? "name" : "left");
      if (!target || sameNode(target, node)) {
        return "named";
      }

      // export const lib = _ hands it on under the new name.
      if (target.type === "identifier") {
        return parent.parent?.parent?.type === "export_statement" ? "opaque" : target;
      }

      return target.type === "object_pattern" && target.descendantsOfType(["rest_pattern", "computed_property_name"]).length === 0 ? "named" : "opaque";
    }
    default:
      return "opaque";
  }
}

// Module specifiers the file uses in ways the call graph cannot follow: a module it hands on whole or indexes by a
// computed name (see moduleUse), a module it re-exports whole (export * from "x", export { default } from "x"), and a
// package name it spells as a plain string (knex({ client: "pg" }), app.set("view engine", "pug")), since a dependency
// can load the package by that name.
export function extractOpaqueSpecifiers(tree: Parser.Tree): string[] {
  const opaque = new Set<string>();
  const bound = new Set<string>();
  const references = new Map<string, Parser.SyntaxNode[]>();
  for (const node of tree.rootNode.descendantsOfType(["identifier", "shorthand_property_identifier"])) {
    const nodes = references.get(node.text);
    if (nodes) {
      nodes.push(node);
    } else {
      references.set(node.text, [node]);
    }
  }

  const follow = (value: Parser.SyntaxNode, specifier: string): void => {
    const use = moduleUse(value);
    if (use === "opaque") {
      opaque.add(specifier);
    } else if (use !== "named") {
      bind(use.text, specifier);
    }
  };
  // Every reference to the name counts, shadowing ignored, so a parameter of the same name can only add to the set.
  const bind = (name: string, specifier: string): void => {
    if (bound.has(`${name}\0${specifier}`)) {
      return;
    }

    bound.add(`${name}\0${specifier}`);
    for (const node of references.get(name) ?? []) {
      if (node.type === "shorthand_property_identifier") {
        opaque.add(specifier);
      } else if (!declares(node)) {
        follow(node, specifier);
      }
    }
  };

  // A template literal without substitutions (`lodash`) is a plain string here, never one the graph reads as an import.
  for (const node of tree.rootNode.descendantsOfType(["string", "template_string"])) {
    // Not the TypeScript keyword string, nor a template literal with substitutions.
    if (!node.isNamed || (node.type === "template_string" && node.descendantsOfType("template_substitution").length > 0)) {
      continue;
    }

    const specifier = node.text.slice(1, -1);
    const holder = node.type === "string" ? node.parent : null;
    const call = holder?.type === "arguments" && sameNode(holder.namedChild(0), node) ? holder.parent : null;
    if (call?.type === "call_expression" && ["require", "import"].includes(call.childForFieldName("function")?.text ?? "")) {
      follow(call, specifier);
    } else if (holder?.type === "import_statement") {
      for (const child of holder.namedChildren.find((entry) => entry.type === "import_clause")?.namedChildren ?? []) {
        const name = child.type === "namespace_import" ? child.namedChild(0) : child.type === "identifier" ? child : null;
        if (name) {
          bind(name.text, specifier);
        }
      }
    } else if (holder?.type === "import_require_clause") {
      bind(holder.namedChild(0)?.text ?? "", specifier);
    } else if (holder?.type === "export_statement") {
      const clause = holder.namedChildren.find((entry) => entry.type === "export_clause");
      if (!clause || /\bdefault\b/.test(clause.text)) {
        opaque.add(specifier);
      }
    } else if (node.parent?.type !== "module" && SPECIFIER.test(specifier)) {
      // Not declare module "x" in a .d.ts file, which only describes the package.
      opaque.add(specifier);
    }
  }

  return [...opaque];
}

export function extractUsedNamesWithLanguage(tree: Parser.Tree, language: unknown): Set<string> {
  return new Set(
    captureNodes(language, tree, NAME_QUERY)
      .filter((capture) => !declaresOrExports(capture.node))
      .map((capture) => capture.node.text),
  );
}

function captureNodes(language: unknown, tree: Parser.Tree, querySource: string): Parser.QueryCapture[] {
  const query = new Parser.Query(language, querySource);
  return query.captures(tree.rootNode);
}

function uniqueBy<T>(items: T[], keyFn: (item: T) => string): T[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = keyFn(item);
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function exportSource(node: Parser.SyntaxNode): string | null {
  const match = node.text.match(/from\s+['"`]([^'"`]+)['"`]/);
  return match?.[1] ?? null;
}

function exportsFromNode(node: Parser.SyntaxNode): ExportRef[] {
  if (node.type !== "export_statement") {
    return [];
  }

  const exportedNames: ExportRef[] = [];
  const exportText = node.text;
  const exportClause = node.namedChildren.find((child) => child.type === "export_clause");
  const source = exportSource(node);

  if (exportClause) {
    for (const specifier of exportClause.namedChildren.filter((child) => child.type === "export_specifier")) {
      const identifiers = specifier.namedChildren.filter((child) => child.type === "identifier");
      if (identifiers.length > 0) {
        exportedNames.push({
          name: identifiers[identifiers.length - 1].text,
          line: lineOf(node),
          ...(source ? { source } : {}),
        });
      }
    }
  }

  const declaration = node.namedChildren.find((child) =>
    ["function_declaration", "class_declaration", "lexical_declaration", "variable_declaration"].includes(child.type),
  );

  if (declaration?.type === "function_declaration" || declaration?.type === "class_declaration") {
    const nameNode = declaration.childForFieldName("name");
    if (nameNode) {
      exportedNames.push({
        name: exportText.startsWith("export default") ? "default" : nameNode.text,
        line: lineOf(node),
      });
    }
  }

  if (declaration?.type === "lexical_declaration" || declaration?.type === "variable_declaration") {
    for (const declarator of declaration.namedChildren.filter((child) => child.type === "variable_declarator")) {
      const nameNode = declarator.childForFieldName("name");
      if (nameNode) {
        exportedNames.push({
          name: nameNode.text,
          line: lineOf(node),
        });
      }
    }
  }

  if (exportText.startsWith("export *")) {
    exportedNames.push({
      name: "*",
      line: lineOf(node),
      ...(source ? { source } : {}),
      isWildcard: true,
    });
  }

  if (exportText.startsWith("export default") && exportedNames.length === 0) {
    exportedNames.push({
      name: "default",
      line: lineOf(node),
    });
  }

  return uniqueBy(exportedNames, (entry) => `${entry.name}:${entry.source ?? ""}:${entry.isWildcard ?? false}`);
}

export function extractRequireCalls(tree: Parser.Tree): ImportRef[] {
  const captures = captureNodes(JavaScript, tree, REQUIRE_QUERY);
  const imports: ImportRef[] = [];

  for (let index = 0; index < captures.length; index += 2) {
    const pathCapture = captures[index + 1];
    if (!pathCapture) {
      continue;
    }

    imports.push({
      source: stripQuotes(pathCapture.node.text),
      kind: "require",
      line: lineOf(pathCapture.node),
      isTypeOnly: false,
    });
  }

  return uniqueBy(imports, (entry) => `${entry.kind}:${entry.source}:${entry.line}`);
}

export function extractESMImports(tree: Parser.Tree): ImportRef[] {
  return extractESMImportsWithLanguage(tree, JavaScript);
}

export function extractESMImportsWithLanguage(tree: Parser.Tree, language: unknown): ImportRef[] {
  const captures = captureNodes(language, tree, IMPORT_QUERY);
  return uniqueBy(
    captures
      .filter((capture) => capture.name === "source")
      .map((capture) => ({
        source: stripQuotes(capture.node.text),
        kind: "esm" as const,
        line: lineOf(capture.node),
        isTypeOnly: false,
      })),
    (entry) => `${entry.kind}:${entry.source}:${entry.line}`,
  );
}

export function extractDynamicImports(tree: Parser.Tree): ImportRef[] {
  return extractDynamicImportsWithLanguage(tree, JavaScript);
}

export function extractDynamicImportsWithLanguage(tree: Parser.Tree, language: unknown): ImportRef[] {
  const captures = captureNodes(language, tree, DYNAMIC_IMPORT_QUERY);
  return uniqueBy(
    captures
      .filter((capture) => capture.name === "path")
      .map((capture) => ({
        source: stripQuotes(capture.node.text),
        kind: "dynamic" as const,
        line: lineOf(capture.node),
        isTypeOnly: false,
      })),
    (entry) => `${entry.kind}:${entry.source}:${entry.line}`,
  );
}

export function extractCallSites(tree: Parser.Tree): CallRef[] {
  return extractCallSitesWithLanguage(tree, JavaScript);
}

export function extractCallSitesWithLanguage(tree: Parser.Tree, language: unknown): CallRef[] {
  const captures = captureNodes(language, tree, CALL_QUERY);
  return uniqueBy(
    captures
      .filter((capture) => capture.name === "callee")
      .map((capture) => ({
        callee: capture.node.text,
        line: lineOf(capture.node),
      })),
    (entry) => `${entry.callee}:${entry.line}`,
  );
}

export function extractExports(tree: Parser.Tree): ExportRef[] {
  return extractExportsWithLanguage(tree, JavaScript);
}

export function extractExportsWithLanguage(tree: Parser.Tree, language: unknown): ExportRef[] {
  const captures = captureNodes(language, tree, EXPORT_QUERY);
  const exports: ExportRef[] = [];

  for (const capture of captures) {
    exports.push(...exportsFromNode(capture.node));
  }

  return uniqueBy(exports, (entry) => `${entry.name}:${entry.line}:${entry.source ?? ""}:${entry.isWildcard ?? false}`);
}

export function parseJavaScriptFile(filePath: string, options: ParseOptions = {}): ParsedModule {
  const tree = parseSource(parser, readFileSync(filePath, "utf8"));

  return {
    file: filePath,
    imports: uniqueBy(
      [...extractRequireCalls(tree), ...extractESMImports(tree), ...extractDynamicImports(tree)],
      (entry) => `${entry.kind}:${entry.source}:${entry.line}`,
    ),
    exports: extractExports(tree),
    calls: extractCallSites(tree),
    ...(options.opaque ? { opaque: extractOpaqueSpecifiers(tree) } : {}),
    ...(options.usedNames ? { usedNames: extractUsedNamesWithLanguage(tree, JavaScript) } : {}),
  };
}
