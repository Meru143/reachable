// tree-sitter JS/JSX parser + import extractor.
import { readFileSync } from "node:fs";

import Parser from "tree-sitter";
import JavaScript from "tree-sitter-javascript";

import type { CallRef, ExportRef, ImportRef, ParsedModule } from "./index.js";

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

const parser = new Parser();
parser.setLanguage(JavaScript);

function stripQuotes(text: string): string {
  return text.replace(/^['"`]|['"`]$/g, "");
}

function lineOf(node: Parser.SyntaxNode): number {
  return node.startPosition.row + 1;
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

function exportNamesFromNode(node: Parser.SyntaxNode): string[] {
  if (node.type !== "export_statement") {
    return [];
  }

  const exportedNames: string[] = [];
  const exportText = node.text;
  const exportClause = node.namedChildren.find((child) => child.type === "export_clause");

  if (exportClause) {
    for (const specifier of exportClause.namedChildren.filter((child) => child.type === "export_specifier")) {
      const identifiers = specifier.namedChildren.filter((child) => child.type === "identifier");
      if (identifiers.length > 0) {
        exportedNames.push(identifiers[identifiers.length - 1].text);
      }
    }
  }

  const declaration = node.namedChildren.find((child) =>
    ["function_declaration", "class_declaration", "lexical_declaration", "variable_declaration"].includes(child.type),
  );

  if (declaration?.type === "function_declaration" || declaration?.type === "class_declaration") {
    const nameNode = declaration.childForFieldName("name");
    if (nameNode) {
      exportedNames.push(exportText.startsWith("export default") ? "default" : nameNode.text);
    }
  }

  if (declaration?.type === "lexical_declaration" || declaration?.type === "variable_declaration") {
    for (const declarator of declaration.namedChildren.filter((child) => child.type === "variable_declarator")) {
      const nameNode = declarator.childForFieldName("name");
      if (nameNode) {
        exportedNames.push(nameNode.text);
      }
    }
  }

  if (exportText.startsWith("export *")) {
    exportedNames.push("*");
  }

  if (exportText.startsWith("export default") && exportedNames.length === 0) {
    exportedNames.push("default");
  }

  return uniqueBy(exportedNames, (name) => name);
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
    for (const name of exportNamesFromNode(capture.node)) {
      exports.push({
        name,
        line: lineOf(capture.node),
      });
    }
  }

  return uniqueBy(exports, (entry) => `${entry.name}:${entry.line}`);
}

export function parseJavaScriptFile(filePath: string): ParsedModule {
  const sourceText = readFileSync(filePath, "utf8");
  const tree = parser.parse(sourceText);

  return {
    file: filePath,
    imports: uniqueBy(
      [...extractRequireCalls(tree), ...extractESMImports(tree), ...extractDynamicImports(tree)],
      (entry) => `${entry.kind}:${entry.source}:${entry.line}`,
    ),
    exports: extractExports(tree),
    calls: extractCallSites(tree),
  };
}
