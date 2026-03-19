// tree-sitter TS/TSX parser + import extractor.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";

import Parser from "tree-sitter";

import {
  extractCallSitesWithLanguage,
  extractDynamicImportsWithLanguage,
  extractESMImportsWithLanguage,
  extractExportsWithLanguage,
} from "./javascript.js";
import type { ImportRef, ParsedModule } from "./index.js";

const require = createRequire(import.meta.url);
const TypeScriptGrammars = require("tree-sitter-typescript") as {
  typescript: unknown;
  tsx: unknown;
};

const IMPORT_TYPE_QUERY = '(import_statement) @import';

const typeScriptParser = new Parser();
typeScriptParser.setLanguage(TypeScriptGrammars.typescript);

const tsxParser = new Parser();
tsxParser.setLanguage(TypeScriptGrammars.tsx);

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

export function extractTypeImports(tree: Parser.Tree, isTsx = false): ImportRef[] {
  const language = isTsx ? TypeScriptGrammars.tsx : TypeScriptGrammars.typescript;
  const query = new Parser.Query(language, IMPORT_TYPE_QUERY);

  return uniqueBy(
    query
      .captures(tree.rootNode)
      .filter((capture) => capture.name === "import" && capture.node.text.startsWith("import type"))
      .map((capture) => {
        const sourceNode = capture.node.childForFieldName("source");
        return {
          source: sourceNode ? sourceNode.text.replace(/^['"`]|['"`]$/g, "") : "",
          kind: "esm" as const,
          line: capture.node.startPosition.row + 1,
          isTypeOnly: true,
        };
      })
      .filter((entry) => entry.source.length > 0),
    (entry) => `${entry.source}:${entry.line}`,
  );
}

export function parseTypeScriptFile(filePath: string, isTsx = false): ParsedModule {
  const sourceText = readFileSync(filePath, "utf8");
  const parser = isTsx ? tsxParser : typeScriptParser;
  const language = isTsx ? TypeScriptGrammars.tsx : TypeScriptGrammars.typescript;
  const tree = parser.parse(sourceText);
  const typeImports = extractTypeImports(tree, isTsx);
  const runtimeImports = extractESMImportsWithLanguage(tree, language).map((entry) => ({
    ...entry,
    isTypeOnly: typeImports.some((typeImport) => typeImport.source === entry.source && typeImport.line === entry.line),
  }));

  return {
    file: filePath,
    imports: uniqueBy(
      [...runtimeImports, ...extractDynamicImportsWithLanguage(tree, language)],
      (entry) => `${entry.kind}:${entry.source}:${entry.line}:${entry.isTypeOnly ?? false}`,
    ),
    exports: extractExportsWithLanguage(tree, language),
    calls: extractCallSitesWithLanguage(tree, language),
  };
}
