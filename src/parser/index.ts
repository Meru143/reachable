// Dispatch to language-specific parsers.
import { readFileSync } from "node:fs";
import path from "node:path";

import { parseJavaScriptFile } from "./javascript.js";
import { parseTypeScriptFile } from "./typescript.js";

export interface ImportRef {
  source: string;
  kind: "require" | "esm" | "dynamic";
  line: number;
  isTypeOnly?: boolean;
}

export interface ExportRef {
  name: string;
  line: number;
  source?: string;
  isWildcard?: boolean;
}

export interface CallRef {
  callee: string;
  line: number;
}

export interface ParsedModule {
  file: string;
  imports: ImportRef[];
  exports: ExportRef[];
  calls: CallRef[];
  /** With `opaque: true`: module specifiers the module uses in ways calls cannot show (handed on whole, a member read
   * through a computed name on it or on a value made from it, or a package name spelled as a string). */
  opaque?: string[];
  /** With `opaque: true`: the local names the module binds a module to, as [name, specifier]. */
  bindings?: Array<[string, string]>;
  /** With `usedNames: true`: names the module uses beyond declaring them or binding them to an export. */
  usedNames?: Set<string>;
}

export type ParseOptions = { usedNames?: boolean; opaque?: boolean };

const LANGUAGES = new Map<string, "js" | "ts" | "tsx">([
  ["", "js"],
  [".js", "js"],
  [".mjs", "js"],
  [".cjs", "js"],
  [".jsx", "js"],
  [".ts", "ts"],
  [".mts", "ts"],
  [".cts", "ts"],
  [".tsx", "tsx"],
]);

/** null when the file is not JavaScript or TypeScript. An extensionless file (bin/www) is JavaScript unless its
 * shebang names another interpreter (#!/bin/sh). */
export function languageOf(filePath: string): "js" | "ts" | "tsx" | null {
  const extension = path.extname(filePath).toLowerCase();
  const language = LANGUAGES.get(extension) ?? null;
  if (extension !== "") {
    return language;
  }

  const firstLine = readFileSync(filePath, "utf8").split("\n", 1)[0] ?? "";
  return !firstLine.startsWith("#!") || /\bnode(?:js)?\b/.test(firstLine) ? language : null;
}

export function parseFile(filePath: string, options: ParseOptions = {}): ParsedModule {
  const language = languageOf(filePath);
  if (language === null) {
    const extension = path.extname(filePath).toLowerCase();
    throw new Error(extension ? `Unsupported file extension: ${extension}` : "Not JavaScript: its shebang names another interpreter");
  }

  return language === "js" ? parseJavaScriptFile(filePath, options) : parseTypeScriptFile(filePath, language === "tsx", options);
}
