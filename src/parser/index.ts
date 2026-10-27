// Dispatch to language-specific parsers.
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
  /** With `usedNames: true`: names the module uses beyond declaring them or binding them to an export. */
  usedNames?: Set<string>;
}

export type ParseOptions = { usedNames?: boolean };

export function parseFile(filePath: string, options: ParseOptions = {}): ParsedModule {
  const extension = path.extname(filePath).toLowerCase();

  if ([".js", ".mjs", ".cjs", ".jsx"].includes(extension)) {
    return parseJavaScriptFile(filePath, options);
  }

  if ([".ts", ".mts"].includes(extension)) {
    return parseTypeScriptFile(filePath, false, options);
  }

  if (extension === ".tsx") {
    return parseTypeScriptFile(filePath, true, options);
  }

  throw new Error(`Unsupported file extension: ${extension}`);
}
