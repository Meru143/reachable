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
}

export function parseFile(filePath: string): ParsedModule {
  const extension = path.extname(filePath).toLowerCase();

  if ([".js", ".mjs", ".cjs", ".jsx"].includes(extension)) {
    return parseJavaScriptFile(filePath);
  }

  if ([".ts", ".mts"].includes(extension)) {
    return parseTypeScriptFile(filePath, false);
  }

  if (extension === ".tsx") {
    return parseTypeScriptFile(filePath, true);
  }

  throw new Error(`Unsupported file extension: ${extension}`);
}
