import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import Parser from "tree-sitter";
import TypeScriptGrammars from "tree-sitter-typescript";
import { afterEach, describe, expect, it } from "vitest";

import { parseFile } from "../../src/parser/index.js";
import { extractTypeImports } from "../../src/parser/typescript.js";

const parser = new Parser();
parser.setLanguage(TypeScriptGrammars.typescript);

const createdDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "reachable-ts-parser-"));
  createdDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (createdDirs.length > 0) {
    const dir = createdDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe("parser/typescript", () => {
  it("marks import type statements as type-only", () => {
    const tree = parser.parse(`
      import type { Request } from "express";
      import { Router } from "express";
    `);

    expect(extractTypeImports(tree)).toEqual([{ source: "express", kind: "esm", line: 2, isTypeOnly: true }]);
  });

  it("parses .tsx files with JSX without error", () => {
    const tempDir = makeTempDir();
    const sourceDir = path.join(tempDir, "src");
    const componentFile = path.join(sourceDir, "App.tsx");

    mkdirSync(sourceDir, { recursive: true });
    writeFileSync(
      componentFile,
      `
        export function App() {
          return <section><span>Hello</span></section>;
        }
      `,
      "utf8",
    );

    const parsedModule = parseFile(componentFile);

    expect(parsedModule.file).toBe(componentFile);
    expect(parsedModule.exports).toEqual([{ name: "App", line: 2 }]);
  });
});
