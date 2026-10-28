import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import Parser from "tree-sitter";
import TypeScriptGrammars from "tree-sitter-typescript";
import { afterEach, describe, expect, it } from "vitest";

import { languageOf, parseFile } from "../../src/parser/index.js";
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

  it("parses files of 32 KB and more", () => {
    const file = path.join(makeTempDir(), "big.ts");
    writeFileSync(file, `import _ from "lodash";\n${"const value: number = 1;\n".repeat(1500)}_.template("x");\n`, "utf8");

    const parsedModule = parseFile(file);

    expect(parsedModule.imports.map((entry) => entry.source)).toEqual(["lodash"]);
    expect(parsedModule.calls).toEqual([{ callee: "_.template", line: 1502 }]);
  });

  it("lists used names in TypeScript files too", () => {
    const file = path.join(makeTempDir(), "lib.ts");
    writeFileSync(file, 'export function template(s: string): string { return s; }\nexport const run = (name: string) => handlers["dispatch"](template(name));\n', "utf8");

    const used = parseFile(file, { usedNames: true }).usedNames;

    expect(used).toContain("template");
    expect(used).toContain("dispatch");
    expect(used).not.toContain("run");
  });

  it("parses .cts like .ts, and an extensionless file as JavaScript unless its shebang names another interpreter", () => {
    const dir = makeTempDir();
    const files = {
      cts: ["greet.cts", 'import _ from "lodash";\nexport const greet = (name: string): string => _.template("Hi")({ name });\n'],
      node: ["www", '#!/usr/bin/env node\nconst app = require("../app");\napp.listen(3000);\n'],
      plain: ["cli", 'require("./main");\n'],
      shell: ["start", "#!/bin/sh\nexec node index.js\n"],
      markdown: ["README.md", "# app\n"],
    };
    for (const [name, source] of Object.values(files)) {
      writeFileSync(path.join(dir, name), source, "utf8");
    }
    const file = (key: keyof typeof files) => path.join(dir, files[key][0]);

    expect(parseFile(file("cts")).calls).toEqual([{ callee: "_.template", line: 2 }]);
    expect(parseFile(file("node")).imports.map((entry) => entry.source)).toEqual(["../app"]);
    expect([file("cts"), file("node"), file("plain"), file("shell"), file("markdown")].map(languageOf)).toEqual(["ts", "js", "js", null, null]);
    expect(() => parseFile(file("shell"))).toThrow("Not JavaScript");
  });
});
