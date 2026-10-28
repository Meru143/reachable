import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { resolveFileCandidate, resolveImport } from "../../src/parser/resolver.js";

const createdDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "reachable-resolver-"));
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

describe("parser/resolver", () => {
  it("resolves relative imports from nested source files", () => {
    const cwd = makeTempDir();
    const fromFile = path.join(cwd, "src", "auth", "middleware.ts");
    const targetFile = path.join(cwd, "src", "utils", "index.ts");

    mkdirSync(path.dirname(fromFile), { recursive: true });
    mkdirSync(path.dirname(targetFile), { recursive: true });
    writeFileSync(fromFile, "export {};\n", "utf8");
    writeFileSync(targetFile, "export const util = true;\n", "utf8");

    expect(resolveImport("../utils", fromFile, cwd)).toBe(targetFile);
  });

  it("resolves tsconfig path aliases", () => {
    const cwd = makeTempDir();
    const fromFile = path.join(cwd, "src", "pages", "home.tsx");
    const targetFile = path.join(cwd, "src", "components", "Button.tsx");

    mkdirSync(path.dirname(fromFile), { recursive: true });
    mkdirSync(path.dirname(targetFile), { recursive: true });
    writeFileSync(
      path.join(cwd, "tsconfig.json"),
      JSON.stringify(
        {
          compilerOptions: {
            baseUrl: ".",
            paths: {
              "@/*": ["src/*"],
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );
    writeFileSync(fromFile, "export {};\n", "utf8");
    writeFileSync(targetFile, "export const Button = () => null;\n", "utf8");

    expect(resolveImport("@/components/Button", fromFile, cwd)).toBe(targetFile);
  });

  it("replaces every wildcard occurrence in tsconfig path targets", () => {
    const cwd = makeTempDir();
    const fromFile = path.join(cwd, "src", "pages", "home.tsx");
    const targetFile = path.join(cwd, "src", "generated", "widgets", "mirror", "widgets.ts");

    mkdirSync(path.dirname(fromFile), { recursive: true });
    mkdirSync(path.dirname(targetFile), { recursive: true });
    writeFileSync(
      path.join(cwd, "tsconfig.json"),
      JSON.stringify(
        {
          compilerOptions: {
            baseUrl: ".",
            paths: {
              "@/*": ["src/generated/*/mirror/*"],
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );
    writeFileSync(fromFile, "export {};\n", "utf8");
    writeFileSync(targetFile, "export const widget = true;\n", "utf8");

    expect(resolveImport("@/widgets", fromFile, cwd)).toBe(targetFile);
  });

  it("resolves a directory to its index file and a compiled name to its TypeScript source, never to a directory", () => {
    const cwd = makeTempDir();
    for (const file of [path.join("lib", "index.js"), path.join("src", "greet.cts"), path.join("src", "util.ts"), path.join("src", "dir.js", "keep")]) {
      mkdirSync(path.dirname(path.join(cwd, file)), { recursive: true });
      writeFileSync(path.join(cwd, file), "", "utf8");
    }

    expect(resolveFileCandidate(path.join(cwd, "lib"))).toBe(path.join(cwd, "lib", "index.js"));
    expect(resolveFileCandidate(path.join(cwd, "src", "greet.cjs"))).toBe(path.join(cwd, "src", "greet.cts"));
    expect(resolveFileCandidate(path.join(cwd, "src", "util.js"))).toBe(path.join(cwd, "src", "util.ts"));
    expect(resolveFileCandidate(path.join(cwd, "src", "greet"))).toBe(path.join(cwd, "src", "greet.cts"));
    expect(resolveFileCandidate(path.join(cwd, "src", "dir.js"))).toBeNull();
  });
});
