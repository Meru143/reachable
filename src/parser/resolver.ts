// Module path resolver (aliases, node_modules).
import { existsSync, statSync } from "node:fs";
import path from "node:path";

import ts from "typescript";

const RESOLVABLE_EXTENSIONS = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"];
// TypeScript sources import each other by their compiled names: ./greet.js is greet.ts, ./greet.cjs is greet.cts.
const TYPESCRIPT_SOURCES = new Map([
  [".js", [".ts", ".tsx"]],
  [".jsx", [".tsx"]],
  [".mjs", [".mts"]],
  [".cjs", [".cts"]],
]);

type TsPathConfig = {
  baseUrl: string;
  paths: Record<string, string[]>;
};

let cachedConfig: { cwd: string; value: TsPathConfig | null } | null = null;

function packageNameFromImport(importPath: string): string {
  if (importPath.startsWith("@")) {
    return importPath.split("/").slice(0, 2).join("/");
  }

  return importPath.split("/")[0];
}

/** The file a path names: the file itself, with an extension added, its TypeScript source, or a directory's index. */
export function resolveFileCandidate(candidate: string): string | null {
  const compiled = path.extname(candidate);
  const sources = (TYPESCRIPT_SOURCES.get(compiled) ?? []).map((source) => `${candidate.slice(0, -compiled.length)}${source}`);
  for (const file of [candidate, ...sources]) {
    if (existsSync(file) && statSync(file).isFile()) {
      return file;
    }
  }

  for (const extension of RESOLVABLE_EXTENSIONS) {
    if (existsSync(`${candidate}${extension}`)) {
      return `${candidate}${extension}`;
    }
  }

  for (const extension of RESOLVABLE_EXTENSIONS) {
    const indexCandidate = path.join(candidate, `index${extension}`);
    if (existsSync(indexCandidate)) {
      return indexCandidate;
    }
  }

  return null;
}

function loadTsPathConfig(cwd: string): TsPathConfig | null {
  if (cachedConfig?.cwd === cwd) {
    return cachedConfig.value;
  }

  const tsconfigPath = path.join(cwd, "tsconfig.json");
  if (!existsSync(tsconfigPath)) {
    cachedConfig = { cwd, value: null };
    return null;
  }

  const readResult = ts.readConfigFile(tsconfigPath, ts.sys.readFile);
  if (readResult.error) {
    cachedConfig = { cwd, value: null };
    return null;
  }

  const compilerOptions = readResult.config?.compilerOptions ?? {};
  const baseUrl = compilerOptions.baseUrl ? path.resolve(cwd, compilerOptions.baseUrl) : cwd;
  const paths = compilerOptions.paths ?? {};
  const value = Object.keys(paths).length > 0 ? { baseUrl, paths } : null;

  cachedConfig = { cwd, value };
  return value;
}

function resolveAlias(importPath: string, cwd: string): string | null {
  const config = loadTsPathConfig(cwd);
  if (!config) {
    return null;
  }

  for (const [aliasPattern, targets] of Object.entries(config.paths)) {
    const escapedPattern = aliasPattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace("\\*", "(.*)");
    const matcher = new RegExp(`^${escapedPattern}$`);
    const match = importPath.match(matcher);

    if (!match) {
      continue;
    }

    const wildcardValue = match[1] ?? "";
    for (const target of targets) {
      const substituted = target.split("*").join(wildcardValue);
      const absoluteTarget = path.isAbsolute(substituted) ? substituted : path.resolve(config.baseUrl, substituted);
      const resolved = resolveFileCandidate(absoluteTarget);
      if (resolved) {
        return resolved;
      }
    }
  }

  return null;
}

export function resolveImport(importPath: string, fromFile: string, cwd: string): string | null {
  if (importPath.startsWith("./") || importPath.startsWith("../")) {
    return resolveFileCandidate(path.resolve(path.dirname(fromFile), importPath));
  }

  const aliasedImport = resolveAlias(importPath, cwd);
  if (aliasedImport) {
    return aliasedImport;
  }

  if (!path.isAbsolute(importPath)) {
    return packageNameFromImport(importPath);
  }

  return resolveFileCandidate(importPath);
}
