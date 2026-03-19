// Reachability analysis orchestration.
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

import { buildGraph } from "./graph/builder.js";
import { findPathTo } from "./graph/traversal.js";
import { logger } from "./utils/logger.js";
import { clearCache, createCacheKey, getCached, getCachedRegardlessOfTtl, setCache } from "./vuln/cache.js";
import { queryBatch } from "./vuln/osv.js";
import { extractVulnSymbols } from "./vuln/symbols.js";
import type { Advisory, ReachabilityResult, VulnSymbol } from "./vuln/types.js";
import { parsePackageLock } from "./utils/packagelock.js";
import { ReachableError } from "./utils/errors.js";

export interface AnalyzeOptions {
  cwd: string;
  entry?: string[];
  ignore?: string[];
  depth?: number;
  dryRun?: boolean;
  noCache?: boolean;
  cacheDir?: string;
  cacheTtlHours?: number;
}

function resolveFileCandidate(candidate: string): string | null {
  if (existsSync(candidate)) {
    return candidate;
  }

  for (const extension of [".ts", ".tsx", ".mts", ".js", ".jsx", ".mjs", ".cjs"]) {
    if (existsSync(`${candidate}${extension}`)) {
      return `${candidate}${extension}`;
    }
  }

  return null;
}

function preferredEntryCandidates(candidate: string, packageDir: string): string[] {
  const relativeCandidate = path.relative(packageDir, candidate);
  const pathSegments = relativeCandidate.split(path.sep);

  if (pathSegments[0] !== "dist") {
    return [candidate];
  }

  const relativeWithoutExtension = relativeCandidate.replace(/^dist[\\/]/, "").replace(/\.[^.]+$/, "");
  const sourceCandidates = [path.join(packageDir, "src", relativeWithoutExtension), path.join(packageDir, relativeWithoutExtension)]
    .map((entryCandidate) => resolveFileCandidate(entryCandidate))
    .filter((entryCandidate): entryCandidate is string => Boolean(entryCandidate));

  return sourceCandidates.length > 0 ? sourceCandidates : [candidate];
}

function packageJsonAt(directory: string): Record<string, unknown> | null {
  const packageJsonPath = path.join(directory, "package.json");
  if (!existsSync(packageJsonPath)) {
    return null;
  }

  return JSON.parse(readFileSync(packageJsonPath, "utf8")) as Record<string, unknown>;
}

function workspaceDirectories(cwd: string): string[] {
  const packageJson = packageJsonAt(cwd);
  const workspaces = packageJson?.workspaces;
  if (!Array.isArray(workspaces)) {
    return [];
  }

  const directories: string[] = [];
  for (const pattern of workspaces.filter((value): value is string => typeof value === "string")) {
    if (pattern.endsWith("/*")) {
      const baseDir = path.join(cwd, pattern.slice(0, -2));
      if (!existsSync(baseDir)) {
        continue;
      }

      for (const entry of readdirSync(baseDir)) {
        const fullPath = path.join(baseDir, entry);
        if (statSync(fullPath).isDirectory() && existsSync(path.join(fullPath, "package.json"))) {
          directories.push(fullPath);
        }
      }
      continue;
    }

    const fullPath = path.join(cwd, pattern);
    if (existsSync(path.join(fullPath, "package.json"))) {
      directories.push(fullPath);
    }
  }

  return directories;
}

function hasPackageLock(directory: string): boolean {
  return existsSync(path.join(directory, "package-lock.json")) || existsSync(path.join(directory, "node_modules", ".package-lock.json"));
}

function collectInstalledPackages(cwd: string) {
  const installedPackages = new Map<string, ReturnType<typeof parsePackageLock>[number]>();
  let foundLockfile = false;

  for (const packageDir of [cwd, ...workspaceDirectories(cwd)]) {
    if (!hasPackageLock(packageDir)) {
      continue;
    }

    foundLockfile = true;

    for (const installedPackage of parsePackageLock(packageDir)) {
      installedPackages.set(`${installedPackage.name}@${installedPackage.version}`, installedPackage);
    }
  }

  if (!foundLockfile) {
    throw new ReachableError("E001", "Run npm install first, or specify --cwd");
  }

  return [...installedPackages.values()];
}

function entryCandidatesForPackage(packageDir: string): string[] {
  const packageJson = packageJsonAt(packageDir);
  if (!packageJson) {
    return [];
  }

  const candidates: string[] = [];
  const main = packageJson.main;
  if (typeof main === "string") {
    const resolvedMain = resolveFileCandidate(path.resolve(packageDir, main));
    if (resolvedMain) {
      candidates.push(...preferredEntryCandidates(resolvedMain, packageDir));
    }
  }

  const exportsField = packageJson.exports;
  if (exportsField && typeof exportsField === "object" && !Array.isArray(exportsField)) {
    const exportMap = exportsField as Record<string, unknown>;
    const rootExport = exportMap["."] ?? exportMap["./index"];
    if (typeof rootExport === "string") {
      const resolvedExport = resolveFileCandidate(path.resolve(packageDir, rootExport));
      if (resolvedExport) {
        candidates.push(...preferredEntryCandidates(resolvedExport, packageDir));
      }
    } else if (rootExport && typeof rootExport === "object") {
      const conditionalExportMap = rootExport as Record<string, unknown>;
      for (const key of ["require", "default"]) {
        const conditionalExport = conditionalExportMap[key];
        if (typeof conditionalExport === "string") {
          const resolvedExport = resolveFileCandidate(path.resolve(packageDir, conditionalExport));
          if (resolvedExport) {
            candidates.push(...preferredEntryCandidates(resolvedExport, packageDir));
            break;
          }
        }
      }
    }
  }

  const binField = packageJson.bin;
  if (typeof binField === "string") {
    const resolvedBin = resolveFileCandidate(path.resolve(packageDir, binField));
    if (resolvedBin) {
      candidates.push(...preferredEntryCandidates(resolvedBin, packageDir));
    }
  } else if (binField && typeof binField === "object") {
    for (const value of Object.values(binField)) {
      if (typeof value !== "string") {
        continue;
      }
      const resolvedBin = resolveFileCandidate(path.resolve(packageDir, value));
      if (resolvedBin) {
        candidates.push(...preferredEntryCandidates(resolvedBin, packageDir));
      }
    }
  }

  for (const fallback of ["src/index.ts", "index.ts", "app.ts"]) {
    const resolvedFallback = resolveFileCandidate(path.resolve(packageDir, fallback));
    if (resolvedFallback) {
      candidates.push(resolvedFallback);
    }
  }

  return [...new Set(candidates)];
}

export function detectEntryPoints(cwd: string, explicitEntries?: string[]): string[] {
  if (explicitEntries && explicitEntries.length > 0) {
    return explicitEntries.map((entry) => path.resolve(cwd, entry));
  }

  const packageDirs = [cwd, ...workspaceDirectories(cwd)];
  const entryPoints = packageDirs.flatMap((packageDir) => entryCandidatesForPackage(packageDir));

  if (entryPoints.length === 0) {
    logger.warn({ cwd }, "No entry point detected");
    throw new ReachableError("E002", "Specify an entry point with --entry src/index.ts");
  }

  return [...new Set(entryPoints)];
}

export function collectSourceFiles(cwd: string): string[] {
  const sourceFiles: string[] = [];
  const ignoredDirectories = new Set(["node_modules", "dist", "coverage", ".git", ".reachable-cache"]);

  function walk(directory: string): void {
    for (const entry of readdirSync(directory)) {
      if (ignoredDirectories.has(entry)) {
        continue;
      }

      const fullPath = path.join(directory, entry);
      const stats = statSync(fullPath);

      if (stats.isDirectory()) {
        walk(fullPath);
        continue;
      }

      if (/\.[cm]?[jt]sx?$/.test(entry)) {
        sourceFiles.push(fullPath);
      }
    }
  }

  walk(cwd);
  return sourceFiles;
}

function cacheSettings(options: AnalyzeOptions): { cacheDir: string; ttlHours: number } {
  return {
    cacheDir: process.env.REACHABLE_CACHE_DIR ?? path.resolve(options.cwd, options.cacheDir ?? ".reachable-cache"),
    ttlHours: options.cacheTtlHours ?? 24,
  };
}

async function advisoriesForPackage(
  packageName: string,
  packageVersion: string,
  options: AnalyzeOptions,
): Promise<{ advisories: Advisory[]; degradedToUnknown: boolean }> {
  const { cacheDir, ttlHours } = cacheSettings(options);
  const cacheKey = createCacheKey(packageName, packageVersion);

  if (!options.noCache) {
    const cached = getCached(cacheKey, cacheDir, ttlHours);
    if (cached) {
      return {
        advisories: cached,
        degradedToUnknown: false,
      };
    }
  }

  if (options.dryRun) {
    return {
      advisories: [],
      degradedToUnknown: false,
    };
  }

  try {
    const advisories = await queryBatch([{ name: packageName, version: packageVersion, ecosystem: "npm" }]);
    if (!options.noCache) {
      setCache(cacheKey, advisories, cacheDir);
    }

    return {
      advisories,
      degradedToUnknown: false,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!options.noCache) {
      const staleAdvisories = getCachedRegardlessOfTtl(cacheKey, cacheDir);
      if (staleAdvisories) {
        logger.warn(
          {
            error: message,
            package: packageName,
            version: packageVersion,
          },
          "Using stale advisory cache after OSV fetch failure",
        );
        return {
          advisories: staleAdvisories,
          degradedToUnknown: true,
        };
      }
    }

    logger.warn(
      {
        error: message,
        package: packageName,
        version: packageVersion,
      },
      "OSV advisory lookup failed; continuing without advisories",
    );
    return {
      advisories: [],
      degradedToUnknown: true,
    };
  }
}

function matchesSymbol(nodeName: string, exportedSymbol: string): boolean {
  return nodeName === exportedSymbol || nodeName.endsWith(`.${exportedSymbol}`);
}

function sortResults(results: ReachabilityResult[]): ReachabilityResult[] {
  const order = new Map<ReachabilityResult["status"], number>([
    ["REACHABLE", 0],
    ["UNKNOWN", 1],
    ["UNREACHABLE", 2],
  ]);

  return [...results].sort((left, right) => {
    const leftOrder = order.get(left.status) ?? 99;
    const rightOrder = order.get(right.status) ?? 99;
    if (leftOrder !== rightOrder) {
      return leftOrder - rightOrder;
    }

    return right.advisory.cvssScore - left.advisory.cvssScore;
  });
}

export async function analyze(options: AnalyzeOptions): Promise<ReachabilityResult[]> {
  const cwd = path.resolve(options.cwd);
  const ignoreSet = new Set(options.ignore ?? []);
  const { cacheDir } = cacheSettings(options);

  if (options.noCache) {
    clearCache(cacheDir);
  }

  const installedPackages = collectInstalledPackages(cwd);
  const entryPoints = detectEntryPoints(cwd, options.entry);
  const sourceFiles = collectSourceFiles(cwd);
  const graph = buildGraph(sourceFiles, entryPoints, cwd);
  const results: ReachabilityResult[] = [];

  for (const installedPackage of installedPackages) {
    const { advisories, degradedToUnknown } = await advisoriesForPackage(installedPackage.name, installedPackage.version, options);

    for (const advisory of advisories) {
      for (const vulnSymbol of extractVulnSymbols(advisory)) {
        if (ignoreSet.has(vulnSymbol.ghsaId)) {
          continue;
        }

        if (degradedToUnknown || vulnSymbol.exportedSymbol === null) {
          results.push({
            advisory: vulnSymbol,
            status: "UNKNOWN",
            callPath: null,
          });
          continue;
        }

        const packageNodeId = `pkg:${vulnSymbol.package}::module`;
        let callPath: string[] | null = null;

        for (const edge of graph.edges.filter((entry) => entry.to === packageNodeId)) {
          const siblingNodes = graph.edges
            .filter((candidate) => candidate.from === edge.from)
            .map((candidate) => graph.nodes.get(candidate.to))
            .filter((candidate): candidate is NonNullable<typeof candidate> => Boolean(candidate));

          const matchingNode = siblingNodes.find((node) => matchesSymbol(node.name, vulnSymbol.exportedSymbol!));
          if (!matchingNode) {
            continue;
          }

          callPath = findPathTo(graph, matchingNode.id);
          if (callPath) {
            break;
          }
        }

        results.push({
          advisory: vulnSymbol as VulnSymbol,
          status: callPath ? "REACHABLE" : "UNREACHABLE",
          callPath,
        });
      }
    }
  }

  return sortResults(results);
}
