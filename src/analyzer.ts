// Reachability analysis orchestration.
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

import { buildGraph, isSkippedTestFile } from "./graph/builder.js";
import { findPathTo } from "./graph/traversal.js";
import type { CallGraph } from "./graph/types.js";
import { languageOf, parseFile } from "./parser/index.js";
import { resolveFileCandidate, resolveImport } from "./parser/resolver.js";
import { logger } from "./utils/logger.js";
import { clearCache, createCacheKey, getCached, getCachedRegardlessOfTtl, setCache } from "./vuln/cache.js";
import { fetchVulns, queryBatch } from "./vuln/osv.js";
import { extractVulnSymbols } from "./vuln/symbols.js";
import type { Advisory, InstalledPackage, ReachabilityResult, UnknownReason } from "./vuln/types.js";
import { addInstalledPackage, excludedPackagePaths, packagesUsedByDependencies, parsePackageLock } from "./utils/packagelock.js";
import { OsvApiError, ReachableError } from "./utils/errors.js";

export interface AnalyzeOptions {
  cwd: string;
  entry?: string[];
  ignore?: string[];
  dryRun?: boolean;
  noCache?: boolean;
  cacheDir?: string;
  cacheTtlHours?: number;
}

export interface AnalyzeResult {
  results: ReachabilityResult[];
  /** name@version of each package OSV could not be asked about: the lookup failed (any advisories shown for it come
   * from an expired cache entry), or, on a dry run, it has no unexpired cache entry. */
  unchecked: string[];
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

function collectInstalledPackages(cwd: string): { installedPackages: InstalledPackage[]; usedByDependencies: Set<string> } {
  const installedPackages = new Map<string, InstalledPackage>();
  const usedByDependencies = new Set<string>();
  let foundLockfile = false;

  for (const packageDir of [cwd, ...workspaceDirectories(cwd)]) {
    if (!hasPackageLock(packageDir)) {
      continue;
    }

    foundLockfile = true;

    for (const installedPackage of parsePackageLock(packageDir)) {
      addInstalledPackage(installedPackages, installedPackage);
    }

    for (const name of packagesUsedByDependencies(packageDir)) {
      usedByDependencies.add(name);
    }
  }

  if (!foundLockfile) {
    throw new ReachableError("E001", "Run npm install first, or specify --cwd");
  }

  return { installedPackages: [...installedPackages.values()], usedByDependencies };
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

// An entry point the graph cannot start from leaves every verdict UNREACHABLE, so a given entry must exist (and
// buildGraph fails on one it cannot parse), and a detected one that is not code is dropped.
export function detectEntryPoints(cwd: string, explicitEntries?: string[]): string[] {
  if (explicitEntries && explicitEntries.length > 0) {
    return explicitEntries.map((entry) => {
      const file = resolveFileCandidate(path.resolve(cwd, entry));
      if (!file) {
        throw new ReachableError("E002", `Entry point not found: ${entry}`);
      }

      return file;
    });
  }

  const packageDirs = [cwd, ...workspaceDirectories(cwd)];
  const entryPoints = packageDirs
    .flatMap((packageDir) => entryCandidatesForPackage(packageDir))
    .filter((file) => {
      if (languageOf(file)) {
        return true;
      }

      logger.warn({ file }, "Skipping an entry point that is not JavaScript or TypeScript");
      return false;
    });

  if (entryPoints.length === 0) {
    logger.warn({ cwd }, "No entry point detected");
    throw new ReachableError("E002", "Specify an entry point with --entry src/index.ts");
  }

  return [...new Set(entryPoints)];
}

export function collectSourceFiles(cwd: string, pattern = /\.[cm]?[jt]sx?$/): string[] {
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

      if (pattern.test(entry)) {
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

type Lookup = {
  advisories: Advisory[];
  degraded: Set<string>;
  /** OSV could not say which advisories affect the package now: some are missing, or all come from an expired cache
   * entry, which cannot hold the ones published since. */
  unchecked: boolean;
};

// Shared by one run: every advisory record is fetched once, and once a lookup has failed (after its retries) for a
// reason that is not about the one request, later packages do not wait through retries of their own.
type OsvSession = { fetched: Map<string, Promise<Advisory>>; outage?: unknown };

// A 404 for a withdrawn id or a 400 for one query is about that request; anything else means OSV is unreachable.
function isOutage(error: unknown): boolean {
  return !(error instanceof OsvApiError) || error.statusCode === 429 || error.statusCode >= 500;
}

async function advisoriesForPackage(packageName: string, packageVersion: string, options: AnalyzeOptions, osv: OsvSession): Promise<Lookup> {
  const { cacheDir, ttlHours } = cacheSettings(options);
  const cacheKey = createCacheKey(packageName, packageVersion);

  if (!options.noCache) {
    const cached = getCached(cacheKey, cacheDir, ttlHours);
    if (cached) {
      return { advisories: cached, degraded: new Set(), unchecked: false };
    }
  }

  if (options.dryRun) {
    return { advisories: [], degraded: new Set(), unchecked: true };
  }

  try {
    if (osv.outage) {
      throw osv.outage;
    }

    const ids = await queryBatch([{ name: packageName, version: packageVersion, ecosystem: "npm" }]).catch((error: unknown) => {
      if (isOutage(error)) {
        osv.outage = error;
      }
      throw error;
    });
    const { advisories, failed } = await fetchVulns(ids, osv.fetched);
    osv.outage ??= failed.find(({ error }) => isOutage(error))?.error;
    if (failed.length === 0) {
      if (!options.noCache) {
        // A cache that cannot be written (read-only checkout) must not turn a successful lookup into a failed one.
        try {
          setCache(cacheKey, advisories, cacheDir);
        } catch (cacheError) {
          logger.warn(
            { error: cacheError instanceof Error ? cacheError.message : String(cacheError), cacheDir },
            "Could not write the advisory cache; continuing without it",
          );
        }
      }

      return { advisories, degraded: new Set(), unchecked: false };
    }

    // Keep the records that arrived. A failed one comes from the stale cache when it has it, and is missing
    // otherwise. A partial result is not cached, so the next run retries.
    const stale = options.noCache ? [] : getCachedRegardlessOfTtl(cacheKey, cacheDir) ?? [];
    const staleRecords = stale.filter((advisory) => failed.some((entry) => entry.id === advisory.id));
    logger.warn(
      {
        package: packageName,
        version: packageVersion,
        failed: failed.map(({ id, error }) => `${id}: ${error instanceof Error ? error.message : String(error)}`),
        fromStaleCache: staleRecords.map((advisory) => advisory.id),
      },
      "Some OSV advisory records could not be fetched",
    );
    return {
      advisories: [...advisories, ...staleRecords],
      degraded: new Set(staleRecords.map((advisory) => advisory.id)),
      unchecked: staleRecords.length < failed.length,
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
        return { advisories: staleAdvisories, degraded: new Set(staleAdvisories.map((advisory) => advisory.id)), unchecked: true };
      }
    }

    logger.warn(
      {
        error: message,
        package: packageName,
        version: packageVersion,
      },
      "OSV advisory lookup failed and nothing is cached; this package is not checked",
    );
    return { advisories: [], degraded: new Set(), unchecked: true };
  }
}

function matchesSymbol(nodeName: string, exportedSymbol: string): boolean {
  return nodeName === exportedSymbol || nodeName.endsWith(`.${exportedSymbol}`);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// A call matching the symbol, in a module that imports the package, on a path from an entry point.
function findCallPath(graph: CallGraph, packageNodeId: string, symbol: string): string[] | null {
  for (const edge of graph.edges.filter((entry) => entry.to === packageNodeId)) {
    const siblingNodes = graph.edges
      .filter((candidate) => candidate.from === edge.from)
      .map((candidate) => graph.nodes.get(candidate.to))
      .filter((candidate): candidate is NonNullable<typeof candidate> => Boolean(candidate));

    const matchingNode = siblingNodes.find((node) => matchesSymbol(node.name, symbol));
    const callPath = matchingNode ? findPathTo(graph, matchingNode.id) : null;
    if (callPath) {
      return callPath;
    }
  }

  return null;
}

function stringLeaves(value: unknown): string[] {
  if (typeof value === "string") {
    return [value];
  }

  return value && typeof value === "object" ? Object.values(value).flatMap(stringLeaves) : [];
}

// Targets of a package.json "exports" or "imports" entry, wildcards included ("./*": "./lib/*.js").
function mapTargets(map: Record<string, unknown> | null, key: string): string[] {
  if (!map) {
    return [];
  }

  if (key in map) {
    return stringLeaves(map[key]);
  }

  for (const [pattern, value] of Object.entries(map)) {
    const [prefix, suffix, ...rest] = pattern.split("*");
    if (suffix !== undefined && rest.length === 0 && key.length >= prefix.length + suffix.length && key.startsWith(prefix) && key.endsWith(suffix)) {
      const match = key.slice(prefix.length, key.length - suffix.length);
      return stringLeaves(value).map((target) => target.split("*").join(match));
    }
  }

  return [];
}

// exportText: the entry files and the files they import directly. usedNames: names used (called, aliased, passed,
// read) in any file the entry files reach through static relative imports and re-exports.
type PackageCode = { exportText: string; usedNames: Set<string> };

// ponytail: a cap instead of streaming; a bigger package stays unconfirmed (UNKNOWN), never UNREACHABLE.
const MAX_PACKAGE_FILES = 2000;

// The installed copy the app loads (node_modules of the project or a workspace), preferring the given version.
// Uses behind a dynamic require are not seen.
function readPackageCode(cwd: string, packageName: string, version: string, importedSubpaths: string[]): PackageCode | null {
  const packageDirs = [cwd, ...workspaceDirectories(cwd)]
    .map((directory) => path.join(directory, "node_modules", packageName))
    .filter((directory) => existsSync(path.join(directory, "package.json")));
  const packageDir = packageDirs.find((directory) => packageJsonAt(directory)?.version === version) ?? packageDirs[0];
  if (!packageDir) {
    return null;
  }

  const manifest = packageJsonAt(packageDir) ?? {};
  const exportsField = manifest.exports;
  const subpathMap =
    exportsField && typeof exportsField === "object" && Object.keys(exportsField).some((key) => key.startsWith("."))
      ? (exportsField as Record<string, unknown>)
      : null;
  const importsMap = manifest.imports && typeof manifest.imports === "object" ? (manifest.imports as Record<string, unknown>) : null;
  const resolve = (target: string, fromFile: string): string | null => {
    const resolved = resolveImport(target, fromFile, packageDir);
    return resolved && path.isAbsolute(resolved) ? resolved : null;
  };
  const manifestPath = path.join(packageDir, "package.json");
  const parsed = new Map<string, ReturnType<typeof parseFile>>();
  const parse = (file: string | null): void => {
    if (!file || parsed.has(file)) {
      return;
    }

    try {
      parsed.set(file, parseFile(file, { usedNames: true }));
    } catch {
      // Not JavaScript or TypeScript (JSON, native addons).
    }
  };

  const resolveEntry = (target: string): string | null => resolve(target.startsWith(".") ? target : `./${target}`, manifestPath);

  // Every target the package exports, subpaths included (pkg/unsafe loads code the root entry may never require).
  for (const entry of [manifest.main ?? "index", manifest.module, ...stringLeaves(exportsField)]) {
    if (typeof entry === "string") {
      parse(resolveEntry(entry));
    }
  }

  // Subpaths the app imports (lodash/template); one that cannot be followed leaves the symbol unconfirmed.
  for (const subpath of importedSubpaths) {
    const files = (subpathMap ? mapTargets(subpathMap, subpath) : [subpath]).map(resolveEntry).filter((file): file is string => file !== null);
    if (files.length === 0) {
      return null;
    }

    files.forEach(parse);
  }

  const entryFiles = new Set(parsed.keys());
  const exportFiles = new Set(entryFiles);
  const queue = [...entryFiles];
  while (queue.length > 0) {
    const file = queue.shift() ?? "";
    const module = parsed.get(file);
    const sources = [...(module?.imports ?? []).map((entry) => entry.source), ...(module?.exports ?? []).flatMap((entry) => entry.source ?? [])];

    for (const source of sources) {
      // The package importing itself by name is not followed, so the symbol stays unconfirmed.
      if (source === packageName || source.startsWith(`${packageName}/`)) {
        return null;
      }

      // "#internal/x" resolves through package.json "imports"; one that cannot be followed leaves it unconfirmed.
      const targets = source.startsWith("#")
        ? mapTargets(importsMap, source).map(resolveEntry)
        : source.startsWith(".")
          ? [resolve(source, file)]
          : [];
      if (source.startsWith("#") && !targets.some((target) => target !== null)) {
        return null;
      }

      for (const target of targets) {
        if (!target || parsed.has(target)) {
          continue;
        }

        if (parsed.size >= MAX_PACKAGE_FILES) {
          return null;
        }

        parse(target);
        if (parsed.has(target)) {
          queue.push(target);
          if (entryFiles.has(file)) {
            exportFiles.add(target);
          }
        }
      }
    }
  }

  return {
    exportText: [...exportFiles].map((file) => readFileSync(file, "utf8")).join("\n"),
    usedNames: new Set([...parsed.values()].flatMap((module) => [...(module.usedNames ?? [])])),
  };
}

// Named exports: CommonJS assignments, compiled ESM, ESM declarations and lists, and namespace members
// (lodash.template = template). A default export is not one: the app can call it by any name.
function exportsSymbol(text: string, symbol: string): boolean {
  const quoted = escapeRegExp(symbol);
  const name = String.raw`(?<![\w$])${quoted}(?![\w$])`;
  return [
    String.raw`\bexports\.${name}`,
    String.raw`\bexports\[\s*["']${quoted}["']\s*\]`,
    String.raw`defineProperty\(\s*(?:module\.)?exports\s*,\s*["']${quoted}["']`,
    String.raw`\bexport\s+(?:declare\s+)?(?:async\s+)?(?:function\*?|class|const|let|var)\s+${name}`,
    String.raw`\bexport\s*\{[^}]*${name}`,
    String.raw`\bmodule\.exports\s*=\s*\{[^}]*${name}`,
    String.raw`[\w$]\.${name}\s*=(?!=)`,
  ].some((pattern) => new RegExp(pattern).test(text));
}

// Local names an export is bound to (exports.template = compile, export { compile as template }, e.template=t in
// minified code): the package's own code uses those names.
function exportedLocalNames(text: string, symbol: string): string[] {
  const name = String.raw`(?<![\w$])${escapeRegExp(symbol)}(?![\w$])`;
  return [
    String.raw`\.${name}\s*=\s*([A-Za-z_$][\w$]*)\s*[;,\n]`,
    String.raw`${name}\s*:\s*([A-Za-z_$][\w$]*)\s*[,}\n]`,
    String.raw`([A-Za-z_$][\w$]*)\s+as\s+${name}`,
  ].flatMap((pattern) => [...text.matchAll(new RegExp(pattern, "g"))].map((match) => match[1]));
}

type Verdict = Omit<ReachabilityResult, "advisory">;

// The app's own files are the only code in the graph: a verdict about dependency code is never UNREACHABLE. An
// UNREACHABLE here still goes through the project and dependency searches in analyze().
function verdictFor(cwd: string, graph: CallGraph, usedByDependencies: Set<string>) {
  const packageCode = new Map<string, PackageCode | null>();

  const unknown = (reason: UnknownReason): Verdict => ({ status: "UNKNOWN", callPath: null, reason });

  // The package exports the symbol and its own code never uses it (no call, alias, callback or read), so only the
  // app's calls can reach it.
  const isEntryPointOfPackage = ({ name, version }: InstalledPackage, symbol: string): boolean => {
    const key = `${name}@${version}`;
    if (!packageCode.has(key)) {
      const subpaths = graph.edges
        .filter((edge) => edge.to === `pkg:${name}::module` && edge.importedFrom.startsWith(`${name}/`))
        .map((edge) => `.${edge.importedFrom.slice(name.length)}`);
      packageCode.set(key, readPackageCode(cwd, name, version, [...new Set(subpaths)]));
    }

    const code = packageCode.get(key);
    if (!code || !exportsSymbol(code.exportText, symbol)) {
      return false;
    }

    const localNames = [symbol, ...exportedLocalNames(code.exportText, symbol)];
    return !localNames.some((localName) => code.usedNames.has(localName));
  };

  return (installed: InstalledPackage, symbol: string | null, confident: boolean, degraded: boolean): Verdict => {
    // The app's imports load the hoisted copy; a copy nested under another package is loaded only by that package.
    if (installed.nested) {
      return unknown("transitive");
    }

    const packageNodeId = `pkg:${installed.name}::module`;
    if (!graph.nodes.has(packageNodeId)) {
      return unknown("not-imported");
    }

    if (symbol === null) {
      return unknown("symbol-unknown");
    }

    const callPath = findCallPath(graph, packageNodeId, symbol);
    if (callPath) {
      return { status: "REACHABLE", callPath };
    }

    // An expired cache entry is good enough to show a call path, never to rule one out.
    if (degraded) {
      return unknown("lookup-failed");
    }

    if (usedByDependencies.has(installed.name)) {
      return unknown("transitive");
    }

    if (!confident || !isEntryPointOfPackage(installed, symbol)) {
      return unknown("symbol-unconfirmed");
    }

    return { status: "UNREACHABLE", callPath: null };
  };
}

// Files whose text can name a function: every source file, and components and templates, which are not parsed.
const PROJECT_FILES = /\.([cm]?[jt]sx?|vue|svelte|astro|ejs|pug|jade|hbs|handlebars|mustache|njk|liquid|eta|html?)$/;

// Which of `symbols` a project file mentions, as raw text, reachable from an entry point or not: every file
// collectSourceFiles finds (test files left out, as in the graph), components and templates, and the graph's own files
// (an extensionless bin, dist/ files an entry imports). Routes loaded with fs.readdirSync and require(file) never join
// the graph, aliases (import { template as t }), callbacks (.map(_.trim)) and re-exports hide calls from it, and a file
// the parser cannot read still counts. One pass for all symbols, stopping once each is found.
function mentionedInProject(cwd: string, graph: CallGraph, symbols: string[]): Set<string> {
  const files = new Set([
    ...[...graph.nodes.values()].filter((node) => node.name === "module" && !node.id.startsWith("pkg:")).map((node) => path.resolve(cwd, node.file)),
    ...collectSourceFiles(cwd, PROJECT_FILES).filter((file) => !isSkippedTestFile(file)),
  ]);
  const name = new RegExp(String.raw`(?<![\w$])(${symbols.map(escapeRegExp).join("|")})(?![\w$])`, "g");
  const found = new Set<string>();
  for (const file of files) {
    for (const match of readFileSync(file, "utf8").matchAll(name)) {
      found.add(match[1]);
    }

    if (found.size === symbols.length) {
      break;
    }
  }

  return found;
}

// ponytail: one pass over the installed packages' JavaScript, capped at 256 MB read; past the cap the would-be
// UNREACHABLE verdicts stay UNKNOWN. Stream the files through a worker pool if bigger trees need an answer.
const MAX_DEPENDENCY_CODE_BYTES = 256 * 1024 * 1024;

// Names among `names` that an installed package's code uses as a module specifier ('lodash', "lodash/fp"): a package
// can require another without declaring it (consolidate@0.16 loads lodash to render templates), so the lockfile's
// dependency lists miss it. Every node_modules folder counts, at any depth, except the packages the analysis leaves
// out (dev-only) and a package's mentions of itself. Symlinks are not followed: npm links workspaces, the app's own
// code, into node_modules. null when the code is too large to read in full.
export function namedInDependencyCode(cwd: string, names: string[], maxBytes = MAX_DEPENDENCY_CODE_BYTES): Set<string> | null {
  const projectDirs = [cwd, ...workspaceDirectories(cwd)];
  const excluded = new Set(projectDirs.filter(hasPackageLock).flatMap((directory) => [...excludedPackagePaths(directory)]));
  const specifier = new RegExp(String.raw`(['"\x60])(${names.map(escapeRegExp).join("|")})(?:/[^'"\x60\s]*)?\1`, "g");
  const found = new Set<string>();
  let bytes = 0;

  // Every file in a package folder; nested node_modules folders hold other packages.
  const readPackage = (directory: string, owner: string): boolean => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!(entry.name === "node_modules" ? readNodeModules(fullPath) : readPackage(fullPath, owner))) {
          return false;
        }
      } else if (entry.isFile() && /\.[cm]?jsx?$/.test(entry.name)) {
        const code = readFileSync(fullPath, "latin1");
        bytes += code.length;
        if (bytes > maxBytes) {
          return false;
        }

        for (const match of code.matchAll(specifier)) {
          if (match[2] !== owner) {
            found.add(match[2]);
          }
        }
      }
    }

    return true;
  };

  // node_modules/<name> and node_modules/@scope/<name>; dot folders (.bin, .cache) are not packages.
  const readNodeModules = (directory: string): boolean =>
    readdirSync(directory, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && !entry.name.startsWith("."))
      .flatMap((entry) =>
        entry.name.startsWith("@")
          ? readdirSync(path.join(directory, entry.name), { withFileTypes: true })
              .filter((scoped) => scoped.isDirectory())
              .map((scoped) => [path.join(directory, entry.name, scoped.name), `${entry.name}/${scoped.name}`])
          : [[path.join(directory, entry.name), entry.name]],
      )
      .every(([packageDir, owner]) => excluded.has(packageDir) || readPackage(packageDir, owner));

  try {
    const complete = projectDirs
      .map((directory) => path.join(directory, "node_modules"))
      .filter((directory) => existsSync(directory))
      .every(readNodeModules);
    return complete ? found : null;
  } catch (error) {
    logger.warn({ error: error instanceof Error ? error.message : String(error) }, "Could not read the installed packages' code");
    return null;
  }
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

export async function analyze(options: AnalyzeOptions): Promise<AnalyzeResult> {
  const cwd = path.resolve(options.cwd);
  const ignoreSet = new Set(options.ignore ?? []);
  const { cacheDir } = cacheSettings(options);

  if (options.noCache) {
    clearCache(cacheDir);
  }

  const { installedPackages, usedByDependencies } = collectInstalledPackages(cwd);
  const entryPoints = detectEntryPoints(cwd, options.entry);
  const graph = buildGraph(collectSourceFiles(cwd), entryPoints, cwd);
  const verdict = verdictFor(cwd, graph, usedByDependencies);
  const osv: OsvSession = { fetched: new Map() };
  const results: ReachabilityResult[] = [];
  const unchecked: string[] = [];

  for (const installedPackage of installedPackages) {
    const { advisories, degraded, unchecked: missing } = await advisoriesForPackage(installedPackage.name, installedPackage.version, options, osv);
    if (missing) {
      unchecked.push(`${installedPackage.name}@${installedPackage.version}`);
    }

    for (const advisory of advisories) {
      for (const { confident, ...vulnSymbol } of extractVulnSymbols(advisory, installedPackage.name)) {
        if (ignoreSet.has(vulnSymbol.ghsaId)) {
          continue;
        }

        results.push({
          advisory: { ...vulnSymbol, installedVersion: installedPackage.version },
          ...verdict(installedPackage, vulnSymbol.exportedSymbol, confident, degraded.has(advisory.id)),
        });
      }
    }
  }

  // Last, each search once for all of them: a mention of the function anywhere in the project, then another
  // package's code naming the package.
  const symbolOf = (result: ReachabilityResult): string => result.advisory.exportedSymbol ?? "";
  const unreachable = results.filter((result) => result.status === "UNREACHABLE");
  const mentioned = unreachable.length > 0 ? mentionedInProject(cwd, graph, [...new Set(unreachable.map(symbolOf))]) : new Set<string>();
  const candidates = [...new Set(unreachable.filter((result) => !mentioned.has(symbolOf(result))).map((result) => result.advisory.package))];
  const named = candidates.length > 0 ? namedInDependencyCode(cwd, candidates) : new Set<string>();
  const checked = results.map((result): ReachabilityResult => {
    if (result.status !== "UNREACHABLE") {
      return result;
    }

    if (mentioned.has(symbolOf(result))) {
      return { ...result, status: "UNKNOWN", reason: "unresolved-reference" };
    }

    return named === null || named.has(result.advisory.package) ? { ...result, status: "UNKNOWN", reason: "transitive" } : result;
  });

  return { results: sortResults(checked), unchecked };
}
