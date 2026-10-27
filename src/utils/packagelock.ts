// Parse package-lock.json v2/v3.
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { loadConfigSync } from "../config/loader.js";
import { ReachableError } from "./errors.js";
import type { ReachableConfig } from "../config/types.js";
import type { InstalledPackage } from "../vuln/types.js";

type PackageLockV3Entry = {
  name?: string;
  version?: string;
  dev?: boolean;
  link?: boolean;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
};

type PackageLockV3 = {
  lockfileVersion?: number;
  packages?: Record<string, PackageLockV3Entry>;
};

type PackageLockV2Node = {
  version?: string;
  dev?: boolean;
  requires?: Record<string, string>;
  dependencies?: Record<string, PackageLockV2Node>;
};

type PackageLockV2 = {
  lockfileVersion?: number;
  dependencies?: Record<string, PackageLockV2Node>;
};

type PackageLock = PackageLockV2 & PackageLockV3;

function packageLockPath(cwd: string): string {
  const directPath = path.join(cwd, "package-lock.json");
  const nodeModulesPath = path.join(cwd, "node_modules", ".package-lock.json");

  if (existsSync(directPath)) {
    return directPath;
  }

  if (existsSync(nodeModulesPath)) {
    return nodeModulesPath;
  }

  throw new ReachableError("E001", "Run npm install first, or specify --cwd");
}

function readPackageLock(cwd: string): PackageLock {
  return JSON.parse(readFileSync(packageLockPath(cwd), "utf8")) as PackageLock;
}

function hasPackagesMap(lockfile: PackageLock): boolean {
  return lockfile.lockfileVersion === 3 || Boolean(lockfile.packages);
}

function shouldIncludePackage(name: string, isDevPackage: boolean, config: ReachableConfig): boolean {
  if (process.argv.includes("--include-dev")) {
    return true;
  }

  if (config.devPackages.includes(name)) {
    return false;
  }

  return !isDevPackage;
}

function packageNameFromPathKey(key: string): string | null {
  const normalized = key.replace(/\\/g, "/");
  const marker = "/node_modules/";

  if (!normalized.includes("node_modules/")) {
    return null;
  }

  const lastMarkerIndex = normalized.lastIndexOf(marker);
  const tail = normalized.slice(lastMarkerIndex + marker.length);
  if (tail.startsWith("@")) {
    return tail.split("/").slice(0, 2).join("/");
  }

  return tail.split("/")[0] ?? null;
}

// Keyed by name@version: a nested copy (node_modules/a/node_modules/lodash@4.17.20) must not be dropped in
// favour of the hoisted one.
function parseV3(lockfile: PackageLockV3, config: ReachableConfig): InstalledPackage[] {
  const packages = new Map<string, InstalledPackage>();

  for (const [packageKey, value] of Object.entries(lockfile.packages ?? {})) {
    if (packageKey === "") {
      continue;
    }

    const name = value.name ?? packageNameFromPathKey(packageKey);
    if (!name || !value.version || !shouldIncludePackage(name, Boolean(value.dev), config)) {
      continue;
    }

    packages.set(`${name}@${value.version}`, {
      name,
      version: value.version,
      ecosystem: "npm",
      dev: Boolean(value.dev),
    });
  }

  return [...packages.values()];
}

function walkV2Dependencies(
  dependencies: Record<string, PackageLockV2Node>,
  visit: (name: string, node: PackageLockV2Node) => void,
): void {
  for (const [name, node] of Object.entries(dependencies)) {
    visit(name, node);

    if (node.dependencies) {
      walkV2Dependencies(node.dependencies, visit);
    }
  }
}

function parseV2(lockfile: PackageLockV2, config: ReachableConfig): InstalledPackage[] {
  const packages = new Map<string, InstalledPackage>();
  walkV2Dependencies(lockfile.dependencies ?? {}, (name, node) => {
    if (node.version && shouldIncludePackage(name, Boolean(node.dev), config)) {
      packages.set(`${name}@${node.version}`, {
        name,
        version: node.version,
        ecosystem: "npm",
        dev: Boolean(node.dev),
      });
    }
  });
  return [...packages.values()];
}

export function parsePackageLock(cwd: string): InstalledPackage[] {
  const lockfile = readPackageLock(cwd);
  const config = loadConfigSync(cwd);

  return hasPackagesMap(lockfile) ? parseV3(lockfile, config) : parseV2(lockfile, config);
}

/**
 * Names that installed packages declare as dependencies, optional or peer dependencies. Their code is not analyzed,
 * so any of them may call into these packages. The project root and folders inside it (workspaces) are the app
 * itself; linked folders outside it (file:../shared) are not analyzed and count like installed packages.
 */
export function packagesUsedByDependencies(cwd: string): Set<string> {
  const lockfile = readPackageLock(cwd);
  const config = loadConfigSync(cwd);
  const used = new Set<string>();

  if (!hasPackagesMap(lockfile)) {
    walkV2Dependencies(lockfile.dependencies ?? {}, (name, node) => {
      if (shouldIncludePackage(name, Boolean(node.dev), config)) {
        Object.keys(node.requires ?? {}).forEach((dependency) => used.add(dependency));
      }
    });
    return used;
  }

  for (const [packageKey, value] of Object.entries(lockfile.packages ?? {})) {
    const name = packageNameFromPathKey(packageKey) ?? (packageKey.startsWith("../") ? value.name ?? packageKey : null);
    if (!name || value.link || !shouldIncludePackage(value.name ?? name, Boolean(value.dev), config)) {
      continue;
    }

    for (const dependency of Object.keys({ ...value.dependencies, ...value.optionalDependencies, ...value.peerDependencies })) {
      used.add(dependency);
    }
  }

  return used;
}
