// Parse package-lock.json v2/v3.
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { loadConfigSync } from "../config/loader.js";
import { ReachableError } from "./errors.js";
import type { InstalledPackage } from "../vuln/types.js";

type PackageLockV3 = {
  lockfileVersion?: number;
  packages?: Record<string, { name?: string; version?: string; dev?: boolean }>;
};

type PackageLockV2Node = {
  version?: string;
  dev?: boolean;
  dependencies?: Record<string, PackageLockV2Node>;
};

type PackageLockV2 = {
  lockfileVersion?: number;
  dependencies?: Record<string, PackageLockV2Node>;
};

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

function shouldIncludePackage(name: string, isDevPackage: boolean, cwd: string): boolean {
  if (process.argv.includes("--include-dev")) {
    return true;
  }

  const config = loadConfigSync(cwd);
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

function parseV3(lockfile: PackageLockV3, cwd: string): InstalledPackage[] {
  const packages = new Map<string, InstalledPackage>();

  for (const [packageKey, value] of Object.entries(lockfile.packages ?? {})) {
    if (packageKey === "") {
      continue;
    }

    const name = value.name ?? packageNameFromPathKey(packageKey);
    if (!name || !value.version || !shouldIncludePackage(name, Boolean(value.dev), cwd)) {
      continue;
    }

    packages.set(name, {
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
  packages: Map<string, InstalledPackage>,
  cwd: string,
): void {
  for (const [name, node] of Object.entries(dependencies)) {
    if (node.version && shouldIncludePackage(name, Boolean(node.dev), cwd)) {
      packages.set(name, {
        name,
        version: node.version,
        ecosystem: "npm",
        dev: Boolean(node.dev),
      });
    }

    if (node.dependencies) {
      walkV2Dependencies(node.dependencies, packages, cwd);
    }
  }
}

function parseV2(lockfile: PackageLockV2, cwd: string): InstalledPackage[] {
  const packages = new Map<string, InstalledPackage>();
  walkV2Dependencies(lockfile.dependencies ?? {}, packages, cwd);
  return [...packages.values()];
}

export function parsePackageLock(cwd: string): InstalledPackage[] {
  const lockfilePath = packageLockPath(cwd);
  const lockfile = JSON.parse(readFileSync(lockfilePath, "utf8")) as PackageLockV2 & PackageLockV3;

  if (lockfile.lockfileVersion === 3 || lockfile.packages) {
    return parseV3(lockfile, cwd);
  }

  return parseV2(lockfile, cwd);
}
