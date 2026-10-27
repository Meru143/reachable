import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { packagesUsedByDependencies, parsePackageLock } from "../../src/utils/packagelock.js";
import { ReachableError } from "../../src/utils/errors.js";

const createdDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "reachable-packagelock-"));
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

describe("utils/packagelock", () => {
  it("parses lockfile v3 package entries", () => {
    const cwd = makeTempDir();
    writeFileSync(
      path.join(cwd, "package-lock.json"),
      JSON.stringify(
        {
          lockfileVersion: 3,
          packages: {
            "": {
              name: "fixture",
            },
            "node_modules/lodash": {
              version: "4.17.20",
            },
            "node_modules/@scope/pkg": {
              version: "1.2.3",
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    expect(parsePackageLock(cwd)).toEqual([
      { name: "lodash", version: "4.17.20", ecosystem: "npm", dev: false },
      { name: "@scope/pkg", version: "1.2.3", ecosystem: "npm", dev: false },
    ]);
  });

  it("parses lockfile v2 dependency trees recursively", () => {
    const cwd = makeTempDir();
    writeFileSync(
      path.join(cwd, "package-lock.json"),
      JSON.stringify(
        {
          lockfileVersion: 2,
          dependencies: {
            express: {
              version: "4.18.2",
              dependencies: {
                qs: {
                  version: "6.11.0",
                },
              },
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    expect(parsePackageLock(cwd)).toEqual([
      { name: "express", version: "4.18.2", ecosystem: "npm", dev: false },
      { name: "qs", version: "6.11.0", ecosystem: "npm", dev: false },
    ]);
  });

  it("filters dev dependencies from config unless include-dev is set", () => {
    const cwd = makeTempDir();
    writeFileSync(
      path.join(cwd, ".reachablerc.json"),
      JSON.stringify(
        {
          devPackages: ["vitest"],
        },
        null,
        2,
      ),
      "utf8",
    );
    writeFileSync(
      path.join(cwd, "package-lock.json"),
      JSON.stringify(
        {
          lockfileVersion: 3,
          packages: {
            "": {
              name: "fixture",
            },
            "node_modules/vitest": {
              version: "2.1.9",
              dev: true,
            },
            "node_modules/lodash": {
              version: "4.17.20",
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    expect(parsePackageLock(cwd)).toEqual([{ name: "lodash", version: "4.17.20", ecosystem: "npm", dev: false }]);
  });

  it("falls back to node_modules/.package-lock.json when present", () => {
    const cwd = makeTempDir();
    const nodeModulesDir = path.join(cwd, "node_modules");
    mkdirSync(nodeModulesDir, { recursive: true });
    writeFileSync(
      path.join(nodeModulesDir, ".package-lock.json"),
      JSON.stringify(
        {
          lockfileVersion: 3,
          packages: {
            "": {
              name: "fixture",
            },
            "node_modules/minimist": {
              version: "1.2.5",
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    expect(parsePackageLock(cwd)).toEqual([{ name: "minimist", version: "1.2.5", ecosystem: "npm", dev: false }]);
  });

  it("keeps every installed version of a package", () => {
    const cwd = makeTempDir();
    writeFileSync(
      path.join(cwd, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "fixture" },
          "node_modules/old-lib/node_modules/lodash": { version: "4.17.20" },
          "node_modules/lodash": { version: "4.18.1" },
        },
      }),
      "utf8",
    );

    expect(parsePackageLock(cwd).map((entry) => `${entry.name}@${entry.version}`)).toEqual(["lodash@4.17.20", "lodash@4.18.1"]);
  });

  it("lists what installed packages depend on, leaving out the app and dev-only packages", () => {
    const cwd = makeTempDir();
    writeFileSync(
      path.join(cwd, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "fixture", dependencies: { express: "^4.0.0", lodash: "^4.0.0" } },
          "packages/web": { name: "web", version: "1.0.0", dependencies: { react: "^18.0.0" } },
          "node_modules/web": { resolved: "packages/web", link: true },
          "node_modules/express": { version: "4.18.2", dependencies: { qs: "6.11.0" }, optionalDependencies: { fsevents: "^2.0.0" } },
          "node_modules/express/node_modules/debug": { version: "2.6.9", dependencies: { ms: "2.0.0" } },
          "node_modules/react-dom": { version: "18.2.0", peerDependencies: { react: "^18.2.0" } },
          "node_modules/eslint": { version: "8.57.1", dev: true, dependencies: { minimatch: "^3.0.0" } },
          "../shared": { name: "shared", version: "1.0.0", dependencies: { semver: "^7.0.0" } },
        },
      }),
      "utf8",
    );

    expect([...packagesUsedByDependencies(cwd)].sort()).toEqual(["fsevents", "ms", "qs", "react", "semver"]);
  });

  it("reads requires from lockfile v1 dependency trees", () => {
    const cwd = makeTempDir();
    writeFileSync(
      path.join(cwd, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 1,
        dependencies: {
          mkdirp: { version: "0.5.1", requires: { minimist: "0.0.8" } },
          minimist: { version: "0.0.8" },
          jest: { version: "29.0.0", dev: true, requires: { chalk: "^4.0.0" } },
        },
      }),
      "utf8",
    );

    expect([...packagesUsedByDependencies(cwd)]).toEqual(["minimist"]);
  });

  it("throws E001 when no lockfile exists", () => {
    const cwd = makeTempDir();

    expect(() => parsePackageLock(cwd)).toThrowError(ReachableError);
    expect(() => parsePackageLock(cwd)).toThrow("Run npm install first, or specify --cwd");
  });
});
