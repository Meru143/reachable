import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import nock from "nock";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  analyze,
  collectSourceFiles,
  detectEntryPoints,
} from "../src/analyzer.js";
import { ReachableError } from "../src/utils/errors.js";
import { createCacheKey } from "../src/vuln/cache.js";
import { fixturePath } from "./helpers.js";
import type { Advisory } from "../src/vuln/types.js";

const createdDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "reachable-analyzer-"));
  createdDirs.push(dir);
  return dir;
}

function writeProjectFile(rootDir: string, relativePath: string, content: string): string {
  const filePath = path.join(rootDir, relativePath);
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, content, "utf8");
  return filePath;
}

function mockOsv(advisoriesByPackage: Record<string, Advisory[]>) {
  return nock("https://api.osv.dev")
    .persist()
    .post("/v1/querybatch")
    .reply(200, (_uri, requestBody) => {
      const payload =
        typeof requestBody === "string"
          ? (JSON.parse(requestBody) as { queries?: Array<{ package?: { name?: string } }> })
          : (requestBody as { queries?: Array<{ package?: { name?: string } }> });
      const packageName = payload.queries?.[0]?.package?.name ?? "";

      return {
        results: [
          {
            vulns: advisoriesByPackage[packageName] ?? [],
          },
        ],
      };
    });
}

function advisoryFor(packageName: string, symbol: string | null, ghsaId: string): Advisory {
  return {
    id: ghsaId,
    aliases: [ghsaId],
    details: symbol ? `The \`${symbol}()\` function is vulnerable.` : "The vulnerable symbol could not be determined.",
    database_specific: {
      cvss: {
        score: 8.1,
      },
    },
    affected: [
      {
        package: {
          name: packageName,
          ecosystem: "npm",
        },
        ecosystem_specific: symbol
          ? {
              imports: [
                {
                  path: `${packageName}.${symbol}`,
                  symbols: [symbol],
                },
              ],
            }
          : undefined,
      },
    ],
  };
}

beforeAll(() => {
  nock.disableNetConnect();
});

afterEach(() => {
  nock.cleanAll();

  while (createdDirs.length > 0) {
    const dir = createdDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

afterAll(() => {
  nock.enableNetConnect();
});

describe("analyzer", () => {
  it("resolves explicit entry points to absolute paths", () => {
    const cwd = fixturePath("simple-express");

    expect(detectEntryPoints(cwd, ["src/index.ts"])).toEqual([path.join(cwd, "src", "index.ts")]);
  });

  it("auto-detects fallback and workspace entry points", () => {
    const simpleEntries = detectEntryPoints(fixturePath("simple-express"));
    const monorepoEntries = detectEntryPoints(fixturePath("monorepo"));
    const cwd = makeTempDir();
    writeProjectFile(
      cwd,
      "package.json",
      JSON.stringify(
        {
          name: "cli-build-output",
          private: true,
          main: "dist/cli/index.js",
          bin: {
            reachable: "dist/cli/index.js",
          },
        },
        null,
        2,
      ),
    );
    writeProjectFile(cwd, path.join("src", "cli", "index.ts"), "export const main = true;\n");
    writeProjectFile(cwd, path.join("dist", "cli", "index.js"), "module.exports = {};\n");
    const buildOutputEntries = detectEntryPoints(cwd);

    expect(simpleEntries).toContain(path.join(fixturePath("simple-express"), "src", "index.ts"));
    expect(monorepoEntries).toEqual(
      expect.arrayContaining([
        path.join(fixturePath("monorepo"), "packages", "pkg-a", "src", "index.ts"),
        path.join(fixturePath("monorepo"), "packages", "pkg-b", "src", "index.ts"),
      ]),
    );
    expect(buildOutputEntries).toContain(path.join(cwd, "src", "cli", "index.ts"));
    expect(buildOutputEntries).not.toContain(path.join(cwd, "dist", "cli", "index.js"));
  });

  it("throws E002 when no entry point can be detected", () => {
    const cwd = makeTempDir();
    writeProjectFile(
      cwd,
      "package.json",
      JSON.stringify(
        {
          name: "missing-entry",
          private: true,
        },
        null,
        2,
      ),
    );

    expect(() => detectEntryPoints(cwd)).toThrowError(ReachableError);
    expect(() => detectEntryPoints(cwd)).toThrow("Specify an entry point with --entry src/index.ts");
  });

  it("collects source files while skipping ignored directories", () => {
    const cwd = makeTempDir();
    const keptFile = writeProjectFile(cwd, path.join("src", "index.ts"), "export const ok = true;\n");
    writeProjectFile(cwd, path.join("dist", "bundle.js"), "export const ignored = true;\n");
    writeProjectFile(cwd, path.join("node_modules", "pkg", "index.js"), "module.exports = {};\n");
    writeProjectFile(cwd, path.join("coverage", "coverage.js"), "export const ignored = true;\n");
    writeProjectFile(cwd, path.join(".reachable-cache", "cache.ts"), "export const ignored = true;\n");

    expect(collectSourceFiles(cwd)).toEqual([keptFile]);
  });

  it("reports reachable and unknown advisories in sorted order", async () => {
    mockOsv({
      lodash: [
        advisoryFor("lodash", null, "GHSA-unknown-symbol"),
        advisoryFor("lodash", "trim", "GHSA-reachable-symbol"),
      ],
    });

    const results = await analyze({
      cwd: fixturePath("simple-express"),
      noCache: true,
    });

    expect(results.map((result) => result.status)).toEqual(["REACHABLE", "UNKNOWN"]);
    expect(results[0]?.callPath?.length ?? 0).toBeGreaterThan(0);
  });

  it("reports unreachable results when only safe symbols are used", async () => {
    mockOsv({
      lodash: [advisoryFor("lodash", "trim", "GHSA-unreachable-symbol")],
    });

    const results = await analyze({
      cwd: fixturePath("safe-usage"),
      noCache: true,
    });

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe("UNREACHABLE");
  });

  it("aggregates lockfiles from workspace roots", async () => {
    mockOsv({
      lodash: [advisoryFor("lodash", "trim", "GHSA-workspace-lodash")],
      minimist: [advisoryFor("minimist", "minimist", "GHSA-workspace-minimist")],
    });

    const results = await analyze({
      cwd: fixturePath("monorepo"),
      noCache: true,
    });

    expect(results.map((result) => result.advisory.package).sort()).toEqual(["lodash", "minimist"]);
  });

  it("marks stale cached advisories as unknown when OSV fetch fails", async () => {
    const cacheDir = path.join(makeTempDir(), ".reachable-cache");
    const cacheKey = createCacheKey("lodash", "4.17.20");
    mkdirSync(cacheDir, { recursive: true });
    writeFileSync(
      path.join(cacheDir, `${cacheKey}.json`),
      JSON.stringify(
        {
          fetchedAt: "2000-01-01T00:00:00.000Z",
          advisories: [advisoryFor("lodash", "trim", "GHSA-stale-cache")],
        },
        null,
        2,
      ),
      "utf8",
    );
    nock("https://api.osv.dev").post("/v1/querybatch").reply(400, "bad request");

    const results = await analyze({
      cwd: fixturePath("simple-express"),
      cacheDir,
      cacheTtlHours: 0,
    });

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe("UNKNOWN");
    expect(results[0]?.advisory.ghsaId).toBe("GHSA-stale-cache");
  });
});
