import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createCacheKey, getCached, setCache } from "../../src/vuln/cache.js";
import type { Advisory } from "../../src/vuln/types.js";

const createdDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "reachable-cache-"));
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

function advisoryFixture(): Advisory {
  return {
    id: "GHSA-test-cache",
    aliases: ["GHSA-test-cache"],
    details: "Cached advisory",
    affected: [
      {
        package: {
          name: "lodash",
          ecosystem: "npm",
        },
      },
    ],
  };
}

describe("vuln/cache", () => {
  it("writes advisories to disk and reads them back", () => {
    const cacheDir = makeTempDir();
    const advisories = [advisoryFixture()];
    const key = createCacheKey("lodash", "4.17.20");

    setCache(key, advisories, cacheDir);

    expect(getCached(key, cacheDir, 24)).toEqual(advisories);
  });

  it("returns null when a cache entry is expired", () => {
    const cacheDir = makeTempDir();
    const key = createCacheKey("lodash", "4.17.20");

    writeFileSync(
      path.join(cacheDir, `${key}.json`),
      JSON.stringify(
        {
          fetchedAt: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString(),
          advisories: [advisoryFixture()],
        },
        null,
        2,
      ),
      "utf8",
    );

    expect(getCached(key, cacheDir, 24)).toBeNull();
  });
});
