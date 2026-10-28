import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  loadConfig,
  loadConfigSync,
} from "../../src/config/loader.js";
import { getDefaultConfig } from "../../src/config/types.js";
import { ConfigError } from "../../src/utils/errors.js";

const createdDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "reachable-config-"));
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

describe("config/loader", () => {
  it("returns default config when no config file exists", async () => {
    const cwd = makeTempDir();

    await expect(loadConfig(cwd)).resolves.toEqual(getDefaultConfig());
    expect(loadConfigSync(cwd)).toEqual(getDefaultConfig());
  });

  it("loads and validates .reachablerc.json", async () => {
    const cwd = makeTempDir();
    writeFileSync(
      path.join(cwd, ".reachablerc.json"),
      JSON.stringify(
        {
          entry: ["src/index.ts"],
          failOn: "moderate",
          ignore: ["GHSA-test"],
          devPackages: ["vitest"],
          cache: {
            ttlHours: 12,
            dir: ".cache/reachable",
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const expected = {
      entry: ["src/index.ts"],
      failOn: "moderate",
      ignore: ["GHSA-test"],
      devPackages: ["vitest"],
      cache: {
        ttlHours: 12,
        dir: ".cache/reachable",
      },
    };

    await expect(loadConfig(cwd)).resolves.toEqual(expected);
    expect(loadConfigSync(cwd)).toEqual(expected);
  });

  it.each([
    ["a mistyped key", { entries: ["src/index.ts"] }, 'Unrecognized key: "entries"'],
    ["a mistyped cache key", { cache: { ttl: 12 } }, 'Unrecognized key: "ttl"'],
  ])("rejects %s, naming the file and the key", async (_label, config, problem) => {
    const cwd = makeTempDir();
    writeFileSync(path.join(cwd, ".reachablerc.json"), JSON.stringify({ $schema: "https://example.com/schema.json", ...config }), "utf8");

    await expect(loadConfig(cwd)).rejects.toThrow(ConfigError);
    await expect(loadConfig(cwd)).rejects.toThrow(problem);
    expect(() => loadConfigSync(cwd)).toThrow(path.join(cwd, ".reachablerc.json"));
  });
});
