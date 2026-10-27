import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
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
import { fixturePath, mockOsv } from "./helpers.js";
import type { Advisory, AdvisoryAffected } from "../src/vuln/types.js";

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

// Shaped like the records GET /v1/vulns/{id} returns for npm: no structured symbols, only the advisory text, and
// sibling packages in `affected`.
function textAdvisory(id: string, details: string, severity = "HIGH"): Advisory {
  return {
    id,
    details,
    database_specific: { severity },
    affected: ["lodash", "lodash-es"].map((name): AdvisoryAffected => ({
      package: { name, ecosystem: "npm" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
    })),
  };
}

const templateAdvisory = textAdvisory(
  "GHSA-35jh-r3h4-6jhm",
  "`lodash` versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
);

// A stand-in for the installed lodash: what it exports, and which of its functions it calls itself.
const installedLodash = [
  "function template(source) { return function render() { return source; }; }",
  "function trim(value) { return String(value).replace(/^ +| +$/g, ''); }",
  "function toNumber(value) { return +value; }",
  "function clamp(number, lower, upper) { return Math.min(Math.max(toNumber(number), lower), upper); }",
  "function baseSet(object, key, value) { object[key] = value; return object; }",
  "function setKey(object, key) { return baseSet(object, key, true); }",
  "function compileTemplate(source) { return source; }",
  "function map(array, iteratee) { var result = []; for (var index = 0; index < array.length; index++) result.push(iteratee(array[index])); return result; }",
  "var lodash = {};",
  "lodash.template = template;",
  "lodash.trim = trim;",
  "lodash.toNumber = toNumber;",
  "lodash.clamp = clamp;",
  "lodash.setKey = setKey;",
  "lodash.map = map;",
  "module.exports = lodash;",
].join("\n");

// An app whose only file is index.js, with lodash@4.17.20 installed (its code, or not installed when null);
// `packages` adds lockfile entries.
function lodashApp(source: string, packages: Record<string, object> = {}, lodashCode: string | null = installedLodash): string {
  const cwd = makeTempDir();
  writeProjectFile(cwd, "package.json", JSON.stringify({ name: "app", private: true, main: "index.js", dependencies: { lodash: "4.17.20" } }));
  writeProjectFile(
    cwd,
    "package-lock.json",
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "app", dependencies: { lodash: "4.17.20" } },
        "node_modules/lodash": { version: "4.17.20" },
        ...packages,
      },
    }),
  );
  if (lodashCode !== null) {
    writeProjectFile(cwd, path.join("node_modules", "lodash", "package.json"), JSON.stringify({ name: "lodash", version: "4.17.20", main: "lodash.js" }));
    writeProjectFile(cwd, path.join("node_modules", "lodash", "lodash.js"), lodashCode);
  }
  writeProjectFile(cwd, "index.js", source);
  return cwd;
}

function verdicts(results: Awaited<ReturnType<typeof analyze>>): Array<[string, string | null, string, string | undefined]> {
  return results.map((result) => [result.advisory.ghsaId, result.advisory.exportedSymbol, result.status, result.reason]);
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

    expect(results.map((result) => [result.status, result.reason])).toEqual([
      ["REACHABLE", undefined],
      ["UNKNOWN", "symbol-unknown"],
    ]);
    expect(results[0]?.callPath?.length ?? 0).toBeGreaterThan(0);
  });

  it("hydrates each advisory and reports it for the installed package only", async () => {
    mockOsv({ lodash: [templateAdvisory] });

    const results = await analyze({ cwd: lodashApp('const _ = require("lodash");\nconsole.log(_.template("x"));\n') });

    expect(results).toEqual([
      {
        advisory: {
          package: "lodash",
          ghsaId: "GHSA-35jh-r3h4-6jhm",
          cvssScore: 7,
          severity: "HIGH",
          exportedSymbol: "template",
          affectedVersionRange: "introduced:0 -> fixed:4.17.21",
        },
        status: "REACHABLE",
        callPath: ["index.js::module", "index.js::call:_.template:2"],
      },
    ]);
  });

  it("caches the full records and reuses them for a dry run", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp('const _ = require("lodash");\nconsole.log(_.map([1], String));\n');

    const fresh = await analyze({ cwd });
    nock.cleanAll();
    const cached = await analyze({ cwd, dryRun: true });
    const [cacheFile] = readdirSync(path.join(cwd, ".reachable-cache"));
    const record = JSON.parse(readFileSync(path.join(cwd, ".reachable-cache", cacheFile ?? ""), "utf8")) as { advisories: Advisory[] };

    expect(cached).toEqual(fresh);
    expect(record.advisories[0]?.affected?.[0]?.package?.name).toBe("lodash");
  });

  it("reports UNREACHABLE when the app is the only importer and never calls the exported symbol", async () => {
    mockOsv({ lodash: [templateAdvisory] });

    const results = await analyze({ cwd: lodashApp('const _ = require("lodash");\nconsole.log(_.map([1, 2], (n) => n * 2));\n') });

    expect(verdicts(results)).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNREACHABLE", undefined]]);
  });

  it("reports UNKNOWN (not-imported) for a package only other dependencies use", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp('const async = require("async");\nasync.series([]);\n', {
      "node_modules/async": { version: "2.6.4", dependencies: { lodash: "^4.17.14" } },
    });

    const results = await analyze({ cwd });

    expect(verdicts(results)).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "not-imported"]]);
  });

  it("reports UNKNOWN (transitive) when other installed packages also depend on it, REACHABLE when the app calls it", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const dependents = { "node_modules/async": { version: "2.6.4", dependencies: { lodash: "^4.17.14" } } };

    const unreached = await analyze({ cwd: lodashApp('const _ = require("lodash");\n_.map([1], String);\n', dependents) });
    const reached = await analyze({ cwd: lodashApp('const _ = require("lodash");\n_.template("x");\n', dependents) });

    expect(verdicts(unreached)).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "transitive"]]);
    expect(verdicts(reached)).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "REACHABLE", undefined]]);
  });

  it("reports UNKNOWN (transitive), never the app's call path, for a copy nested under another package", async () => {
    mockOsv({ "lodash@4.17.20": [templateAdvisory] });
    const cwd = lodashApp('const _ = require("lodash");\n_.template("x");\n', {
      "node_modules/lodash": { version: "4.18.1" },
      "node_modules/old-lib": { version: "1.0.0", dependencies: { lodash: "4.17.20" } },
      "node_modules/old-lib/node_modules/lodash": { version: "4.17.20" },
    });

    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "transitive"]]);
  });

  it("finds the package's own calls in any file its entry reaches through static imports", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp(
      'const _ = require("lodash");\n_.map([1], String);\n',
      {},
      'exports.template = require("./lib/template");\nexports.render = require("./lib/core").render;\n',
    );
    writeProjectFile(cwd, path.join("node_modules", "lodash", "lib", "template.js"), "module.exports = function template(source) { return source; };\n");
    writeProjectFile(cwd, path.join("node_modules", "lodash", "lib", "core.js"), 'exports.render = require("./pipeline");\n');
    writeProjectFile(cwd, path.join("node_modules", "lodash", "lib", "pipeline.js"), 'module.exports = require("./render");\n');
    writeProjectFile(cwd, path.join("node_modules", "lodash", "lib", "render.js"), 'const template = require("./template");\nmodule.exports = (source) => template(source);\n');

    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "symbol-unconfirmed"]]);
  });

  it("reads every subpath the package exports", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp('const _ = require("lodash");\n_.map([1], String);\n', {}, "function template(s) { return s; }\nexports.template = template;\n");
    writeProjectFile(cwd, path.join("node_modules", "lodash", "package.json"), JSON.stringify({ name: "lodash", version: "4.17.20", exports: { ".": "./lodash.js", "./unsafe": "./unsafe.js" } }));
    writeProjectFile(cwd, path.join("node_modules", "lodash", "unsafe.js"), 'const { template } = require("./lodash.js");\nexports.renderUnsafe = (s) => template(s);\n');

    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "symbol-unconfirmed"]]);
  });

  it("reads the subpaths the app imports, and stays UNKNOWN when one cannot be found", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const deep = lodashApp('const _ = require("lodash");\nconst render = require("lodash/render");\nrender(_.map([1], String));\n');
    writeProjectFile(deep, path.join("node_modules", "lodash", "render.js"), 'var lodash = require("./lodash.js");\nmodule.exports = function render(s) { return lodash.template(s); };\n');
    const missing = lodashApp('const _ = require("lodash");\nrequire("lodash/missing");\n_.map([1], String);\n');

    expect(verdicts(await analyze({ cwd: deep }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "symbol-unconfirmed"]]);
    expect(verdicts(await analyze({ cwd: missing }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "symbol-unconfirmed"]]);
  });

  it("does not count dev-only dependents", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp('const _ = require("lodash");\n_.map([1], String);\n', {
      "node_modules/eslint-plugin-lodash": { version: "7.4.0", dev: true, dependencies: { lodash: "^4.17.21" } },
    });

    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNREACHABLE", undefined]]);
  });

  it("reports UNKNOWN (symbol-unconfirmed) unless the installed package exports the symbol and never calls it itself", async () => {
    mockOsv({
      lodash: [
        textAdvisory("GHSA-calls-itself", "ReDoS via the `toNumber` function."),
        textAdvisory("GHSA-not-exported", "Code injection via the compileTemplate function."),
        textAdvisory("GHSA-named-as-a-call", "Prototype Pollution via file `index.js`, function `setKey()` (lines 69-95)."),
      ],
    });
    const source = 'const _ = require("lodash");\n_.map([1], String);\n';

    const installed = await analyze({ cwd: lodashApp(source) });
    const notInstalled = await analyze({ cwd: lodashApp(source, {}, null) });

    expect(verdicts(installed)).toEqual([
      ["GHSA-calls-itself", "toNumber", "UNKNOWN", "symbol-unconfirmed"],
      ["GHSA-not-exported", "compileTemplate", "UNKNOWN", "symbol-unconfirmed"],
      ["GHSA-named-as-a-call", "setKey", "UNKNOWN", "symbol-unconfirmed"],
    ]);
    expect(verdicts(notInstalled).map(([, , status, reason]) => [status, reason])).toEqual([
      ["UNKNOWN", "symbol-unconfirmed"],
      ["UNKNOWN", "symbol-unconfirmed"],
      ["UNKNOWN", "symbol-unconfirmed"],
    ]);
  });

  it.each([
    ["minified code", "function c(s){return s}function d(s){return c(s)}exports.template=c,exports.render=d;"],
    ["an ES export list", "function compile(s) { return s; }\nexport function render(s) { return compile(s); }\nexport { compile as template };\n"],
  ])("counts calls to the local name an export is bound to, in %s", async (_label, lodashCode) => {
    mockOsv({ lodash: [templateAdvisory] });

    const results = await analyze({ cwd: lodashApp('const _ = require("lodash");\n_.map([1], String);\n', {}, lodashCode) });

    expect(verdicts(results)).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "symbol-unconfirmed"]]);
  });

  it.each([
    ["an alias", "function template(s) { return s; }\nconst alias = template;\nexports.template = template;\nexports.render = (s) => alias(s);\n"],
    ["a callback", "function template(s) { return s; }\nexports.template = template;\nexports.renderAll = (items) => items.map(template);\n"],
    ["a dispatch table", "function template(s) { return s; }\nconst handlers = { template };\nexports.template = template;\nexports.run = (name, s) => handlers[name](s);\n"],
    ["a second export name", "function template(s) { return s; }\nexports.template = template;\nexports.render = template;\n"],
    ["an ES export under another name", "export function template(s) { return s; }\nexport { template as render };\n"],
    ["an object export under another name", "function template(s) { return s; }\nmodule.exports = { template, render: template };\n"],
    ["a default export", "export default function template(s) { return s; }\nexport { template };\n"],
    ["a string property", 'function template(s) { return s; }\nexports.template = template;\nexports.run = (s) => exports["template"](s);\n'],
  ])("treats a package's own use of the symbol through %s as a possible internal call", async (_label, lodashCode) => {
    mockOsv({ lodash: [templateAdvisory] });

    const results = await analyze({ cwd: lodashApp('const _ = require("lodash");\n_.map([1], String);\n', {}, lodashCode) });

    expect(verdicts(results)).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "symbol-unconfirmed"]]);
  });

  it.each([
    ["module.exports = { ... }", "function template(s) { return s; }\nfunction render(s) { return s; }\nmodule.exports = { template, render };\n"],
    ["ES exports", "export function template(s) { return s; }\nexport function render(s) { return s; }\n"],
  ])("still confirms an exported symbol the package never uses itself (%s)", async (_label, lodashCode) => {
    mockOsv({ lodash: [templateAdvisory] });

    const results = await analyze({ cwd: lodashApp('const _ = require("lodash");\n_.map([1], String);\n', {}, lodashCode) });

    expect(verdicts(results)).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNREACHABLE", undefined]]);
  });

  it("still reports REACHABLE for a symbol it could not confirm when the app calls it", async () => {
    mockOsv({ lodash: [textAdvisory("GHSA-named-as-a-call", "Prototype Pollution via file `index.js`, function `setKey()`.")] });

    const results = await analyze({ cwd: lodashApp('const _ = require("lodash");\n_.setKey({}, "a");\n') });

    expect(verdicts(results)).toEqual([["GHSA-named-as-a-call", "setKey", "REACHABLE", undefined]]);
  });

  it.each([
    ["a renamed import", 'const { template: compile } = require("lodash");\ncompile("x");\n'],
    ["a callback", 'const _ = require("lodash");\n["x"].map(_.template);\n'],
    ["a re-export through another module", 'const lib = require("./lib");\nlib.template("x");\n'],
  ])("reports UNKNOWN (unresolved-reference) when app code names the symbol in %s", async (_label, source) => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp(source);
    writeProjectFile(cwd, "lib.js", 'module.exports = require("lodash");\n');

    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "unresolved-reference"]]);
  });

  it("reports UNKNOWN (unresolved-reference) when a component file it cannot parse names the symbol", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp('const _ = require("lodash");\n_.map([1], String);\n');
    writeProjectFile(cwd, path.join("src", "App.vue"), '<script setup>\nimport _ from "lodash";\nconst html = _.template("x")();\n</script>\n');

    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "unresolved-reference"]]);
  });

  it("does not read the symbol from files no entry point reaches", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp('const _ = require("lodash");\n_.map([1], String);\n');
    writeProjectFile(cwd, path.join("scripts", "unused.js"), 'const _ = require("lodash");\n_.template("x");\n');

    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNREACHABLE", undefined]]);
  });

  it("reads calls from source files of 32 KB and more", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const padding = `// ${"x".repeat(100)}\n`.repeat(400);
    const cwd = lodashApp(`const _ = require("lodash");\n${padding}_.template("x");\n`);

    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "REACHABLE", undefined]]);
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

  it("marks stale cached advisories as unknown when hydrating a record fails", async () => {
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
    nock("https://api.osv.dev")
      .post("/v1/querybatch")
      .reply(200, { results: [{ vulns: [{ id: "GHSA-stale-cache" }] }] })
      .get("/v1/vulns/GHSA-stale-cache")
      .reply(404, { code: 5, message: "Bug not found." });

    const results = await analyze({
      cwd: fixturePath("simple-express"),
      cacheDir,
      cacheTtlHours: 0,
    });

    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe("UNKNOWN");
    expect(results[0]?.reason).toBe("lookup-failed");
    expect(results[0]?.advisory.ghsaId).toBe("GHSA-stale-cache");
  });

  it("reports the records that arrived when another record lookup fails, without caching the partial result", async () => {
    const cwd = lodashApp('const _ = require("lodash");\n_.template("x");\n');
    nock("https://api.osv.dev")
      .post("/v1/querybatch")
      .reply(200, { results: [{ vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }, { id: "GHSA-gone" }] }] })
      .get("/v1/vulns/GHSA-35jh-r3h4-6jhm")
      .reply(200, templateAdvisory)
      .get("/v1/vulns/GHSA-gone")
      .reply(404, { code: 5, message: "Bug not found." });

    const results = await analyze({ cwd });

    expect(verdicts(results)).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "REACHABLE", undefined]]);
    expect(existsSync(path.join(cwd, ".reachable-cache"))).toBe(false);
  });

  it("falls back to the stale cached record for a record lookup that fails", async () => {
    const cwd = lodashApp('const _ = require("lodash");\n_.template("x");\n');
    writeProjectFile(
      cwd,
      path.join(".reachable-cache", `${createCacheKey("lodash", "4.17.20")}.json`),
      JSON.stringify({ fetchedAt: "2000-01-01T00:00:00.000Z", advisories: [textAdvisory("GHSA-gone", "ReDoS via the `trim` function.", "MODERATE")] }),
    );
    nock("https://api.osv.dev")
      .post("/v1/querybatch")
      .reply(200, { results: [{ vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }, { id: "GHSA-gone" }] }] })
      .get("/v1/vulns/GHSA-35jh-r3h4-6jhm")
      .reply(200, templateAdvisory)
      .get("/v1/vulns/GHSA-gone")
      .reply(404, { code: 5, message: "Bug not found." });

    expect(verdicts(await analyze({ cwd }))).toEqual([
      ["GHSA-35jh-r3h4-6jhm", "template", "REACHABLE", undefined],
      ["GHSA-gone", "trim", "UNKNOWN", "lookup-failed"],
    ]);
  });

  it("never uses the id-only records 1.0.11 and earlier cached, fresh or stale", async () => {
    const cwd = lodashApp('const _ = require("lodash");\n_.template("x");\n');
    const legacyKey = createHash("sha256").update("lodash@4.17.20").digest("hex");
    writeProjectFile(
      cwd,
      path.join(".reachable-cache", `${legacyKey}.json`),
      JSON.stringify({ fetchedAt: new Date().toISOString(), advisories: [{ id: "GHSA-35jh-r3h4-6jhm", modified: "2026-10-17T02:55:38Z" }] }),
    );

    nock("https://api.osv.dev").post("/v1/querybatch").reply(400, "bad request");
    const offline = await analyze({ cwd });
    mockOsv({ lodash: [templateAdvisory] });
    const online = await analyze({ cwd });

    expect(offline).toEqual([]);
    expect(verdicts(online)).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "REACHABLE", undefined]]);
    expect(online[0]?.advisory.package).toBe("lodash");
  });
});
