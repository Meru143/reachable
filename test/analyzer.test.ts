import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import nock from "nock";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import {
  analyze,
  collectSourceFiles,
  detectEntryPoints,
  namedInDependencyCode,
} from "../src/analyzer.js";
import { ParseError, ReachableError } from "../src/utils/errors.js";
import { logger } from "../src/utils/logger.js";
import { createCacheKey } from "../src/vuln/cache.js";
import { fixturePath, mockOsv } from "./helpers.js";
import type { Advisory, AdvisoryAffected } from "../src/vuln/types.js";

// OSV retries back off for seconds; the tests do not wait.
vi.mock("node:timers/promises", () => ({ setTimeout: () => Promise.resolve() }));

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
function lodashApp(source: string, packages: Record<string, object> = {}, lodashCode: string | null = installedLodash, cwd = makeTempDir()): string {
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

function verdicts({ results }: Awaited<ReturnType<typeof analyze>>): Array<[string, string | null, string, string | undefined]> {
  return results.map((result) => [result.advisory.ghsaId, result.advisory.exportedSymbol, result.status, result.reason]);
}

beforeAll(() => {
  nock.disableNetConnect();
});

afterEach(() => {
  nock.cleanAll();
  vi.unstubAllGlobals();

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

    const { results } = await analyze({
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

    const { results } = await analyze({ cwd: lodashApp('const _ = require("lodash");\nconsole.log(_.template("x"));\n') });

    expect(results).toEqual([
      {
        advisory: {
          package: "lodash",
          ghsaId: "GHSA-35jh-r3h4-6jhm",
          cvssScore: 7,
          severity: "HIGH",
          exportedSymbol: "template",
          affectedVersionRange: "introduced:0 -> fixed:4.17.21",
          installedVersion: "4.17.20",
        },
        status: "REACHABLE",
        callPath: ["index.js::module", "index.js::call:_.template:2"],
      },
    ]);
  });

  it("keeps the fetched advisories when the cache cannot be written", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp('const _ = require("lodash");\n_.template("x");\n');
    const blocker = writeProjectFile(cwd, "not-a-directory", "a file where the cache directory would go\n");

    const results = await analyze({ cwd, cacheDir: path.join(blocker, "cache") });

    expect(verdicts(results)).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "REACHABLE", undefined]]);
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

  it.each([
    [
      "a package.json imports alias",
      { imports: { "#internal/*": "./internal/*" } },
      'const { template } = require("#internal/template.js");\nexports.template = template;\nexports.render = require("#internal/render.js");\n',
    ],
    ["a self-reference", {}, 'function template(s) { return s; }\nexports.template = template;\nexports.render = require("lodash/render");\n'],
    ["an import alias it cannot resolve", {}, 'function template(s) { return s; }\nexports.template = template;\nexports.render = require("#internal/render.js");\n'],
  ])("follows %s inside the package, or stays UNKNOWN", async (_label, manifest, lodashCode) => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp('const _ = require("lodash");\n_.map([1], String);\n', {}, lodashCode);
    const packageDir = path.join("node_modules", "lodash");
    writeProjectFile(cwd, path.join(packageDir, "package.json"), JSON.stringify({ name: "lodash", version: "4.17.20", main: "lodash.js", ...manifest }));
    writeProjectFile(cwd, path.join(packageDir, "internal", "template.js"), "module.exports.template = function template(s) { return s; };\n");
    writeProjectFile(cwd, path.join(packageDir, "internal", "render.js"), 'const { template } = require("./template.js");\nmodule.exports = (s) => template(s);\n');
    writeProjectFile(cwd, path.join(packageDir, "render.js"), 'const { template } = require("./lodash.js");\nmodule.exports = (s) => template(s);\n');

    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "symbol-unconfirmed"]]);
  });

  it("resolves an imported subpath through a wildcard export", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp('const _ = require("lodash");\nconst map = require("lodash/fp/map");\nmap(_.identity);\n', {}, "function template(s) { return s; }\nexports.template = template;\n");
    writeProjectFile(cwd, path.join("node_modules", "lodash", "package.json"), JSON.stringify({ name: "lodash", version: "4.17.20", exports: { ".": "./lodash.js", "./fp/*": "./fp/*.js" } }));
    writeProjectFile(cwd, path.join("node_modules", "lodash", "fp", "map.js"), "module.exports = (fn) => (list) => list.map(fn);\n");

    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNREACHABLE", undefined]]);
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

  it("reads the symbol from files no entry point reaches, since they may still run", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp('const _ = require("lodash");\n_.map([1], String);\n');
    writeProjectFile(cwd, path.join("scripts", "unused.js"), 'const _ = require("lodash");\n_.template("x");\n');

    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "unresolved-reference"]]);
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

    const { results } = await analyze({
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
          advisories: [advisoryFor("lodash", "template", "GHSA-stale-cache")],
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

    const { results } = await analyze({
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
    expect(results.unchecked).toEqual(["lodash@4.17.20"]);
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

    const scan = await analyze({ cwd });

    expect(verdicts(scan)).toEqual([
      ["GHSA-35jh-r3h4-6jhm", "template", "REACHABLE", undefined],
      ["GHSA-gone", "trim", "UNKNOWN", "lookup-failed"],
    ]);
    // The stale record may predate changes to the advisory.
    expect(scan.unchecked).toEqual(["lodash@4.17.20"]);
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

    expect(offline).toEqual({ results: [], unchecked: ["lodash@4.17.20"] });
    expect(verdicts(online)).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "REACHABLE", undefined]]);
    expect(online.results[0]?.advisory.package).toBe("lodash");
  });

  // Each regression below is named after the verification fixture of 1.0.12 that gave a false UNREACHABLE.
  const greetLib = 'const _ = require("lodash");\nexports.greet = (name) => _.template("Hello <%= name %>")({ name });\n';

  it("parses an extensionless bin as JavaScript (f9b-bincli)", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp("");
    writeProjectFile(cwd, "package.json", JSON.stringify({ name: "app", bin: { greet: "bin/greet" } }));
    writeProjectFile(cwd, path.join("bin", "greet"), '#!/usr/bin/env node\nconst { greet } = require("../lib/greet.js");\nconsole.log(greet("world"));\n');
    writeProjectFile(cwd, path.join("lib", "greet.js"), greetLib);

    const { results } = await analyze({ cwd });

    expect(results.map((result) => [result.status, result.callPath])).toEqual([
      ["REACHABLE", ["bin/greet::module", "lib/greet.js::module", "lib/greet.js::call:_.template:2"]],
    ]);
  });

  it("resolves a main that names a directory to its index file (f16-maindir)", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp("");
    writeProjectFile(cwd, "package.json", JSON.stringify({ name: "app", main: "lib" }));
    writeProjectFile(cwd, path.join("lib", "index.js"), greetLib);

    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "REACHABLE", undefined]]);
  });

  it("follows an extensionless --entry such as bin/www (f9-binwww)", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp("");
    writeProjectFile(cwd, "package.json", JSON.stringify({ name: "app", scripts: { start: "node ./bin/www" } }));
    writeProjectFile(cwd, path.join("bin", "www"), '#!/usr/bin/env node\nvar app = require("../app");\nrequire("http").createServer(app).listen(3000);\n');
    writeProjectFile(cwd, "app.js", 'var router = require("./routes/index");\nmodule.exports = (req, res) => router(req, res);\n');
    writeProjectFile(cwd, path.join("routes", "index.js"), 'var _ = require("lodash");\nmodule.exports = function (req, res) {\n  res.end(_.template("Hi <%= name %>")({ name: req.url }));\n};\n');

    const { results } = await analyze({ cwd, entry: ["bin/www"] });

    expect(results.map((result) => [result.status, result.callPath])).toEqual([
      ["REACHABLE", ["bin/www::module", "app.js::module", "routes/index.js::module", "routes/index.js::call:_.template:3"]],
    ]);
  });

  it("fails, naming the file, on a given entry that is missing or cannot be parsed (f1-cfgtypo)", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp('const _ = require("lodash");\n_.template("x");\n');
    writeProjectFile(cwd, path.join("bin", "start"), "#!/bin/sh\nexec node index.js\n");

    await expect(analyze({ cwd, entry: ["src/index.js"] })).rejects.toMatchObject({ code: "E002", message: "Entry point not found: src/index.js" });
    await expect(analyze({ cwd, entry: ["index.js", "indx.js"] })).rejects.toThrow("Entry point not found: indx.js");
    await expect(analyze({ cwd, entry: ["package.json"] })).rejects.toThrow(ParseError);
    await expect(analyze({ cwd, entry: ["bin/start"] })).rejects.toThrow("Cannot parse entry point bin/start: Not JavaScript");
  });

  it("skips a detected bin that is a shell script, and fails with E002 when nothing usable is left", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp('const _ = require("lodash");\n_.template("x");\n');
    writeProjectFile(cwd, path.join("bin", "start"), "#!/bin/sh\nexec node index.js\n");
    writeProjectFile(cwd, "package.json", JSON.stringify({ name: "app", main: "index.js", bin: { start: "bin/start" } }));

    expect(detectEntryPoints(cwd)).toEqual([path.join(cwd, "index.js")]);
    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "REACHABLE", undefined]]);

    writeProjectFile(cwd, "package.json", JSON.stringify({ name: "app", bin: { start: "bin/start" } }));
    expect(() => detectEntryPoints(cwd)).toThrow(ReachableError);
  });

  it("analyzes an entry point named like a test file", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp("");
    writeProjectFile(cwd, "smoke.test.js", 'const _ = require("lodash");\n_.template("x");\n');

    expect(verdicts(await analyze({ cwd, entry: ["smoke.test.js"] }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "REACHABLE", undefined]]);
  });

  it.each([
    ["the entry imports lodash too (f5-dynroute)", 'const _ = require("lodash");\nconsole.log(_.map(Object.keys(routes), String));\n'],
    ["only the route imports lodash (f5b-dynroute-only)", "console.log(routes.greet('world'));\n"],
  ])("reports UNKNOWN (unresolved-reference) for a call in a route loaded with fs.readdirSync, when %s", async (_label, usage) => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp(
      `const fs = require("fs");\nconst path = require("path");\nconst routes = {};\nfor (const file of fs.readdirSync(path.join(__dirname, "routes"))) {\n  routes[path.basename(file, ".js")] = require(path.join(__dirname, "routes", file));\n}\n${usage}`,
    );
    writeProjectFile(cwd, path.join("routes", "greet.js"), 'const _ = require("lodash");\nmodule.exports = (name) => _.template("Hello <%= name %>")({ name });\n');

    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "unresolved-reference"]]);
  });

  it("searches the project once for every symbol, telling apart names that share a prefix", async () => {
    mockOsv({ lodash: [textAdvisory("GHSA-29mw-wpgm-hmr9", "ReDoS via the `trim` and `trimEnd` functions.", "MODERATE")] });
    const cwd = lodashApp(
      'const _ = require("lodash");\n_.map([1], String);\n',
      {},
      "function trim(s) { return s; }\nfunction trimEnd(s) { return s; }\nfunction map(a, f) { return a.map(f); }\nmodule.exports = { trim, trimEnd, map };\n",
    );
    writeProjectFile(cwd, path.join("scripts", "tidy.js"), 'const { trimEnd } = require("lodash");\nconsole.log(trimEnd("x "));\n');

    expect(verdicts(await analyze({ cwd }))).toEqual([
      ["GHSA-29mw-wpgm-hmr9", "trimEnd", "UNKNOWN", "unresolved-reference"],
      ["GHSA-29mw-wpgm-hmr9", "trim", "UNREACHABLE", undefined],
    ]);
  });

  it("reports UNKNOWN (unresolved-reference) when a template file names the symbol", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp('const _ = require("lodash");\n_.map([1], String);\n');
    writeProjectFile(cwd, path.join("views", "index.ejs"), "<%= _.template(body)() %>\n");

    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "unresolved-reference"]]);
  });

  it("parses .cts files and resolves a TypeScript import by its compiled name (f18-cts)", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp("");
    rmSync(path.join(cwd, "index.js"));
    writeProjectFile(cwd, "package.json", JSON.stringify({ name: "app", main: "dist/index.js" }));
    writeProjectFile(cwd, path.join("src", "index.ts"), 'import _ from "lodash";\nimport { greet } from "./greet.cjs";\nexport const doubled = _.map([1, 2], (n) => n * 2);\nexport const hello = greet("visitor");\n');
    writeProjectFile(cwd, path.join("src", "greet.cts"), 'import _ from "lodash";\nexport function greet(name: string): string {\n  return _.template("Hello <%= name %>")({ name });\n}\n');

    const { results } = await analyze({ cwd });

    expect(results.map((result) => [result.status, result.callPath])).toEqual([
      ["REACHABLE", ["src/index.ts::module", "src/greet.cts::module", "src/greet.cts::call:_.template:3"]],
    ]);
  });

  it("reports UNKNOWN (transitive) when another package's code requires it without declaring it (f8-consolidate-0.16.0)", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp('const cons = require("consolidate");\nconst _ = require("lodash");\nmodule.exports = { engine: cons.lodash, items: _.map([1], String) };\n', {
      "node_modules/consolidate": { version: "0.16.0", dependencies: { bluebird: "^3.7.2" } },
    });
    writeProjectFile(cwd, path.join("node_modules", "consolidate", "package.json"), JSON.stringify({ name: "consolidate", version: "0.16.0", main: "index.js" }));
    writeProjectFile(cwd, path.join("node_modules", "consolidate", "lib", "consolidate.js"), "exports.lodash = function (str, options) {\n  return require('lodash').template(str)(options);\n};\n");
    const declared = lodashApp('const _ = require("lodash");\n_.map([1], String);\n');
    writeProjectFile(declared, path.join("node_modules", "lodash", "fp.js"), "module.exports = require('lodash');\n");

    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "transitive"]]);
    // lodash naming itself does not count.
    expect(verdicts(await analyze({ cwd: declared }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNREACHABLE", undefined]]);
  });

  it("reports what it could not check when OSV is unreachable and nothing is cached, asking OSV no further (f12-offline)", async () => {
    const offline = vi.fn(() => Promise.reject(new TypeError("fetch failed")));
    vi.stubGlobal("fetch", offline);
    const cwd = lodashApp('const _ = require("lodash");\n_.template("x");\n', { "node_modules/qs": { version: "6.7.0" } });

    expect(await analyze({ cwd })).toEqual({ results: [], unchecked: ["lodash@4.17.20", "qs@6.7.0"] });
    // The first lookup and its three retries; qs is not tried once lodash's lookup has failed.
    expect(offline).toHaveBeenCalledTimes(4);
  });

  it("reports REACHABLE from an expired cache entry when OSV is unreachable (f12-offline)", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new TypeError("fetch failed"))));
    const cwd = lodashApp('const _ = require("lodash");\n_.template("x");\n');
    writeProjectFile(
      cwd,
      path.join(".reachable-cache", `${createCacheKey("lodash", "4.17.20")}.json`),
      JSON.stringify({ fetchedAt: "2000-01-01T00:00:00.000Z", advisories: [templateAdvisory, textAdvisory("GHSA-29mw-wpgm-hmr9", "ReDoS via the `trim` function.", "MODERATE")] }),
    );

    const scan = await analyze({ cwd });

    // The expired entry cannot hold advisories published since, so the package still counts as not checked.
    expect(scan.unchecked).toEqual(["lodash@4.17.20"]);
    expect(verdicts(scan)).toEqual([
      ["GHSA-35jh-r3h4-6jhm", "template", "REACHABLE", undefined],
      ["GHSA-29mw-wpgm-hmr9", "trim", "UNKNOWN", "lookup-failed"],
    ]);
  });

  it("stops asking OSV once advisory records fail with a network error", async () => {
    const osv = vi.fn((url: string) =>
      url.endsWith("/querybatch")
        ? Promise.resolve(new Response(JSON.stringify({ results: [{ vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }] }] })))
        : Promise.reject(new TypeError("fetch failed")),
    );
    vi.stubGlobal("fetch", osv);
    const cwd = lodashApp('const _ = require("lodash");\n_.template("x");\n', { "node_modules/qs": { version: "6.7.0" } });

    expect(await analyze({ cwd })).toEqual({ results: [], unchecked: ["lodash@4.17.20", "qs@6.7.0"] });
    // lodash's batch query and its record's four attempts; nothing for qs.
    expect(osv).toHaveBeenCalledTimes(5);
  });

  it("counts a package with no cached data on a dry run, without asking OSV", async () => {
    const cwd = lodashApp('const _ = require("lodash");\n_.template("x");\n');

    expect(await analyze({ cwd, dryRun: true })).toEqual({ results: [], unchecked: ["lodash@4.17.20"] });
  });

  // Each regression below is named after the verification fixture of 1.0.13 that gave a false UNREACHABLE.
  const unresolved = [["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "unresolved-reference"]];

  it("reads the symbol from extensionless scripts that node runs and no entry point imports (h-binwww-main, h-script-noext)", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const source = 'const _ = require("lodash");\nmodule.exports = _.map([1], String);\n';
    const shebang = lodashApp(source);
    writeProjectFile(shebang, path.join("bin", "www"), '#!/usr/bin/env node\nconst _ = require("lodash");\nconsole.log(_.template("Listening on <%= port %>")({ port: 3000 }));\n');
    const plain = lodashApp(source);
    writeProjectFile(plain, path.join("scripts", "report"), 'const _ = require("lodash");\nprocess.stdout.write(_.template("Report for <%= who %>")({ who: "me" }));\n');
    // Not read: text node would not run (a license, a shell script) and a binary.
    const other = lodashApp(source);
    writeProjectFile(other, "LICENSE", "Use this template freely.\n");
    writeProjectFile(other, path.join("bin", "start"), "#!/bin/sh\ncp template.html public/\n");
    writeProjectFile(other, path.join("bin", "tool"), "\u007fELF\0\0 require template\n");

    expect(verdicts(await analyze({ cwd: shebang }))).toEqual(unresolved);
    expect(verdicts(await analyze({ cwd: plain }))).toEqual(unresolved);
    expect(verdicts(await analyze({ cwd: other }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNREACHABLE", undefined]]);
  });

  it.each([
    ["a computed member (f13-computed)", 'const _ = require("lodash");\nconst fn = "temp" + "late";\nconsole.log(_[fn]("x")());\n'],
    ["a copy handed to the views (h-twig)", 'const _ = require("lodash");\napp.use((req, res, next) => { res.locals.lib = Object.assign({}, _); next(); });\n'],
    ["the module passed to other code (h-ns-passed)", 'const _ = require("lodash");\nconst render = require("./render");\nrender(_, "Hi");\n'],
    ["its name passed to a dependency that loads it (h-computed-spec)", 'const _ = require("lodash");\nconst render = require("tplkit");\nconsole.log(_.map([1], String), render("lodash", "Hi"));\n'],
  ])("reports UNKNOWN (unresolved-reference) when the app uses the package through %s", async (_label, source) => {
    mockOsv({ lodash: [templateAdvisory] });

    expect(verdicts(await analyze({ cwd: lodashApp(source) }))).toEqual(unresolved);
  });

  it.each([
    ["views/index.twig", "<p>{{ lib.template(greeting) }}</p>\n"],
    ["views/index.marko", "import _ from 'lodash';\n<p>${_.template(input.greeting)({})}</p>\n"],
    ["views/index.dust", "<p>{@render template=greeting /}</p>\n"],
    ["pages/post.mdx", "import _ from 'lodash'\n\n{_.template(props.body)()}\n"],
    ["src/render.coffee", "_ = require 'lodash'\nmodule.exports = (s) -> _.template(s)()\n"],
  ])("reports UNKNOWN (unresolved-reference) when %s names the symbol (h-view-marko, h-view-dust)", async (file, text) => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp('const _ = require("lodash");\n_.map([1], String);\n');
    writeProjectFile(cwd, file, text);

    expect(verdicts(await analyze({ cwd }))).toEqual(unresolved);
  });

  it("searches npm's linked install store, leaving out its dev-only packages (h-linked)", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    // npm install --install-strategy=linked: node_modules/<name> links to node_modules/.store/<name>@<version>-<hash>/node_modules/<name>.
    const linked = (cwd: string, name: string, version: string, code: string): void => {
      const dir = path.join(cwd, "node_modules", ".store", `${name}@${version}-qQuXSNEsRBRAg3LApLeIwg`, "node_modules", name);
      writeProjectFile(dir, "package.json", JSON.stringify({ name, version, main: "index.js" }));
      writeProjectFile(dir, "index.js", code);
      symlinkSync(dir, path.join(cwd, "node_modules", name), "junction");
    };
    const prod = lodashApp('const cons = require("consolidate");\nconst _ = require("lodash");\nmodule.exports = { engine: cons.lodash, items: _.map([1], String) };\n', {
      "node_modules/consolidate": { version: "0.16.0" },
    });
    linked(prod, "consolidate", "0.16.0", "exports.lodash = (str, options) => require('lodash').template(str)(options);\n");
    const dev = lodashApp('const _ = require("lodash");\n_.map([1], String);\n', { "node_modules/eslint-plugin-lodash": { version: "7.4.0", dev: true } });
    linked(dev, "eslint-plugin-lodash", "7.4.0", "module.exports = require('lodash');\n");

    expect(verdicts(await analyze({ cwd: prod }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNKNOWN", "transitive"]]);
    expect(verdicts(await analyze({ cwd: dev }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "UNREACHABLE", undefined]]);
  });

  it("does not take a project inside a __tests__ folder for test files (__tests__/app2)", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp(
      'const fs = require("fs");\nconst _ = require("lodash");\nconst routes = {};\nfor (const file of fs.readdirSync(__dirname + "/routes")) routes[file] = require(__dirname + "/routes/" + file);\nconsole.log(_.map(Object.keys(routes), String));\n',
      {},
      installedLodash,
      path.join(makeTempDir(), "__tests__", "app2"),
    );
    writeProjectFile(cwd, path.join("routes", "greet.js"), 'const _ = require("lodash");\nmodule.exports = (name) => _.template("Hello <%= name %>")({ name });\n');

    expect(verdicts(await analyze({ cwd }))).toEqual(unresolved);
  });

  it("finds the source of a dist/ entry that is not built, and warns about an entry it cannot find (h-main-missing)", async () => {
    mockOsv({ lodash: [templateAdvisory] });
    const cwd = lodashApp("");
    rmSync(path.join(cwd, "index.js"));
    writeProjectFile(cwd, "package.json", JSON.stringify({ name: "app", main: "dist/server.js", bin: { cli: "bin/cli.js" } }));
    writeProjectFile(cwd, path.join("bin", "cli.js"), '#!/usr/bin/env node\nconst _ = require("lodash");\nconsole.log(_.map([1], String));\n');
    writeProjectFile(cwd, path.join("src", "server.ts"), 'import _ from "lodash";\nexport const page = (s: string) => _.template(s)({});\n');
    const warn = vi.spyOn(logger, "warn");

    expect(detectEntryPoints(cwd)).toEqual([path.join(cwd, "src", "server.ts"), path.join(cwd, "bin", "cli.js")]);
    expect(verdicts(await analyze({ cwd }))).toEqual([["GHSA-35jh-r3h4-6jhm", "template", "REACHABLE", undefined]]);

    rmSync(path.join(cwd, "src"), { recursive: true });
    expect(detectEntryPoints(cwd)).toEqual([path.join(cwd, "bin", "cli.js")]);
    expect(warn).toHaveBeenCalledWith(expect.objectContaining({ file: "dist/server.js" }), "Skipping an entry point package.json names that does not exist");
    warn.mockRestore();
  });
});

describe("namedInDependencyCode", () => {
  it("finds module specifiers in installed packages' code at any depth, except a package's own, dev-only packages' and linked workspaces'", () => {
    const cwd = makeTempDir();
    writeProjectFile(
      cwd,
      "package-lock.json",
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "app", workspaces: ["packages/*"] },
          "node_modules/a": { version: "1.0.0" },
          "node_modules/a/node_modules/b": { version: "1.0.0" },
          "node_modules/@scope/c": { version: "1.0.0" },
          "node_modules/minimist": { version: "1.2.5" },
          "node_modules/devtool": { version: "1.0.0", dev: true },
          "node_modules/web": { resolved: "packages/web", link: true },
          "packages/web": { name: "web" },
        },
      }),
    );
    writeProjectFile(cwd, path.join("node_modules", "a", "index.js"), "module.exports = require('lodash/fp');\n");
    writeProjectFile(cwd, path.join("node_modules", "a", "node_modules", "b", "index.cjs"), 'const chalk = require("chalk");\n');
    writeProjectFile(cwd, path.join("node_modules", "@scope", "c", "index.mjs"), "export default await import(`debug`);\n");
    writeProjectFile(cwd, path.join("node_modules", "minimist", "index.js"), "module.exports = require('minimist/lib');\n");
    writeProjectFile(cwd, path.join("node_modules", "devtool", "index.js"), "require('qs');\n");
    writeProjectFile(cwd, path.join("node_modules", ".cache", "app.js"), "require('express');\n");
    writeProjectFile(cwd, path.join("node_modules", "a", "index.d.ts"), "import 'semver';\n");
    writeProjectFile(cwd, path.join("packages", "web", "index.js"), "require('react');\n");
    symlinkSync(path.join(cwd, "packages", "web"), path.join(cwd, "node_modules", "web"), "junction");
    const names = ["lodash", "chalk", "debug", "minimist", "qs", "express", "semver", "react"];

    expect(namedInDependencyCode(cwd, names)).toEqual(new Set(["lodash", "chalk", "debug"]));
    // Past the byte limit nothing is ruled out.
    expect(namedInDependencyCode(cwd, names, 10)).toBeNull();

    // Nor when a package links out of the project (file:../shared): its code is not searched.
    const shared = makeTempDir();
    writeProjectFile(shared, "index.js", "require('qs');\n");
    symlinkSync(shared, path.join(cwd, "node_modules", "shared"), "junction");
    expect(namedInDependencyCode(cwd, names)).toBeNull();
  });
});
