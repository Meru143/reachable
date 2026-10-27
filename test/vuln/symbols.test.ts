import { describe, expect, it } from "vitest";

import { extractVulnSymbols } from "../../src/vuln/symbols.js";
import type { Advisory } from "../../src/vuln/types.js";

// GHSA-35jh-r3h4-6jhm as GET https://api.osv.dev/v1/vulns/GHSA-35jh-r3h4-6jhm returns it (trimmed).
const lodashTemplateAdvisory: Advisory = {
  id: "GHSA-35jh-r3h4-6jhm",
  summary: "Command Injection in lodash",
  details: "`lodash` versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
  aliases: ["CVE-2021-23337"],
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }],
  database_specific: { severity: "HIGH" },
  affected: [
    { package: { name: "lodash", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] },
    { package: { name: "lodash-es", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] },
    { package: { name: "lodash.template", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { last_affected: "4.5.0" }] }] },
    { package: { name: "lodash-template", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { last_affected: "1.0.0" }] }] },
    { package: { name: "lodash-rails", ecosystem: "RubyGems" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] },
  ],
};

function textAdvisory(packageName: string, text: { summary?: string; details?: string }): Advisory {
  return {
    id: "GHSA-test-text-symbol",
    ...text,
    database_specific: { severity: "MODERATE" },
    affected: [{ package: { name: packageName, ecosystem: "npm" } }],
  };
}

function symbolsOf(packageName: string, text: { summary?: string; details?: string }) {
  return extractVulnSymbols(textAdvisory(packageName, text), packageName).map(({ exportedSymbol, confident }) => ({ exportedSymbol, confident }));
}

describe("vuln/symbols", () => {
  it("extracts vulnerable symbols from structured OSV import data", () => {
    const advisory: Advisory = {
      id: "OSV-1",
      aliases: ["GHSA-1111-2222-3333"],
      details: "Structured symbol metadata is present.",
      database_specific: {
        cvss: {
          score: 8.4,
        },
      },
      affected: [
        {
          package: {
            name: "lodash",
            ecosystem: "npm",
          },
          ranges: [
            {
              type: "ECOSYSTEM",
              events: [{ introduced: "0" }, { fixed: "4.17.21" }],
            },
          ],
          ecosystem_specific: {
            imports: [
              {
                path: "lodash.trim",
                symbols: ["trim"],
              },
            ],
          },
        },
      ],
    };

    expect(extractVulnSymbols(advisory, "lodash")).toEqual([
      {
        package: "lodash",
        ghsaId: "GHSA-1111-2222-3333",
        cvssScore: 8.4,
        severity: "HIGH",
        exportedSymbol: "trim",
        affectedVersionRange: "introduced:0 -> fixed:4.17.21",
        confident: true,
      },
    ]);
  });

  it("returns null for exportedSymbol when no structured symbol or text match exists", () => {
    const advisory: Advisory = {
      id: "OSV-2",
      aliases: ["GHSA-4444-5555-6666"],
      details: "This advisory affects runtime behavior without naming a function.",
      affected: [
        {
          package: {
            name: "minimist",
            ecosystem: "npm",
          },
        },
      ],
    };

    expect(extractVulnSymbols(advisory, "minimist")).toEqual([
      {
        package: "minimist",
        ghsaId: "GHSA-4444-5555-6666",
        cvssScore: 0,
        severity: "LOW",
        exportedSymbol: null,
        affectedVersionRange: "",
        confident: false,
      },
    ]);
  });

  it("reports a hydrated record against the installed package only, with its severity and range", () => {
    expect(extractVulnSymbols(lodashTemplateAdvisory, "lodash")).toEqual([
      {
        package: "lodash",
        ghsaId: "GHSA-35jh-r3h4-6jhm",
        cvssScore: 7,
        severity: "HIGH",
        exportedSymbol: "template",
        affectedVersionRange: "introduced:0 -> fixed:4.17.21",
        confident: true,
      },
    ]);
    expect(extractVulnSymbols(lodashTemplateAdvisory, "lodash.template").map((row) => [row.package, row.affectedVersionRange])).toEqual([
      ["lodash.template", "introduced:0 -> last_affected:4.5.0"],
    ]);
  });

  it("joins the ranges of every entry for the installed package", () => {
    const advisory: Advisory = {
      ...lodashTemplateAdvisory,
      affected: [
        { package: { name: "lodash", ecosystem: "npm" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "3.10.2" }] }] },
        { package: { name: "lodash", ecosystem: "npm" }, ranges: [{ events: [{ introduced: "4.0.0" }, { fixed: "4.17.21" }] }] },
      ],
    };

    expect(extractVulnSymbols(advisory, "lodash")).toHaveLength(1);
    expect(extractVulnSymbols(advisory, "lodash")[0]?.affectedVersionRange).toBe("introduced:0 -> fixed:3.10.2; introduced:4.0.0 -> fixed:4.17.21");
  });

  it("never uses the package's own name as the vulnerable symbol", () => {
    expect(symbolsOf("lodash", { details: "`lodash` versions prior to 4.17.21 are vulnerable." })).toEqual([{ exportedSymbol: null, confident: false }]);
    expect(symbolsOf("minimist", { summary: "Prototype pollution in `minimist()`" })).toEqual([{ exportedSymbol: null, confident: false }]);
    expect(symbolsOf("decode-uri-component", { details: "The `decodeUriComponent` function is vulnerable." })).toEqual([
      { exportedSymbol: null, confident: false },
    ]);
  });

  it.each([
    ["via the template function", ["template"]],
    ["in the `zipObjectDeep` function", ["zipObjectDeep"]],
    ["The `set` function fails to validate which Object properties it updates.", ["set"]],
    ["Code Injection via `_.template` imports key names", ["template"]],
    ["unlimited recursion in _.flatten and _.isEqual", ["flatten", "isEqual"]],
    ["ReDoS via the `toNumber`, `trim` and `trimEnd` functions.", ["toNumber", "trim", "trimEnd"]],
    ["The functions `pick`, `set`, `setWith`, `update`, `updateWith`, and `zipObjectDeep` allow pollution.", ["pick", "set", "setWith", "update", "updateWith", "zipObjectDeep"]],
    ["Prototype Pollution in `_.unset` and `_.omit` functions", ["unset", "omit"]],
  ])("names every function in %j, confidently", (details, names) => {
    expect(symbolsOf("lodash", { details })).toEqual(names.map((exportedSymbol) => ({ exportedSymbol, confident: true })));
  });

  it("takes foo() calls from the summary and lead paragraph, never confidently", () => {
    expect(symbolsOf("minimatch", { summary: "minimatch has ReDoS: matchOne() combinatorial backtracking" })).toEqual([
      { exportedSymbol: "matchOne", confident: false },
    ]);
    expect(symbolsOf("jsonwebtoken", { summary: "Signature validation bypass in jwt.verify()" })).toEqual([{ exportedSymbol: "verify", confident: false }]);
    // NVD-style code locations name an internal helper.
    expect(symbolsOf("minimist", { details: "Prototype Pollution via file `index.js`, function `setKey()` (lines 69-95)." })).toEqual([
      { exportedSymbol: "setKey", confident: false },
    ]);
    expect(symbolsOf("tar", { details: "### Summary\n\nPath traversal.\n\n### Details\n\n`stripAbsolutePath()` removes `C:`." })).toEqual([
      { exportedSymbol: null, confident: false },
    ]);
  });

  it("ignores code samples, globals, Node built-ins and prose", () => {
    const summary = "Code injection: the `Function()` constructor runs `alert(1)`, and `path.resolve()` follows the link";
    const details = [
      "All versions are vulnerable via the `trim` function. `Object.prototype` is polluted.",
      "",
      "```js",
      "// reaches the sink via the toNumber function",
      "lo.toNumber(s); console.log(Date.now());",
      "```",
      "",
      "The injected function runs via the vulnerable function.",
    ].join("\n");

    expect(symbolsOf("lodash", { summary, details })).toEqual([{ exportedSymbol: "trim", confident: true }]);
  });

  it("keeps a confident reading when a name also appears as a call", () => {
    expect(symbolsOf("lodash", { summary: "Injection in `_.template()`", details: "via the template function" })).toEqual([
      { exportedSymbol: "template", confident: true },
    ]);
  });
});
