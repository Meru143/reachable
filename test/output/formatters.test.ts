import { afterEach, describe, expect, it, vi } from "vitest";

import { formatJson } from "../../src/output/json.js";
import { formatMarkdown } from "../../src/output/markdown.js";
import { formatTable } from "../../src/output/table.js";
import type { ReachabilityResult } from "../../src/vuln/types.js";

function resultsFixture(): ReachabilityResult[] {
  return [
    {
      advisory: {
        package: "lodash",
        ghsaId: "GHSA-reachable",
        cvssScore: 8.1,
        severity: "HIGH",
        exportedSymbol: "trim",
        affectedVersionRange: "introduced:0 -> fixed:4.17.21",
      },
      status: "REACHABLE",
      callPath: ["src/index.ts::module", "src/index.ts::call:lodash.trim:12"],
    },
    {
      advisory: {
        package: "minimist",
        ghsaId: "GHSA-unknown",
        cvssScore: 5.6,
        severity: "MODERATE",
        exportedSymbol: null,
        affectedVersionRange: "introduced:0 -> fixed:1.2.6",
      },
      status: "UNKNOWN",
      callPath: null,
    },
    {
      advisory: {
        package: "qs",
        ghsaId: "GHSA-unreachable",
        cvssScore: 7.5,
        severity: "HIGH",
        exportedSymbol: "parse",
        affectedVersionRange: "introduced:0 -> fixed:6.10.3",
      },
      status: "UNREACHABLE",
      callPath: null,
    },
  ];
}

describe("output formatters", () => {
  it("formats JSON with summary counts", () => {
    const parsed = JSON.parse(formatJson(resultsFixture())) as {
      summary: {
        reachable: number;
        unreachable: number;
        unknown: number;
      };
      results: ReachabilityResult[];
    };

    expect(parsed.summary).toEqual({
      reachable: 1,
      unreachable: 1,
      unknown: 1,
    });
    expect(parsed.results).toHaveLength(3);
  });

  it("formats markdown with summary, reachable paths, and collapsible unreachable items", () => {
    const markdown = formatMarkdown(resultsFixture());

    expect(markdown).toContain("| Reachable | Unknown | Unreachable |");
    expect(markdown).toContain("## Reachable");
    expect(markdown).toContain("could not be confirmed as reachable or unreachable.");
    expect(markdown).toContain("Path: `src/index.ts::module -> src/index.ts::call:lodash.trim:12`");
    expect(markdown).toContain("<details>");
    expect(markdown).toContain("[GHSA-reachable](https://github.com/advisories/GHSA-reachable)");
  });

  it("formats table output with separate sections and reachable paths", () => {
    const table = formatTable(resultsFixture());

    expect(table).toContain("REACHABLE");
    expect(table).toContain("UNKNOWN");
    expect(table).toContain("UNREACHABLE");
    expect(table).toContain("GHSA-reachable");
    expect(table).toContain("Path: src/index.ts::module -> src/index.ts::call:lodash.trim:12");
  });

  it("shows why a result is unknown in every format that lists unknown results", () => {
    const unknown: ReachabilityResult = {
      advisory: {
        package: "lodash",
        ghsaId: "GHSA-35jh-r3h4-6jhm",
        cvssScore: 7,
        severity: "HIGH",
        exportedSymbol: "template",
        affectedVersionRange: "introduced:0 -> fixed:4.17.21",
        installedVersion: "4.17.20",
      },
      status: "UNKNOWN",
      callPath: null,
      reason: "transitive",
    };

    expect(JSON.parse(formatJson([unknown])).results[0].reason).toBe("transitive");
    expect(formatMarkdown([unknown])).toContain(
      "- **lodash@4.17.20** [GHSA-35jh-r3h4-6jhm](https://github.com/advisories/GHSA-35jh-r3h4-6jhm) via `template` could not be confirmed as reachable or unreachable (transitive).",
    );
    expect(formatTable([unknown])).toContain("Reason: transitive");
    expect(formatTable([unknown])).toContain("lodash@4.17.20");
  });

  it("formats empty markdown and table output with an explicit no-results message", () => {
    const markdown = formatMarkdown([]);
    const table = formatTable([]);

    expect(markdown).toContain("No advisories found.");
    expect(table).toContain("No advisories found.");
  });

  it("says which packages could not be checked: a JSON field, a closing line in the table and markdown", () => {
    const notice = "1 package could not be checked (the OSV lookup failed and nothing is cached), so these results are incomplete: lodash@4.17.20.";

    expect(JSON.parse(formatJson(resultsFixture(), ["lodash@4.17.20"])).unchecked).toEqual(["lodash@4.17.20"]);
    expect(JSON.parse(formatJson(resultsFixture())).unchecked).toEqual([]);
    expect(formatTable(resultsFixture(), notice).endsWith(`\n\n${notice}`)).toBe(true);
    expect(formatMarkdown(resultsFixture(), notice).endsWith(`\n\n**${notice}**`)).toBe(true);
    expect(formatTable([], notice)).toBe(`No advisories found in the packages that were checked.\n\n${notice}`);
    expect(formatMarkdown([], notice)).toContain(`No advisories found in the packages that were checked.\n\n**${notice}**`);
  });

  describe("with NO_COLOR", () => {
    afterEach(() => {
      vi.unstubAllEnvs();
      vi.resetModules();
    });

    it("prints no colour codes, table borders included", async () => {
      vi.stubEnv("NO_COLOR", "1");
      vi.stubEnv("FORCE_COLOR", undefined);
      vi.resetModules();
      const { formatTable: plainTable } = await import("../../src/output/table.js");

      expect(plainTable(resultsFixture())).not.toMatch(new RegExp(`${String.fromCharCode(27)}\\[`));
    });
  });
});
