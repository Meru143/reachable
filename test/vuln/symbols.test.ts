import { describe, expect, it } from "vitest";

import { extractVulnSymbols } from "../../src/vuln/symbols.js";
import type { Advisory } from "../../src/vuln/types.js";

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

    expect(extractVulnSymbols(advisory)).toEqual([
      {
        package: "lodash",
        ghsaId: "GHSA-1111-2222-3333",
        cvssScore: 8.4,
        severity: "HIGH",
        exportedSymbol: "trim",
        affectedVersionRange: "introduced:0 -> fixed:4.17.21",
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

    expect(extractVulnSymbols(advisory)).toEqual([
      {
        package: "minimist",
        ghsaId: "GHSA-4444-5555-6666",
        cvssScore: 0,
        severity: "LOW",
        exportedSymbol: null,
        affectedVersionRange: "",
      },
    ]);
  });
});
