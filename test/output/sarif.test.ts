import { describe, expect, it } from "vitest";

import { formatSarif } from "../../src/output/sarif.js";
import type { ReachabilityResult } from "../../src/vuln/types.js";

function reachableResult(ghsaId: string, severity: "CRITICAL" | "HIGH" | "MODERATE" | "LOW"): ReachabilityResult {
  return {
    advisory: {
      package: "lodash",
      ghsaId,
      cvssScore: severity === "CRITICAL" ? 9.8 : severity === "HIGH" ? 8.1 : 5.6,
      severity,
      exportedSymbol: "trim",
      affectedVersionRange: "introduced:0 -> fixed:4.17.21",
    },
    status: "REACHABLE",
    callPath: ["src/index.ts::module", "src/index.ts::call:trim:12"],
  };
}

describe("output/sarif", () => {
  it("outputs SARIF with version 2.1.0", () => {
    const sarif = JSON.parse(formatSarif([reachableResult("GHSA-1111-2222-3333", "HIGH")])) as {
      version: string;
    };

    expect(sarif.version).toBe("2.1.0");
  });

  it("names the installed version in the message", () => {
    const result = reachableResult("GHSA-1111-2222-3333", "HIGH");
    const sarif = JSON.parse(formatSarif([{ ...result, advisory: { ...result.advisory, installedVersion: "4.17.20" } }])) as {
      runs: Array<{ results: Array<{ message: { text: string } }> }>;
    };

    expect(sarif.runs[0].results[0]?.message.text).toBe("lodash@4.17.20 trim is reachable");
  });

  it("maps each reachable result to a SARIF result entry", () => {
    const sarif = JSON.parse(
      formatSarif([
        reachableResult("GHSA-1111-2222-3333", "HIGH"),
        reachableResult("GHSA-4444-5555-6666", "MODERATE"),
      ]),
    ) as {
      runs: Array<{ results: Array<{ ruleId: string; level: string }> }>;
    };

    expect(sarif.runs[0].results).toHaveLength(2);
    expect(sarif.runs[0].results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ ruleId: "GHSA-1111-2222-3333", level: "error" }),
        expect.objectContaining({ ruleId: "GHSA-4444-5555-6666", level: "warning" }),
      ]),
    );
  });

  it("excludes unreachable results from SARIF output", () => {
    const sarif = JSON.parse(
      formatSarif([
        reachableResult("GHSA-1111-2222-3333", "HIGH"),
        {
          advisory: {
            package: "lodash",
            ghsaId: "GHSA-7777-8888-9999",
            cvssScore: 8.1,
            severity: "HIGH",
            exportedSymbol: "trim",
            affectedVersionRange: "introduced:0 -> fixed:4.17.21",
          },
          status: "UNREACHABLE",
          callPath: null,
        },
      ]),
    ) as {
      runs: Array<{ results: Array<{ ruleId: string }> }>;
    };

    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0]?.ruleId).toBe("GHSA-1111-2222-3333");
  });

  it("records in the run whether the scan was complete, for consumers that read only the SARIF", () => {
    type Run = { invocations: Array<{ executionSuccessful: boolean; toolExecutionNotifications?: Array<{ level: string; message: { text: string } }> }> };
    const run = (sarif: string) => (JSON.parse(sarif) as { runs: Run[] }).runs[0]?.invocations;
    const notice = "1 package could not be checked (the OSV lookup failed), so these results are incomplete: lodash@4.17.20.";

    expect(run(formatSarif([]))).toEqual([{ executionSuccessful: true }]);
    expect(run(formatSarif([], notice, true))).toEqual([{ executionSuccessful: false, toolExecutionNotifications: [{ level: "error", message: { text: notice } }] }]);
    expect(run(formatSarif([], "1 package had no cached advisory data.", false))).toEqual([
      { executionSuccessful: true, toolExecutionNotifications: [{ level: "warning", message: { text: "1 package had no cached advisory data." } }] },
    ]);
  });
});
