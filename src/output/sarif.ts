// SARIF v2.1.0 formatter.
import packageJson from "../../package.json";
import { packageLabel, type ReachabilityResult } from "../vuln/types.js";

function levelForSeverity(severity: string): "error" | "warning" {
  return severity === "CRITICAL" || severity === "HIGH" ? "error" : "warning";
}

function locationFromPath(callPath: string[] | null): { uri: string; line: number } {
  const target = callPath?.[callPath.length - 1] ?? "";
  const match = target.match(/^(.*)::call:[^:]+:(\d+)$/);
  if (match) {
    return {
      uri: match[1],
      line: Number(match[2]),
    };
  }

  const [uri] = target.split("::");
  return {
    uri,
    line: 1,
  };
}

/** `notice`: the packages that could not be checked; `incomplete`: that makes the scan incomplete (not a dry run). */
export function formatSarif(results: ReachabilityResult[], notice = "", incomplete = false): string {
  const sarifResults = results
    .filter((result) => result.status === "REACHABLE")
    .map((result) => {
      const location = locationFromPath(result.callPath);
      return {
        ruleId: result.advisory.ghsaId,
        level: levelForSeverity(result.advisory.severity),
        message: {
          text: `${packageLabel(result.advisory)} ${result.advisory.exportedSymbol ?? "unknown"} is reachable`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: location.uri,
              },
              region: {
                startLine: location.line,
              },
            },
          },
        ],
      };
    });

  return JSON.stringify(
    {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "reachable",
              version: packageJson.version,
            },
          },
          // For consumers that read only the SARIF: an incomplete scan did not succeed, and a dry run's gaps are a warning.
          invocations: [
            {
              executionSuccessful: !incomplete,
              ...(notice ? { toolExecutionNotifications: [{ level: incomplete ? "error" : "warning", message: { text: notice } }] } : {}),
            },
          ],
          results: sarifResults,
        },
      ],
    },
    null,
    2,
  );
}
