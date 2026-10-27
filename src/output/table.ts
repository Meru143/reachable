// cli-table3 terminal output.
import Table from "cli-table3";
import { Chalk } from "chalk";

import { packageLabel, type ReachabilityResult } from "../vuln/types.js";

const chalk = new Chalk({ level: process.env.NO_COLOR ? 0 : 1 });

function sectionColor(status: ReachabilityResult["status"]) {
  if (status === "REACHABLE") {
    return chalk.red;
  }

  if (status === "UNKNOWN") {
    return chalk.yellow;
  }

  return chalk.green.dim;
}

function sortByScore(results: ReachabilityResult[]): ReachabilityResult[] {
  return [...results].sort((left, right) => right.advisory.cvssScore - left.advisory.cvssScore);
}

export function formatTable(results: ReachabilityResult[]): string {
  if (results.length === 0) {
    return "No advisories found.";
  }

  const sections: ReachabilityResult["status"][] = ["REACHABLE", "UNKNOWN", "UNREACHABLE"];
  const blocks: string[] = [];

  for (const status of sections) {
    const rows = sortByScore(results.filter((result) => result.status === status));
    if (rows.length === 0) {
      continue;
    }

    const color = sectionColor(status);
    const table = new Table({
      head: ["Severity", "Package", "GHSA ID", "Status", "Vulnerable Symbol"],
      wordWrap: true,
    });

    for (const row of rows) {
      table.push([
        row.advisory.severity,
        packageLabel(row.advisory),
        row.advisory.ghsaId,
        row.status,
        row.advisory.exportedSymbol ?? "unknown",
      ]);

      if (row.status === "REACHABLE" && row.callPath?.length) {
        table.push([
          {
            colSpan: 5,
            content: chalk.dim(`Path: ${row.callPath.join(" -> ")}`),
          },
        ]);
      }

      if (row.reason) {
        table.push([
          {
            colSpan: 5,
            content: chalk.dim(`Reason: ${row.reason}`),
          },
        ]);
      }
    }

    blocks.push(`${color(status)}\n${table.toString()}`);
  }

  return blocks.join("\n\n");
}
