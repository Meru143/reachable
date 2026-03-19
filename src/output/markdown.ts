// GitHub PR comment formatter.
import type { ReachabilityResult } from "../vuln/types.js";

function linkGhsa(id: string): string {
  return `[${id}](https://github.com/advisories/${id})`;
}

function summaryCount(results: ReachabilityResult[], status: ReachabilityResult["status"]): number {
  return results.filter((result) => result.status === status).length;
}

export function formatMarkdown(results: ReachabilityResult[]): string {
  const reachable = results.filter((result) => result.status === "REACHABLE");
  const unknown = results.filter((result) => result.status === "UNKNOWN");
  const unreachable = results.filter((result) => result.status === "UNREACHABLE");

  const lines = [
    "| Reachable | Unknown | Unreachable |",
    "| --- | --- | --- |",
    `| ${summaryCount(results, "REACHABLE")} | ${summaryCount(results, "UNKNOWN")} | ${summaryCount(results, "UNREACHABLE")} |`,
    "",
  ];

  if (results.length === 0) {
    lines.push("No advisories found.");
    return lines.join("\n");
  }

  if (reachable.length > 0) {
    lines.push("## Reachable");
    for (const result of reachable) {
      lines.push(`- **${result.advisory.package}** ${linkGhsa(result.advisory.ghsaId)} via \`${result.advisory.exportedSymbol ?? "unknown"}\``);
      if (result.callPath?.length) {
        lines.push(`  Path: \`${result.callPath.join(" -> ")}\``);
      }
    }
    lines.push("");
  }

  if (unknown.length > 0) {
    lines.push("## Unknown");
    for (const result of unknown) {
      lines.push(`- **${result.advisory.package}** ${linkGhsa(result.advisory.ghsaId)} could not be confirmed as reachable or unreachable.`);
    }
    lines.push("");
  }

  if (unreachable.length > 0) {
    lines.push("<details>");
    lines.push("<summary>Unreachable advisories</summary>");
    lines.push("");
    for (const result of unreachable) {
      lines.push(`- **${result.advisory.package}** ${linkGhsa(result.advisory.ghsaId)} via \`${result.advisory.exportedSymbol ?? "unknown"}\``);
    }
    lines.push("");
    lines.push("</details>");
  }

  return lines.join("\n");
}
