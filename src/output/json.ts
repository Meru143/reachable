// JSON formatter.
import type { ReachabilityResult } from "../vuln/types.js";

/** `unchecked`: name@version of the packages whose advisories could not be looked up. */
export function formatJson(results: ReachabilityResult[], unchecked: string[] = []): string {
  const summary = {
    reachable: results.filter((result) => result.status === "REACHABLE").length,
    unreachable: results.filter((result) => result.status === "UNREACHABLE").length,
    unknown: results.filter((result) => result.status === "UNKNOWN").length,
  };

  return JSON.stringify({ summary, results, unchecked }, null, 2);
}
