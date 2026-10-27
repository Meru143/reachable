// `reachable scan` subcommand.
import { appendFileSync } from "node:fs";

import { Command, Option } from "commander";

import { analyze } from "../analyzer.js";
import { loadConfig } from "../config/loader.js";
import { formatJson } from "../output/json.js";
import { formatMarkdown } from "../output/markdown.js";
import { formatSarif } from "../output/sarif.js";
import { formatTable } from "../output/table.js";
import { logger, setVerbose } from "../utils/logger.js";
import type { AnalyzeOptions } from "../analyzer.js";
import type { ReachabilityResult } from "../vuln/types.js";

type ScanCommandOptions = {
  cache: boolean;
  cwd?: string;
  depth?: string;
  dryRun?: boolean;
  entry?: string[];
  failOn?: "critical" | "high" | "moderate" | "low" | "all";
  format?: "table" | "json" | "sarif" | "markdown";
  ignore?: string[];
  quiet?: boolean;
  reachableOnly?: boolean;
  verbose?: boolean;
};

function formatResults(
  format: NonNullable<ScanCommandOptions["format"]>,
  results: ReachabilityResult[],
  unchecked: string[],
  notice: string,
): string {
  switch (format) {
    case "json":
      return formatJson(results, unchecked);
    case "sarif":
      return formatSarif(results);
    case "markdown":
      return formatMarkdown(results, notice);
    case "table":
    default:
      return formatTable(results, notice);
  }
}

function failsThreshold(results: ReachabilityResult[], failOn: NonNullable<ScanCommandOptions["failOn"]>): boolean {
  const thresholdOrder = {
    low: 0,
    moderate: 1,
    high: 2,
    critical: 3,
  } as const;
  return results.some((result) => {
    if (result.status !== "REACHABLE") {
      return false;
    }

    if (failOn === "all") {
      return true;
    }

    return thresholdOrder[result.advisory.severity.toLowerCase() as keyof typeof thresholdOrder] >= thresholdOrder[failOn];
  });
}

// "" when every package was checked.
function incompleteNotice(unchecked: string[], dryRun: boolean): string {
  if (unchecked.length === 0) {
    return "";
  }

  const count = unchecked.length === 1 ? "1 package" : `${unchecked.length} packages`;
  const names = unchecked.length > 10 ? `${unchecked.slice(0, 10).join(", ")} and ${unchecked.length - 10} more` : unchecked.join(", ");
  return dryRun
    ? `${count} had no cached advisory data (or only expired data), so this dry run did not check them: ${names}.`
    : `${count} could not be checked (the OSV lookup failed and nothing is cached), so these results are incomplete: ${names}.`;
}

function writeGitHubSummary(results: ReachabilityResult[], notice: string): void {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) {
    return;
  }

  try {
    appendFileSync(summaryPath, `${formatMarkdown(results, notice)}\n`, "utf8");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.warn({ error: message, summaryPath }, "Failed to write GitHub Actions summary");
  }
}

export const scanCommand = new Command("scan")
  .description("Scan a project for reachable vulnerabilities")
  .option("--entry <files...>", "Entry point files")
  .addOption(new Option("--format <format>", "Output format").choices(["table", "json", "sarif", "markdown"]).default("table"))
  // No commander default: an absent --fail-on falls back to the config's failOn, which defaults to high.
  .addOption(new Option("--fail-on <severity>", "Minimum severity that fails the scan (default: failOn from the config, else high)").choices(["critical", "high", "moderate", "low", "all"]))
  .option("--reachable-only", "Only print reachable advisories")
  .option("--no-cache", "Skip the local advisory cache")
  .option("--dry-run", "Use cached advisories only")
  .option("--quiet", "Suppress command output")
  // Retired: it never limited anything. Still accepted so existing scripts keep working.
  .addOption(new Option("--depth <number>").hideHelp())
  .option("--ignore <ids...>", "Ignore GHSA identifiers")
  .option("--cwd <path>", "Project root directory", process.cwd())
  .option("--verbose", "Show verbose logging")
  .action(async (options: ScanCommandOptions) => {
    setVerbose(Boolean(options.verbose));
    if (options.depth !== undefined) {
      process.stderr.write("--depth has no effect (every import is followed) and will be removed.\n");
    }

    const cwd = options.cwd ?? process.cwd();
    const config = await loadConfig(cwd);
    const analyzeOptions: AnalyzeOptions = {
      cwd,
      entry: options.entry ?? config.entry,
      ignore: options.ignore ?? config.ignore,
      dryRun: options.dryRun ?? false,
      noCache: options.cache === false,
      cacheDir: config.cache.dir,
      cacheTtlHours: config.cache.ttlHours,
    };

    const { results, unchecked } = await analyze(analyzeOptions);
    const filteredResults = options.reachableOnly ? results.filter((result) => result.status === "REACHABLE") : results;
    const failOn = options.failOn ?? config.failOn;
    const format = options.format ?? "table";
    const notice = incompleteNotice(unchecked, Boolean(options.dryRun));

    writeGitHubSummary(filteredResults, notice);

    if (!options.quiet) {
      process.stdout.write(`${formatResults(format, filteredResults, unchecked, notice)}\n`);
    }

    if (notice) {
      process.stderr.write(`${notice}\n`);
    }

    // 1: a REACHABLE advisory at or above the threshold. 2: an incomplete scan, except on a dry run, which reads the
    // cache only by design.
    process.exitCode = failsThreshold(results, failOn) ? 1 : unchecked.length > 0 && !options.dryRun ? 2 : 0;
  });
