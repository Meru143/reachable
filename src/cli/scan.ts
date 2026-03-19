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

type ScanCommandOptions = {
  cache: boolean;
  cwd?: string;
  depth?: number;
  dryRun?: boolean;
  entry?: string[];
  failOn?: "critical" | "high" | "moderate" | "low" | "all";
  format?: "table" | "json" | "sarif" | "markdown";
  ignore?: string[];
  quiet?: boolean;
  reachableOnly?: boolean;
  verbose?: boolean;
};

function formatResults(format: NonNullable<ScanCommandOptions["format"]>, results: Awaited<ReturnType<typeof analyze>>): string {
  switch (format) {
    case "json":
      return formatJson(results);
    case "sarif":
      return formatSarif(results);
    case "markdown":
      return formatMarkdown(results);
    case "table":
    default:
      return formatTable(results);
  }
}

function failsThreshold(
  results: Awaited<ReturnType<typeof analyze>>,
  failOn: NonNullable<ScanCommandOptions["failOn"]>,
): boolean {
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

function writeGitHubSummary(results: Awaited<ReturnType<typeof analyze>>): void {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) {
    return;
  }

  try {
    appendFileSync(summaryPath, `${formatMarkdown(results)}\n`, "utf8");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.warn({ error: message, summaryPath }, "Failed to write GitHub Actions summary");
  }
}

export const scanCommand = new Command("scan")
  .description("Scan a project for reachable vulnerabilities")
  .option("--entry <files...>", "Entry point files")
  .addOption(new Option("--format <format>", "Output format").choices(["table", "json", "sarif", "markdown"]).default("table"))
  .addOption(new Option("--fail-on <severity>", "Minimum severity that fails the scan").choices(["critical", "high", "moderate", "low", "all"]).default("high"))
  .option("--reachable-only", "Only print reachable advisories")
  .option("--no-cache", "Skip the local advisory cache")
  .option("--dry-run", "Use cached advisories only")
  .option("--quiet", "Suppress command output")
  .option("--depth <number>", "Maximum traversal depth", (value: string) => Number(value), 20)
  .option("--ignore <ids...>", "Ignore GHSA identifiers")
  .option("--cwd <path>", "Project root directory", process.cwd())
  .option("--verbose", "Show verbose logging")
  .action(async (options: ScanCommandOptions) => {
    setVerbose(Boolean(options.verbose));
    const cwd = options.cwd ?? process.cwd();
    const config = await loadConfig(cwd);
    const analyzeOptions: AnalyzeOptions = {
      cwd,
      entry: options.entry ?? config.entry,
      ignore: options.ignore ?? config.ignore,
      depth: options.depth ?? 20,
      dryRun: options.dryRun ?? false,
      noCache: options.cache === false,
      cacheDir: config.cache.dir,
      cacheTtlHours: config.cache.ttlHours,
    };

    const results = await analyze(analyzeOptions);
    const filteredResults = options.reachableOnly ? results.filter((result) => result.status === "REACHABLE") : results;
    const failOn = options.failOn ?? config.failOn;
    const format = options.format ?? "table";

    writeGitHubSummary(filteredResults);

    if (!options.quiet) {
      process.stdout.write(`${formatResults(format, filteredResults)}\n`);
    }

    process.exitCode = failsThreshold(results, failOn) ? 1 : 0;
  });
