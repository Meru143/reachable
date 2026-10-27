// `reachable trace <package>` subcommand.
import { Command } from "commander";

import { collectSourceFiles, detectEntryPoints } from "../analyzer.js";
import { buildGraph } from "../graph/builder.js";
import { findPathTo } from "../graph/traversal.js";
import { chalk } from "../utils/color.js";

type TraceOptions = {
  cwd?: string;
  entry?: string[];
};

export const traceCommand = new Command("trace")
  .description("Trace reachable paths to a package")
  .argument("<package>", "Package name to trace")
  .option("--entry <files...>", "Entry point files")
  .option("--cwd <path>", "Project root directory", process.cwd())
  .action(async (pkg: string, options: TraceOptions) => {
    const cwd = options.cwd ?? process.cwd();
    const entryPoints = detectEntryPoints(cwd, options.entry);
    const graph = buildGraph(collectSourceFiles(cwd), entryPoints, cwd);
    const packageNodeId = `pkg:${pkg}::module`;
    const incomingEdges = graph.edges.filter((edge) => edge.to === packageNodeId);
    const paths = incomingEdges
      .map((edge) => {
        const pathToImporter = findPathTo(graph, edge.from);
        return pathToImporter ? [...pathToImporter, packageNodeId] : null;
      })
      .filter((value): value is string[] => value !== null);

    if (paths.length === 0) {
      process.stdout.write(`No reachable paths found to ${pkg}\n`);
      process.exitCode = 0;
      return;
    }

    for (const [index, foundPath] of paths.entries()) {
      process.stdout.write(`${chalk.cyan(`Path ${index + 1}`)}\n`);
      for (const [depth, segment] of foundPath.entries()) {
        process.stdout.write(`${"  ".repeat(depth)}${chalk.green(segment)}\n`);
      }
    }
    process.exitCode = 0;
  });
