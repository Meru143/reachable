#!/usr/bin/env node
// Commander root command setup.
import { Command, CommanderError } from "commander";
import { createRequire } from "node:module";

import { graphCommand } from "./graph.js";
import { scanCommand } from "./scan.js";
import { traceCommand } from "./trace.js";
import { ReachableError } from "../utils/errors.js";
import { logger } from "../utils/logger.js";

const require = createRequire(__filename);
const packageJson = require("../../package.json") as { version: string };

function writeCliError(error: unknown): void {
  const normalizedError = error instanceof Error ? error : new Error(String(error));
  const code =
    error instanceof ReachableError ? error.code : error instanceof CommanderError ? error.code : "UNHANDLED_ERROR";
  const message = logger.level === "debug" && normalizedError.stack ? normalizedError.stack : normalizedError.message;

  if (logger.level === "debug") {
    logger.error({ code }, normalizedError.message);
  }

  process.stderr.write(`${message}\n`);
  process.exit(2);
}

// exitOverride on every command: commander would otherwise exit 1 itself on a usage error in a subcommand.
export const program = new Command()
  .name("reachable")
  .version(packageJson.version)
  .description("Vulnerability reachability analyzer for Node.js projects")
  .exitOverride()
  .addCommand(scanCommand.exitOverride())
  .addCommand(traceCommand.exitOverride())
  .addCommand(graphCommand.exitOverride());

export async function run(argv: string[]): Promise<void> {
  try {
    await program.parseAsync(argv);
  } catch (error) {
    // Commander has already printed the help, the version or the usage error. A usage error exits 2, like any
    // other error, so that 1 always means a finding.
    if (error instanceof CommanderError) {
      process.exitCode = error.exitCode === 0 ? 0 : 2;
      return;
    }

    writeCliError(error);
  }
}

if (process.argv[1]) {
  process.on("uncaughtException", (error) => {
    writeCliError(error);
  });

  process.on("unhandledRejection", (reason) => {
    writeCliError(reason);
  });

  void run(process.argv);
}
