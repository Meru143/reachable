// cosmiconfig loader for .reachablerc.
import { cosmiconfig, cosmiconfigSync } from "cosmiconfig";
import { z } from "zod";

import { ConfigError } from "../utils/errors.js";
import { ConfigSchema, getDefaultConfig, type ReachableConfig } from "./types.js";

type SearchResult = { config: unknown; filepath: string } | null;

// An invalid config stops the scan (exit code 2), naming the file and each problem.
function validate(result: SearchResult): ReachableConfig {
  if (!result) {
    return getDefaultConfig();
  }

  const parsed = ConfigSchema.safeParse(result.config);
  if (!parsed.success) {
    throw new ConfigError(`Invalid configuration in ${result.filepath}:\n${z.prettifyError(parsed.error)}`);
  }

  return parsed.data;
}

export async function loadConfig(cwd: string): Promise<ReachableConfig> {
  return validate(await cosmiconfig("reachable").search(cwd));
}

export function loadConfigSync(cwd: string): ReachableConfig {
  return validate(cosmiconfigSync("reachable").search(cwd));
}
