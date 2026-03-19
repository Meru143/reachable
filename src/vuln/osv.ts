// OSV REST API client (POST /v1/querybatch).
import { setTimeout as sleep } from "node:timers/promises";

import packageJson from "../../package.json";

import { OsvApiError } from "../utils/errors.js";
import type { Advisory } from "./types.js";

const USER_AGENT = `reachable/${packageJson.version}`;
const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";

function retryAfterMs(headerValue: string | null): number {
  if (!headerValue) {
    return 2000;
  }

  const parsed = Number(headerValue);
  if (Number.isNaN(parsed)) {
    return 2000;
  }

  return parsed >= 1000 ? parsed : parsed * 1000;
}

export async function queryBatch(
  packages: { name: string; version: string; ecosystem: string }[],
): Promise<Advisory[]> {
  const body = {
    queries: packages.map((pkg) => ({
      package: {
        name: pkg.name,
        ecosystem: pkg.ecosystem,
      },
      version: pkg.version,
    })),
  };

  for (let attempt = 0; attempt <= 3; attempt += 1) {
    const response = await fetch(OSV_BATCH_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
      },
      body: JSON.stringify(body),
    });

    if (response.status === 429) {
      if (attempt === 3) {
        throw new OsvApiError(response.status, "OSV API rate limit exceeded");
      }

      await sleep(retryAfterMs(response.headers.get("Retry-After")));
      continue;
    }

    if (response.status >= 500) {
      if (attempt === 3) {
        const message = await response.text();
        throw new OsvApiError(response.status, message || "OSV API server error");
      }

      await sleep(2000 * 2 ** attempt);
      continue;
    }

    if (!response.ok) {
      const message = await response.text();
      throw new OsvApiError(response.status, message || "OSV API request failed");
    }

    const payload = (await response.json()) as { results?: Array<{ vulns?: Advisory[] }> };
    return (payload.results ?? []).flatMap((result) => result.vulns ?? []);
  }

  return [];
}
