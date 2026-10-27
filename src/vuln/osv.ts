// OSV REST API client. POST /v1/querybatch lists the vulnerability ids for a package version (only id and
// modified); GET /v1/vulns/{id} returns the full record with affected packages, severity and details.
import { setTimeout as sleep } from "node:timers/promises";

import packageJson from "../../package.json";

import { OsvApiError } from "../utils/errors.js";
import type { Advisory } from "./types.js";

const USER_AGENT = `reachable/${packageJson.version}`;
const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns/";
const VULN_CONCURRENCY = 8;

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

// Retries 429 (after Retry-After) and 5xx (exponential backoff) three times, then throws OsvApiError.
async function requestJson<T>(url: string, body?: unknown): Promise<T> {
  for (let attempt = 0; ; attempt += 1) {
    const response = await fetch(url, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
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

    return (await response.json()) as T;
  }
}

/** Ids of the vulnerabilities affecting the given package versions. */
export async function queryBatch(packages: { name: string; version: string; ecosystem: string }[]): Promise<string[]> {
  const payload = await requestJson<{ results?: Array<{ vulns?: Array<{ id: string }> }> }>(OSV_BATCH_URL, {
    queries: packages.map((pkg) => ({
      package: {
        name: pkg.name,
        ecosystem: pkg.ecosystem,
      },
      version: pkg.version,
    })),
  });

  return (payload.results ?? []).flatMap((result) => result.vulns ?? []).map((vuln) => vuln.id);
}

/**
 * Full OSV records for the given ids, each id fetched once and at most VULN_CONCURRENCY at a time.
 * Share `fetched` across calls to fetch an id once per run.
 */
export async function fetchVulns(ids: string[], fetched = new Map<string, Promise<Advisory>>()): Promise<Advisory[]> {
  const uniqueIds = [...new Set(ids)];
  const advisories: Advisory[] = [];

  for (let start = 0; start < uniqueIds.length; start += VULN_CONCURRENCY) {
    const batch = uniqueIds.slice(start, start + VULN_CONCURRENCY).map((id) => {
      const pending = fetched.get(id) ?? requestJson<Advisory>(`${OSV_VULN_URL}${encodeURIComponent(id)}`);
      fetched.set(id, pending);
      return pending;
    });
    advisories.push(...(await Promise.all(batch)));
  }

  return advisories;
}
