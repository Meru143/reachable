// Utility functions for loading test fixtures and mocking OSV.
import { readFileSync } from "node:fs";
import path from "node:path";

import nock from "nock";

import type { Advisory } from "../src/vuln/types.js";

export function fixturePath(...segments: string[]): string {
  return path.join(process.cwd(), "test", "fixtures", ...segments);
}

export function readFixture(...segments: string[]): string {
  return readFileSync(fixturePath(...segments), "utf8");
}

/**
 * Mocks OSV like the real API: the batch query returns only ids, GET /v1/vulns/{id} returns the full record.
 * Keys are package names, or name@version for one version only.
 */
export function mockOsv(advisoriesByPackage: Record<string, Advisory[]>) {
  const records = new Map(Object.values(advisoriesByPackage).flat().map((advisory) => [advisory.id, advisory]));

  return nock("https://api.osv.dev")
    .persist()
    .post("/v1/querybatch")
    .reply(200, (_uri, requestBody) => {
      const payload = (typeof requestBody === "string" ? JSON.parse(requestBody) : requestBody) as {
        queries?: Array<{ package?: { name?: string }; version?: string }>;
      };
      const packageName = payload.queries?.[0]?.package?.name ?? "";
      const advisories = advisoriesByPackage[`${packageName}@${payload.queries?.[0]?.version}`] ?? advisoriesByPackage[packageName] ?? [];

      return {
        results: [{ vulns: advisories.map(({ id }) => ({ id, modified: "2026-10-01T00:00:00Z" })) }],
      };
    })
    .get(/^\/v1\/vulns\//)
    .reply((uri) => {
      const record = records.get(decodeURIComponent(uri.split("/").pop() ?? ""));
      return record ? [200, record] : [404, { code: 5, message: "Bug not found." }];
    });
}
