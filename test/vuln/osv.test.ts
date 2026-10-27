import nock from "nock";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { OsvApiError } from "../../src/utils/errors.js";
import type { Advisory } from "../../src/vuln/types.js";

const packageQuery = [{ name: "lodash", version: "4.17.20", ecosystem: "npm" }] as const;

function advisoryFixture(id = "GHSA-35jh-r3h4-6jhm"): Advisory {
  return {
    id,
    aliases: ["CVE-2021-23337"],
    details: "`lodash` versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
    database_specific: { severity: "HIGH" },
    affected: [{ package: { name: "lodash", ecosystem: "npm" } }],
  };
}

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
}

// A fetch stand-in that answers GET /v1/vulns/{id} after a tick, recording calls and peak concurrency.
function stubVulnFetch(respond: (id: string, attempt: number) => Response = (id) => json(advisoryFixture(id))) {
  const calls: string[] = [];
  const stats = { inFlight: 0, maxInFlight: 0 };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const id = decodeURIComponent(url.split("/").pop() ?? "");
      calls.push(id);
      stats.inFlight += 1;
      stats.maxInFlight = Math.max(stats.maxInFlight, stats.inFlight);
      await new Promise((resolve) => setTimeout(resolve, 5));
      stats.inFlight -= 1;
      return respond(id, calls.filter((call) => call === id).length);
    }),
  );
  return { calls, stats };
}

beforeAll(() => {
  nock.disableNetConnect();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.doUnmock("node:timers/promises");
  vi.resetModules();
  nock.cleanAll();
});

afterAll(() => {
  nock.enableNetConnect();
});

describe("vuln/osv", () => {
  it("returns the vulnerability ids from a batch query", async () => {
    nock("https://api.osv.dev")
      .post("/v1/querybatch")
      .reply(200, {
        results: [{ vulns: [{ id: "GHSA-35jh-r3h4-6jhm", modified: "2026-10-17T02:55:38Z" }, { id: "GHSA-29mw-wpgm-hmr9", modified: "2025-09-29T21:12:31Z" }] }],
      });
    const { queryBatch } = await import("../../src/vuln/osv.js");

    await expect(queryBatch([...packageQuery])).resolves.toEqual(["GHSA-35jh-r3h4-6jhm", "GHSA-29mw-wpgm-hmr9"]);
  });

  it("retries after an HTTP 429 response", async () => {
    const scope = nock("https://api.osv.dev")
      .post("/v1/querybatch")
      .reply(429, {}, { "Retry-After": "0" })
      .post("/v1/querybatch")
      .reply(200, { results: [{ vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }] }] });
    const { queryBatch } = await import("../../src/vuln/osv.js");

    await expect(queryBatch([...packageQuery])).resolves.toEqual(["GHSA-35jh-r3h4-6jhm"]);
    expect(scope.isDone()).toBe(true);
  });

  it("retries server errors and then throws OsvApiError", async () => {
    vi.doMock("node:timers/promises", () => ({
      setTimeout: () => Promise.resolve(),
    }));
    const { queryBatch } = await import("../../src/vuln/osv.js");
    nock("https://api.osv.dev")
      .post("/v1/querybatch")
      .times(4)
      .reply(500, "server down");

    const pendingQuery = queryBatch([...packageQuery]);

    await expect(pendingQuery).rejects.toMatchObject({
      name: OsvApiError.name,
      statusCode: 500,
      message: "server down",
    });
  });

  it("hydrates each id with GET /v1/vulns/{id}, once per id, in order", async () => {
    const { calls } = stubVulnFetch();
    const { fetchVulns } = await import("../../src/vuln/osv.js");

    const advisories = await fetchVulns(["GHSA-a", "GHSA-b", "GHSA-a"]);

    expect(advisories.map((advisory) => advisory.id)).toEqual(["GHSA-a", "GHSA-b"]);
    expect(advisories[0]?.affected?.[0]?.package?.name).toBe("lodash");
    expect(calls).toEqual(["GHSA-a", "GHSA-b"]);
    expect(vi.mocked(fetch).mock.calls[0]?.[0]).toBe("https://api.osv.dev/v1/vulns/GHSA-a");
  });

  it("shares fetched records across calls and caps concurrent requests at 8", async () => {
    const { calls, stats } = stubVulnFetch();
    const { fetchVulns } = await import("../../src/vuln/osv.js");
    const fetched = new Map<string, Promise<Advisory>>();
    const ids = Array.from({ length: 20 }, (_, index) => `GHSA-${index}`);

    await fetchVulns(ids, fetched);
    await fetchVulns(["GHSA-3", "GHSA-19"], fetched);

    expect(calls).toHaveLength(20);
    expect(stats.maxInFlight).toBe(8);
  });

  it("retries a record lookup like the batch query and throws after the last attempt", async () => {
    vi.doMock("node:timers/promises", () => ({
      setTimeout: () => Promise.resolve(),
    }));
    const { calls } = stubVulnFetch((id, attempt) => {
      if (id === "GHSA-flaky" && attempt === 1) {
        return new Response("{}", { status: 429, headers: { "Retry-After": "0" } });
      }
      if (id === "GHSA-flaky" && attempt === 2) {
        return new Response("busy", { status: 503 });
      }
      return id === "GHSA-down" ? new Response("server down", { status: 500 }) : json(advisoryFixture(id));
    });
    const { fetchVulns } = await import("../../src/vuln/osv.js");

    await expect(fetchVulns(["GHSA-flaky"])).resolves.toMatchObject([{ id: "GHSA-flaky" }]);
    await expect(fetchVulns(["GHSA-down"])).rejects.toMatchObject({ name: OsvApiError.name, statusCode: 500 });
    expect(calls.filter((id) => id === "GHSA-flaky")).toHaveLength(3);
    expect(calls.filter((id) => id === "GHSA-down")).toHaveLength(4);
  });

  it("throws OsvApiError when a record does not exist", async () => {
    stubVulnFetch(() => new Response('{"code":5,"message":"Bug not found."}', { status: 404 }));
    const { fetchVulns } = await import("../../src/vuln/osv.js");

    await expect(fetchVulns(["GHSA-gone"])).rejects.toMatchObject({ name: OsvApiError.name, statusCode: 404 });
  });
});
