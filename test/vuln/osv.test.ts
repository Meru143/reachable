import nock from "nock";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { OsvApiError } from "../../src/utils/errors.js";
import type { Advisory } from "../../src/vuln/types.js";

const packageQuery = [{ name: "lodash", version: "4.17.20", ecosystem: "npm" }] as const;

function advisoryFixture(): Advisory {
  return {
    id: "OSV-LO-1",
    aliases: ["GHSA-7777-8888-9999"],
    details: "Example advisory",
    affected: [
      {
        package: {
          name: "lodash",
          ecosystem: "npm",
        },
      },
    ],
  };
}

beforeAll(() => {
  nock.disableNetConnect();
});

afterEach(() => {
  vi.doUnmock("node:timers/promises");
  vi.resetModules();
  nock.cleanAll();
});

afterAll(() => {
  nock.enableNetConnect();
});

describe("vuln/osv", () => {
  it("returns advisories from a successful batch query", async () => {
    const advisory = advisoryFixture();
    nock("https://api.osv.dev").post("/v1/querybatch").reply(200, {
      results: [{ vulns: [advisory] }],
    });
    const { queryBatch } = await import("../../src/vuln/osv.js");

    await expect(queryBatch([...packageQuery])).resolves.toEqual([advisory]);
  });

  it("retries after an HTTP 429 response", async () => {
    const advisory = advisoryFixture();
    const scope = nock("https://api.osv.dev")
      .post("/v1/querybatch")
      .reply(429, {}, { "Retry-After": "0" })
      .post("/v1/querybatch")
      .reply(200, { results: [{ vulns: [advisory] }] });
    const { queryBatch } = await import("../../src/vuln/osv.js");

    await expect(queryBatch([...packageQuery])).resolves.toEqual([advisory]);
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
});
