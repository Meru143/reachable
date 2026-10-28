import nock from "nock";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { analyze } from "../../src/analyzer.js";
import { fixturePath, mockOsv } from "../helpers.js";
import type { Advisory } from "../../src/vuln/types.js";

function advisoryFor(packageName: string, symbol: string, ghsaId: string): Advisory {
  return {
    id: ghsaId,
    aliases: [ghsaId],
    details: `The \`${symbol}()\` entry point is vulnerable.`,
    database_specific: {
      cvss: {
        score: 8.1,
      },
    },
    affected: [
      {
        package: {
          name: packageName,
          ecosystem: "npm",
        },
        ecosystem_specific: {
          imports: [
            {
              path: `${packageName}.${symbol}`,
              symbols: [symbol],
            },
          ],
        },
      },
    ],
  };
}

beforeAll(() => {
  nock.disableNetConnect();
});

afterEach(() => {
  nock.cleanAll();
});

afterAll(() => {
  nock.enableNetConnect();
});

describe("integration/reachable", () => {
  it("reports a reachable vulnerability for the simple fixture", async () => {
    mockOsv({
      lodash: [advisoryFor("lodash", "trim", "GHSA-reachable-lodash")],
    });

    const { results } = await analyze({
      cwd: fixturePath("simple-express"),
      noCache: true,
    });
    const reachable = results.find((result) => result.status === "REACHABLE" && result.advisory.package === "lodash");

    expect(reachable).toBeDefined();
    expect(reachable?.callPath?.length ?? 0).toBeGreaterThan(0);
  });

  it("does not report lodash as reachable when only safe functions are called", async () => {
    mockOsv({
      lodash: [advisoryFor("lodash", "trim", "GHSA-safe-lodash")],
    });

    const { results } = await analyze({
      cwd: fixturePath("safe-usage"),
      noCache: true,
    });

    expect(results.filter((result) => result.status === "REACHABLE" && result.advisory.package === "lodash")).toHaveLength(0);
  });

  it("analyzes each workspace when run from the monorepo root", async () => {
    mockOsv({
      lodash: [advisoryFor("lodash", "trim", "GHSA-workspace-lodash")],
      minimist: [advisoryFor("minimist", "minimist", "GHSA-workspace-minimist")],
    });

    const { results } = await analyze({
      cwd: fixturePath("monorepo"),
      noCache: true,
    });
    const lodash = results.find((result) => result.advisory.package === "lodash");
    const minimist = results.find((result) => result.advisory.package === "minimist");

    expect(lodash?.status).toBe("REACHABLE");
    expect(lodash?.callPath?.[0]).toBe("packages/pkg-a/src/index.ts::module");
    // pkg-b's import is seen (not "not-imported"); the advisory names only the package itself, whose default
    // export can be bound to any name, so no symbol can be matched.
    expect([minimist?.status, minimist?.reason, minimist?.advisory.exportedSymbol]).toEqual(["UNKNOWN", "symbol-unknown", null]);
  });
});
