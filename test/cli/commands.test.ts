import { afterEach, describe, expect, it, vi } from "vitest";

const appendFileSyncMock = vi.fn();
const analyzeMock = vi.fn();
const loadConfigMock = vi.fn();
const formatJsonMock = vi.fn();
const formatMarkdownMock = vi.fn();
const formatSarifMock = vi.fn();
const formatTableMock = vi.fn();
const setVerboseMock = vi.fn();
const collectSourceFilesMock = vi.fn();
const detectEntryPointsMock = vi.fn();
const buildGraphMock = vi.fn();
const parseFileMock = vi.fn();
const isNodeReachableMock = vi.fn();
const findPathToMock = vi.fn();
const ansiPattern = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, "g");

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    appendFileSync: appendFileSyncMock,
  };
});

vi.mock("../../src/analyzer.js", () => ({
  analyze: analyzeMock,
  collectSourceFiles: collectSourceFilesMock,
  detectEntryPoints: detectEntryPointsMock,
}));

vi.mock("../../src/config/loader.js", () => ({
  loadConfig: loadConfigMock,
}));

vi.mock("../../src/output/json.js", () => ({
  formatJson: formatJsonMock,
}));

vi.mock("../../src/output/markdown.js", () => ({
  formatMarkdown: formatMarkdownMock,
}));

vi.mock("../../src/output/sarif.js", () => ({
  formatSarif: formatSarifMock,
}));

vi.mock("../../src/output/table.js", () => ({
  formatTable: formatTableMock,
}));

vi.mock("../../src/utils/logger.js", () => ({
  setVerbose: setVerboseMock,
}));

vi.mock("../../src/graph/builder.js", () => ({
  buildGraph: buildGraphMock,
}));

vi.mock("../../src/parser/index.js", () => ({
  parseFile: parseFileMock,
}));

vi.mock("../../src/graph/traversal.js", () => ({
  isNodeReachable: isNodeReachableMock,
  findPathTo: findPathToMock,
}));

describe("cli commands", () => {
  afterEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
    process.exitCode = 0;
    delete process.env.GITHUB_STEP_SUMMARY;
  });

  it("runs scan with merged config, formatter output, and failure threshold", async () => {
    loadConfigMock.mockResolvedValue({
      entry: ["src/index.ts"],
      failOn: "moderate",
      ignore: ["GHSA-ignore"],
      devPackages: [],
      cache: {
        ttlHours: 24,
        dir: ".reachable-cache",
      },
    });
    analyzeMock.mockResolvedValue([
      {
        advisory: {
          package: "lodash",
          ghsaId: "GHSA-reachable",
          cvssScore: 8.1,
          severity: "HIGH",
          exportedSymbol: "trim",
          affectedVersionRange: "introduced:0 -> fixed:4.17.21",
        },
        status: "REACHABLE",
        callPath: ["src/index.ts::module", "src/index.ts::call:lodash.trim:12"],
      },
    ]);
    formatJsonMock.mockReturnValue("{\"ok\":true}");

    const stdoutWrite = vi.spyOn(process.stdout, "write").mockReturnValue(true);
    const { scanCommand } = await import("../../src/cli/scan.js");

    await scanCommand.parseAsync([
      "node",
      "scan",
      "--cwd",
      process.cwd(),
      "--format",
      "json",
      "--fail-on",
      "moderate",
      "--verbose",
    ]);

    expect(setVerboseMock).toHaveBeenCalledWith(true);
    expect(loadConfigMock).toHaveBeenCalledWith(process.cwd());
    expect(analyzeMock).toHaveBeenCalledWith({
      cwd: process.cwd(),
      entry: ["src/index.ts"],
      ignore: ["GHSA-ignore"],
      depth: 20,
      dryRun: false,
      noCache: false,
      cacheDir: ".reachable-cache",
      cacheTtlHours: 24,
    });
    expect(formatJsonMock).toHaveBeenCalled();
    expect(stdoutWrite).toHaveBeenCalledWith("{\"ok\":true}\n");
    expect(process.exitCode).toBe(1);
  });

  it("suppresses scan output in quiet mode and filters reachable results", async () => {
    loadConfigMock.mockResolvedValue({
      entry: [],
      failOn: "high",
      ignore: [],
      devPackages: [],
      cache: {
        ttlHours: 24,
        dir: ".reachable-cache",
      },
    });
    analyzeMock.mockResolvedValue([
      {
        advisory: {
          package: "lodash",
          ghsaId: "GHSA-reachable",
          cvssScore: 8.1,
          severity: "HIGH",
          exportedSymbol: "trim",
          affectedVersionRange: "",
        },
        status: "REACHABLE",
        callPath: ["src/index.ts::module"],
      },
      {
        advisory: {
          package: "minimist",
          ghsaId: "GHSA-unknown",
          cvssScore: 5.2,
          severity: "MODERATE",
          exportedSymbol: null,
          affectedVersionRange: "",
        },
        status: "UNKNOWN",
        callPath: null,
      },
    ]);

    const stdoutWrite = vi.spyOn(process.stdout, "write").mockReturnValue(true);
    const { scanCommand } = await import("../../src/cli/scan.js");

    await scanCommand.parseAsync(["node", "scan", "--cwd", process.cwd(), "--quiet", "--reachable-only"]);

    expect(formatTableMock).not.toHaveBeenCalled();
    expect(stdoutWrite).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
  });

  it("writes a markdown summary when GITHUB_STEP_SUMMARY is set", async () => {
    loadConfigMock.mockResolvedValue({
      entry: [],
      failOn: "high",
      ignore: [],
      devPackages: [],
      cache: {
        ttlHours: 24,
        dir: ".reachable-cache",
      },
    });
    analyzeMock.mockResolvedValue([
      {
        advisory: {
          package: "lodash",
          ghsaId: "GHSA-summary",
          cvssScore: 8.1,
          severity: "HIGH",
          exportedSymbol: "trim",
          affectedVersionRange: "",
        },
        status: "REACHABLE",
        callPath: ["src/index.ts::module"],
      },
    ]);
    formatTableMock.mockReturnValue("table output");
    formatMarkdownMock.mockReturnValue("## Summary");
    process.env.GITHUB_STEP_SUMMARY = "/tmp/reachable-summary.md";

    const stdoutWrite = vi.spyOn(process.stdout, "write").mockReturnValue(true);
    const { scanCommand } = await import("../../src/cli/scan.js");

    await scanCommand.parseAsync(["node", "scan", "--cwd", process.cwd()]);

    expect(stdoutWrite).toHaveBeenCalledWith("table output\n");
    expect(formatMarkdownMock).toHaveBeenCalledWith([
      {
        advisory: {
          package: "lodash",
          ghsaId: "GHSA-summary",
          cvssScore: 8.1,
          severity: "HIGH",
          exportedSymbol: "trim",
          affectedVersionRange: "",
        },
        status: "REACHABLE",
        callPath: ["src/index.ts::module"],
      },
    ]);
    expect(appendFileSyncMock).toHaveBeenCalledWith("/tmp/reachable-summary.md", "## Summary\n", "utf8");
  });

  it("prints graph output with import and export reachability", async () => {
    parseFileMock.mockReturnValue({
      file: "src/index.ts",
      imports: [{ kind: "esm", source: "lodash", line: 1, isTypeOnly: false }],
      exports: [{ name: "run", line: 2 }],
      calls: [],
    });
    detectEntryPointsMock.mockReturnValue(["/workspace/src/index.ts"]);
    collectSourceFilesMock.mockReturnValue(["/workspace/src/index.ts"]);
    buildGraphMock.mockReturnValue({
      nodes: new Map(),
      edges: [],
      entryPoints: ["src/index.ts::module"],
    });
    isNodeReachableMock.mockReturnValue(true);

    const stdoutWrite = vi.spyOn(process.stdout, "write").mockReturnValue(true);
    const { graphCommand } = await import("../../src/cli/graph.js");

    await graphCommand.parseAsync(["node", "graph", "src/index.ts", "--cwd", "/workspace"]);

    expect(stdoutWrite).toHaveBeenCalledWith(
      "File: src/index.ts\n\nImports:\n- esm: lodash\n\nExports:\n- run (reachable)\n",
    );
    expect(process.exitCode).toBe(0);
  });

  it("prints a no-path message when trace finds no reachable package paths", async () => {
    detectEntryPointsMock.mockReturnValue(["/workspace/src/index.ts"]);
    collectSourceFilesMock.mockReturnValue(["/workspace/src/index.ts"]);
    buildGraphMock.mockReturnValue({
      nodes: new Map(),
      edges: [],
      entryPoints: ["src/index.ts::module"],
    });

    const stdoutWrite = vi.spyOn(process.stdout, "write").mockReturnValue(true);
    const { traceCommand } = await import("../../src/cli/trace.js");

    await traceCommand.parseAsync(["node", "trace", "lodash", "--cwd", "/workspace"]);

    expect(stdoutWrite).toHaveBeenCalledWith("No reachable paths found to lodash\n");
    expect(process.exitCode).toBe(0);
  });

  it("prints traced package paths as an indented tree", async () => {
    detectEntryPointsMock.mockReturnValue(["/workspace/src/index.ts"]);
    collectSourceFilesMock.mockReturnValue(["/workspace/src/index.ts"]);
    buildGraphMock.mockReturnValue({
      nodes: new Map(),
      edges: [{ from: "src/index.ts::module", to: "pkg:lodash::module", importedFrom: "lodash" }],
      entryPoints: ["src/index.ts::module"],
    });
    findPathToMock.mockReturnValue(["src/index.ts::module"]);

    const stdoutWrite = vi.spyOn(process.stdout, "write").mockReturnValue(true);
    const { traceCommand } = await import("../../src/cli/trace.js");

    await traceCommand.parseAsync(["node", "trace", "lodash", "--cwd", "/workspace"]);

    const rendered = stdoutWrite.mock.calls.map((call) => String(call[0]).replace(ansiPattern, "")).join("");

    expect(rendered).toContain("Path 1\n");
    expect(rendered).toContain("src/index.ts::module\n");
    expect(rendered).toContain("  pkg:lodash::module\n");
    expect(process.exitCode).toBe(0);
  });
});
