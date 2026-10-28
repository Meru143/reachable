import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

// Each test imports the whole CLI afresh (tree-sitter, the TypeScript resolver), which can take seconds on a cold run.
describe("cli/index", { timeout: 30_000 }, () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.resetModules();
    process.exitCode = 0;
  });

  async function run(args: string[]) {
    const originalArgv = [...process.argv];
    process.argv[1] = "";
    const cli = await import("../../src/cli/index.js");
    process.argv.splice(0, process.argv.length, ...originalArgv);
    const stdout = vi.spyOn(process.stdout, "write").mockReturnValue(true);
    const stderr = vi.spyOn(process.stderr, "write").mockReturnValue(true);

    await cli.run(["node", "reachable", ...args]);
    const text = (spy: typeof stdout) => spy.mock.calls.map((call) => String(call[0])).join("");
    return { stdout: text(stdout), stderr: text(stderr) };
  }

  it("prints the version on stdout only, and exits 0", async () => {
    const packageJson = await import("../../package.json");

    expect(await run(["--version"])).toEqual({ stdout: `${packageJson.version}\n`, stderr: "" });
    expect(process.exitCode).toBe(0);
  });

  it.each([
    ["an unknown output format", ["scan", "--format", "bogus"]],
    ["an unknown severity", ["scan", "--fail-on", "severe"]],
    ["an unknown option", ["scan", "--bogus"]],
    ["an unknown command", ["bogus"]],
  ])("exits 2 on a usage error: %s", async (_label, args) => {
    const { stderr } = await run(args);

    expect(stderr).toMatch(/^error: /);
    expect(process.exitCode).toBe(2);
  });

  it("exits 2 on a config with a key it does not know, naming the file and the key", async () => {
    const cwd = mkdtempSync(path.join(os.tmpdir(), "reachable-cli-"));
    writeFileSync(path.join(cwd, ".reachablerc.json"), JSON.stringify({ failon: "low" }));
    const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);

    const { stderr } = await run(["scan", "--cwd", cwd]);
    rmSync(cwd, { recursive: true, force: true });

    expect(stderr).toContain(`Invalid configuration in ${path.join(cwd, ".reachablerc.json")}`);
    expect(stderr).toContain('Unrecognized key: "failon"');
    expect(exit).toHaveBeenCalledWith(2);
  });

  it("registers the root program metadata and subcommands", async () => {
    const originalArgv = [...process.argv];
    process.argv[1] = "";

    const [{ program }, packageJson] = await Promise.all([
      import("../../src/cli/index.js"),
      import("../../package.json"),
    ]);

    expect(program.name()).toBe("reachable");
    expect(program.description()).toBe("Vulnerability reachability analyzer for Node.js projects");
    expect(program.version()).toBe(packageJson.version);
    expect(program.commands.map((command) => command.name())).toEqual(["scan", "trace", "graph"]);

    process.argv.splice(0, process.argv.length, ...originalArgv);
  });
});
