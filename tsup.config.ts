// Bundle configuration for the reachable CLI entry point.
import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/cli/index.ts"],
  format: ["cjs"],
  dts: true,
  outDir: "dist",
  clean: true,
  sourcemap: true,
  target: "node22",
});
