# 2026-03-19-reachable-todo.md
# reachable — Detailed TODO List

---

## Phase 1: Project Setup

### 1.1 Repository Initialization
- [x] Run `npm init -y` in new `reachable/` directory
- [x] Set `name`, `version: "0.1.0"`, `description` in `package.json`
- [x] Set `"type": "module"` in `package.json` for ESM
- [x] Add `"bin": { "reachable": "./dist/cli/index.js" }` to `package.json`
- [x] Add `"engines": { "node": ">=18.0.0" }` to `package.json`
- [x] Create `README.md` with project name and one-line description
- [x] Create `LICENSE` file (MIT)
- [x] Create `.gitignore` (node_modules, dist, .reachable-cache, coverage)
- [x] Create `CHANGELOG.md` with initial `## [Unreleased]` section
- [x] Run `git init && git add -A && git commit -m "chore: initial scaffold"`

### 1.2 Directory Structure
- [x] Create `src/` directory
- [x] Create `src/cli/` directory
- [x] Create `src/parser/` directory
- [x] Create `src/graph/` directory
- [x] Create `src/vuln/` directory
- [x] Create `src/output/` directory
- [x] Create `src/config/` directory
- [x] Create `src/utils/` directory
- [x] Create `test/` directory
- [x] Create `test/fixtures/` directory
- [x] Create `test/fixtures/simple-express/` with `package.json` and `src/index.ts`
- [x] Create `test/fixtures/unused-lodash/` with a lodash import that never calls vulnerable fn
- [x] Create `test/fixtures/monorepo/` with two workspace packages
- [x] Create `.github/workflows/` directory

### 1.3 TypeScript Setup
- [x] Run `npm install --save-dev typescript@5 @types/node`
- [x] Create `tsconfig.json` with `"module": "ESNext"`, `"moduleResolution": "bundler"`, `"target": "ES2022"`, `"strict": true`
- [x] Create `tsup.config.ts` with entry `src/cli/index.ts`, format `["cjs"]`, `dts: true`, `outDir: "dist"`

### 1.4 CLI Framework Setup
- [x] Run `npm install commander@12`
- [x] Create `src/cli/index.ts` with root `Command` named `"reachable"`
- [x] Set program `version` from `package.json` at runtime using `createRequire`
- [x] Add `description("Vulnerability reachability analyzer for Node.js projects")`
- [x] Register subcommands: `scan`, `trace`, `graph` (stubs initially)

### 1.5 Config System
- [x] Run `npm install cosmiconfig zod`
- [x] Create `src/config/types.ts` with `ConfigSchema` zod object
- [x] Define fields: `entry`, `failOn`, `ignore`, `devPackages`, `cache.ttlHours`, `cache.dir`
- [x] Create `src/config/loader.ts` with `loadConfig(cwd: string)` using `cosmiconfig("reachable")`
- [x] Apply `ConfigSchema.parse()` to loaded config for validation
- [x] Export `getDefaultConfig()` returning all defaults

### 1.6 Logging Setup
- [x] Run `npm install pino`
- [x] Create `src/utils/logger.ts` exporting a `pino` logger instance
- [x] Read `LOG_LEVEL` from `process.env` with fallback `"warn"`
- [x] Export `setVerbose(val: boolean)` that sets level to `"debug"`
- [x] Use `pino-pretty` only when `process.stdout.isTTY` is true

### 1.7 Build & Release Config
- [x] Create `.github/workflows/ci.yml` with triggers on `push` and `pull_request`
- [x] Create `.github/workflows/release.yml` triggered on tag `v*`
- [x] Run `npm install --save-dev semantic-release @semantic-release/changelog @semantic-release/git`
- [x] Create `.releaserc.json` configuring semantic-release with npm and changelog plugins
- [x] Create `Makefile` with targets: `lint`, `test`, `build`, `test-integration`

### 1.8 Testing Setup
- [x] Run `npm install --save-dev vitest @vitest/coverage-v8`
- [x] Create `vitest.config.ts` with `include: ["test/**/*.test.ts"]`
- [x] Create `vitest.integration.config.ts` with `include: ["test/**/*.integration.ts"]`
- [x] Create `test/helpers.ts` with utility functions for loading fixtures

---

## Phase 2: AST Parser

### 2.1 tree-sitter Setup
- [x] Run `npm install tree-sitter tree-sitter-javascript tree-sitter-typescript`
- [x] Create `src/parser/index.ts` with `parseFile(filePath: string): ParsedModule` dispatch function
- [x] Add extension detection: `.js`, `.mjs`, `.cjs` → JavaScript parser; `.ts`, `.mts` → TypeScript; `.tsx`, `.jsx` → respective X grammar
- [x] Export `ParsedModule` interface: `{ file: string; imports: ImportRef[]; exports: ExportRef[]; calls: CallRef[] }`

### 2.2 JavaScript Parser
- [x] Create `src/parser/javascript.ts`
- [x] Initialize `new Parser()` and call `parser.setLanguage(JavaScript)` using `tree-sitter-javascript` grammar
- [x] Implement `extractRequireCalls(tree: Tree): ImportRef[]` — query for `(call_expression function: (identifier) @fn arguments: (arguments (string) @path) (#eq? @fn "require"))`
- [x] Implement `extractESMImports(tree: Tree): ImportRef[]` — query for `(import_declaration source: (string) @source)`
- [x] Implement `extractDynamicImports(tree: Tree): ImportRef[]` — query for `(await_expression (call_expression function: (import) arguments: (arguments (string) @path)))`
- [x] Implement `extractCallSites(tree: Tree): CallRef[]` — query for `(call_expression function: [(member_expression) (identifier)] @callee)`
- [x] Implement `extractExports(tree: Tree): ExportRef[]` — query for `(export_statement)`

### 2.3 TypeScript Parser
- [x] Create `src/parser/typescript.ts`
- [x] Initialize parser with `require("tree-sitter-typescript").typescript` grammar
- [x] Reuse `extractESMImports` logic from JS parser (TS uses same import syntax)
- [x] Add `extractTypeImports()` — detect `import type { ... }` and mark `isTypeOnly: true` on `ImportRef`
- [x] Skip type-only imports in call graph (they don't generate runtime calls)
- [x] Handle `.tsx` files by switching to `require("tree-sitter-typescript").tsx` grammar

### 2.4 Path Resolver
- [x] Create `src/parser/resolver.ts`
- [x] Implement `resolveImport(importPath: string, fromFile: string, cwd: string): string | null`
- [x] Handle relative paths (`./`, `../`) using `path.resolve`
- [x] Handle `node_modules` imports — return the package name without resolving to file
- [x] Load `tsconfig.json` paths aliases using `typescript` package's `readConfigFile`
- [x] Apply path alias substitution before resolution
- [x] Handle index file resolution (`import "./utils"` → `./utils/index.ts`)

---

## Phase 3: Call Graph Builder

### 3.1 Types
- [ ] Create `src/graph/types.ts`
- [ ] Define `CallNode` interface: `{ id: string; file: string; name: string; line: number; isEntryPoint: boolean }`
- [ ] Define `CallEdge` interface: `{ from: string; to: string; importedFrom: string }`
- [ ] Define `CallGraph` interface: `{ nodes: Map<string, CallNode>; edges: CallEdge[]; entryPoints: string[] }`

### 3.2 Graph Builder
- [ ] Create `src/graph/builder.ts`
- [ ] Implement `buildGraph(files: string[], entryPoints: string[], cwd: string): CallGraph`
- [ ] For each file: call `parseFile()`, create `CallNode` for each exported function
- [ ] For each import reference: create `CallEdge` from importing file to imported module
- [ ] Detect test files (`*.test.*`, `*.spec.*`, `__tests__/`) and skip unless `--include-tests` set
- [ ] Detect and handle circular imports: track visited nodes in a `Set<string>`, skip if already visited
- [ ] Log warning when circular import detected

### 3.3 BFS Traversal
- [ ] Create `src/graph/traversal.ts`
- [ ] Implement `findReachableNodes(graph: CallGraph, maxDepth: number): Set<string>` using BFS from all entry points
- [ ] Implement `findPathTo(graph: CallGraph, targetNodeId: string): string[] | null` returning ordered path
- [ ] Implement `isNodeReachable(graph: CallGraph, nodeId: string): boolean`
- [ ] Terminate BFS branch when `depth > maxDepth`, log warning
- [ ] Return `null` path (not false) when target node not in graph at all

---

## Phase 4: Vulnerability Fetcher

### 4.1 OSV API Client
- [ ] Create `src/vuln/osv.ts`
- [ ] Implement `queryBatch(packages: {name: string; version: string; ecosystem: string}[]): Promise<Advisory[]>`
- [ ] Build request body: `{ queries: packages.map(p => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }`
- [ ] POST to `https://api.osv.dev/v1/querybatch` with `Content-Type: application/json`
- [ ] Set `User-Agent: reachable/<version>` header on all requests
- [ ] Parse response `results[].vulns` array from each batch result
- [ ] Implement retry logic: on HTTP 429, wait `retryAfterMs` (from `Retry-After` header or 2000ms) and retry up to 3 times
- [ ] On HTTP 5xx, retry with exponential backoff: 2s, 4s, 8s
- [ ] Throw `OsvApiError` with status code and message on non-retryable failure

### 4.2 Advisory Cache
- [ ] Create `src/vuln/cache.ts`
- [ ] Implement `getCached(key: string, cacheDir: string, ttlHours: number): Advisory[] | null`
- [ ] Cache key format: `sha256(packageName + "@" + packageVersion).hex`
- [ ] Store cache file at `<cacheDir>/<key>.json` containing `{ fetchedAt: ISO8601, advisories: Advisory[] }`
- [ ] Compare `fetchedAt` against `Date.now()` to determine expiry
- [ ] Implement `setCache(key: string, data: Advisory[], cacheDir: string): void`
- [ ] Create `cacheDir` with `fs.mkdirSync(dir, { recursive: true })` if not exists
- [ ] Implement `clearCache(cacheDir: string): void` for `--no-cache` flag

### 4.3 Symbol Extractor
- [ ] Create `src/vuln/symbols.ts`
- [ ] Implement `extractVulnSymbols(advisory: Advisory): VulnSymbol[]`
- [ ] Check `advisory.affected[].ecosystem_specific.imports` for structured symbol list (OSV schema field)
- [ ] If structured data absent, attempt regex extraction from `advisory.details` text: match patterns like `` `functionName()` `` or `"functionName"` near "vulnerable" or "affected"
- [ ] Return `exportedSymbol: null` when symbol cannot be determined
- [ ] Map OSV CVSS score to `severity`: `>= 9.0` → CRITICAL, `>= 7.0` → HIGH, `>= 4.0` → MODERATE, `< 4.0` → LOW

### 4.4 Package Lock Parser
- [ ] Create `src/utils/packagelock.ts`
- [ ] Implement `parsePackageLock(cwd: string): InstalledPackage[]`
- [ ] Detect lockfile version: v2 uses `dependencies` key, v3 uses `packages` key
- [ ] Parse v3 format: iterate `packages` object, skip `""` (root), extract `name` from key and `version` from value
- [ ] Parse v2 format: recursively walk `dependencies` tree
- [ ] Deduplicate packages by name (use resolved version)
- [ ] Filter out `devDependencies` based on config unless `--include-dev` flag set

---

## Phase 5: Reachability Analyzer

### 5.1 Core Analyzer
- [ ] Create `src/analyzer.ts`
- [ ] Implement `analyze(options: AnalyzeOptions): Promise<ReachabilityResult[]>`
- [ ] Step 1: Call `parsePackageLock()` to get all installed packages
- [ ] Step 2: Call `queryBatch()` (with cache) to fetch all advisories
- [ ] Step 3: For each advisory, call `extractVulnSymbols()` to get vulnerable symbol
- [ ] Step 4: Call `buildGraph()` on all project source files
- [ ] Step 5: For each advisory with a known symbol, call `isNodeReachable()` → REACHABLE or UNREACHABLE
- [ ] Step 6: For advisories with `exportedSymbol: null`, classify as UNKNOWN
- [ ] Return sorted results: REACHABLE first, then UNKNOWN, then UNREACHABLE

### 5.2 Entry Point Auto-Detection
- [ ] Read `package.json` at `cwd`
- [ ] Check `main` field — resolve to absolute path if present
- [ ] Check `exports["."]` or `exports["./index"]` — parse conditional exports, prefer `require` or `default`
- [ ] Check `bin` field values — each binary is also an entry point
- [ ] Scan for `src/index.ts`, `index.ts`, `app.ts` as fallback heuristics
- [ ] Log warning when no entry point found and none specified via `--entry`

---

## Phase 6: CLI Commands

### 6.1 `reachable scan` Command
- [ ] Create `src/cli/scan.ts` exporting a `Command`
- [ ] Register `--entry <files...>` option (string array, repeatable)
- [ ] Register `--format <format>` option with choices `["table","json","sarif","markdown"]`
- [ ] Register `--fail-on <severity>` option with choices `["critical","high","moderate","low","all"]`
- [ ] Register `--reachable-only` boolean flag
- [ ] Register `--no-cache` boolean flag
- [ ] Register `--dry-run` boolean flag
- [ ] Register `--quiet` boolean flag
- [ ] Register `--depth <number>` option (integer, default 20)
- [ ] Register `--ignore <ids...>` option (string array)
- [ ] Load config using `loadConfig(cwd)` and merge with CLI flags (flags win)
- [ ] Call `analyze(options)` with merged config
- [ ] Pipe result to appropriate formatter based on `--format`
- [ ] Set exit code: 0 if no REACHABLE above threshold, 1 if REACHABLE found, 2 on error

### 6.2 `reachable trace` Command
- [ ] Create `src/cli/trace.ts` exporting a `Command`
- [ ] Accept positional argument `<package>` (required)
- [ ] Build call graph and show all paths from entry points to calls into `<package>`
- [ ] Display as an indented tree using chalk for coloring
- [ ] Exit 0 if no paths found (print "No reachable paths found to <package>")

### 6.3 `reachable graph` Command
- [ ] Create `src/cli/graph.ts` exporting a `Command`
- [ ] Accept positional argument `<file>` (required)
- [ ] Parse the file and print all imports and exports as a formatted list
- [ ] Show which exported symbols are reachable from entry points

---

## Phase 7: Output Formatters

### 7.1 Table Formatter
- [ ] Create `src/output/table.ts`
- [ ] Install `npm install cli-table3 chalk`
- [ ] Render separate sections for REACHABLE (red), UNKNOWN (yellow), UNREACHABLE (green/dim)
- [ ] Columns: `Severity`, `Package`, `GHSA ID`, `Status`, `Vulnerable Symbol`
- [ ] Sort rows within each section by CVSS score descending
- [ ] Print call path under REACHABLE rows in dimmed text
- [ ] Respect `NO_COLOR` env var — disable chalk when set

### 7.2 JSON Formatter
- [ ] Create `src/output/json.ts`
- [ ] Output `{ summary: { reachable: N, unreachable: N, unknown: N }, results: ReachabilityResult[] }`
- [ ] Include `callPath` in each REACHABLE result
- [ ] Write to `process.stdout` only (not logger)

### 7.3 SARIF Formatter
- [ ] Create `src/output/sarif.ts`
- [ ] Implement SARIF v2.1.0 schema: `{ version: "2.1.0", $schema: "...", runs: [{ tool, results }] }`
- [ ] Set `tool.driver.name: "reachable"`, `tool.driver.version`
- [ ] Map each REACHABLE result to a SARIF `result` with `level: "error"` or `"warning"` based on severity
- [ ] Set `result.locations[0].physicalLocation` to the call site file + line from `callPath[0]`
- [ ] Only include REACHABLE results in SARIF output (not UNKNOWN or UNREACHABLE)

### 7.4 Markdown Formatter
- [ ] Create `src/output/markdown.ts`
- [ ] Output GitHub-flavored markdown suitable for PR comments
- [ ] Use collapsible `<details>` sections for UNREACHABLE items
- [ ] Include a summary badge table at the top
- [ ] Format GHSA IDs as links to `https://github.com/advisories/<id>`

---

## Phase 8: Error Handling

### 8.1 Custom Error Classes
- [ ] Create `src/utils/errors.ts`
- [ ] Implement `ReachableError extends Error` with `code: string` field
- [ ] Implement `OsvApiError extends ReachableError` with `statusCode: number`
- [ ] Implement `ParseError extends ReachableError` with `file: string`
- [ ] Implement `ConfigError extends ReachableError`

### 8.2 CLI Error Handler
- [ ] In `src/cli/index.ts`, add `.exitOverride()` and catch `CommanderError`
- [ ] Add global `process.on("uncaughtException")` handler — log error with code, exit 2
- [ ] Add `process.on("unhandledRejection")` handler — log rejection, exit 2
- [ ] Never print stack traces in non-verbose mode — only print `error.message`

---

## Phase 9: Unit Tests

### 9.1 Parser Tests
- [ ] Create `test/parser/javascript.test.ts`
- [ ] Test `extractRequireCalls` on CJS fixture file — asserts correct import paths
- [ ] Test `extractESMImports` on ESM fixture file — asserts source strings
- [ ] Test `extractDynamicImports` on fixture with `import()` — asserts path extraction
- [ ] Test `extractCallSites` — asserts member expression calls detected
- [ ] Create `test/parser/typescript.test.ts`
- [ ] Test `import type` statements marked as `isTypeOnly: true`
- [ ] Test `.tsx` file parses JSX without error
- [ ] Create `test/parser/resolver.test.ts`
- [ ] Test relative path resolution for `../utils` from `src/auth/middleware.ts`
- [ ] Test tsconfig path alias `@/components/Button` resolves to `src/components/Button.tsx`

### 9.2 Graph Tests
- [ ] Create `test/graph/builder.test.ts`
- [ ] Test 2-file graph: A imports B, asserts edge A→B
- [ ] Test circular import: A imports B, B imports A — asserts no infinite loop, warning logged
- [ ] Create `test/graph/traversal.test.ts`
- [ ] Test BFS finds node at depth 3 in a chain A→B→C→D
- [ ] Test `findPathTo` returns correct ordered array
- [ ] Test `isNodeReachable` returns false for isolated node

### 9.3 Vuln Tests
- [ ] Create `test/vuln/cache.test.ts`
- [ ] Test write + read cycle in temp directory
- [ ] Test expired entry (set `fetchedAt` to 48h ago with 24h TTL) returns null
- [ ] Create `test/vuln/symbols.test.ts`
- [ ] Test extraction from fixture OSV advisory with `ecosystem_specific.imports`
- [ ] Test null return when advisory has no structured symbol and no text match
- [ ] Create `test/vuln/osv.test.ts` using `nock` to intercept HTTP
- [ ] Test successful batch query returns mapped advisories
- [ ] Test HTTP 429 triggers retry with backoff
- [ ] Test HTTP 500 triggers retry, then throws `OsvApiError`

### 9.4 Output Tests
- [ ] Create `test/output/sarif.test.ts`
- [ ] Assert SARIF output contains correct `version: "2.1.0"`
- [ ] Assert each REACHABLE result maps to a SARIF result object
- [ ] Assert UNREACHABLE results are NOT included in SARIF output

---

## Phase 10: Integration Tests

### 10.1 Fixture: Simple Express App with Reachable Vuln
- [ ] Create `test/fixtures/simple-express/package.json` with a known-vulnerable dep pinned to vulnerable version
- [ ] Create `test/fixtures/simple-express/src/index.ts` that calls the vulnerable function
- [ ] Create `test/integration/reachable.integration.ts`
- [ ] Run `analyze()` on fixture, assert result contains at least 1 REACHABLE entry
- [ ] Assert the call path array is non-empty for the REACHABLE result

### 10.2 Fixture: Package Imported but Safe Function Only
- [ ] Create `test/fixtures/safe-usage/src/index.ts` that imports lodash but only calls `.cloneDeep` (not a vulnerable fn)
- [ ] Run `analyze()` on fixture, assert 0 REACHABLE results for lodash advisories

### 10.3 Monorepo Fixture
- [ ] Create `test/fixtures/monorepo/package.json` with `workspaces: ["packages/*"]`
- [ ] Create two workspace packages each with their own source and lockfile
- [ ] Assert both workspaces are analyzed when `--cwd` points to monorepo root

---

## Phase 11: CI/CD Pipeline

### 11.1 GitHub Actions CI
- [ ] Create `.github/workflows/ci.yml`
- [ ] Add `on: [push, pull_request]` trigger
- [ ] Add job `lint` running `npm run lint`
- [ ] Add job `typecheck` running `npx tsc --noEmit`
- [ ] Add job `test` running `npx vitest run --coverage`
- [ ] Add job `build` running `npm run build`
- [ ] Set up Node.js matrix: 18.x, 20.x, 22.x
- [ ] Upload coverage report to Codecov with `codecov/codecov-action@v4`

### 11.2 Release Workflow
- [ ] Create `.github/workflows/release.yml`
- [ ] Trigger on `workflow_dispatch` and `push` to `main` with conventional commits
- [ ] Run `semantic-release` with `NPM_TOKEN` secret

### 11.3 Security
- [ ] Add `npm audit --audit-level=high` step to CI job
- [ ] Add CodeQL analysis workflow targeting JavaScript/TypeScript

---

## Phase 12: Documentation

### 12.1 README.md
- [ ] Add CI badge, npm version badge, license badge
- [ ] Add "Why reachable?" section with `npm audit` comparison
- [ ] Add Installation section: `npm install -g reachable` and `npx reachable`
- [ ] Add Quick Start section with `reachable scan` output screenshot (ASCII)
- [ ] Add Config file reference section
- [ ] Add Flags reference table
- [ ] Add CI Integration section with GitHub Actions example YAML

### 12.2 Community Files
- [ ] Create `CONTRIBUTING.md` with development setup steps
- [ ] Create `CODE_OF_CONDUCT.md` using Contributor Covenant 2.1
- [ ] Create `SECURITY.md` with vulnerability disclosure policy
- [ ] Create `.github/ISSUE_TEMPLATE/bug_report.md`
- [ ] Create `.github/ISSUE_TEMPLATE/feature_request.md`
- [ ] Create `.github/PULL_REQUEST_TEMPLATE.md`
- [ ] Create `.editorconfig` with indent_style=space, indent_size=2
