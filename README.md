# reachable

![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?logo=githubactions&logoColor=white)
![npm](https://img.shields.io/npm/v/%40merupatel%2Freachable)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

`reachable` is a local-first CLI that answers the question developers ask after `npm audit`: is the vulnerable code path actually reachable from my application?

It parses JavaScript and TypeScript with tree-sitter, builds a project call graph, queries OSV advisories, and reports whether the vulnerable symbol is reachable, unknown, or unreachable from your entry points.

## Why reachable?

`npm audit` reports package-level risk. It does not know whether your code imports or calls the vulnerable function. That leads to noisy CI failures, broad dependency upgrade churn, and teams ignoring entire audit reports.

`reachable` adds source-aware triage:

- It traces entry points through your code instead of flagging every installed vulnerable package equally.
- It separates `REACHABLE`, `UNKNOWN`, and `UNREACHABLE` findings so real risk rises to the top.
- It works locally in CI without a hosted service, account, or API key.

## Installation

```bash
npm install -g @merupatel/reachable
```

Run without installing globally:

```bash
npx @merupatel/reachable@latest scan
```

## Quick Start

Scan the current project:

```bash
reachable scan --format table
```

Example terminal output:

```text
REACHABLE
+-----------+---------+----------------------+------------+-------------------+
| Severity  | Package | GHSA ID              | Status     | Vulnerable Symbol |
+-----------+---------+----------------------+------------+-------------------+
| HIGH      | lodash  | GHSA-xxxx-yyyy-zzzz  | REACHABLE  | trim              |
+-----------+---------+----------------------+------------+-------------------+
  src/index.ts::module
  src/index.ts::call:lodash.trim:12

UNREACHABLE
+-----------+---------+----------------------+--------------+-------------------+
| Severity  | Package | GHSA ID              | Status       | Vulnerable Symbol |
+-----------+---------+----------------------+--------------+-------------------+
| HIGH      | lodash  | GHSA-aaaa-bbbb-cccc  | UNREACHABLE  | trim              |
+-----------+---------+----------------------+--------------+-------------------+
```

Trace a package from the entry point:

```bash
reachable trace lodash
```

Inspect a single file's imports, exports, and reachable symbols:

```bash
reachable graph src/index.ts
```

## Configuration

`reachable` loads project configuration from `.reachablerc.json` or `reachable.config.js`.

Example:

```json
{
  "entry": ["src/index.ts", "src/worker.ts"],
  "failOn": "high",
  "ignore": ["GHSA-xxxx-xxxx-xxxx"],
  "devPackages": ["vitest", "@types/node"],
  "cache": {
    "ttlHours": 24,
    "dir": ".reachable-cache"
  }
}
```

Configuration fields:

| Field | Type | Description |
| --- | --- | --- |
| `entry` | `string[]` | Explicit entry points when auto-detection is not enough |
| `failOn` | `critical \| high \| moderate \| low \| all` | Minimum reachable severity that sets a failing exit code |
| `ignore` | `string[]` | GHSA IDs to suppress |
| `devPackages` | `string[]` | Packages treated as dev-only and excluded from lockfile analysis |
| `cache.ttlHours` | `number` | Advisory cache TTL |
| `cache.dir` | `string` | Advisory cache directory |

## Flags Reference

### `reachable scan`

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--entry <files...>` | `string[]` | auto-detect | Override detected entry points |
| `--format <format>` | `table \| json \| sarif \| markdown` | `table` | Output format |
| `--fail-on <severity>` | `critical \| high \| moderate \| low \| all` | `high` | Failure threshold |
| `--reachable-only` | `boolean` | `false` | Show only reachable advisories |
| `--no-cache` | `boolean` | `false` | Ignore and clear the local advisory cache |
| `--dry-run` | `boolean` | `false` | Skip remote advisory fetches and use cache only |
| `--quiet` | `boolean` | `false` | Suppress formatter output |
| `--depth <number>` | `number` | `20` | Maximum traversal depth |
| `--ignore <ids...>` | `string[]` | `[]` | Ignore GHSA identifiers |
| `--cwd <path>` | `string` | current directory | Project root to analyze |
| `--verbose` | `boolean` | `false` | Enable debug logging |

### `reachable trace`

```bash
reachable trace <package> [--cwd <path>] [--entry <files...>]
```

### `reachable graph`

```bash
reachable graph <file> [--cwd <path>] [--entry <files...>]
```

## CI Integration

Minimal GitHub Actions usage:

```yaml
name: Reachability

on:
  pull_request:

jobs:
  reachable:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - run: npx @merupatel/reachable@latest scan --format markdown --fail-on high
```

Use `--format sarif` to feed GitHub code scanning or `--format markdown` to post PR-friendly summaries.

## Development

```bash
npm ci
npm run lint
npm run test
npm run test-integration
npm run build
```

The project uses:

- tree-sitter for source parsing
- commander for the CLI
- vitest for unit and integration tests
- semantic-release for release automation

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the contributor workflow.
