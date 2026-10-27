# reachable

![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?logo=githubactions&logoColor=white)
![npm](https://img.shields.io/npm/v/%40merupatel%2Freachable)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

`reachable` is a local-first CLI for JavaScript and TypeScript that answers the question developers ask after `npm audit`: is the vulnerable code path actually reachable from my application?

It parses JavaScript and TypeScript with tree-sitter, builds a project call graph, queries OSV advisories, and reports whether the vulnerable symbol is reachable, unknown, or unreachable from your entry points.

Live page: [merup.me/reachable](https://merup.me/reachable/)

The point is not to replace package-level scanners. It is to rank the work that actually matters by asking the next question those tools cannot answer on their own: does your code reach the vulnerable symbol?

![reachable CLI demo](docs/assets/reachable-demo.gif)

- Cut false-positive dependency noise by separating `REACHABLE`, `UNKNOWN`, and `UNREACHABLE` findings.
- Fail CI on code paths that actually matter instead of every advisory in the lockfile.
- Run locally or in GitHub Actions without a hosted service, account, or API key.

## Why reachable?

`npm audit` reports package-level risk. It does not know whether your code imports or calls the vulnerable function. That leads to noisy CI failures, broad dependency upgrade churn, and teams ignoring entire audit reports.

`reachable` adds source-aware triage:

- It traces entry points through your code instead of flagging every installed vulnerable package equally.
- It separates `REACHABLE`, `UNKNOWN`, and `UNREACHABLE` findings so real risk rises to the top.
- It works locally in CI without a hosted service, account, or API key.

## Why Not Just `npm audit`?

| Tool | Flags vulnerable packages | Checks whether your code reaches the vulnerable symbol | Local-first CLI |
| --- | --- | --- | --- |
| `reachable` | Yes | Yes | Yes |
| `npm audit` | Yes | No | Yes |
| Dependabot alerts | Yes | No | No |

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

Example terminal output, for an app whose `index.js` calls `_.template` with `lodash@4.17.20` installed (rows trimmed):

```text
REACHABLE
┌──────────┬─────────┬─────────────────────┬───────────┬───────────────────┐
│ Severity │ Package │ GHSA ID             │ Status    │ Vulnerable Symbol │
├──────────┼─────────┼─────────────────────┼───────────┼───────────────────┤
│ HIGH     │ lodash  │ GHSA-35jh-r3h4-6jhm │ REACHABLE │ template          │
├──────────┴─────────┴─────────────────────┴───────────┴───────────────────┤
│ Path: index.js::module -> index.js::call:_.template:2                    │
└──────────────────────────────────────────────────────────────────────────┘

UNKNOWN
┌──────────┬─────────┬─────────────────────┬─────────┬───────────────────┐
│ Severity │ Package │ GHSA ID             │ Status  │ Vulnerable Symbol │
├──────────┼─────────┼─────────────────────┼─────────┼───────────────────┤
│ MODERATE │ lodash  │ GHSA-29mw-wpgm-hmr9 │ UNKNOWN │ toNumber          │
├──────────┴─────────┴─────────────────────┴─────────┴───────────────────┤
│ Reason: symbol-unconfirmed                                             │
└────────────────────────────────────────────────────────────────────────┘

UNREACHABLE
┌──────────┬─────────┬─────────────────────┬─────────────┬───────────────────┐
│ Severity │ Package │ GHSA ID             │ Status      │ Vulnerable Symbol │
├──────────┼─────────┼─────────────────────┼─────────────┼───────────────────┤
│ MODERATE │ lodash  │ GHSA-29mw-wpgm-hmr9 │ UNREACHABLE │ trim              │
├──────────┼─────────┼─────────────────────┼─────────────┼───────────────────┤
│ MODERATE │ lodash  │ GHSA-f23m-r3pf-42rh │ UNREACHABLE │ unset             │
└──────────┴─────────┴─────────────────────┴─────────────┴───────────────────┘
```

`toNumber` is UNKNOWN rather than UNREACHABLE because lodash calls `toNumber` itself (from `_.clamp`, `_.debounce` and others), so code that never names it can still reach it.

Trace a package from the entry point:

```bash
reachable trace lodash
```

Inspect a single file's imports, exports, and reachable symbols:

```bash
reachable graph src/index.ts
```

## How verdicts are decided

For each installed package (every version in the lockfile, dev dependencies excluded), `reachable` asks OSV which advisories affect it, fetches each advisory's full record, and keeps the entries for that package only. It takes the vulnerable functions from the advisory's wording ("via the template function", "the `toNumber`, `trim` and `trimEnd` functions", "`_.template`", "`foo()`"), one row per function. It never takes the package's own name as a function.

- `REACHABLE`: a file that imports the package calls the function by name (`_.template(...)`, `template(...)`), and that file is on an import path from an entry point. The call path is the evidence.
- `UNREACHABLE`: only when all of these hold: your code imports the package, this is the copy it loads (not one nested under another package), and no other installed package depends on it; the advisory names the function plainly (not only as a call such as `setKey()`); the installed package exports the function from its entry files and does not call it itself; no file reachable from an entry point mentions the name; and no call path exists.
- `UNKNOWN`: everything else. The JSON output carries a `reason`, and the table and markdown show it:

| Reason | Meaning |
| --- | --- |
| `lookup-failed` | The OSV lookup failed; the verdict comes from an expired cache entry. |
| `not-imported` | Your code never imports the package. It is installed for other dependencies, whose code is not analyzed. |
| `symbol-unknown` | The advisory does not name a vulnerable function. |
| `transitive` | Other installed packages depend on the package and may reach the function. Either your code imports the package without reaching the function, or this copy is nested under another package (`node_modules/a/node_modules/b`) and only that package loads it. |
| `symbol-unconfirmed` | The named function is not confirmed as an entry point of the package: it is named only as a call, the package's entry files do not export it, or the package calls it itself. |
| `unresolved-reference` | The name appears in reachable code outside a call the graph resolves, such as a renamed import, a callback (`.map(_.template)`) or a re-export. |

## Limitations

- Dependencies' own code is not analyzed. An advisory that only dependency code could reach is `UNKNOWN`, never `UNREACHABLE`. The vulnerable package itself is read only to confirm that its entry files export the function and that none of the files they reach through static imports call it. Calls behind a dynamic `require` are not seen, and a package of more than 2,000 files is not read, so its functions stay `UNKNOWN`.
- Calls are matched by name: any `x.template(...)` in a file that imports lodash counts as a call to `template`. This errs towards `REACHABLE`.
- Only code reachable from the entry points counts. Pass `--entry` for scripts, workers and anything `package.json` does not name.
- In TypeScript files only `import` statements are read; a package loaded there with `require` looks not imported (`UNKNOWN`).
- If an OSV lookup fails and nothing is cached for the package, its advisories are left out of the results; a warning is logged to stderr.
- OSV gives CVSS as a vector, so `cvssScore` is the floor of the advisory's GitHub severity band (`HIGH` is 7.0) unless OSV carries a numeric score.

## What changed in 1.0.12

- Advisories are complete again. Up to 1.0.11, `reachable` read OSV's batch endpoint, which returns only advisory ids, so every result came out as package `unknown`, score 0, severity `LOW`, symbol `unknown` and status `UNKNOWN`. It now fetches each advisory's record. Caches written by earlier versions are ignored; you can delete `.reachable-cache`.
- Only the installed package's entry in an advisory is reported (a lodash advisory no longer adds rows for `lodash-es` or `lodash.template`).
- `UNREACHABLE` follows the rules above, and `UNKNOWN` results carry a `reason`.
- Every function an advisory names gets its own row, and the package's own name is never used as one.
- Source files of 32 KB or more are analyzed; they used to be skipped.
- Every installed version of a package is checked, not only one per name. A copy nested under another package is `UNKNOWN` (`transitive`), because only that package loads it.
- Logs go to stderr, so `--format json` and `--format sarif` output stays valid when a warning is logged.

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
