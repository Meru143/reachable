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
┌──────────┬────────────────┬─────────────────────┬───────────┬───────────────────┐
│ Severity │ Package        │ GHSA ID             │ Status    │ Vulnerable Symbol │
├──────────┼────────────────┼─────────────────────┼───────────┼───────────────────┤
│ HIGH     │ lodash@4.17.20 │ GHSA-35jh-r3h4-6jhm │ REACHABLE │ template          │
├──────────┴────────────────┴─────────────────────┴───────────┴───────────────────┤
│ Path: index.js::module -> index.js::call:_.template:2                           │
└─────────────────────────────────────────────────────────────────────────────────┘

UNKNOWN
┌──────────┬────────────────┬─────────────────────┬─────────┬───────────────────┐
│ Severity │ Package        │ GHSA ID             │ Status  │ Vulnerable Symbol │
├──────────┼────────────────┼─────────────────────┼─────────┼───────────────────┤
│ MODERATE │ lodash@4.17.20 │ GHSA-29mw-wpgm-hmr9 │ UNKNOWN │ toNumber          │
├──────────┴────────────────┴─────────────────────┴─────────┴───────────────────┤
│ Reason: symbol-unconfirmed                                                    │
└───────────────────────────────────────────────────────────────────────────────┘

UNREACHABLE
┌──────────┬────────────────┬─────────────────────┬─────────────┬───────────────────┐
│ Severity │ Package        │ GHSA ID             │ Status      │ Vulnerable Symbol │
├──────────┼────────────────┼─────────────────────┼─────────────┼───────────────────┤
│ MODERATE │ lodash@4.17.20 │ GHSA-29mw-wpgm-hmr9 │ UNREACHABLE │ trim              │
├──────────┼────────────────┼─────────────────────┼─────────────┼───────────────────┤
│ MODERATE │ lodash@4.17.20 │ GHSA-f23m-r3pf-42rh │ UNREACHABLE │ unset             │
└──────────┴────────────────┴─────────────────────┴─────────────┴───────────────────┘
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

- `REACHABLE`: a file that imports the package calls the function by name (`_.template(...)`, `template(...)`), and that file is on an import path from an entry point. The call path is the evidence. An advisory read from an expired cache entry, because OSV could not be reached, can still be `REACHABLE`.
- `UNREACHABLE`: only when all of these hold:
  - every entry point resolved to a file and parsed (an `--entry` or config `entry` that is missing or cannot be parsed stops the scan with exit code 2, and so does finding no usable entry point; a `main`, `exports` or `bin` target that does not exist is skipped with a warning);
  - your code imports the package, and this is the copy it loads (not one nested under another package);
  - your source files use the package only by name: none hands the whole module on (`render(_)`, `Object.assign({}, _)`, `app.locals.lib = _`, `export default _`, `module.exports = require('lodash')`, `export * from 'lodash'`), reads a member through a computed name (`_[name]`), or spells the package's name as a string other than in an import or a TypeScript type (`render('lodash', text)`, `app.set('view engine', 'pug')`), since a dependency can load a package by its name;
  - no other installed package declares it (`dependencies`, `optionalDependencies` or `peerDependencies` in the lockfile) or names it as a module specifier in its code (`'lodash'`, `"lodash/fp"`), in any `node_modules` folder, npm's linked install store (`node_modules/.store`) included;
  - the advisory names the function plainly (not only as a call such as `setKey()`), and the installed package exports it and never uses it itself (no call, alias or callback);
  - no file of the project mentions the name, read as plain text, whether or not an entry point reaches it: every source file (`.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts`, test files left out as in the call graph), every component, template or view (`.vue`, `.svelte`, `.astro`, `.marko`, `.mdx`, `.ejs`, `.pug`, `.jade`, `.hbs`, `.handlebars`, `.mustache`, `.njk`, `.nunjucks`, `.liquid`, `.eta`, `.twig`, `.dust`, `.swig`, `.haml`, `.hamlc`, `.hjs`, `.hogan`, `.jst`, `.tpl`, `.tmpl`, `.vash`, `.edge`, `.art`, `.eco`, `.ect`, `.j2`, `.jinja`, `.jinja2`, `.html`, `.htm`), CoffeeScript (`.coffee`, `.litcoffee`), and every extensionless file node may run (`bin/www`, `scripts/report`: a shebang naming `node`, `nodejs`, `bun`, `deno` or `tsx`, or no shebang and a `require` or `import` in it);
  - no call path exists, and the advisory record is current (not from an expired cache entry).

  `UNREACHABLE` means no path reaches the functions the advisory names. A flaw in an internal helper that other functions share is not seen (see [Limitations](#limitations)).
- `UNKNOWN`: everything else. The JSON output carries a `reason`, and the table and markdown show it:

| Reason | Meaning |
| --- | --- |
| `lookup-failed` | OSV could not be reached, and the advisory comes from an expired cache entry: enough to show a call path, not to rule one out. |
| `not-imported` | Your code never imports the package. Other dependencies may use it, and their code is not analyzed. |
| `symbol-unknown` | The advisory does not name a vulnerable function. |
| `transitive` | Another installed package may load it: one declares it as a dependency, or names it in its code as a module specifier (a `require('lodash')` it never declared, in `node_modules` or npm's linked install store), or the installed packages hold more JavaScript than the 256 MB that is searched. Or this copy is nested under another package (`node_modules/a/node_modules/b`), and only that package loads it. |
| `symbol-unconfirmed` | The named function is not confirmed as an entry point of the package: it is named only as a call, the package's entry files do not export it, or the package uses it itself (a call, an alias, a callback), so its other functions may reach it. |
| `unresolved-reference` | The name appears in a project file outside a call the graph resolves: a renamed import, a callback (`.map(_.template)`), a re-export, a file no entry point imports (routes loaded with `fs.readdirSync` and `require(file)`, an extensionless script), a component, template or view, a comment. Or your code uses the package in a way calls cannot show: it hands the whole module on (to a view engine, another module or a dependency), reads a member through a computed name (`_[name]`), or spells the package's name as a string a dependency can load it by. |

## Limitations

- Advisories name public functions, and a flaw in an internal helper that other public functions share is not seen. In lodash 4.17.20, `_.pullAt` reaches `baseUnset`, while GHSA-xxjr-mmjv-4gpg and GHSA-f23m-r3pf-42rh name `unset` and `omit`: an app that calls only `_.pullAt` gets `UNREACHABLE` for both. `UNREACHABLE` means no path reaches the functions the advisory names.
- Dependencies' own code is not analyzed for calls. An advisory that only dependency code could reach is `UNKNOWN`, never `UNREACHABLE`. The vulnerable package itself is read only to confirm that its entry files export the function and that none of the files they reach through static imports use it; the entry files include every subpath it exports and any subpath your code imports (`lodash/template`). Imports inside the package are followed when relative or `#`-aliased through its `imports` field; one it can't follow, such as the package importing itself by name, keeps the verdict `UNKNOWN`. Uses behind a dynamic `require` are not seen, and a package of more than 2,000 files is not read, so its functions stay `UNKNOWN`.
- Other installed packages are only searched, as text, for the package's name as a module specifier: `.js`, `.cjs`, `.mjs` and `.jsx` files in every `node_modules` folder at any depth, npm's linked install store (`node_modules/.store`) and other dot folders node can load from (`.prisma`) included, except `.bin` and `.cache`, dev-only packages (by install folder, or by name and version in the store), the package's own copies, and symlinks, which are not followed: npm links workspaces there, whose code the call graph reads, a linked install links each package to its folder in the store, and `file:` dependencies link out of the project, which leaves the search incomplete and those results `UNKNOWN` (`transitive`). Past 256 MB of code the search stops, with the same result. A package whose name a dependency builds at runtime from something your code does not spell out as a string (`'lo' + 'dash'`, a configuration file, an environment variable) is not seen.
- Calls are matched by name, per file: any `x.template(...)` in a file that imports lodash counts as a call to `template`, even inside a function nothing calls. This errs towards `REACHABLE`.
- A call counts only on an import path from an entry point. Detected entry points are `package.json`'s `main`, `exports` (the target of every condition, type declarations aside) and `bin`, or `src/index.ts`, `index.ts` and `app.ts`: a directory resolves to its `index` file, an extensionless file (`bin/www`) is read as JavaScript, a `bin` that is a shell script is skipped with a warning, and so is a target that does not exist, after looking for the source of a `dist/` target (`src/server.ts` for `dist/server.js`). Pass `--entry` for scripts, workers and anything `package.json` does not name, such as the `bin/www` an Express generator app starts from its `start` script. A file no entry point imports cannot make a verdict `REACHABLE`, but a mention of the name in it keeps the verdict from being `UNREACHABLE`.
- The project search counts every mention of the name, in comments and strings too. It skips the `node_modules`, `dist`, `coverage` and `.git` folders, except files the call graph reaches; other build output in the project (`.next`, `build`, `out`) is searched, so a bundle that contains the name keeps the verdict `UNKNOWN`. A project file over 64 MB is not read and counts as naming every function, so those verdicts stay `UNKNOWN`. Test files are left out by their path inside the project (`*.test.js`, `*.spec.ts`, a `__tests__` folder). Components, templates, views, CoffeeScript and extensionless scripts are only searched, never parsed, so inside them a use through a computed name or a hand-off of the whole module is not seen; other formats (`.md`, `.json`, `.yaml`, shell scripts) are not read.
- In your source files, a use through a computed name (`_[name]()`) or a hand-off of the whole module keeps the package's verdicts `UNKNOWN`. Every reference to the module's local name counts, so a parameter that shares the name (`(_, i) => f(_)`) can count too. A module value built at runtime (`require('lo' + 'dash')`, `_.runInContext()`) is not followed, and in the package's own code a call through a computed name is not seen.
- In TypeScript files only `import` statements are read; a package loaded there with `require` looks not imported (`UNKNOWN`).
- If an OSV lookup fails after three retries (a rate limit, a server error, a network error), the package is not checked. Its advisories come from an expired cache entry if there is one (`lookup-failed`, unless a call path makes them `REACHABLE`), but that entry cannot hold advisories published since, so the output says how many packages could not be checked, JSON lists them in `unchecked`, SARIF marks the run as not successful, and the scan exits 2 unless a `REACHABLE` result already fails the threshold. After a failure that is not about one request, the run stops asking OSV and uses the cache for the remaining packages. When only some of a package's advisory records fail, the others are reported and a failed one comes from the expired cache entry if it holds it; the package is not checked either way.
- OSV gives CVSS as a vector, so `cvssScore` is the floor of the advisory's GitHub severity band (`HIGH` is 7.0) unless OSV carries a numeric score.

## What changed in 1.0.14

1.0.13 could still report `UNREACHABLE` for code the app runs. Those verdicts are now `UNKNOWN` or `REACHABLE`:

- A use of the package that calls cannot show keeps it `UNKNOWN` (`unresolved-reference`): the module handed on whole (`res.locals.lib = Object.assign({}, _)` for a view engine, `render(_)`, `export default _`, `module.exports = require('lodash')`, `export * from 'lodash'`), a member read through a computed name (`_[fn]`), or the package's name passed as a string to code that loads it (`render('lodash', text)`, `createRequire(import.meta.url)('lodash')`).
- Extensionless scripts that no entry point imports (`bin/www` started by `npm start`, `scripts/report`) are searched for the name, and so are more view, component and source formats (`.twig`, `.marko`, `.dust`, `.mdx`, `.coffee` and others listed above).
- npm's linked install (`--install-strategy=linked`) keeps every package in `node_modules/.store`. That store is now searched for packages that load the package without declaring it, leaving out dev-only ones.
- A project that itself sits in a `__tests__` folder no longer has all its files left out as tests.
- Every target of `package.json` `exports` is an entry point: each condition (`require`, `import`, `node`, `default`), a plain `exports` string and top-level conditions, not only the first `require` or `default` target that exists.
- A name spelled with escapes (`_.temp\u{6c}ate()`, `'lo\x64ash'`) is decoded before it is matched, in calls, bindings and the project search.
- A `main`, `exports` or `bin` target in unbuilt `dist/` output is looked up as its source (`src/server.ts` for `dist/server.js`), and a target that cannot be found is skipped with a warning, not silently.

## What changed in 1.0.13

1.0.12 could still report `UNREACHABLE` for code the app runs. Those verdicts are now `REACHABLE` or `UNKNOWN`, and an incomplete scan says so:

- An extensionless `bin` (`bin/greet`, `bin/www`) is read as JavaScript, a `main` that names a directory resolves to its `index` file, `.cts` files are parsed, and a TypeScript import of `./greet.cjs` finds `greet.cts`. An `--entry` or config `entry` that is missing or cannot be parsed stops the scan with exit code 2, naming the file.
- A mention of the function in any project file keeps the verdict from `UNREACHABLE`, not only in files an entry point imports (routes loaded with `fs.readdirSync`), and templates (`.ejs`, `.pug`, `.hbs`, `.njk`, `.html` and others) count too.
- A package that another installed package requires without declaring it (consolidate 0.16 and lodash) is `UNKNOWN` (`transitive`).
- An OSV outage no longer reads as a clean scan: the packages that could not be checked are named (`unchecked` in JSON) and the scan exits 2. Network errors are retried like server errors. An expired cache entry still shows a `REACHABLE` call path.
- `failOn` in the config applies when `--fail-on` is not given.
- Table and trace output carry colour codes only on a terminal or with `FORCE_COLOR`; `NO_COLOR` turns them off. `--version` prints to stdout only, and usage errors exit 2, not 1.

## What changed in 1.0.12

- Advisories carry their package, severity and functions. Up to 1.0.11, `reachable` read OSV's batch endpoint, which returns only advisory ids, so every result came out as package `unknown`, score 0, severity `LOW`, symbol `unknown` and status `UNKNOWN`. It now fetches each advisory's record. Caches written by earlier versions are ignored; you can delete `.reachable-cache`.
- Only the installed package's entry in an advisory is reported (a lodash advisory no longer adds rows for `lodash-es` or `lodash.template`).
- `UNREACHABLE` follows the rules above, and `UNKNOWN` results carry a `reason`.
- Results name the installed version (`lodash@4.17.20` in the table, markdown and SARIF; `advisory.installedVersion` in JSON).
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
| `failOn` | `critical \| high \| moderate \| low \| all` | Minimum reachable severity that sets a failing exit code, when `--fail-on` is not given (default `high`) |
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
| `--fail-on <severity>` | `critical \| high \| moderate \| low \| all` | config `failOn`, else `high` | Failure threshold |
| `--reachable-only` | `boolean` | `false` | Show only reachable advisories |
| `--no-cache` | `boolean` | `false` | Ignore and clear the local advisory cache |
| `--dry-run` | `boolean` | `false` | Skip remote advisory fetches and use cache only; packages with no cached data are named in the output |
| `--quiet` | `boolean` | `false` | Suppress formatter output |
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

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No `REACHABLE` advisory at or above the threshold, and every package was checked. A `--dry-run` names the packages it had no cached data for, without changing the exit code. |
| `1` | A `REACHABLE` advisory at or above the threshold: `--fail-on`, else `failOn` from the config, else `high`. |
| `2` | An error (no lockfile, an entry point that is missing or cannot be parsed, no entry point detected), a usage error (an unknown option, command or value), or an incomplete scan: a package whose advisories could not be looked up, unless a `REACHABLE` result already fails the threshold. |

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
