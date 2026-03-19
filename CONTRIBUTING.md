# Contributing

Thanks for contributing to `reachable`.

## Development Setup

1. Install Node.js 18 or newer.
2. Clone the repository.
3. Install dependencies:

```bash
npm ci
```

4. Run the validation commands:

```bash
npm run lint
npm run typecheck
npm run test
npm run test-integration
npm run build
```

## Project Workflow

- Keep changes focused and small.
- Add or update tests for behavior changes.
- Follow the existing CLI names, config keys, and output formats.
- Prefer conservative fixes over broad refactors unless the task requires the refactor.

## Pull Requests

Before opening a pull request:

1. Make sure lint, typecheck, unit tests, integration tests, and build all pass locally.
2. Update docs when flags, config, workflows, or output behavior change.
3. Use conventional commits when practical, for example `feat:`, `fix:`, `test:`, or `chore:`.

## Reporting Issues

- Use the bug report template for defects and regressions.
- Use the feature request template for product or UX ideas.
- For security-sensitive issues, do not open a public issue. Follow [SECURITY.md](./SECURITY.md).
