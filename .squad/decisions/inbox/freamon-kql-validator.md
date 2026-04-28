# Decision: KQL Validator Library Design

**Date:** 2026-04-28T12:01:11-05:00
**By:** Freamon (KQL Engineer)
**Status:** Implemented

## What

Built `lib/kql-validator/` — a pure Node.js offline KQL syntax validation library with 4 modules:
- `index.js` — public API: `validateQuery()`, `validateFile()`, `validateDirectory()`, `extractQueries()`
- `parser.js` — structural validation: delimiters, let statements, pipe operators, common mistakes
- `reporter.js` — output formatting: console, CI annotations, JSON
- `operators.js` — reference data: ~60 operators, 250+ functions, ~50 Sentinel/Defender tables

## Why

- CI pipeline (`.github/workflows/kql-validate.yml`) requires KQL validation on every PR
- CLI command `secops-squad kql validate` needs a library to call
- Phase 1 exit criteria requires KQL CI validation

## Key Design Choices

1. **Offline-only** — no Azure workspace connectivity; validates syntax structure only
2. **Error vs Warning distinction** — `= instead of ==` in where clauses is an error (not a warning); `project *` and missing time filters are warnings
3. **Where-clause scoping** — assignment check is scoped to the where body up to the next pipe, preventing false positives on `join kind=inner` patterns
4. **Let statement mid-line semicolons** — parser correctly handles `let x = 24h; Table | where ...` as a valid single-line pattern
5. **Markdown extraction** — supports both ````kql` and ````kusto` fenced code blocks
6. **CommonJS modules** — compatible with ESM dynamic import (`await import()`) used by test suite
7. **Zero dependencies** — pure Node.js ≥18, no npm packages required

## Test Results

56/57 of Carver's tests pass. The 1 failure is a test-side bug (query generator produces 756 chars, test asserts >1000).
