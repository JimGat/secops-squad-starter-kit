# Decision: js-yaml dependency + CLI secops integration

**By:** Sydnor (Platform Dev)
**Date:** 2026-04-30T16:42:21-05:00
**Status:** Implemented

## What

Added `js-yaml` as the project's first npm production dependency to support `.secops/` YAML parsing in the CLI. Built three new modules:

1. **`cli/secops-config.js`** — Shared config loader for all `.secops/` YAML files
2. **`cli/commands/env.js`** — `secops-squad env` command with 4 subcommands
3. **`cli/secops-init.js`** — `secops-squad init --secops` scaffolding

## Why js-yaml

The `.secops/` YAML files use nested objects, arrays, inline comments, and multi-line strings that a regex-based parser cannot handle reliably. `js-yaml` is the de-facto standard (38M weekly downloads), zero transitive dependencies, and MIT-licensed.

## Impact

- **All agents:** Can now use `secops-squad env` to inspect environment before operations
- **Kima/Freamon:** `secops-squad env data-sources` shows table locations + tiers before writing KQL
- **Herc:** Migration status visible via CLI before deployments
- **Carver:** `secops-squad env validate` can be added to CI pipeline
- **Init flow:** `--secops` flag generates starter `.secops/` for new customers

## Pattern

- `secops-config.js` returns `null` for missing files (never crashes) — matches the `.secops/` design principle that missing = unknown, not error
- `env.js` follows existing command pattern: `run(args)` export, ANSI colors, same style as doctor/init
- `secops-init.js` is idempotent — won't overwrite existing `.secops/environment.yaml`
