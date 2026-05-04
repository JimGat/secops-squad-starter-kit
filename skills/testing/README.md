---
title: Testing Skills
category: testing
author: Carver
version: 1.0.0
last_updated: 2026-05-04
---

# Testing Skills

## Purpose

Testing skills teach agents how to validate SecOps workflows, API integrations, and `.secops/` configuration handling. Unit tests verify individual skills in isolation; integration tests verify that multi-skill orchestration pipelines produce correct end-to-end results with proper error handling, rate limiting, and environment awareness.

## Skill Index

| Skill | Description | Complexity |
|---|---|---|
| `integration-test-suite.md` | End-to-end workflow validation for all 5 orchestration workflows | Advanced |

## Who Uses These Skills

- **Carver** — Primary owner; writes and maintains test suites, quality gates
- **All agents** — Reference test patterns when adding new skills or modifying APIs
- **Sydnor** — CI/CD pipeline integration; runs tests on PR

## Design Principles

1. **Mock at the boundary** — Replace HTTP calls with mock factories, never mock internal logic
2. **Test the contract** — Every API wrapper returns `@{ ok = $true; data = ... }` or `@{ ok = $false; error = ... }`; tests validate that shape
3. **Environment isolation** — Tests use their own `.secops/` fixtures; never touch real Azure resources
4. **Deterministic data** — Synthetic generators produce consistent, reproducible test data
5. **Failure is the feature** — Error-handling tests are as important as happy-path tests

## Test Framework

- **PowerShell:** Pester v5+ for API wrapper and workflow testing
- **JavaScript:** `node:test` + `node:assert/strict` for `lib/` modules (see `lib/kql-validator/`, `lib/graph-security/`)
- **KQL:** Offline syntax validation via `lib/kql-validator/` — no workspace required

## Relationship to Other Skill Domains

| Dependency | What We Test |
|---|---|
| `skills/orchestration/` | Workflow handoffs, pattern composition, error propagation |
| `skills/powershell/` | API wrappers, rate limiting, auth patterns |
| `skills/kql/` | Query builder output, cross-workspace routing |
| `skills/msft-security/` | Sentinel, Defender, eDiscovery, Purview API responses |
| `.secops/` | Config loading, graceful degradation, migration state |

## Getting Started

1. Read `integration-test-suite.md` for end-to-end workflow test patterns
2. Use mock API factories to avoid real Azure dependencies
3. Create test `.secops/` fixtures per scenario (single-tenant, multi-tenant, gov cloud)
4. Run Pester tests: `Invoke-Pester -Path ./tests/ -Output Detailed`
5. Run JS tests: `node --test lib/**/*.test.js`

## CI Integration

Test validation is a required quality gate on all PRs. See `.github/workflows/` for pipeline configuration. KQL validation runs via `secops-squad kql validate`; API wrapper tests run via `node --test`; integration workflow tests run via Pester.
