# Project Context

- **Owner:** John Spaid
- **Project:** secops-squad — SecOps framework for Microsoft Security products (Sentinel, Defender, Entra ID Protection), KQL, Logic Apps, Log Analytics, Azure Data Explorer
- **Stack:** KQL, Logic Apps, Azure Functions, Bicep, PowerShell, Node.js/TypeScript
- **Created:** 2026-04-28

## Learnings

<!-- Append new learnings below. Each entry is something lasting about the project. -->

📌 Team initialized on 2026-04-28 — full squad scaffolded with SecOps-focused roles and routing.

📌 **Phase 1: Framework Architecture Finalized** (2026-04-28)
- Skills-first architecture: markdown skills by domain (kql/, soar/, detection/, log-analytics/, adx/, msft-security/)
- Persona-driven onboarding: init wizard with Azure discovery, personas include soc-analyst, detection-engineering, threat-hunting, cloud-security, incident-response, full-soc
- Quality gates: KQL CI validation (Carver), SOAR rollback plans mandatory (Herc), threat model ceremony for detection (McNulty)
- Coverage analysis: MITRE ATT&CK tagging required for all detection/KQL skills
- CLI strategy: secops-squad wraps @bradygaster/squad-cli, additive security commands
- Phase 1 exit: init wizard, soc-analyst persona, 3 KQL skills, 3 SOAR skills, KQL CI, getting-started docs
- Target: new user → working SecOps team with KQL hunting + phishing response in ≤ 15 minutes

📌 **KQL Validator Test Suite Written** (2026-04-28)
- Created `lib/kql-validator/kql-validator.test.js` — 45 tests across 9 describe blocks
- Test categories: valid KQL (10), invalid KQL (8), edge cases (10), markdown extraction (7), file validation (7), directory validation (5), warning detection (4), return shape contract (2), fixture sanity (4)
- Tests written from spec, not implementation — defines the contract for Freamon's validator
- All tests use `node:test` + `node:assert/strict`, runnable via `node --test`
- Graceful degradation: tests fail (not crash) when validator module isn't built yet
- Created 4 fixture files in `lib/kql-validator/fixtures/`: valid-hunting-query.kql, valid-detection-rule.kql, invalid-syntax.kql, sample-skill.md
- Fixture sanity tests pass independently; validator tests awaiting Freamon's implementation
- Temp files written to `__test_tmp__` inside the test dir and cleaned up in `after` hooks
- Package.json already has `"test": "node --test lib/**/*.test.js"` — test file is auto-discovered
