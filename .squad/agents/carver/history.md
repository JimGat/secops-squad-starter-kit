# History

<!-- Populated automatically during squad sessions. -->

## Learnings

<!-- Append new learnings below. Each entry is something lasting about the project. -->
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

📌 **Graph Security API Test Suite Written** (2026-04-28)
- Created `lib/graph-security/graph-security.test.js` — 169 tests across 28 describe blocks
- Modules covered: auth (4 blocks), alerts (4 blocks), incidents (6 blocks), threat-intelligence (5 blocks), secure-score (4 blocks), utils (2 blocks), index/factory (2 blocks + exports)
- Mocking approach: `mock.fn()` from `node:test` to replace `globalThis.fetch` — no external mock libraries needed
- Helper pattern: `mockClient()` returns `{tenantId, getToken}`, `mockFetch(status, body)` installs a fake fetch
- URL-encoding gotcha: `URLSearchParams` encodes `$` as `%24` in URLs — test assertions must use `decodeURIComponent()` before regex matching
- All API modules follow `{ok, data?, error?, status?}` return contract — tests validate both success and error shapes
- Edge cases tested: empty results, malformed JSON, null tokens, missing required fields, URL-encoding of path params, frozen constants, OData nextLink pagination, bulk operations with stopOnError
- Auth tests cover: client credentials (validation, token acquisition, caching, cache clear), managed identity (App Service path, IMDS fallback, network errors), device code (validation, request failures)
- CommonJS modules loaded via `createRequire(import.meta.url)` since test file uses ESM (consistent with kql-validator tests)

📌 **Bicep Templates Refactored for Phase 2 Integration** (2026-05-04)
- Updated all 11 Bicep templates in `templates/bicep/` with Phase 2 integration comment blocks
- SOAR templates (6): main, phishing-response, compromised-account, malware-containment, ip-enrichment, teams-notification
- ADX templates (5): main, cluster, database, tables, ingestion
- Each template now references: relevant PowerShell wrapper skills, `.secops/` config files, post-deployment scripts, and rate-limiting considerations
- Created `templates/bicep/README.md` (222 lines) documenting template inventory, Phase 2 skill cross-reference, pre-deployment checklist, parameter cross-reference, post-deployment automation patterns, rate limiting table, and architecture overview
- Skills referenced: sentinel-api-wrapper.md, defender-api-wrapper.md, data-tiering-commands.md, rate-limiting.md, sentinel-mcp-server.md, workbook-automation.md
- Pattern: comment blocks inserted between file header and `targetScope` declaration in all templates
- QA observation: Templates are structurally sound but post-deployment scripts (Configure-SoarPlaybooks.ps1, Configure-AdxSecurityLake.ps1) don't exist yet — they are forward-referenced for future implementation
