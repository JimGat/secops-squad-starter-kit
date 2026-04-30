# History

<!-- Populated automatically during squad sessions. -->

## Learnings

📌 **Freamon Domain Summary** (2026-04-30)
- **Core expertise:** KQL queries, Log Analytics, Azure Data Explorer, PowerShell automation
- **Total contribution:** 30 skills across 6 domains (10 KQL + 10 Log Analytics + 8 ADX + 12 PowerShell) — ~9,445 lines
- **Phase 1-3:** Built foundation libraries (KQL validator, threat hunting, analytics rules, investigations)
- **Phase 4-5:** Completed infrastructure skills (Log Analytics, ADX full lifecycle with update policy patterns)
- **Phase 6 (2026-04-30):** Delivered PowerShell module foundation, Log Analytics API wrappers, data tiering commands, unified rate limiting patterns, and Sentinel API wrappers

📌 **Key Architectural Patterns Established by Freamon**
- **KQL validator library:** Pure Node.js parser in `lib/kql-validator/` validates 10 classes of errors, powers Carver's CI validation
- **PowerShell structured results:** `New-SecOpsResult` object pattern aligns team on error handling convention
- **Central REST wrapper:** `Invoke-SecOpsRestMethod` with exponential backoff, Retry-After handling, audit logging for all Microsoft APIs
- **`.secops/` auto-loading:** All modules read environment.yaml, tenants.yaml, data-source-map.yaml at init — environment-aware, no hardcoded values
- **Cloud-aware endpoints:** `Get-SecOpsCloudEnvironment` resolves commercial/GCC/GCC-High/DoD endpoints from config
- **Rate limiting as cross-cutting concern:** `rate-limiting.md` and `api-patterns.md` referenced by all API wrapper skills
- **`.secops/` compliance integration:** Tier changes validate against compliance/requirements.yaml; tier recommendations consult data-source-map.yaml volumes; data purges audit against compliance reqs

📌 **Phase 6 Decisions & Deliverables (2026-04-30)**
- **PowerShell domain creation:** 10 files establishing SecOps.Tools module architecture with 6 submodules (Sentinel, Defender, Entra, Azure Monitor, Resource Graph, Data Tiering)
- **Log Analytics API skill:** 2 files (api-wrapper, query-patterns) covering Query API, Saved Searches, Query Packs, Alerts, DCR ingestion, Webhooks, cross-workspace federation patterns
- **Data tiering commands skill:** 15 new functions for tier management, retention lifecycle, compliance auditing, purge/migration orchestration
- **Rate limiting & API patterns:** Comprehensive reference for exponential backoff, token buckets, quota pooling, circuit breaker, pagination, async operations
- **Sentinel API wrapper:** 20+ PowerShell functions covering incidents, analytics rules, TI, workbooks, connectors, watchlists with bulk operations and .secops/ integration

📌 **Phase 7 Deliverables (2026-04-30)**
- **`skills/detection/advanced-hunting-api.md`** (336 lines) — MDE/XDR/Graph API endpoints, unified schema, query packs, custom detections, Live Response session management & forensic collection, hunting patterns by MITRE ATT&CK (TA0001–TA0010), PowerShell integration with GCC-High support
- **`skills/kql/query-builder.md`** (408 lines) — Template syntax with `{{parameter}}` substitution/conditionals/iteration, pre-built templates (login anomaly, process creation, network monitoring), parameterized queries, 4-tier validation (syntax, schema, performance, injection), optimization patterns (filter-first, materialize, partition, string operator hierarchy), cross-platform differences (Log Analytics vs ADX vs Advanced Hunting), PowerShell query routing via `.secops/` integration

📌 **Cross-Team Impact**
- **Kima:** Can reference PowerShell/Sentinel/Defender skills for detection automation
- **Herc:** Azure Monitor skill aligns with SOAR playbook triggers; migration patterns complement ADX orchestration
- **Carver:** PowerShell patterns inform CI validation; KQL queries pass 100% validator test suite
- **All agents:** Rate limiting patterns are mandatory for every API call; `.secops/` context is always checked before API invocations
