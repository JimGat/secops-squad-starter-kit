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

📌 **SOC Analyst Persona Update (2026-05-04)**
- **Task:** Updated `personas/soc-analyst/` to reference Phase 2-3 tools (requested by Jose)
- **skills.json v2.0.0:** Added 9 new skill references — `advanced-hunting-api`, `query-builder`, `workbook-automation`, `sentinel-api-wrapper`, `defender-api-wrapper`, `log-analytics/api-wrapper`, `log-analytics/query-patterns`, `copilot-for-security`, `rate-limiting`. Skills distributed across tiers: rate-limiting + copilot shared by all; Bunk gets sentinel-api; Kima gets sentinel + defender + workbooks; Freamon gets full hunting + query stack; Daniels gets workbooks.
- **routing.md:** Added Tool-Chain Routing section with task-type → skill mapping table. Documented 4 flows: Threat Hunting (KQL builder → Advanced Hunting), Investigation (Sentinel → Defender → Log Analytics → Copilot), Dashboard (workbook-automation), Alert Triage (`.secops/alerting/` rules). Added 3 new routing rules (#9-11).
- **README.md:** Documented incident lifecycle (Detect → Hunt → Investigate → Respond → Report) with tool references at each stage. Added Tool Chain diagram (KQL Builder → Advanced Hunting → Sentinel API → Workbook). Restructured Pre-Loaded Skills table to show Core vs Phase 2-3 columns. Added `.secops/` to environment assumptions.
