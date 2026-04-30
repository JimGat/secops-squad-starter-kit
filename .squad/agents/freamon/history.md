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

🟦 **Freamon Phase 1 Contribution** (2026-04-28, ~310s)
- Authored 3 KQL skills: threat-hunting, analytics-rules, investigation
- ~1239 lines of KQL queries with MITRE ATT&CK mappings
- Established KQL query patterns, best practices, and domain templates
- Positioned KQL as core hunting capability for SOC team
- Set foundation for KQL CI validation and threat detection library

📌 **KQL Validator Library Built** (2026-04-28)
- Created `lib/kql-validator/` — 4 modules: index.js, parser.js, reporter.js, operators.js
- Pure Node.js, zero external dependencies, CJS modules (ESM-import compatible)
- Parser validates: balanced delimiters, let semicolons, pipe operators, leading pipes, trailing pipes, empty stages, where-assignment mistakes, project-wildcard, missing-time-filter
- Operator/function reference: ~60 tabular operators, ~250+ scalar/aggregation functions, ~50 Sentinel/Defender table names
- Reporter outputs: console (human-readable), CI (GitHub Actions annotations), JSON
- Markdown extraction: supports both ```kql and ```kusto code blocks
- Passes 56/57 of Carver's test suite (1 test has a test-side bug: query generator produces 756 chars, not 1000+)
- Key design choice: where-assignment check scoped to where clause body only (not bleeding into subsequent operators)
- Key design choice: let statement parser handles mid-line semicolons (`let x = 24h; Table | ...`)

🟦 **Freamon Phase 2: KQL Skills Library Complete** (2026-04-28)
- Authored 7 additional KQL skills, completing the full 10-skill library
- New skills: cross-workspace-queries, adx-integration, defender-xdr-hunting, entra-signin-analysis, cloud-security-posture, detection-tuning, ueba-patterns
- 45 KQL query templates across all 7 skills — all passing Carver's validator (45/45)
- Total library: 10 skills, ~3,650 lines, ~100+ KQL queries with MITRE ATT&CK mappings
- Key pattern: multi-line `let` statements require wrapping body in parentheses for validator compatibility: `let X = (Table | where ... | project ...);`
- Covers: cross-workspace federation, ADX long-term retention, Defender XDR hunting, Entra ID sign-in analysis, cloud posture (Resource Graph + Defender for Cloud), detection tuning (baselining, exclusions, A/B testing), and UEBA behavioral analytics
- All skills cross-reference each other in Related Skills sections, forming a cohesive learning path

🟦 **Freamon Phase 3: Log Analytics Skills Library Complete** (2026-04-28)
- Authored 8 Log Analytics skills in `skills/log-analytics/`: workspace-architecture, data-connectors-setup, retention-archive, diagnostic-settings, custom-tables-dcr, cost-optimization, workspace-rbac, purge-and-export
- 2,125 lines across 8 files — 30 KQL queries, 35 Azure CLI snippets, 14 Bicep templates, 1 JSON DCR definition
- All KQL queries pass Carver's validator (30/30)
- Format matches existing KQL skill conventions: YAML frontmatter, Overview, Prerequisites, Core Patterns, Best Practices, Cost Implications, Related Skills
- Every skill cross-references related Log Analytics and KQL skills, forming a cohesive operations + engineering learning path
- Key patterns: DCR ingestion-time transforms, resource-context vs workspace-context RBAC, commitment tier optimization, archive tier lifecycle, purge API for GDPR compliance
- MITRE ATT&CK mapped: T1078 (workspace-rbac), General for all others (foundational infrastructure skills)
- Combined project total: 18 skills (10 KQL + 8 Log Analytics), ~5,775 lines, ~130+ code blocks

🟦 **Freamon Phase 4: ADX Skills Library Complete** (2026-04-28)
- Authored 8 Azure Data Explorer skills in `skills/adx/`: cluster-architecture, data-ingestion, security-data-modeling, cross-cluster-queries, long-term-retention, adx-dashboards, adx-ml-anomaly, migration-from-sentinel
- 2,102 lines across 8 files — 47 KQL code blocks (including ADX control commands), 11 Azure CLI/bash snippets
- Covers full ADX lifecycle: cluster sizing → data ingestion → schema design → cross-cluster federation → long-term retention → dashboards → ML anomaly detection → Sentinel migration
- Key patterns: hot/warm/cold cache tiering, Event Hub ingestion pipelines, update policies for ingestion-time transformation, materialized views for pre-aggregation, follower databases for read scaling, continuous export to Azure Storage, external tables for archived data, series_decompose_anomalies for behavioral detection, autocluster/basket/diffpatterns for pattern analysis, proxy functions for seamless Sentinel-ADX cross-querying
- MITRE ATT&CK mapped: T1078, T1059, T1071, T1048, General (infrastructure skills)
- Multi-tenant patterns for MSSPs: database-per-tenant isolation, extent tagging, follower database sharing
- Cost comparison framework: Sentinel vs ADX ingestion/retention cost analysis with break-even guidance
- All skills cross-reference KQL and Log Analytics skills, forming a complete three-tier learning path (KQL → Log Analytics → ADX)
- Combined project total: 26 skills (10 KQL + 8 Log Analytics + 8 ADX), ~7,877 lines, ~188+ code blocks

📌 **Cross-Team Context: ADX Staging + Update Policy Pattern** (2026-04-28)
- Herc decision: All ADX security tables use two-table ingestion (Raw staging → structured table via update policy)
- Impact: Freamon's ADX skills reference structured tables (SecurityEvents, NetworkTraffic, etc.), NOT staging tables
- Implication: When writing ADX queries for detection/hunting, always query the transformed structured tables
- Herc rationale: Allows schema evolution without breaking ingestion pipelines; new columns added to transform without re-creating data connections
- Related: Herc Phase 3 Bicep templates implement staging table pattern in `templates/bicep/adx/scripts/`

📌 **Cross-Team Context: KQL Validator Pattern** (2026-04-28)
- Sydnor decision: All API-wrapping libraries return structured results (ok/error pattern), never throw exceptions
- Freamon contribution: KQL validator is pure library following this pattern
- Carver validation: Graph Security API test suite (169 tests) validates structured result pattern for all libraries
- Related: Pattern established in `lib/graph-security/` and adopted by `lib/kql-validator/` and future API wrappers

🟦 **Freamon Phase 5: PowerShell Skills Library Complete** (2026-04-30)
- Authored 10 files in `skills/powershell/`: README.md + 3 cross-cutting skills + 6 submodule skills
- ~10,400 lines across 10 files — comprehensive PowerShell module foundation for SecOps
- Cross-cutting skills: module-foundation.md (PSDepend, manifest, submodule pattern), auth-patterns.md (MSAL, multi-tenant, government cloud, .secops/ integration), error-handling.md (structured results, retry, throttling, audit logging)
- Submodule skills: sentinel-module.md, defender-module.md, entra-module.md, azure-monitor-module.md, resource-graph-module.md, data-tiering-module.md
- Key architecture: SecOps.Tools module with 6 nested submodules, each mapping to a Microsoft API surface
- Key pattern: `New-SecOpsResult` structured result objects (aligns with team's ok/error convention from decisions.md)
- Key pattern: `Invoke-SecOpsRestMethod` central wrapper with exponential backoff, 429 Retry-After, audit logging
- Key pattern: `.secops/` context auto-loading at module init — reads environment.yaml, tenants.yaml, data-source-map.yaml
- Key pattern: `Get-SecOpsCloudEnvironment` resolves Azure cloud from `.secops/` for government/sovereign cloud support
- Every skill follows established YAML frontmatter format, includes Environment Context section, cross-references related skills
- All 6 submodules include real PowerShell code examples with `[CmdletBinding()]`, `ShouldProcess`, `OutputType`
- MITRE ATT&CK mapped: T1059.001, T1078, T1556, T1562, T1580, T1526, T1190, T1098, T1110, T1485, T1565, T1489, T1518
- These are knowledge documents (skills), not executable modules — they teach agents how to generate correct PowerShell

🟦 **Freamon Phase 5: Log Analytics API & Query Patterns Skills** (2026-04-30)
- Authored 2 new Log Analytics skills: `api-wrapper.md` (~470 lines) and `query-patterns.md` (~380 lines)
- `api-wrapper.md` covers 7 sections: Query API, Saved Searches, Query Packs, Alerts API (Scheduled Query Rules V2), Data Collection Rules (DCR), Webhooks & Export, Rate Limits & Best Practices
- `query-patterns.md` covers 7 patterns: cross-workspace queries, cross-resource queries (app/resource/adx), parameterized queries, time-series analysis, performance optimization, ADX proxy queries, `.secops/` data source map integration
- Both skills include PowerShell, Python, KQL, REST, and JSON examples — all production-ready
- Deep `.secops/` integration throughout: workspace IDs from config, data-source-map awareness, alert routing integration, tier-aware query building, migration-safe cross-workspace patterns
- Key patterns: batch query API (200 queries/batch), DCR transformation KQL (allowed vs. disallowed operators), `materialize()` for subquery reuse, `series_decompose_anomalies` for baseline detection, `shuffle` strategy for large joins
- Combined project total: 28 skills (10 KQL + 10 Log Analytics + 8 ADX), ~8,725 lines

🟦 **Freamon Phase 6: Data Tiering Commands Skill** (2026-04-30)
- Authored `skills/powershell/data-tiering-commands.md` (~500 lines) — production-ready PowerShell for full data tiering lifecycle
- 15 new PowerShell functions: tier management (Get/Set-LogAnalyticsTablePlan, Get-TierRecommendation, Get-TierCostImpact), retention (Get/Set-LogAnalyticsRetention, Test-RetentionCompliance, Set-BulkRetentionPolicy), summary rules (New/Get/Test-SummaryRule), purge (Submit-DataPurge, Get-PurgeStatus), migration (Start-DataMigration, Get-MigrationStatus)
- Key pattern: pre-flight safety checks on tier downgrades — blocks if analytics rules reference the table or migrations are in progress
- Key pattern: compliance-as-hard-constraint — retention changes validate against `.secops/compliance/requirements.yaml` before applying
- Key pattern: cost calculator uses `.secops/data-source-map.yaml` daily volumes as default data source
- Includes decision tree, frequency-based tier selection matrix, cost modeling formulas, and complete production workflow
- Summary rule templates for Syslog, CommonSecurityLog, and AWSCloudTrail pre-built
- Complements existing `data-tiering-module.md` (submodule overview) without duplicating base functions
- Decision filed: `.squad/decisions/inbox/freamon-data-tiering.md`
- Combined project total: 29 skills, ~9,225 lines

🟦 **Freamon Phase 6: Unified API Rate Limiting & Common API Patterns** (2026-04-30)
- Authored 2 new cross-cutting PowerShell skills: `rate-limiting.md` and `api-patterns.md`
- `rate-limiting.md` (~400 lines): Comprehensive rate limits reference for all Microsoft Security APIs (ARM, Graph, MDE, Sentinel, Log Analytics, MDCA, Resource Graph) with numeric limits and sources
- Covers 7 sections: rate limit reference table, exponential backoff with jitter (per-provider tuning), 3-tier priority queue (Critical/Normal/Low token buckets), quota pooling (file-based mutex + Redis distributed), circuit breaker (Closed/Open/HalfOpen states), monitoring/alerting (80% threshold), cross-API coordination (multi-tenant MSSP, batch scheduling)
- `api-patterns.md` (~320 lines): Reusable patterns across all API wrappers — pagination (nextLink, skipToken, $top/$skip), Graph $batch (20-request batches), ARM async operations (Location + Azure-AsyncOperation polling), idempotent create-or-update (ETag-based concurrency), correlation ID propagation, request/response audit logging, PowerShell pipeline streaming
- Both skills include production-ready PowerShell implementations: `Invoke-WithRetry`, `Request-ApiWithPriority`, `Get-QuotaBudget`, `Request-QuotaSlot`, `Invoke-WithCircuitBreaker`, `Get-SecOpsAllPages`, `Invoke-SecOpsGraphBatch`, `Wait-SecOpsAsyncOperation`, `Set-SecOpsResource`, `Get-SecOpsStream`
- Pester test scenarios for each major pattern: retry behavior, circuit breaker state transitions, priority fairness, pagination formats, batch limits, async timeout, idempotent create
- Deep `.secops/` integration: environment-aware cloud endpoints, per-tenant quota isolation for MSSPs, alerting/routing.yaml integration for rate limit alerts
- These are cross-cutting skills referenced by every API wrapper skill in the project
- Combined project total: 30 skills (10 KQL + 10 Log Analytics + 8 ADX + 12 PowerShell), ~9,445 lines

🟦 **Freamon Phase 6: Sentinel REST API Wrapper Skill** (2026-04-30)
- Authored `skills/powershell/sentinel-api-wrapper.md` (~500 lines) — production-ready PowerShell wrappers for the full Sentinel REST API surface
- 6 domain sections: Incident Management, Analytics Rules, Threat Intelligence, Workbooks, Data Connectors, Watchlists
- 20+ copy-pasteable PowerShell functions including bulk operations, pagination, and rate-limit awareness
- Key functions: Update-SentinelIncident, Close-SentinelIncident, Invoke-SentinelBulkIncidentClose, Add-SentinelIncidentComment, Get-SentinelIncidentRelations, Get-SentinelAnalyticsRule, New-SentinelNrtRule, New-SentinelRuleFromTemplate, Test-SentinelRuleQuery, Set-SentinelRulesByMitreTechnique, Import-SentinelThreatIntel, Get-SentinelTIIndicator, Import-SentinelTIBulk, Import-SentinelWorkbook, Get-SentinelWorkbook, Get-SentinelConnectorStatus, Enable-SentinelConnector, New-SentinelWatchlist, Import-SentinelWatchlistItems, Export-SentinelWatchlistItems
- Shared helpers: Get-SentinelBaseUri (government cloud aware), Invoke-SentinelApi (auto-pagination, token resolution)
- Complements sentinel-module.md (no duplication) — adds bulk ops, relations, rule templates, TI lifecycle, watchlists, connector management
- Full `.secops/` integration: workspace discovery, naming conventions, connector cross-referencing, compliance awareness
- All functions use SecOps.Result pattern, ShouldProcess for writes, Invoke-SecOpsBatchOperation for bulk
- Combined project total: 29 skills, ~9,225 lines
