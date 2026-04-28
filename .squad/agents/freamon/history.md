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
