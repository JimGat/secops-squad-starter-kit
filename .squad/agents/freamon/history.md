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
