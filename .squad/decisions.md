

# Squad Decisions

## Active Decisions


### 2026-04-30T15:05:29-05:00: Customer Knowledge Framework (.secops/) and Platform Gap Priorities

**By:** McNulty (Lead)

**Status:** Proposed

**Requested by:** Jose Paid

**What:** Two decisions for team review:

1. **Customer Knowledge Framework** — Proposed `.secops/` directory structure for environment-specific knowledge:
   - YAML format for human-editability + machine-parseability
   - Gitignored by default (contains environment-specific data like workspace IDs, tenant IDs)
   - Separate from `.squad/` — framework internals vs. customer environment
   - Auto-discovery pattern — agents append to `discovery-log.yaml`, human review before promotion
   - Key files: `environment.yaml`, `data-sources/data-source-map.yaml`, `workspaces/*.yaml`, `alerting/routing.yaml`

2. **Platform Gap Priorities — New Skill Domains** — Four new skill domains proposed (all Critical priority):
   - `skills/powershell/` — Az.SecurityInsights, Az.OperationalInsights (SOC engineers are PS-first, zero coverage today)
   - `skills/mcp/` — Sentinel MCP Server integration (agents can't execute KQL without this)
   - `skills/azure-monitor/` — Action Groups, Alert Rules, Workbooks (operational alerting backbone)
   - `skills/entra-id/` — Conditional Access as code, PIM automation (daily SOC operations)

**Why:** 16 critical gaps identified across Microsoft's security platform. No PowerShell module skills despite target audience being PS-first. Agents write KQL but can't execute it (no MCP integration). Customer environments are invisible to agents. MSSP/multi-tenant scenarios completely unaddressed.

**Impact:**
- **Kima:** Owns new `msft-security` gaps (MDE APIs, Defender for Cloud Apps)
- **Freamon:** Owns new `kql/resource-graph-hunting.md`, data tiering skills, Query API skill
- **Herc:** Owns Azure Monitor skills (action groups, alert rules)
- **Sydnor:** Owns `.secops/` scaffolding in CLI (`secops-squad env init`), config schema extension
- **All agents:** Must learn to consult `.secops/` before making environment assumptions

**Full Analysis:** See `docs/platform-coverage-gap-analysis.md`

### 2026-04-30T16:42:00-05:00: .secops/ Customer Knowledge Framework — Schema v1.0

**By:** Sydnor (Platform Dev)

**Status:** Proposed

**Blocks:** All Phase 1 downstream work (skills integration, agent routing, CLI env commands)

**What:** Created the `.secops/` directory as the customer-specific environment knowledge framework for secops-squad. Foundational schema that all agents, skills, and CLI commands depend on for environment-aware operations.

**Structure:**
```
.secops/ (16 files across 6 subdirectories)
├── README.md + environment.yaml
├── workspaces/    (README.md + example-workspace.yaml)
├── data-sources/  (README.md + data-source-map.yaml + migrations.yaml)
├── identity/      (README.md + tenants.yaml + rbac-conventions.yaml)
├── alerting/      (README.md + routing.yaml + escalation.yaml)
├── compliance/    (README.md + requirements.yaml)
└── discovery-log.yaml
```

**Key Design Decisions:**
1. Schema version `1.0` in every YAML file — Enables version-aware agent behavior and backward compatibility
2. Separate from `.squad/` — `.secops/` is customer environment data; `.squad/` is framework internals
3. YAML, not JSON — Human-editable with inline comments for SOC engineers
4. All files standalone — Missing files = "unknown," not "error"
5. Append-only discovery log — Bridge between agent auto-discovery and human-verified authoritative data
6. MSSP-first multi-tenancy — Supports enterprise through full MSSP with Lighthouse delegations
7. Cross-cloud metadata — `source_cloud` field enables AWS/GCP correlation context
8. Compliance as hard constraint — `prohibited_regions` are enforced, not suggestions
9. Escalation with severity overrides — Critical alerts can skip triage tiers
10. Templates, not real data — All files use "Contoso Corp" examples; will be `.gitignored` in production

**Scenarios Supported:** Single-tenant enterprise, multi-tenant, MSSP, CSP, government cloud, GDPR/NIS2/DORA/PCI-DSS/FedRAMP, cross-cloud, data tiering, active migrations, ADX + Sentinel hybrid

**Impact on Team:**
- **Freamon:** Consult `data-source-map.yaml` before KQL queries
- **Kima:** Check `tenants.yaml` for cross-tenant detection rules
- **Herc:** Check `compliance/requirements.yaml` before SOAR deployments
- **Sydnor:** Build `secops-squad env init` CLI command against this schema
- **All agents:** Append to `discovery-log.yaml` when discovering environment facts

### 2026-04-30T16:42:21-05:00: Agent .secops/ Environment Context Integration

**By:** Sydnor (Platform Dev)

**Status:** Implemented

**What:** All secops-squad agents now have a standardized protocol for discovering and using customer environment context from the `.secops/` knowledge framework before performing any security operations task.

**Changes Made:**
1. New Copilot skill: `.copilot/skills/secops-environment-context.md` — defines the 7-step discovery flow, critical rules, discovery-log append protocol, government cloud awareness, multi-tenant patterns, and data residency enforcement
2. 11 domain skills updated with `## Environment Context` section — consistent block directing agents to check data-source-map, migrations, workspace config, and compliance before executing the skill
3. 6 agent charters updated (McNulty, Kima, Freamon, Herc, Sydnor, Carver) — `.secops/` context check added as first item under "How I Work"
4. Routing table updated — `.secops/` is self-serve; agents read it directly without coordinator routing

**Why:** The `.secops/` framework captures customer-specific environment facts. Without agent integration, this data sits unused. With it, agents make environment-aware decisions: correct KQL table references, compliant region selections, migration-safe recommendations.

**Key Design Choices:**
1. Copilot-level skill (`.copilot/skills/`) — discoverable by Copilot skill system, not just squad internals
2. Self-serve, not routed — agents check `.secops/` themselves. No coordinator bottleneck
3. Graceful degradation — if `.secops/` doesn't exist, agents proceed with defaults and suggest `secops-squad init --secops`
4. Append-only discovery log — agents write new facts to `discovery-log.yaml` but never modify existing entries
5. Consistent section block — all 11 skill files use identical `## Environment Context` wording

**Impact:**
- **All agents:** Must check `.secops/` before Azure resource, data source, or workspace operations
- **Freamon:** KQL queries now respect `data-source-map.yaml` for table locations
- **Kima:** Detection rules check compliance before region-specific deployments
- **Herc:** SOAR playbooks verify workspace config and data residency
- **Carver:** Can validate that other agents' outputs respect `.secops/` context

### 2026-04-30T16:42:21-05:00: js-yaml dependency + CLI secops integration

**By:** Sydnor (Platform Dev)

**Status:** Implemented

**What:** Added `js-yaml` as the project's first npm production dependency to support `.secops/` YAML parsing in the CLI. Built three new modules:
1. `cli/secops-config.js` — Shared config loader for all `.secops/` YAML files
2. `cli/commands/env.js` — `secops-squad env` command with 4 subcommands
3. `cli/secops-init.js` — `secops-squad init --secops` scaffolding

**Why js-yaml:** The `.secops/` YAML files use nested objects, arrays, inline comments, and multi-line strings that a regex-based parser cannot handle reliably. `js-yaml` is the de-facto standard (38M weekly downloads), zero transitive dependencies, and MIT-licensed.

**Impact:**
- **All agents:** Can now use `secops-squad env` to inspect environment before operations
- **Kima/Freamon:** `secops-squad env data-sources` shows table locations + tiers before writing KQL
- **Herc:** Migration status visible via CLI before deployments
- **Carver:** `secops-squad env validate` can be added to CI pipeline
- **Init flow:** `--secops` flag generates starter `.secops/` for new customers

**Pattern:**
- `secops-config.js` returns `null` for missing files (never crashes) — matches `.secops/` design principle
- `env.js` follows existing command pattern: `run(args)` export, ANSI colors, same style as doctor/init
- `secops-init.js` is idempotent — won't overwrite existing `.secops/environment.yaml`


# Decision: README follows Squad structural pattern

**Date:** 2026-05-04T17:12:14.241-05:00
**By:** Sydnor (Platform Dev)
**Status:** Active

## What

README.md now follows the same structural pattern as the upstream [Squad README](https://github.com/bradygaster/squad): alpha warning → value prop → Quick Start with ✓ Validate → Commands table → feature sections → directory tree → samples → FAQ → docs links → Built On.

## Why

Consistency with the upstream project we're built on. Users familiar with Squad will find the same information flow. The ✓ Validate pattern after each install step reduces support questions.

## Impact

- Section headers no longer use emoji (cleaner, matches Squad convention)
- Documentation section split into three tables (Guides, Reference, Developer) for scannability
- Skill counts corrected to match SKILLS_CATALOG.md (Detection: 9, Microsoft Security: 16)
- All future README edits should maintain this structure


## Governance

- All meaningful changes require team consensus
- Document architectural decisions here
- Keep history focused on work, decisions focused on direction


# Decision: Bicep Template Phase 2 Integration Pattern

**Date:** 2026-05-04T07:53:46-05:00
**By:** Carver (Tester/QA)
**Status:** Proposed

## What

All 11 Bicep templates now include standardized Phase 2 integration comment blocks that reference PowerShell wrapper skills, `.secops/` config files, and post-deployment scripts. A new `templates/bicep/README.md` serves as the central cross-reference.

## Key Design Choices

1. **Comment-only changes** — No Bicep logic was modified. Integration points are documented via comment blocks, not code changes. This preserves template correctness and avoids deployment regressions.

2. **Forward-referenced scripts** — Templates reference `Configure-SoarPlaybooks.ps1` and `Configure-AdxSecurityLake.ps1` that don't exist yet. These scripts should be created by Herc/Sydnor as Phase 2 deliverables.

3. **Rate limiting cross-reference** — Every template references `rate-limiting.md` with specific API limits relevant to its domain (e.g., MDE 100 calls/min for malware-containment, Graph 10K/10min for compromised-account).

4. **`.secops/` is advisory, not enforced** — Templates document which `.secops/` files to consult but don't programmatically read them. Bicep runs in ARM context where local files aren't accessible. The post-deployment scripts will be the enforcement point.

## QA Observations

- **Gap: No deployment validation tests exist** — There's no CI that validates Bicep templates compile (`az bicep build`). Recommend adding a CI step.
- **Gap: Post-deployment scripts are vapor** — The referenced PS1 scripts need to be implemented. Tracked as forward references.
- **Gap: README references `sentinel/` template directory** — The `templates/bicep/sentinel/` directory exists but only contains `.gitkeep`. The README architecture diagram doesn't mention it (correct, since it has no templates).

## Impact

- **Herc:** Needs to create `Configure-SoarPlaybooks.ps1` and `Configure-AdxSecurityLake.ps1`
- **Sydnor:** README references `secops-squad env validate` — must be functional
- **All agents:** Should consult `templates/bicep/README.md` before deploying templates


# Decision: Integration Test Suite Architecture

**Date:** 2026-05-04T07:53:46-05:00
**By:** Carver (Tester/QA)
**Status:** Proposed
**Requested by:** Jose

## What

Created `skills/testing/integration-test-suite.md` — a skill document defining the test architecture, mock factories, and end-to-end test scenarios for all 5 orchestration workflows from `cross-skill-orchestration.md`.

## Key Decisions

1. **Mock at the HTTP boundary** — Override `Invoke-RestMethod` globally in test scope rather than mocking individual skill functions. Tests validate the full workflow chain, not isolated steps.

2. **URI-pattern matching with regex** — `Register-MockResponse` uses regex patterns against URIs, allowing a single mock to cover paginated/parameterized endpoints without registering every URL variant.

3. **Configurable failure injection** — `FailCount` parameter on mocks enables testing retry logic, circuit breakers, and partial failure without separate mock setups per failure mode.

4. **Test `.secops/` fixtures, not real configs** — `New-TestSecopsConfig` generates deterministic fixtures for single-tenant, multi-tenant, and gov-cloud scenarios. Tests never touch the project root `.secops/`.

5. **Pester v5+ as PowerShell test framework** — Aligns with existing JS test patterns (`node:test`) but uses the PowerShell ecosystem's standard. Pester's `Mock`/`Should -Invoke` patterns complement the custom harness for different testing layers.

6. **Structured result contract validation** — `Assert-SuccessResult`/`Assert-ErrorResult` helpers enforce the `@{ ok; data/error }` contract established in `decisions.md` across all workflow outputs.

## Impact

- **Carver:** Owns and maintains all test patterns; integration tests become a quality gate on orchestration PRs
- **All agents:** Reference test data generators when building new API integrations
- **Sydnor:** Can integrate `Invoke-Pester` into CI pipeline alongside existing `node --test`
- **Freamon/Kima/Herc:** Workflow changes must pass corresponding integration test scenario

## Open Questions

- Should Pester test files be created alongside skills (`skills/testing/tests/`) or in a top-level `tests/` directory? Currently the skill describes patterns but doesn't create actual test files.
- Do we need a shared `tests/helpers/test-harness.ps1` file extracted from the skill, or should each test file bootstrap its own harness?


# Decision: Cross-Cloud Connectors Skill & Platform Domain

**Date:** 2026-05-04T08:41:39-05:00
**By:** Freamon (KQL Engineer)
**Status:** Implemented
**Requested by:** Jose

## What

Created `skills/platform/cross-cloud-connectors.md` (509 lines) — a comprehensive skill document covering AWS, GCP, and multi-SIEM data ingestion into Microsoft Sentinel. Also created the new `skills/platform/` domain directory.

## Key Decisions

1. **New `skills/platform/` domain** — Cross-cloud connectors span KQL, Log Analytics, and PowerShell domains. Rather than forcing this into an existing domain, created `platform/` for cross-cutting infrastructure skills that don't belong to a single product area.

2. **ASIM as the unification layer** — All cross-cloud KQL examples normalize to ASIM schemas (Authentication, NetworkSession). This enables unifying parsers that transparently query Azure + AWS + GCP in a single query. Cross-cloud correlation queries depend on consistent ASIM field mapping.

3. **Tier recommendations per source** — Embedded cost-aware tier guidance directly in the skill. CloudTrail → Basic, GuardDuty → Analytics, VPC Flow Logs → Auxiliary. These align with `.secops/data-source-map.yaml` tier field conventions.

4. **SPL→KQL translation table** — Included 10 common SPL-to-KQL patterns for Splunk migration. This is the most common multi-SIEM scenario for Sentinel customers.

5. **PowerShell health functions use `.secops/`** — `Get-CrossCloudConnectorHealth` and `Test-CrossCloudIngestionVolume` read from `data-source-map.yaml` to auto-discover cross-cloud sources, following the established `.secops/` auto-loading pattern.

## Impact

- **Kima:** Can reference ASIM parsers for cross-cloud detection rules
- **Herc:** Connector setup automation patterns available for SOAR playbooks
- **All agents:** New `platform/` domain available for future cross-cutting skills
- **`.secops/`:** data-source-map.yaml examples for `source_cloud: aws/gcp` entries established as templates




# Decision: MSSP Workflow Patterns and `.secops/mssp-config.yaml` Schema

**Date:** 2026-05-04T09:00:00-05:00
**By:** Freamon (KQL Engineer)
**Status:** Proposed

## What

Created `skills/orchestration/mssp-workflows.md` establishing MSSP-specific operational patterns:

1. **`mssp-config.yaml` as MSSP control plane** — New `.secops/` file defining SOC team assignments, customer→team mappings, billing tiers (Gold/Silver/Bronze with cost-per-GB and SCU allocations), SLA definitions (response time targets per severity per tier), analyst rotation schedules, and per-customer notification channels (PagerDuty, Teams, email, ServiceNow).

2. **Three-tier service model** — Bronze (basic monitoring, 60-min High SLA, 8x5), Silver (threat hunting + custom detections, 30-min High SLA, 8x5), Gold (dedicated analyst + 24x7 + compliance reporting, 15-min High SLA). Detection rule packs, feature access, and billing rates all key off this tier.

3. **Centralized vs Distributed config pattern** — Recommended centralized `mssp-config.yaml` for <20 customers, per-customer `.secops/customers/<slug>/` folders for 20+, hybrid for 50+.

4. **Analyst state preservation** — `Switch-MSSPCustomer -PreserveState` saves/restores investigation context (open incidents, last query) per tenant in `.secops/analyst-state/`.

## Why

MSSPs are the most complex deployment model for secops-squad. Without structured workflow patterns, MSSP SOC analysts face: (a) no SLA tracking mechanism, (b) manual tenant onboarding taking hours, (c) no billing visibility, (d) context loss when switching between customers. The `mssp-config.yaml` schema gives agents structured access to customer tier, team assignment, and SLA targets.

## Impact

- **Sydnor:** `mssp-config.yaml` schema needs CLI support (`secops-squad env` should parse it). Consider `secops-squad mssp` subcommand.
- **Kima:** Detection rules should be tagged by tier so `Deploy-TierDetectionRules` can select appropriate rule packs.
- **Herc:** SOAR playbooks may need tier-aware escalation paths from `mssp-config.yaml`.
- **All agents:** When `org_type: "mssp"`, check `mssp-config.yaml` for customer context before operations.


# Freamon — Phase 6 Skill Decisions (2026-05-04)

**By:** Freamon (KQL Engineer)
**Requested by:** Jose

## Decision: TI Feed Configuration in `.secops/`

**What:** Introduced `data-sources/ti-feeds.yaml` as the standard location for TI feed configuration within the `.secops/` framework. Schema supports 7 feed sources (CISA KEV, abuse.ch, VirusTotal, Shodan, OTX, MISP, Defender TI) with per-feed enable/disable, schedule, API key vault references, and quota tracking.

**Why:** TI feed management is environment-specific — which feeds are enabled, API quotas, and refresh schedules vary per customer. Centralizing this in `.secops/` follows the established pattern and lets `Import-ThreatIntelFeed` auto-configure from YAML instead of requiring parameters.

**Impact:**
- **Kima:** Detection rules can reference TI watchlist aliases from feed config
- **Herc:** SOAR playbooks can check feed health before relying on TI enrichment
- **Sydnor:** CLI `env` command could surface TI feed status

## Decision: Multi-Source IOC Confidence Scoring

**What:** Established a pattern where IOCs appearing in 3+ independent feeds get "High" confidence, 2 feeds = "Medium", 1 = "Low". Both KQL (ThreatIntelligenceIndicator aggregation) and PowerShell (`Get-IOCEnrichment`) implement this scoring.

**Why:** Single-source IOC matches generate too many false positives. Multi-source correlation dramatically increases true positive rate without requiring analyst judgment at triage time.

## Decision: Performance Skill as Platform Cross-Cutting Concern

**What:** Placed performance-tuning.md in `skills/platform/` rather than `skills/kql/` or `skills/powershell/` because it spans KQL optimization, API wrapper patterns, rate limiting, MCP server efficiency, and cost analysis.

**Why:** Performance touches every domain. Placing it in platform alongside cross-cloud-connectors and multi-tenant-support signals that all agents should reference it. The KQL anti-pattern table and query checklist should be consulted by anyone writing production queries.


# Decision: SOC Analyst Persona v2.0.0 — Phase 2-3 Tool Integration

**Date:** 2026-05-04T07:53:46-05:00
**By:** Freamon (KQL Engineer)
**Requested by:** Jose
**Status:** Proposed

## What

Updated the `personas/soc-analyst/` persona (skills.json, routing.md, README.md) to reference Phase 2-3 skills: Advanced Hunting API, KQL query-builder, workbook automation, Sentinel/Defender/Log Analytics API wrappers, Copilot for Security enrichment, and rate limiting patterns.

## Key Choices

1. **skills.json bumped to v2.0.0** — Breaking change: added `path` fields to new skill entries for explicit skill file references. Existing skill names preserved for backward compatibility.
2. **Rate limiting and Copilot for Security are shared skills** — All tiers need API rate limiting (mandatory cross-cutting concern) and Copilot enrichment. Added to `shared` array rather than duplicating per-agent.
3. **Tier-appropriate skill distribution** — Bunk (L1) gets minimal API access (sentinel-api-wrapper only). Kima (L2) gets Sentinel + Defender + workbooks. Freamon (L3) gets the full query/hunting stack. Daniels gets workbooks for operational dashboards.
4. **Tool-chain routing added to routing.md** — New section maps task types to ordered tool chains (e.g., "Threat hunting → KQL builder → Advanced Hunting API"). This is additive — existing severity-based and work-type routing tables are unchanged.
5. **`.secops/alerting/` integration** — Alert triage routing now references `.secops/alerting/routing.yaml` and `escalation.yaml` for environment-specific rules. This connects the persona to the customer knowledge framework.

## Why

The SOC analyst persona referenced Phase 1 skills only. Phase 2-3 delivered 9 new skills that directly serve SOC workflows but weren't wired into the persona. Without these references, users installing the soc-analyst persona wouldn't discover the Advanced Hunting API, KQL builder, or API wrappers — the tools that make programmatic SOC operations possible.

## Impact

- **Kima:** Now has explicit `defender-api-wrapper` and `workbook-automation` assignments
- **Bunk:** Now has `sentinel-api-wrapper` for programmatic incident triage
- **Daniels:** Now has `workbook-automation` for SOC operational dashboards
- **All agents:** `rate-limiting` and `copilot-for-security` are shared baseline skills
- **Other personas:** May want similar Phase 2-3 updates (detection-engineering, threat-hunting, incident-response)

## Review Requested From

- **McNulty:** Architecture review — does the tool-chain routing pattern work for other personas?
- **Kima:** Confirm Kima's skill assignments are appropriate for L2 workflows




# Decision: Persona Configuration Updates for Phases 2-3

**Date:** 2026-05-04T07:53:46-05:00
**By:** Herc (Automation/SOAR)
**Requested by:** Jose
**Status:** Proposed

## What

Updated two persona configurations to reference all Phase 2-3 skills:

### incident-response persona (v1.0.0 → v2.0.0)
- Added 7 new skill references across shared and per-agent assignments
- Sydnor gets eDiscovery, Purview, and data tiering for forensic evidence governance
- Beadie gets compliance framework mappings for regulatory reporting
- Rawls gets workbook automation for post-incident dashboards
- All agents get api-patterns and rate-limiting as shared skills
- New routing rules for compliance checks, evidence preservation, data classification, and post-incident reporting
- 3 new operational rules enforcing compliance assessment, legal holds, and mandatory dashboards

### full-soc persona (v1.0.0 → v2.0.0)
- Expanded from ~24 skill references to 60+ covering all Phase 2-3 domains
- New `infrastructure_skills` section for platform-level skills (MCP servers, data tiering, workspace setup)
- Every agent gets expanded skill set matching their domain expertise
- Cutty (Automation) goes from 3 skills to 11 — now covers full SOAR + compliance + monitoring portfolio
- Routing expanded from 16 to 27 domain entries, 6 to 12 cross-functional scenarios
- 5 new routing rules for compliance, legal holds, automation, threat feeds, and MCP self-serve

## Why

Phase 2-3 produced 30+ new skills across powershell/, msft-security/, soar/, detection/, and kql/ domains. Without persona updates, users installing these personas would miss the new capabilities. The incident-response and full-soc personas are the most impacted because they span the broadest operational surface.

## Key Design Choices

1. **Shared vs per-agent**: Foundation skills (api-patterns, rate-limiting, auth-patterns, error-handling, module-foundation) are shared. Domain-specific skills are per-agent.
2. **infrastructure_skills section**: New top-level section in full-soc for platform skills that don't belong to any single agent (MCP servers, workspace setup, API reference).
3. **Path references**: New skills include explicit `path` fields pointing to skill file locations for discoverability.
4. **Routing rules are prescriptive**: "Compliance assessment before closure" and "legal holds before evidence collection" are mandatory rules, not suggestions.
5. **MCP servers are self-serve**: Any agent can query Sentinel/Defender data via MCP without routing through another agent.

## Impact

- **All persona users**: Installing incident-response or full-soc now gets the full Phase 2-3 skill set
- **McNulty**: May want to review the infrastructure_skills pattern for adoption in other personas
- **Sydnor**: CLI `init` command should respect the new `infrastructure_skills` section when installing personas
- **Other personas** (soc-analyst, detection-engineering, threat-hunting, cloud-security): Should be updated similarly in a follow-up task






# Decision: Gov Cloud Support + Copilot Workflow Skills

**Date:** 2026-05-04T08:41:39-05:00
**By:** Kima (SecOps Engineer)
**Requested by:** Jose
**Status:** Implemented

## What

Created two new skill documents:

1. **`skills/platform/gov-cloud-support.md`** (~640 lines) — Sovereign cloud support covering GCC, GCC High, DoD, Azure Government, and Azure China environments with endpoint resolution, auth flows, feature availability, and compliance constraints.

2. **`skills/orchestration/copilot-security-workflows.md`** (~780 lines) — Copilot for Security enriched workflow patterns with 5 enrichment types, 3 workflow templates, SCU cost management, and graceful degradation.

## Key Design Decisions

1. **`organization.cloud` as single source of truth** — All endpoint resolution flows from this single field in `.secops/environment.yaml`. No hardcoded commercial URLs anywhere in agent code.

2. **Feature availability as guard, not assumption** — `Test-SecOpsCloudFeature` must be called before any operation that may not exist in sovereign clouds. Silent failures are unacceptable in government environments.

3. **Mandatory fallback paths** — Every Copilot-dependent workflow includes a non-AI fallback. GCC High/DoD customers get functional (if less enriched) workflows without Copilot.

4. **SCU budget per workflow** — Individual workflow SCU limits prevent a single runaway triage from consuming the entire monthly budget.

5. **Certificate-based auth required for GCC High/DoD** — Client secrets are development-only in sovereign clouds. Production service principals must use X.509 certificates.

## Impact

- **All agents:** Must use `Get-SecOpsCloudEndpoints` instead of hardcoded URLs
- **Herc:** SOAR playbooks must call `Test-SecOpsCloudFeature` before Copilot actions
- **Freamon:** KQL queries targeting gov clouds must use `api.loganalytics.us` (not `.io`)
- **Sydnor:** CLI `env` commands should surface cloud type prominently
- **Carver:** Validation should verify no hardcoded commercial endpoints in new skills

## Why

Government customers represent a significant deployment target. Without explicit sovereign cloud support, agents would silently fail against incorrect endpoints, attempt unavailable features, or violate data residency requirements — all unacceptable in regulated environments.


# Decision: Attack Simulation & Cloud App Discovery API Skills

**By:** Kima (SecOps Engineer)
**Date:** 2026-05-04T09:50:42-05:00
**Priority:** P6 (Optional)

## What

Created two optional API skill documents:
1. `skills/msft-security/attack-simulation-api.md` — Attack Simulation Training via Graph API
2. `skills/msft-security/cloud-app-discovery-api.md` — MDCA Discovery REST API

## Design Choices

1. **Complements, not duplicates:** `cloud-app-discovery-api.md` extends the existing `defender-cloud-apps.md` (which covers CASB policy design) with API-level automation. No content overlap.
2. **Simulation-to-detection correlation:** `attack-simulation-api.md` includes Sentinel KQL queries that cross-reference simulation targets with detection alerts — this is a novel capability not covered by any existing skill.
3. **`.secops/` config patterns:** Both skills define new YAML config blocks (`attack_simulation`, `cloud_app_discovery`, `sanctioned-apps.yaml`, `simulation-campaigns.yaml`) following the schema v1.0 pattern established by Sydnor.

## Impact

- **Kima:** Owns both skills; total contribution now 22 skills
- **Herc:** Can reference simulation scheduling for SOAR automation
- **Freamon:** KQL queries in both skills follow validated patterns
- **No blocking dependencies:** Both skills are optional extensions


# Decision: Phase 2-3 Persona Skill & Routing Updates

**Date:** 2026-05-04T07:53:46-05:00
**By:** Kima (SecOps Engineer)
**Requested by:** Jose
**Status:** Proposed

## What

Updated three persona configurations (detection-engineering, threat-hunting, cloud-security) to reference Phase 2-3 skills, API wrappers, and MCP tools. All three personas bumped from v1.0.0 → v2.0.0.

### Changes Per Persona

| Persona | New Skills | Files Updated |
|---------|-----------|---------------|
| detection-engineering | 8 (sentinel-api-wrapper, sentinel-mcp-server, sentinel-api-reference, data-tiering-commands, workbook-automation, log-analytics/api-wrapper, log-analytics/query-patterns, kql/query-builder) | skills.json, routing.md, README.md |
| threat-hunting | 8 (sentinel-api-wrapper, sentinel-mcp-server, sentinel-api-reference, data-tiering-commands, log-analytics/api-wrapper, log-analytics/query-patterns, kql/query-builder, workbook-automation) | skills.json, routing.md, README.md |
| cloud-security | 6 (defender-api-wrapper, defender-mcp-server, defender-api-permissions, advanced-hunting-api, copilot-for-security, defender-cloud-apps) | skills.json, routing.md, README.md |

## Key Design Decisions

1. **MCP-first tool selection** — All routing files establish MCP → PowerShell → REST as the priority order for tool selection. Agents use MCP for interactive operations; pipelines use PowerShell wrappers for automation.

2. **Shared vs per-agent skill placement** — API wrappers and MCP tools that all agents need (sentinel-api-wrapper, sentinel-mcp-server, sentinel-api-reference, defender-api-wrapper, defender-mcp-server, defender-api-permissions) are placed in `shared`. Domain-specific tools (workbook-automation, data-tiering-commands, advanced-hunting-api, copilot-for-security, defender-cloud-apps) are placed per-agent based on routing ownership.

3. **Routing files include API operation tables** — Each routing.md now has an "API & Tool Routing" section mapping specific operations to skills and responsible agents. This makes tool selection deterministic for agents.

4. **Version bump to 2.0.0** — Breaking change: new shared skills mean all agents in these personas get additional context. Bumped major version to signal this.

## Why

Phase 2-3 delivered 20+ PowerShell wrappers, MCP server integrations, and API references for both Sentinel and Defender. These skills were built but not yet wired into persona configurations — meaning agents using these personas couldn't discover or route to them. This update closes the gap.

## Impact

- **Sydnor:** CLI `secops-squad init` will install updated personas with Phase 2-3 skills pre-loaded
- **Freamon:** KQL/Log Analytics skills now referenced by detection-engineering and threat-hunting personas
- **Herc:** workbook-automation skill now referenced by detection-engineering (Daniels) and threat-hunting (Rhonda)
- **Carver:** Can validate that persona skill references resolve to actual skill files

## Open Questions

- Should `incident-response` and `full-soc` personas also get Phase 2-3 updates? (Not in current task scope)
- Should `soc-analyst` persona reference copilot-for-security? (Natural fit for Tier 1 analyst workflows)


# Decision: Readiness Assessment Findings — Three End-to-End Workflows

**By:** McNulty (Lead)  
**Date:** 2026-05-04T16:25:25.217-05:00  
**Requested by:** John Spaid  
**Status:** Findings — action required  

---

## Summary

Three end-to-end workflows assessed against current repo state. All three are partially functional. One has a broken command promise (`workspace connect`), one has a name-field discrepancy in the agent file, and one is entirely template-only with no connectivity path implemented. Priorities and specific file fixes are documented below.

---

## Finding 1: `workspace connect` is a broken promise — HIGH PRIORITY

**File:** `cli/index.js` lines 38–41 + `cli/commands/init.js` line 413

`init.js` explicitly tells users: _"Connect Azure later with `secops-squad workspace connect`"_. However, `index.js` registers `workspace` with no `module:` field — it falls through to the `"This command is not yet implemented"` stub. This is a user-facing broken promise. Sydnor should either implement `cli/commands/workspace.js` or remove the suggestion from the init output.

**Decision:** `workspace connect` must be either implemented or the post-init prompt must be updated to point users to `secops-squad env` instead. Do not ship a command that advertises itself in init output but silently fails.

---

## Finding 2: Agent frontmatter `name:` field conflicts with CLI invocation pattern

**File:** `.github/agents/secops-squad.agent.md` frontmatter (line 2)

Current: `name: SecOps Squad` (space-separated)  
CLI invocation: `copilot --agent secops-squad` (hyphen-separated)

If the Copilot CLI matches against the `name:` frontmatter field (not the filename), this will silently fail — "secops squad" ≠ "secops-squad". The safer fix is to align the `name:` field with the filename: `name: secops-squad`. Sydnor should verify CLI matching behavior and update accordingly.

---

## Finding 3: `.github/copilot-instructions.md` not deployed

**File:** `.squad/templates/copilot-instructions.md` (template only — not active)  
**Missing:** `.github/copilot-instructions.md`

The copilot instructions template exists but has not been deployed to the active `.github/copilot-instructions.md` location. This means Copilot sessions have no custom workspace-level instructions. Sydnor should add deployment of this file to the install script or document the manual step.

---

## Finding 4: `.env.example` only covers Sentinel — incomplete for Workflow 3

**File:** `.env.example`

Covers only `AZURE_SUBSCRIPTION_ID`, `AZURE_TENANT_ID`, `SENTINEL_WORKSPACE_ID`, `SENTINEL_WORKSPACE_NAME`, `SENTINEL_RESOURCE_GROUP`. No variables for Defender XDR, Defender for Cloud, Defender for Identity, Defender for Endpoint, or Entra ID Protection. Kima should define what variables each product needs, then Sydnor updates `.env.example`.

---

## Finding 5: No Defender product connectivity skills — MEDIUM PRIORITY

No dedicated skills exist for testing or configuring connections to:
- Defender XDR (Microsoft 365 Defender)
- Defender for Cloud
- Defender for Identity
- Defender for Endpoint
- Entra ID Protection

Kima owns this gap. At minimum a `skills/msft-security/connectivity-setup.md` covering API prerequisites, required permissions, and CLI verification commands per product.


# Decision: Multi-Tenant SecOps Skill Domain

**By:** Sydnor (Platform Dev)
**Date:** 2026-05-04T08:41:39-05:00
**Status:** Proposed

## What

Created `skills/platform/` as a new skill domain for infrastructure-level SecOps capabilities, starting with `multi-tenant-support.md` — a comprehensive guide for MSSP, enterprise, and ISV multi-tenant scenarios using Azure Lighthouse, `.secops/` schema extensions, and production PowerShell patterns.

## Key Design Choices

1. **New `platform` domain** — Multi-tenancy spans all security products; it doesn't fit in any existing domain (kql, soar, detection). Platform skills are the foundation layer consumed by all domain skills.

2. **`.secops/` schema extensions** — Added `tenant_id` scoping to workspace YAML and data-source-map entries, plus a new `tenant-context.yaml` for agent-managed active tenant tracking. These are additive extensions to schema v1.0 (no breaking changes).

3. **Token-per-tenant with caching** — Every API call acquires a tenant-specific token via `Get-TenantScopedToken` with in-memory cache. No implicit "current context" reliance — prevents cross-tenant data leakage.

4. **SLA-tier-aware routing** — Alert escalation paths vary per tenant based on `sla_tier` in the Lighthouse delegation config (premium = PagerDuty/15min, standard = Teams/60min). This is MSSP-critical.

5. **Isolation verification** — `Test-TenantIsolation` function confirms tokens for one tenant cannot access another tenant's subscriptions. Designed for periodic compliance checks.

## Impact

- **All agents:** Must check `org_type` in `environment.yaml` before assuming single-tenant
- **Freamon:** Cross-tenant KQL queries use `Invoke-CrossTenantQuery` pattern
- **Kima:** Detection rules must consider per-tenant data source mappings
- **Herc:** SOAR playbooks should use `Assert-TenantIsolation` before write operations
- **Sydnor:** CLI `env` commands should surface tenant context and switching

## Files Created

- `skills/platform/README.md` (68 lines)
- `skills/platform/multi-tenant-support.md` (558 lines)


# Decision: Cross-Skill Orchestration Skill Architecture

**By:** Sydnor (Platform Dev)
**Date:** 2026-05-04T07:53:46-05:00
**Status:** Proposed

## What

Created `skills/orchestration/` as a new skill domain that teaches agents how to compose multi-skill workflows. This is the glue layer between domain skills — it doesn't replace them, it orchestrates them.

## Key Design Choices

1. **Five reusable orchestration patterns** — Sequential Pipeline, Fan-Out/Fan-In, Conditional Branching, Loop/Iteration with circuit breaker, Checkpoint/Resume. Each is a standalone PowerShell function that can be composed.

2. **Structured result objects everywhere** — All pattern functions and workflow steps use `@{ ok = $true; data = ... }` return shape, consistent with `lib/graph-security/` and `error-handling.md`.

3. **Checkpoint state in `.secops/checkpoints/`** — Long-running workflows (like eDiscovery searches) save state to JSON files under `.secops/`, consistent with the framework's role as customer environment data store.

4. **Dead letter queue in `.secops/dead-letter/`** — Failed items persist for retry. New directory under `.secops/` — needs team review on whether this belongs there or in `.squad/`.

5. **Circuit breaker in entity loops** — Consecutive failure counting with automatic halt. Prevents cascading API abuse during fan-out operations.

## Impact

- **All agents:** Can now reference orchestration patterns when composing multi-step workflows
- **Coordinator:** Has decomposition table mapping workflow steps to responsible agents
- **Freamon:** KQL query building and execution steps in hunting/investigation workflows
- **Kima:** Sentinel, eDiscovery, Purview steps in investigation/compliance workflows
- **Herc:** SOAR and dashboard steps in reporting workflows

## Open Questions

1. Should `.secops/checkpoints/` and `.secops/dead-letter/` be `.gitignored`? They contain runtime state, not configuration.
2. Should orchestration patterns be extracted to `lib/orchestration/` as importable modules, or remain as skill-documented patterns?


# Decision: Microsoft Security Connectivity Setup Skill

**Date:** 2026-05-04T16:45:02.077-05:00
**By:** Kima (SecOps Engineer)
**Requested by:** John Spaid

## What Was Created

New skill file: `skills/msft-security/connectivity-setup.md`

A comprehensive connectivity setup guide covering all 6 Microsoft Security products targeted by the secops-squad framework. This skill fills a gap between "installed" and "ready to use" — users had no single, authoritative path to verify every product is wired up correctly.

## What It Covers

1. **Quick Connectivity Test** — single PowerShell block that runs all 6 checks in sequence and prints a color-coded summary. Functions as a "doctor command" for the security product stack.

2. **Per-product sections** (Microsoft Sentinel, Defender XDR, Defender for Cloud, Defender for Identity, Defender for Endpoint, Entra ID Protection), each containing:
   - Required Roles / App Registration Permissions table
   - Step-by-step setup instructions with Azure CLI commands
   - Verification commands (copy-paste ready)
   - Common Issues & Fixes table

3. **Troubleshooting Matrix** — 20 error messages mapped to root causes and actionable fixes.

4. **Authentication Summary table** — maps each product to its API target, auth method, and token resource scope. Helps agents determine which auth context is needed before calling any product.

## Key Design Decisions

- **Cross-references over duplication:** `defender-api-permissions.md` already covers the full permissions matrix in detail. This skill references it rather than duplicating content. Same pattern for `sentinel-workspace-setup.md`, `gov-cloud-support.md`, and each product's dedicated skill.
- **Frontmatter format:** Follows the exact pattern established in `sentinel-workspace-setup.md` and `defender-api-permissions.md` — YAML frontmatter with `title`, `category`, `difficulty`, `mitre_attack`, `products`, `author: Kima`, `version`, `last_updated`.
- **Environment Context section:** Follows the standard block used across all Kima skills — directs agents to `.secops/` before running tests.
- **MDE disambiguation:** MDE uses `WindowsDefenderATP` resource permissions (not Graph). This is the most common agent confusion point and is highlighted explicitly in the setup steps, troubleshooting table, and authentication summary.

## Impact

- **All personas:** New users now have a single skill to run immediately after `secops-squad install` to confirm connectivity across all products.
- **Agent operations:** Agents running connectivity checks can reference this skill's verification commands to self-diagnose before attempting product-specific operations.
- **Skill catalog:** Adds a new entry to `skills/msft-security/` that complements the existing product-specific skills by providing a unified entry point.

## Status

Ready for review. No existing skills were modified.


# Decision: CLI Readiness Fixes (8 issues)

**By:** Sydnor (Platform Dev)
**Date:** 2026-05-04T16:45:02.077-05:00
**Status:** Implemented

## Summary

Resolved all 8 readiness issues identified by McNulty's assessment. All changes are backward-compatible and non-breaking.

## Changes

### FIX 1 — CRITICAL: init.js post-init message (cli/commands/init.js)
Changed broken reference `secops-squad workspace connect` → `secops-squad env validate`. The `workspace connect` command did not exist; `env validate` is the correct implemented command.

### FIX 2 — CRITICAL: workspace.js implemented (cli/commands/workspace.js)
Created new command file with three subcommands:
- `connect` — prompts for workspace name, resource group, subscription; writes `.secops/workspaces/{name}.yaml`; updates `environment.yaml` default_workspace; verifies Azure login first
- `status` — reads `.secops/environment.yaml` and workspace YAML, shows connection details, optionally runs `az account show`
- `disconnect` — removes `default_workspace` from `environment.yaml`, preserves workspace file

Also added `module: "./commands/workspace.js"` to the workspace entry in `cli/index.js`.

### FIX 3 — HIGH: Agent name field (`.github/agents/secops-squad.agent.md`)
Changed frontmatter `name: SecOps Squad` → `name: secops-squad` to match filename stem for reliable `--agent secops-squad` flag matching.

### FIX 4 — HIGH: Deployed copilot-instructions.md (`.github/copilot-instructions.md`)
Copied `.squad/templates/copilot-instructions.md` → `.github/copilot-instructions.md`. This file provides squad-aware context to the Copilot coding agent when it autonomously picks up issues.

### FIX 5 — HIGH: doctor.js Azure + SecOps checks (cli/commands/doctor.js)
Added two new health checks:
- `checkAzureConnectivity()` — runs `az account show --output json`, shows subscription name/ID/tenant on success; warns "Azure not logged in. Run: az login" on failure
- `checkSecopsConfig()` — checks `.secops/environment.yaml` existence; warns if `organization.name === "Contoso Corp"` (template default); passes with org name if customized; warns if missing

Both inserted into the checks array immediately after `checkAzureCli()`. Added `js-yaml` require at top of file.

### FIX 6 — HIGH: Expanded .env.example
Expanded from 6 lines to full coverage of all 6 Microsoft Security products: MDE, Defender XDR, Defender for Cloud, Defender for Identity, Entra ID Protection, plus ADX. Each section has comments explaining app registration requirements and API permissions.

### FIX 7 — MEDIUM: mcp-config.json standardized (`.copilot/mcp-config.json`)
Renamed key `EXAMPLE-github` → `github`. Updated package from `@anthropic/github-mcp-server` → `@modelcontextprotocol/server-github` (standard MCP GitHub server package).

### FIX 8 — LOW: install.sh dead $? check (install.sh)
Replaced unreachable `if [ $? -ne 0 ]` block (dead code under `set -euo pipefail`) with proper `if ! git clone ...` pattern that works correctly whether or not `set -e` is active.

## Impact

- `secops-squad workspace connect/status/disconnect` now fully functional
- `secops-squad doctor` now shows Azure login status and SecOps config health
- Copilot coding agent picks up correct squad instructions from `.github/copilot-instructions.md`
- `--agent secops-squad` flag now reliably resolves to the agent file
- Install script is correct under `set -euo pipefail`
- No breaking changes to existing commands or schemas


# Decision: CLI Shim and PATH Auto-Setup

**Date:** 2026-05-08T16:08:28.643-05:00
**By:** Sydnor (Platform Dev)
**Status:** Implemented

## What

Added `secops-squad.cmd` batch wrapper in the project root and updated `install.ps1` to automatically add the install directory to the user's PATH (both session and persistent). Users can now run `secops-squad init` directly after installation instead of `node cli\index.js init`.

## Why

The previous post-install experience required users to either manually modify PATH or use the verbose `node cli\index.js` invocation. This created friction for new users and made the CLI feel unpolished.

## Impact

- **All agents:** Documentation and instructions can now reference `secops-squad <command>` instead of `node cli\index.js <command>`.
- **README / docs:** Any getting-started guides should use the short form.
- **install.sh (Linux/macOS):** Should get a similar treatment (symlink or shell wrapper) for parity.

## Files Changed

- `secops-squad.cmd` (new) -- batch wrapper forwarding to `node cli\index.js`
- `install.ps1` -- PATH setup + simplified post-install message

# Decision: ASCII-Only Policy for PowerShell Scripts

**Date:** 2026-05-08T15:50:14.020-05:00
**Author:** Sydnor (Platform Dev)
**Status:** Proposed

## Context

A user on PowerShell 5.1 hit a `ParseException` (`UnexpectedToken`) when running `install.ps1`. The root cause: PS5 reads UTF-8 files without a BOM as ANSI (Windows-1252). Emoji characters (✅, ❌, ⚠️) and Unicode box-drawing characters (┌─┐│└─┘) became garbled multi-byte sequences under ANSI interpretation, breaking string parsing.

## Decision

All PowerShell scripts in this repository (`.ps1`, `.psm1`, `.psd1`) must:

1. **Use only ASCII characters (U+0000–U+007F) in source code.** No emoji, no box-drawing, no em-dashes, no smart quotes. Use ASCII equivalents: `[OK]`, `[FAIL]`, `[WARN]`, `+---+`/`|` for boxes, `--` for dashes.
2. **Be saved with UTF-8 BOM encoding** (`EF BB BF` byte prefix). This tells PS5 to interpret the file as UTF-8 rather than ANSI.

Both measures together provide defense in depth — ASCII content survives any encoding interpretation, and the BOM provides correct decoding if Unicode is ever reintroduced accidentally.

## Consequences

- PowerShell scripts will look slightly less pretty in terminals that support Unicode, but they will work everywhere.
- Contributors adding Unicode characters to PS scripts will need to be corrected in review.
- A CI lint step could enforce this in the future (e.g., `grep -P '[^\x00-\x7F]'` on `.ps1` files).

# Decision: Update Command Uses Git Remote Merge Strategy

**Date:** 2026-05-08T15:06:07.002-05:00
**By:** Sydnor (Platform Dev)
**Status:** Implemented

## What

Added `secops-squad update` CLI command that pulls latest starter-kit changes via a git remote named `starter-kit`. Uses `git merge --allow-unrelated-histories` since installed projects have no shared git history with the template repo.

## Why

The install flow (install.ps1/install.sh) shallow-clones the starter-kit, deletes `.git`, and inits a fresh repo. Users had no way to get upstream improvements. A git-remote-based merge is the simplest approach that preserves local customizations while pulling new files.

## Impact

- **All agents:** The `starter-kit` remote may appear in `.git/config` after users run `update`. Don't treat it as the project's origin.
- **Sydnor:** Owns this command going forward. Any starter-kit structural changes (new top-level dirs, renamed files) should be tested against the merge path.
- **Kima/Freamon/Herc:** New skills or templates added to the starter-kit will flow to users via this command automatically.

### 2026-05-08T16:09:41.073-05:00: Workspace Connect — Azure Auto-Discovery

**By:** Sydnor (Platform Dev)

**Status:** Implemented

**What:** Rewrote `cli/commands/workspace.js` `connect()` to auto-discover Microsoft Sentinel workspaces from Azure instead of manually prompting for workspace name, resource group, and subscription ID.

**New flow:**
1. Verify `az` CLI installed, auto-run `az login` if not authenticated (uses `stdio: 'inherit'` for browser flow)
2. List enabled subscriptions, present numbered picker if multiple
3. Discover all Log Analytics workspaces via `az monitor log-analytics workspace list`
4. Check Sentinel on each workspace via `az rest` against `SecurityInsights({name})` solution endpoint
5. Present Sentinel-enabled workspaces (or all workspaces if none have Sentinel) as numbered list
6. Write `.secops/workspaces/<name>.yaml` with auto-populated fields matching schema v1.0
7. Update `.secops/environment.yaml` default_workspace

**Key design choices:**
- `execAz()` helper with configurable timeout (30s default, 120s for login), `inherit` stdio, and `allowFail` options — replaces single-purpose `execSafe()`
- Resource group parsed from ARM resource ID regex, not from a separate API call
- Sentinel detection via `Microsoft.OperationsManagement/solutions` REST API (simpler than querying alert rules)
- Graceful fallback: if no Sentinel workspaces found, show all LA workspaces with warning

**Impact:**
- All agents: `workspace connect` now produces richer YAML (includes `workspace_id`, `region`, `sentinel_enabled`, `tier`)
- Kima/Freamon: Can rely on `sentinel_enabled: true` in workspace config for conditional logic
- Users: Zero manual typing of GUIDs or resource group names
