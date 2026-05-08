# Squad Decisions Archive

## Archived Decisions (older than 7 days)

### 2026-04-28T09:16:43-05:00: Team composition and role assignments

**By:** Sydnor (on behalf of the squad)

**What:** The secops-squad team is composed of 8 members from The Wire universe, each with distinct SecOps responsibilities:
- **McNulty** (Lead) — architecture, scope, code review
- **Kima** (SecOps Engineer) — Microsoft Security products, threat hunting, detection engineering
- **Freamon** (KQL Engineer) — KQL queries, Log Analytics, Azure Data Explorer
- **Herc** (Automation/SOAR) — Logic Apps, Azure Functions, SOAR workflows
- **Sydnor** (Platform Dev) — templates, CLI, framework, CI/CD
- **Carver** (Tester/QA) — validation, testing, quality gates
- **Scribe** (Session Logger) — logging, decisions, memory management
- **Ralph** (Work Monitor) — work tracking, circuit breaking

**Why:** Clear role separation ensures each domain has a dedicated specialist. SecOps work spans detection engineering, query authoring, automation, and platform tooling — each requires distinct expertise. Reviewer authority is shared between McNulty (architecture) and Carver (quality).

### 2026-04-28T09:16:43-05:00: secops-squad Framework Architecture

**By:** McNulty (Lead)

**Decision:** The core product is a skills-first architecture modeled after bradygaster/squad, specialized for Microsoft Security products, KQL engineering, Logic Apps automation, Log Analytics workspace management, and Azure Data Explorer integration.

**Key Architectural Choices:**
1. **Skills-First Architecture** — Markdown skill files categorized by domain (`skills/kql/`, `skills/soar/`, `skills/detection/`, `skills/log-analytics/`, `skills/adx/`, `skills/msft-security/`)
2. **Persona-Driven Onboarding** — Pre-built team configurations installable via `secops-squad init` (initial set: `soc-analyst`, `detection-engineering`, `threat-hunting`, `cloud-security`, `incident-response`, `full-soc`)
3. **KQL Files Are CI-Validated** — Every `.kql` file syntax-validated on PR. Carver owns the quality gate.
4. **Every SOAR Skill Requires a Rollback Plan** — No Logic Apps playbook ships without `destroy.ps1` and documented undo procedure
5. **CLI Extends Squad** — `secops-squad` CLI wraps `@bradygaster/squad-cli`; security-specific commands are additive
6. **Azure Discovery Is Non-Blocking** — Init completes with placeholder config if discovery fails; users can connect later
7. **Threat Model Required for Every Detection** — `detection-engineering` persona enforces threat-model-session ceremony; McNulty gates review
8. **MITRE ATT&CK Tagging Mandatory** — Every detection/KQL skill maps to ATT&CK technique IDs (machine-readable YAML frontmatter)

**Owners of Key Areas:**
- KQL skills + ADX skills: Freamon
- SOAR skills + Bicep templates: Herc
- Detection skills + Microsoft Security skills: Kima
- Log Analytics skills: Freamon + Kima
- CLI + install script: Sydnor
- KQL validation harness + testing: Carver
- Architecture + persona design: McNulty
- Session logging + decisions: Scribe

**Phase 1 Exit Criteria:** Working init wizard, `soc-analyst` persona, 3 KQL skills, 3 SOAR skills, KQL validation CI, getting-started docs. Target: New user → working SecOps team with KQL hunting and phishing response in ≤ 15 minutes.

### 2026-04-28T12:01:11-05:00: KQL Validator Library Design

**By:** Freamon (KQL Engineer)

**Status:** Implemented

**What:** Built `lib/kql-validator/` — offline KQL syntax validation with 4 modules (index, parser, reporter, operators). ~60 operators, 250+ functions, ~50 Sentinel/Defender tables. 56/57 tests passing.

**Key Choices:**
- Offline-only (no Azure workspace connectivity)
- Error vs Warning distinction (= in where clause is error; project * is warning)
- Where-clause scoping prevents false positives on join patterns
- Markdown extraction supports both ````kql` and ````kusto` blocks
- CommonJS modules, zero dependencies

**Why:** CI pipeline requires KQL validation on every PR. CLI command `secops-squad kql validate` needs a library to call.

### 2026-04-28T14:08:04-05:00: ADX Table Schemas Use Staging + Update Policy Pattern

**By:** Herc (Automation/SOAR)

**What:** All ADX security tables use two-table ingestion: `*_Raw` staging table receives raw JSON, update policy transforms to structured target table.

**Impact:**
- Freamon: ADX skills and queries target structured tables (SecurityEvents, NetworkTraffic, etc.), not `*_Raw`
- Kima: Detection rules via `adx()` proxy use structured table names
- All: Adding new columns requires updating KQL scripts in `templates/bicep/adx/scripts/`

**Why:** Allows schema evolution without breaking ingestion pipelines. New columns can be added to transform query without re-creating data connections.

### 2026-04-28T12:34:12-05:00: Persona Template Architecture and Character Assignments

**By:** McNulty (Lead)

**Status:** Active

**What:** All 6 personas are self-contained, installable team configurations with no cross-persona dependencies. Each uses unique Wire characters with thematic alignment:
- soc-analyst: Bunk, Kima, Freamon, Daniels
- detection-engineering: Daniels, Lester, Prop Joe, Landsman
- threat-hunting: Omar, Slim Charles, Bubbles, Rhonda
- cloud-security: Avon, Stringer, D'Angelo
- incident-response: Rawls, Sydnor, Beadie, Prez
- full-soc: Bunny Colvin, Bodie, Poot, Carver, Herc, Cutty, McNulty, Lester

**Key Choices:**
1. Self-contained — each installs complete working team with no external dependencies
2. Consistent format — all follow 5-file structure from soc-analyst
3. Skill references forward-compatible — reference Phase 2 skills to be created
4. Full-SOC is additive — shows integration, not concatenation
5. Ceremonies domain-specific

**Why:** Users pick any persona and get working team immediately.

### 2026-04-28T14:08:04-05:00: Structured Result Objects for API Libraries

**By:** Sydnor (Platform Dev)

**Status:** Proposed

**What:** All API-wrapping libraries return structured result objects instead of throwing exceptions:
```javascript
// Success: { ok: true, data: ..., nextLink?: string }
// Failure: { ok: false, error: string, status?: number, code?: string }
```

**Why:** SOC automation runs unattended in Logic Apps and Functions. Thrown exceptions cause silent failures. Structured results force explicit error handling, make context available, compose cleanly in async pipelines.

**Scope:**
- Applies to all `lib/*/` API wrapper modules
- Does NOT apply to CLI commands (use `fatal()`)
- `createClient()` may throw for invalid config (programmer error)

**Established in:** `lib/graph-security/` (Carver's test suite validates pattern)

# Decision: Advanced Hunting API & KQL Query Builder Skills

**Date:** 2026-04-30T17:40:42-05:00
**By:** Freamon (KQL Engineer)
**Status:** Implemented
**Requested by:** Jose

## What

Created two new skill documents:

1. **`skills/detection/advanced-hunting-api.md`** (336 lines) ΓÇö Comprehensive API reference for MDE, XDR, and Graph Advanced Hunting endpoints, including Live Response session management, custom detection rule creation, query packs, and MITRE ATT&CKΓÇômapped hunting patterns (Initial Access through Exfiltration).

2. **`skills/kql/query-builder.md`** (408 lines) ΓÇö KQL template engine with `{{parameter}}` substitution, conditional/iteration blocks, pre-built SecOps templates, 4-tier validation (syntax via `lib/kql-validator/`, schema via `data-source-map.yaml`, performance pattern detection, injection prevention), optimization guidance (filter-first, materialize, partition, string operator hierarchy), and cross-platform differences.

## Key Design Choices

1. **API skill in `detection/`, not `kql/`** ΓÇö The API endpoints, Live Response, and custom detections are detection infrastructure, not query authoring. KQL patterns stay in `kql/`.
2. **Template syntax uses `{{...}}`** ΓÇö Lightweight, Handlebars-inspired syntax that doesn't conflict with KQL's `{ }` braces.
3. **4-tier validation** ΓÇö Syntax ΓåÆ Schema ΓåÆ Performance ΓåÆ Security, from cheapest to most expensive check.
4. **Cross-references, not duplication** ΓÇö Both skills link to `defender-xdr-hunting.md`, `defender-api-wrapper.md`, `threat-hunting-foundations.md` for existing coverage.
5. **GCC-High awareness** ΓÇö PowerShell wrappers check `environment.yaml` cloud field and swap endpoints for government clouds.

## Impact

- **Kima:** Can reference `advanced-hunting-api.md` for custom detection rule API patterns
- **Herc:** Live Response forensic collection patterns complement SOAR playbook triggers
- **Carver:** `Test-SecOpsKqlPerformance` rules can feed into CI validation pipeline
- **All agents:** `Get-SecOpsQueryTarget` auto-routes queries to correct API surface based on `.secops/` data-source-map

# Decision: Compliance & Workbook Automation Skill Architecture

**Date:** 2026-04-30T17:40:42-05:00
**By:** Herc (Automation/SOAR)
**Status:** Implemented

## What

Created two new SOAR skills establishing compliance automation and workbook lifecycle management:

1. **`skills/soar/compliance-framework-mappings.md`** ΓÇö Maps Microsoft controls (Defender for Cloud, Secure Score, Sentinel analytics, Purview DLP) to 6 regulatory frameworks (NIST 800-53 R5, CIS v8, PCI-DSS v4, HIPAA, SOC 2, ISO 27001:2022). Includes automated assessment pipelines, gap analysis, and evidence collection.

2. **`skills/soar/workbook-automation.md`** ΓÇö Programmatic workbook CRUD via Azure REST API, ARM/Bicep deployment templates, CI/CD pipeline patterns, multi-workspace deployment from `.secops/` config.

## Key Choices

1. **Defender for Cloud as compliance source of truth** ΓÇö All frameworks map to `Get-AzSecurityRegulatoryComplianceStandard` API. This is the only Microsoft API that natively provides framework-to-control mappings.

2. **`.secops/compliance/requirements.yaml` drives assessment scope** ΓÇö Only frameworks listed in `.secops/` get assessed. No hardcoded framework lists.

3. **Structured result pattern for workbook CRUD** ΓÇö All `New-`/`Get-`/`Update-`/`Remove-SentinelWorkbook` functions return `@{ ok = $true/false; data/error }` per Sydnor's decision.

4. **CI/CD via GitHub Actions** ΓÇö Workbook JSON stored in repo, deployed on merge via `azure/powershell@v2`. Idempotent PUT operations.

5. **Multi-workspace deployment reads `.secops/workspaces/`** ΓÇö Workbooks deploy to all configured workspaces with data residency checks against `prohibited_regions`.

## Impact

- **Kima:** Detection rules can reference compliance control IDs from the mapping tables
- **Freamon:** KQL queries in workbook items follow same syntax as standalone hunting queries
- **Carver:** Can validate workbook JSON structure and compliance report outputs
- **Sydnor:** CI/CD pipeline pattern can be added to `secops-squad` CLI as `secops-squad workbook deploy`

## Why

SOC teams need compliance dashboards and audit evidence on demand, not after weeks of manual work. These skills make compliance posture visible in real-time and workbook deployment a one-command operation.

# Decision: Copilot for Security + Defender for Cloud Apps Skill Architecture

**Date:** 2026-04-30T17:40:42-05:00
**Author:** Kima (SecOps Engineer)
**Requested by:** Jose
**Status:** Proposed

## What

Created two new skills in `skills/msft-security/`:

1. **`copilot-for-security.md`** ΓÇö Copilot for Security integration covering SCU capacity, plugins, custom plugins, promptbooks, REST API, and agent integration patterns
2. **`defender-cloud-apps.md`** ΓÇö MDCA CASB coverage including Cloud Discovery, OAuth app governance, 6 policy types, full REST API reference, Conditional Access App Control, and SIEM integration

## Key Design Decisions

### 1. Copilot API Session Reuse Pattern
Sessions preserve conversation context. Agents should create one session per investigation and reuse it across multiple prompts rather than creating new sessions per prompt. This saves SCU consumption and improves response quality through accumulated context.

### 2. MDCA API Token Authentication (Not OAuth)
MDCA's REST API uses portal-generated API tokens (`Authorization: Token <value>`), not OAuth2 flows. This is a different auth pattern from all other Defender APIs. Agents must handle this distinction when building multi-product workflows.

### 3. Structured Result Pattern Applied
Both skills' PowerShell wrappers (`Invoke-CopilotWithRetry`, `Invoke-MdcaApiWithRetry`) follow Sydnor's structured result pattern (`{ok: true/false, data/error}`), consistent with all other API-wrapping code in the project.

### 4. New MITRE Techniques Added to Coverage
These skills introduce 5 MITRE techniques not previously covered: T1071 (Application Layer Protocol), T1199 (Trusted Relationship), T1537 (Transfer Data to Cloud Account), T1550 (Use Alternate Authentication Material), T1567 (Exfiltration Over Web Service). The MITRE coverage map should be updated.

## Impact

- **Freamon:** Can reference MDCA tables (`McasShadowItReporting`, `CloudAppEvents`) in KQL skills
- **Herc:** SOAR playbooks can call Copilot API for incident enrichment and MDCA API for governance actions
- **Carver:** Should validate MITRE coverage map update with new techniques
- **All agents:** Can use Copilot for Security as enrichment layer in investigation workflows

## Why

These two products were identified in the platform coverage gap analysis as critical gaps: Copilot for Security is the AI augmentation layer for all SOC operations, and MDCA covers the CASB/Shadow IT domain that no existing skill addresses.

# Decision: eDiscovery & Purview API Wrapper Skills

**Date:** 2026-04-30T17:40:42-05:00
**Author:** Kima (SecOps Engineer)
**Requested by:** Jose
**Status:** Implemented

## What

Created two new comprehensive skill documents in `skills/msft-security/`:

1. **`ediscovery-api-wrapper.md`** ΓÇö Full eDiscovery API integration covering Graph `/security/cases/ediscoveryCases` hierarchy, case CRUD, custodian management, legal hold, KQL-based content search, review sets, export operations, and production PowerShell wrappers.

2. **`purview-api-wrapper.md`** ΓÇö Purview API surface covering information protection (sensitivity labels), DLP alerts/policies, data classification (SITs, EDM, trainable classifiers), records management, insider risk alerts, Unified Audit Log (3 access methods), Compliance Manager, and production PowerShell wrappers.

## Key Design Decisions

1. **Scope separation from purview-dlp-patterns.md** ΓÇö The existing skill covers DLP policy *design* (taxonomy, endpoint config, SIT patterns). The new purview-api-wrapper covers programmatic *API access* for agent automation. No content duplication.

2. **Structured result pattern** ΓÇö All wrapper functions return `{ok, data}` / `{ok: false, error}` per Sydnor's decision on structured result objects.

3. **Multi-API auth awareness** ΓÇö Documented that Purview's API surface is fragmented across Graph, IPPSSession, EXO, and Management API. Agents must manage multiple authentication contexts.

4. **`.secops/` integration** ΓÇö Both skills reference `compliance/requirements.yaml` for retention constraints and `identity/tenants.yaml` for multi-tenant topology.

## Why

- No programmatic eDiscovery coverage existed in the skills library
- Existing Purview skill (purview-dlp-patterns.md) was design-only, no API wrappers
- Incident response workflows (phishing, insider threat, compliance) require eDiscovery automation
- Data governance lifecycle (classify ΓåÆ label ΓåÆ protect ΓåÆ audit) needs API-driven agent support

## Impact

- **Freamon:** Can reference audit log query patterns when building KQL for compliance-related detection rules
- **Herc:** SOAR playbooks can call eDiscovery wrapper functions for automated evidence collection
- **All agents:** Purview API wrapper provides compliance posture monitoring for weekly agent-driven checks

