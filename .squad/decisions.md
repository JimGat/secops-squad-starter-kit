# Squad Decisions

## Active Decisions

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

## Governance

- All meaningful changes require team consensus
- Document architectural decisions here
- Keep history focused on work, decisions focused on direction
