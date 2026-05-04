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

🔷 **Sydnor Phase 1 Contribution** (2026-04-28, ~180s)
- Scaffolded 24 directories and root-level project files
- Generated `package.json`, `README.md`, `CONTRIBUTING.md`, CLI structure
- Built GitHub Actions workflows for CI/CD and orchestration
- Created getting-started documentation and initial setup scripts
- Established project foundation for team collaboration

🔷 **CLI Init Wizard + Squad Doctor** (2026-04-28T12:01:11-05:00)
- Built `cli/commands/init.js` — interactive wizard with persona discovery, Azure CLI auto-detection, config generation, persona file installation. Supports `--no-interactive --persona <name>` for CI/scripted use. Uses readline (no deps). Detects existing config (idempotent). Validates against schema.
- Built `cli/commands/doctor.js` — 8-point environment health check: Node version, Git, config validation, team roster parsing, Azure CLI, GitHub CLI, skills.json cross-reference, KQL template syntax. ✅/⚠️/❌ output with actionable messages. Exit code 1 on failure.
- Updated `cli/index.js` — wired init and doctor to real modules, kept other stubs. Version now reads from package.json. Main function is async to support readline prompts. Errors caught with clean messages.
- Added `secops-squad.config.json` to `.gitignore` — it's user-generated per-machine config.
- Only `soc-analyst` persona has full files — other 5 are scaffolds. Init handles this gracefully with a warning.
- Zero external dependencies — readline, fs, path, child_process only. Cross-platform (path.join everywhere).

🔷 **Phase 3: Graph Security API Library** (2026-04-28T14:08:04-05:00)
- Built `lib/graph-security/` — zero-dependency Node.js library for Microsoft Graph Security API v1.0.
- **auth.js** — Three auth flows: client credentials, managed identity (App Service + IMDS), device code (interactive CLI). In-memory token cache with 5-min expiry buffer and `clearTokenCache()` for testing.
- **alerts.js** — `listAlerts`, `getAlert`, `updateAlert`, `listAlertsByEntity` (user/IP/host/fileHash). OData filtering, pagination via nextLink, constants for `SEVERITY` and `ALERT_STATUS`.
- **incidents.js** — `listIncidents`, `getIncident`, `updateIncident`, `addComment`, `getIncidentAlerts`. Constants for `INCIDENT_STATUS`, `INCIDENT_CLASSIFICATION`, `INCIDENT_DETERMINATION`.
- **threat-intelligence.js** — `listIndicators`, `createIndicator`, `deleteIndicator`, `bulkCreateIndicators` (rate-limited batch), `convertIOCToIndicator` (IOC format converter). Constants for `INDICATOR_TYPE`, `INDICATOR_ACTION`, `THREAT_TYPE`.
- **secure-score.js** — `getSecureScore`, `getSecureScoreHistory`, `getControlProfiles`, `getRecommendations` (sorted by impact, filters out already-implemented controls).
- **utils.js** — Shared HTTP layer: `graphGet/Post/Patch/Delete` with auto-retry on 429 (exponential backoff, 3 retries), structured error normalization for all HTTP status codes, OData value-array unwrapping, nextLink extraction.
- **index.js** — `createClient(config)` factory supporting 4 auth methods (clientCredentials, managedIdentity, deviceCode, pre-acquired token). Re-exports all modules and constants.
- **README.md** — Full docs: app registration setup, permission table, quick-start per module, error handling patterns, pagination recipes, rate limiting guidance, Sentinel/Logic App integration examples.
- Design: every function validates inputs, returns `{ok, data?, error?, status?}` result objects (never throws for API errors), full JSDoc on all exports.
- All native fetch, zero npm dependencies, Node 18+ required.

📌 **Graph Security library pattern established** — structured result objects `{ok, data?, error?, status?}` are the standard return shape for all API-wrapping libraries in this project. Matches the squad zero-dep convention.

🔷 **Phase 3 Round 2: CLI Commands + Plugin Architecture** (2026-04-28T14:27:56-05:00)
- Built 5 new CLI commands, all zero-dependency, following existing init/doctor patterns:
  - **`cli/commands/skill.js`** — `skill list` scans skills/ with YAML frontmatter parsing (title, category, difficulty, MITRE tags, products). Supports `--category` filter and `--json` output. `skill add <name>` copies from library to `.squad/skills/`.
  - **`cli/commands/persona.js`** — `persona list` shows all 6 personas with readiness status and current active indicator. `persona switch <name>` backs up current config, copies persona files, updates config, and shows skill diff (added/removed/kept).
  - **`cli/commands/kql-validate.js`** — `kql validate <file|glob>` integrates with `lib/kql-validator/`. Handles .kql files directly and extracts KQL blocks from .md files. Table and JSON output formats. Exit code 1 on any failure.
  - **`cli/commands/playbook.js`** — `playbook list` scans `templates/bicep/soar/`. `playbook deploy <name>` generates `az deployment group create` command, reads parameters from Bicep and config, supports `--dry-run`. Validates az CLI auth before live deploy.
  - **`cli/commands/plugin.js`** — `plugin install/list/remove` CLI surface for plugin system.
- Built **plugin architecture** in `lib/plugins/`:
  - **`index.js`** — Plugin loader: scans `.squad/plugins/`, validates `plugin.json` manifests (name, version, type, description, files), lists/loads plugins.
  - **`installer.js`** — Install from local path, git URL, or npm package. Auto-detects source type. Copies to `.squad/plugins/{name}/`, validates manifest schema.
  - **`registry.js`** — Tracks installed plugins in `.squad/plugins/registry.json` with version, source, install date. Supports list/get/register/unregister.
- Updated **`cli/index.js`** — registered all 5 new commands with module paths and updated help text.
- Created **install scripts**: `install.sh` (bash) and `install.ps1` (PowerShell) — prerequisite checks (Node 18+, git, gh, az), clone, npm install, PATH guidance.
- All files tested: skill list/add, persona list, kql validate with glob, playbook list/deploy --dry-run, plugin list. Zero external dependencies.

📌 **YAML frontmatter parsing** — skill .md files use `---` delimited YAML with arrays (mitre_attack, products). Parser handles inline comments on array items (e.g., `- T1078  # Valid Accounts`).

🔷 **Phase 1 Foundation: `.secops/` Customer Knowledge Framework** (2026-04-30T16:42:00-05:00)
- Built `.secops/` directory — 16 files across 6 subdirectories (workspaces, data-sources, identity, alerting, compliance + root).
- Schema v1.0: every YAML file has `schema_version: "1.0"`, extensive inline comments, Contoso Corp example values.
- **Key paths:** `.secops/environment.yaml` (primary descriptor), `.secops/data-sources/data-source-map.yaml` (table location map — most critical for agents), `.secops/discovery-log.yaml` (append-only agent discovery log).
- Design: all files standalone (missing = unknown, not error), unknown fields preserved (forward-compatible), YAML for comments + human-editability.
- Supports: multi-tenant, MSSP/Lighthouse, government cloud, cross-cloud (AWS/GCP), data tiering (Analytics/Basic/Auxiliary/Archive), active migrations, compliance constraints.
- Decision doc written to `.squad/decisions/inbox/sydnor-secops-schema-v1.md`.

📌 **`.secops/` separation from `.squad/`** — `.secops/` holds customer environment data (tenants, workspaces, data sources); `.squad/` holds framework internals (agents, routing, config). This is an architectural boundary — never mix them.

📌 **Discovery log pattern** — Agents append to `.secops/discovery-log.yaml` during normal operations. Humans review and promote confirmed facts to authoritative YAML files. Entries are never modified or deleted by agents.

🔷 **Sample Contoso Config: `samples/secops-contoso/`** (2026-04-30T16:42:21-05:00)
- Built 13 files (12 YAML + README.md) under `samples/secops-contoso/.secops/` — a complete, realistic demo of the framework.
- **Environment:** 2 tenants (prod + dev/test), 3 subscriptions, cross-cloud (AWS + GCP), Lighthouse commented-out.
- **Workspaces:** prod-sentinel (500GB commitment, 10 custom tables, 8 connectors), dev-sentinel (detection testing), soc-adx (long-term retention, external tables over blob).
- **Data sources:** 20+ tables across Analytics/Basic/Auxiliary/Archive tiers, cross-cloud identity mapping, migration flags.
- **Migrations:** 1 in-progress (ADX→Sentinel Auxiliary), 1 planned (workspace consolidation), 1 completed (MMA→AMA).
- **Identity:** Full tenant topology with B2B access, service principals, L1-L3 RBAC role bundles, PIM policies, 2 custom role definitions.
- **Alerting:** 7 routing rules (Teams, PagerDuty, ServiceNow), 4-tier escalation (L1→L2→L3→CISO), after-hours policy.
- **Compliance:** US data residency, NIST 800-53 + PCI-DSS + SOC 2, 9 per-table retention overrides.
- **Discovery log:** 6 realistic entries (table confirmations, tier limitations, permission errors, migration verification).
- All cross-references validated: subscription IDs, tenant IDs, workspace names, migration refs, ADX cluster names consistent across files.

📌 **Sample config cross-reference pattern** — When creating multi-file configs, subscription IDs, tenant IDs, workspace names, table names, and migration IDs must be consistent across all files. Validated via automated checks.

🔷 **CLI `.secops/` Integration** (2026-04-30T16:42:21-05:00)
- Built `cli/secops-config.js` — config loader module with `loadEnvironment()`, `loadWorkspace()`, `listWorkspaces()`, `loadDataSourceMap()`, `loadMigrations()`, `loadDiscoveryLog()`, `validateAll()`. Schema version validation. Uses `js-yaml` (first npm dependency).
- Built `cli/commands/env.js` — 4 subcommands: `env` (summary), `env validate` (schema check), `env workspaces` (workspace listing), `env data-sources` (data source map + migrations). Follows existing command pattern (`run(args)` export).
- Built `cli/secops-init.js` — scaffolds `.secops/` directory from scratch. Interactive mode prompts for org name, cloud type, region. Non-interactive with `--org`, `--cloud`, `--region` flags. Generates valid schema v1.0 YAML files. Skips if `.secops/environment.yaml` already exists (idempotent).
- Wired `init --secops` routing in `cli/index.js` — intercepts before normal init dispatch.
- Added `js-yaml` to `package.json` dependencies — needed for reliable YAML parsing of complex schema.

📌 **`js-yaml` is the project's first npm dependency** — added to parse `.secops/` YAML files which use nested objects, arrays, and comments that a simple regex parser can't handle reliably. All other modules remain zero-dependency.

🔷 **Agent Environment Context Integration** (2026-04-30T16:42:21-05:00)
- Created `.copilot/skills/secops-environment-context.md` — Copilot-level skill teaching all agents the 7-step `.secops/` discovery flow (environment → data sources → migrations → workspaces → compliance → execute → log discoveries).
- Covers: government cloud endpoint awareness, multi-tenant/MSSP/Lighthouse patterns, data residency enforcement, discovery-log.yaml append protocol with confidence levels.
- Added `## Environment Context` section to 11 domain skill files (kql/2, log-analytics/4, detection/2, soar/1, adx/1, msft-security/1) — consistent block referencing data-source-map, migrations, workspace config, and compliance before skill execution.
- Updated all 6 agent charters (McNulty, Kima, Freamon, Herc, Sydnor, Carver) — added `.secops/` context check as first item under "How I Work".
- Added self-serve routing rule to `.squad/routing.md` — agents read `.secops/` directly, no coordinator routing needed.

📌 **`.copilot/skills/` vs `.squad/skills/`** — `.copilot/skills/` holds Copilot-platform-level skills (consumed by GitHub Copilot skill system); `.squad/skills/` holds squad-internal conventions. The secops-environment-context skill is in `.copilot/skills/` because it needs to be discoverable by the Copilot skill resolution system, not just squad agents.

🔷 **Phase 1 Foundation Complete — Scribe Session** (2026-04-30T16:42:21-05:00)
- All Phase 1 foundation agents completed: sydnor-schema (18 files), sydnor-gitignore, sydnor-cli (8 files, 874 lines), sydnor-samples (13 files), sydnor-agent-ctx (20 files modified).
- Decision merging: 4 new decisions from inbox merged into decisions.md (Customer Knowledge Framework, Schema v1.0, Agent Context Integration, CLI Integration). No archival triggered (6981 bytes < 20KB).
- Orchestration log written: `2026-04-30T16-42-phase1-complete.md` with full manifest and status.
- Session log written: `2026-04-30T16-42-phase1-foundation.md` (brief summary).
- Sydnor history updated with Phase 1 completion marker.
- Git commit pending: `.squad/` files only (decisions.md, logs, orchestration-log, agent histories).
- Phase 2 ready: Skills development, persona templates, CLI expansion.

🔷 **Cross-Skill Orchestration Skill** (2026-05-04T07:53:46-05:00)
- Created `skills/orchestration/` domain — teaches agents how to compose multi-skill workflows across Sentinel, eDiscovery, Purview, Defender, and other tools.
- **`skills/orchestration/README.md`** (52 lines) — Domain overview, dependency map, usage guide.
- **`skills/orchestration/cross-skill-orchestration.md`** (522 lines) — Full orchestration skill with:
  - 5 orchestration patterns: Sequential Pipeline, Fan-Out/Fan-In, Conditional Branching, Loop/Iteration, Checkpoint/Resume — each with production PowerShell.
  - 5 pre-built workflow templates: Incident Investigation, Compliance Export, Threat Hunting Campaign, Data Tiering Migration, Shadow IT Assessment — all fully executable.
  - Error handling: circuit breaker (in loop pattern), retry with exponential backoff, dead letter queue, partial failure handling.
  - `.secops/` integration: reads data-source-map, environment, routing, compliance; writes to discovery-log.
  - Agent orchestration patterns: decomposition table, handoff protocol, result aggregation.
- Cross-references 20+ existing skill files across all 7 domains (powershell, kql, detection, msft-security, soar, log-analytics, adx).
- Follows established conventions: YAML frontmatter, `@{ ok = $true; data = ... }` result objects, `.secops/` context checks.

🔷 **Multi-Tenant SecOps Skill** (2026-05-04T08:41:39-05:00)
- Created `skills/platform/` domain — new skill domain for infrastructure-level SecOps capabilities.
- **`skills/platform/README.md`** (68 lines) — Domain overview, skill inventory, dependency map, `.secops/` integration guide.
- **`skills/platform/multi-tenant-support.md`** (558 lines) — Comprehensive multi-tenant skill covering:
  - Azure Lighthouse: onboarding (ARM + PowerShell), RBAC scoping, cross-workspace incident management
  - `.secops/` multi-tenant schema: extended `environment.yaml` with tenant array, per-tenant workspace mappings, tenant-scoped data sources, tenant context file, cross-tenant discovery log entries
  - API wrapper patterns: `Get-TenantScopedToken` (cached), `Invoke-TenantScopedApi`, `Invoke-CrossTenantQuery` (union across workspaces), `Assert-TenantIsolation`
  - Cross-tenant workflows: MSSP incident dashboard, unified threat hunting with cross-tenant correlation, compliance posture rollup, SLA-tier-aware alert routing
  - PowerShell patterns: `Switch-SecOpsTenant`, `Invoke-ParallelTenantOperation` (throttled + retry), token cache management
  - Security: least privilege table, audit logging, data residency enforcement, isolation verification
- All PowerShell follows `@{ ok = $true; data = ... }` result object convention.
- MSSP-friendly: supports 10–100+ customer tenants with SLA-tier-aware escalation paths.

📌 **`skills/platform/` domain established** — infrastructure-level skills that span security products (multi-tenancy, API patterns, environment management). Consumed by all other skill domains.
