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
