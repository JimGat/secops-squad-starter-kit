# History

<!-- Populated automatically during squad sessions. -->

## Learnings

📌 **Framework Architecture Complete** — Skills-first architecture (domain-sorted .md files), persona-driven onboarding, CLI with plugin system, init wizard, environment context framework (.secops/).

📌 **CLI Built** — `secops-squad` wraps @bradygaster/squad-cli. Commands: init (wizard), doctor (health check), skill (list/add), persona (list/switch), kql-validate, playbook (deploy), plugin (install/list/remove), env (validate/.secops/ tooling). Zero external deps except js-yaml for YAML parsing.

📌 **`.secops/` Framework** — Customer knowledge layer (tenants, workspaces, data sources, compliance, routing). 16 files, 6 subdirectories, schema v1.0 with examples. Separate from `.squad/` (framework internals). All agents read `.secops/` for environment context before operations.

📌 **Orchestration Skills Established** — `skills/orchestration/` and `skills/platform/` domains cover multi-skill workflows, multi-tenant support, API orchestration patterns, and MSSP scenarios.

📌 **Sample Config** — Contoso Corp demo under `samples/secops-contoso/.secops/` — 13 files, 2 tenants, cross-cloud, full compliance + discovery log.

📌 **Agent Integration** — `.copilot/skills/secops-environment-context.md` teaches all agents the 7-step discovery flow. All 6 agent charters updated with environment context requirement.


🔷 **CLI Readiness Fixes — 8 issues resolved** (2026-05-04T16:45:02.077-05:00)
- **FIX 1:** `cli/commands/init.js` — corrected post-init message from broken `secops-squad workspace connect` to `secops-squad env validate`.
- **FIX 2:** Created `cli/commands/workspace.js` — full `connect` / `status` / `disconnect` implementation. `connect` prompts for workspace name, resource group, subscription; writes `.secops/workspaces/{name}.yaml` and updates `environment.yaml` default_workspace. `status` reads config and optionally verifies `az account show`. `disconnect` clears default_workspace while preserving the workspace file. Wired into `cli/index.js` with `module:` field.
- **FIX 3:** `.github/agents/secops-squad.agent.md` frontmatter — changed `name: SecOps Squad` to `name: secops-squad` to match filename stem for `--agent` flag matching.
- **FIX 4:** Created `.github/copilot-instructions.md` from template — provides Copilot coding agent instructions for picking up squad issues.
- **FIX 5:** `cli/commands/doctor.js` — added `checkAzureConnectivity()` (runs `az account show`, shows subscription/tenant details, warns if not logged in) and `checkSecopsConfig()` (checks `.secops/environment.yaml`, warns if using "Contoso Corp" defaults or missing). Added `js-yaml` import. Both inserted after `checkAzureCli()`.
- **FIX 6:** `.env.example` — expanded to cover all 6 Microsoft Security products with per-section comments.
- **FIX 7:** `.copilot/mcp-config.json` — renamed key `EXAMPLE-github` to `github`, updated package to `@modelcontextprotocol/server-github`.
- **FIX 8:** `install.sh` — replaced dead `True` check (unreachable under `set -euo pipefail`) with proper `if ! git clone ...` pattern.

📌 **js-yaml must be required at top of doctor.js** — doctor.js now uses yaml.load() in checkSecopsConfig(). The import must remain.

📌 **workspace.js pattern** — connect is async (readline prompts); status and disconnect are sync. run() export is async. All three interact with .secops/workspaces/*.yaml and .secops/environment.yaml via js-yaml.

🔷 **README.md Rewrite — Squad Structure Pattern** (2026-05-04T17:12:14.241-05:00)
- Rewrote README.md to follow the bradygaster/squad README structural pattern: alpha warning → "What is X?" value prop → Quick Start with ✓ Validate steps → All Commands table → Personas → Parallel execution → Skills → .secops/ framework → Products → API Wrappers → What Gets Created (directory tree) → Samples → FAQ → Troubleshooting → Documentation (split into 3 tables: Guides, Reference, Developer) → Built On → Status
- Updated skill counts to match SKILLS_CATALOG.md (Detection: 9, Microsoft Security: 16 — corrected from 10/18 in old README)
- Removed emoji from section headers for cleaner markdown rendering (matching Squad pattern)
- Added "Agents Work in Parallel" section showing SecOps-specific parallel execution example (BEC detection scenario)
- Verified all 20 local file links resolve to existing files
- Badge updated: removed "Phase 3" (too internal), added "status: alpha" (matching Squad), kept skills-96 and Node.js badges
- README expanded from 210 to 302 lines — no content dropped, structure improved