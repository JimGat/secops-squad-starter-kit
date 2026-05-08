# History

<!-- Populated automatically during squad sessions. -->

## Learnings

[CMD] **Workspace Connect Auto-Discovery** (2026-05-08T16:09:41.073-05:00)
- Rewrote `cli/commands/workspace.js` `connect()` from manual prompts to Azure auto-discovery flow.
- New flow: check az CLI → auto-login → pick subscription → discover Log Analytics workspaces → check Sentinel via SecurityInsights solution REST call → user picks → write `.secops/workspaces/<name>.yaml` + update `environment.yaml`.
- Sentinel detection: `az rest --method get` against `Microsoft.OperationsManagement/solutions/SecurityInsights({workspaceName})` — 200 = enabled, error = not.
- `execAz()` helper replaces `execSafe()` with configurable timeout (30s default, 120s for login), `inherit` stdio for interactive `az login`, and `allowFail` for non-fatal checks.
- Workspace YAML now uses `subscription` (not `subscription_id`) and `workspace_id` (customerId GUID) to match example-workspace.yaml schema.
- Resource group extracted from workspace ARM resource ID via regex on `/resourceGroups/([^/]+)/`.
- If no Sentinel workspaces found, falls back to showing all LA workspaces with a warning.
- `status()` and `disconnect()` functions unchanged.

[CMD]**CLI Shim + PATH Auto-Setup** (2026-05-08T16:08:28.643-05:00)
- Created `secops-squad.cmd` in project root: `@echo off / node "%~dp0cli\index.js" %*`. Standard Windows batch wrapper pattern.
- `install.ps1` now adds `$InstallDir` to both session PATH (`$env:Path`) and persistent user PATH (`[Environment]::SetEnvironmentVariable`). Both are idempotent (checks `-notlike "*$InstallDir*"` before adding).
- Post-install message simplified: tells users to run `secops-squad init` directly, mentions restarting other terminals for PATH propagation.
- All strings are ASCII-only, no em-dashes or emoji in comments. Validated with PS5.1 parser.

🔷 **PS5 Encoding Fix** (2026-05-08T15:50:14.020-05:00)
- PowerShell 5.1 reads UTF-8 files without a BOM as ANSI (Windows-1252). Multi-byte Unicode characters (emoji, box-drawing) become garbled, breaking string parsing and causing cascading `UnexpectedToken` errors.
- Fix: replaced all non-ASCII characters in `install.ps1` with ASCII equivalents (`[OK]`, `[FAIL]`, `[WARN]`, `+---+`/`|` box) and re-saved with UTF-8 BOM (`EF BB BF`).
- Both fixes applied together for maximum robustness: ASCII content survives any encoding interpretation, and the BOM ensures PS5 reads UTF-8 correctly if Unicode is ever reintroduced.
- Verified with `[System.Management.Automation.Language.Parser]::ParseFile()` — zero parse errors.

🔷 **Update Command** (2026-05-08T15:06:07.002-05:00)
- Created `cli/commands/update.js` — adds `starter-kit` git remote, fetches, and merges `starter-kit/main` with `--allow-unrelated-histories`.
- Registered in `cli/index.js` as the `update` command with module path `./commands/update.js`.
- Pre-flight checks: verifies git repo, refuses to run with uncommitted changes, handles existing remote gracefully.
- Merge conflict path: exits with instructions for manual resolution instead of crashing.
- README.md updated: new "Updating" section after Quick Start, and row added to All Commands table.
- Pattern: sync command using `child_process.execSync`, same ANSI color helpers as other commands, `run()` export.

🔷 **Starter-Kit Clone Guard** (2026-05-08T11:39:37.415-05:00)
- Added `[!WARNING]` callout in README.md Quick Start section (before "### 2. Install") telling users not to clone the repo directly.
- Added `isStarterKitRepo()` detection in `cli/commands/init.js` — checks `.git/config` for "secops-squad-starter-kit" remote URL and `package.json` for `@secops-squad/secops-squad-starter-kit` name.
- Warning prints after `printBanner()` but does NOT block execution — informational only.
- Install URLs point to `x3nc0n/secops-squad-starter-kit` repo (the GitHub remote name, not the local folder).

📌 **Framework Architecture Complete**— Skills-first architecture (domain-sorted .md files), persona-driven onboarding, CLI with plugin system, init wizard, environment context framework (.secops/).

📌 **CLI Built** — `secops-squad` wraps @bradygaster/squad-cli. Commands: init (wizard), doctor (health check), skill (list/add), persona (list/switch), kql-validate, playbook (deploy), plugin (install/list/remove), env (validate/.secops/ tooling). Zero external deps except js-yaml for YAML parsing.

📌 **`.secops/` Framework** — Customer knowledge layer (tenants, workspaces, data sources, compliance, routing). 16 files, 6 subdirectories, schema v1.0 with examples. Separate from `.squad/` (framework internals). All agents read `.secops/` for environment context before operations.

📌 **Orchestration Skills Established** — `skills/orchestration/` and `skills/platform/` domains cover multi-skill workflows, multi-tenant support, API orchestration patterns, and MSSP scenarios.

📌 **Sample Config** — Contoso Corp demo under `samples/secops-contoso/.secops/` — 13 files, 2 tenants, cross-cloud, full compliance + discovery log.

📌 **Agent Integration** — `.copilot/skills/secops-environment-context.md` teaches all agents the 7-step discovery flow. All 6 agent charters updated with environment context requirement.


🔷 **Install Directory Rename** (2026-05-07T12:45:11.843-05:00)
- Default install directory changed from `~/secops-squad-starter-kit` to `~/secops-squad` in both install.ps1 and install.sh.
- Banner text, status messages, and git init commit message updated to drop "-starter-kit" suffix.
- README.md and docs/getting-started.md updated for new install path.
- GitHub repo URL (`x3nc0n/secops-squad-starter-kit`) intentionally preserved — only the local folder name changed.
- `SECOPS_SQUAD_DIR` env var override in install.sh still works as before.

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