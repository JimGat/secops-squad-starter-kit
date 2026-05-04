# History

<!-- Populated automatically during squad sessions. -->

## Learnings

<!-- Append new learnings below. Each entry is something lasting about the project. -->

### 2026-04-30: Platform Coverage Gap Analysis

- **52 skills across 6 domains** is the current inventory. Good breadth but significant depth gaps.
- **Biggest blind spot: PowerShell modules.** Zero dedicated PS skills despite SOC engineers being PS-first. `Az.SecurityInsights` and `Az.OperationalInsights` are the most critical gaps.
- **Sentinel MCP integration is the game-changer.** Without it, agents write KQL but can't execute it. Azure MCP Server exists; we need a skill for configuring and using it.
- **Unified Data Platform (Basic/Auxiliary/Summary Rules)** is where Microsoft is pushing Sentinel. Our data tiering coverage is fragmented across cost-optimization and retention-archive. Needs a dedicated skill.
- **16 critical gaps, 25 important, 15 nice-to-have** identified across 12 Microsoft platform areas.
- **4 new skill domains proposed:** `powershell/`, `mcp/`, `azure-monitor/`, `entra-id/` — all critical.
- **Customer Knowledge Framework:** Proposed `.secops/` directory structure with YAML files for environment-specific knowledge (workspaces, data sources, migrations, routing, compliance). YAML chosen over JSON/markdown for human-editability + machine-parseability.
- **Key design decision:** `.secops/` is gitignored by default (environment-specific data) and separate from `.squad/` (framework internals). Agents consult `.secops/data-sources/data-source-map.yaml` before writing queries.
- **Auto-discovery pattern:** Agents append to `.secops/discovery-log.yaml` when they find environment facts. Human review required before promoting to data-source-map.
- **Scenarios customers neglect:** Multi-tenant MSSP, Lighthouse delegation limitations, government cloud feature gaps, cross-cloud identity mapping, retention-aware queries, data residency constraints.
- **Key file:** `docs/platform-coverage-gap-analysis.md` — full analysis document.

### 2026-05-04: End-to-End Workflow Readiness Assessment

**Workflow 1 — Install Script → Personal Repo**
- Both `install.ps1` and `install.sh` correctly implement clone-strip-.git-reinit. The approach is sound; the result is a personal unlinked repo.
- `node_modules` exists. Single dependency (`js-yaml`) is in `dependencies`, not devDependencies — `--production` install works correctly.
- **Critical gap:** `init.js` line 413 tells users to run `secops-squad workspace connect` post-init, but `workspace` has no `module:` in `index.js` (lines 38–41). It falls through to the "not yet implemented" stub. This is a broken user-facing promise.
- `secops-squad.config.json` is NOT created by the install scripts — only by `init`. Running `doctor` before `init` fails by design. This is documented but not automated.
- `install.sh` has a dead-code `$?` check at line 110 — `set -euo pipefail` at the top of the file would have already exited if `git clone` failed. Non-blocking but a code smell.

**Workflow 2 — `copilot --agent secops-squad` Grounding**
- `.github/agents/secops-squad.agent.md` exists and is substantial (83.7KB).
- **Name field discrepancy:** frontmatter `name: SecOps Squad` (space) vs. filename `secops-squad.agent.md` (hyphen). If CLI matches on `name:` field, `--agent secops-squad` will silently fail. Needs verification and likely alignment to `name: secops-squad`.
- **No `.github/copilot-instructions.md`** deployed. Only `.squad/templates/copilot-instructions.md` exists (template only). Active workspace-level Copilot instructions are missing.
- `.copilot/mcp-config.json` contains only an EXAMPLE GitHub MCP server with `${GITHUB_TOKEN}`. No Azure, no Sentinel MCP. Not configured for actual use.
- Grounding sources are correct structurally: `.squad/`, `.copilot/skills/secops-environment-context.md`, `.secops/`, `skills/`. But `.secops/` is all Contoso Corp template data — no real customer context.

**Workflow 3 — Microsoft Security Product Connectivity**
- `.secops/environment.yaml` is comprehensive in schema but entirely "Contoso Corp" template. All GUIDs are fake. Gap between template state and connected state requires manual editing of 6+ YAML files.
- `secops-squad workspace connect` — does not exist (see Workflow 1 finding).
- `doctor` only checks whether Azure CLI is installed (warning, not fail). Does NOT test `az account show`, subscription access, or workspace ping.
- `.env.example` covers only Sentinel (5 variables). No variables defined for Defender XDR, Defender for Cloud, Defender for Identity, Defender for Endpoint, or Entra ID Protection.
- Skills exist for Azure AD/O365 connectors (`data-connectors-setup.md`) and cross-cloud (`cross-cloud-connectors.md`), but ZERO skills for the 6 Microsoft security products in the workflow. Kima owns this gap.
- `secops-squad env` command IS implemented (env.js has a module) — this works for reading `.secops/` state. It's not a connectivity tester but it's functional.

**Key pattern observed:** The CLI has several stub commands registered in `index.js` that fall through to "not yet implemented" — `workspace`, `status`, `playbook`, `plugin`. These need to be either implemented or clearly marked as coming soon in user output rather than silently printing a generic stub message after being advertised in init output.
