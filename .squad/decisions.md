

# Squad Decisions

## Active Decisions

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



# Decision: GitHub CLI promoted to required dependency

**Date:** 2026-05-08T16:21:48.253-05:00
**By:** Sydnor (Platform Dev)
**Status:** Accepted

## What

GitHub CLI (`gh`) is now a **required** dependency in `install.ps1`, upgraded from optional. The install script will auto-install it via `winget install GitHub.cli` if missing.

Additionally, the GitHub Copilot CLI extension (`gh extension install github/gh-copilot`) is now installed as part of the bootstrap.

## Why

- `gh` is required for squad issue mode (Ralph's issue routing, label-based work assignment).
- The `copilot --agent secops-squad` launch command depends on the `gh-copilot` extension.
- The primary workflow (`copilot --agent secops-squad`) cannot function without both `gh` and the copilot extension.

## Impact

- **All agents:** The `copilot` command is now the documented entry point. References to `node cli/index.js` are removed from README.
- **Users:** Fresh installs get `gh` and `gh-copilot` automatically. Users still need to run `gh auth login` manually (cannot be automated in a non-interactive script).
- **install.ps1:** Fails if `gh` cannot be installed (same as Git and Node.js).

# Decision: gh CLI and az CLI are optional — connected during agent session

**Date:** 2026-05-08T16:41:19.514-05:00
**By:** Sydnor (Platform Dev)
**Status:** Implemented

## What

GitHub CLI (`gh`) and Azure CLI (`az`) are no longer install-time prerequisites for secops-squad.
They are optional tools that users connect interactively during a Copilot session when they first need them.

## Why

Most users don't have `gh` or `az` configured before starting. Requiring them upfront creates friction
and failed installs for users who just want to try the tool. The agent can guide interactive auth
far more gracefully than a shell script can.

## Changes

- `install.ps1`: `gh` demoted from required (`$true`) to optional (`$false`). `Ensure-GhCopilotExtension` removed entirely.
- `install.sh`: no change needed (gh was already optional).
- `README.md`: prerequisites table updated; `--yolo` promoted as primary launch command.
- `cli/commands/doctor.js`: `checkCopilotCli()` added as required check; gh/az remain optional warnings.

## Impact

- **All agents:** Users may not have `gh` or `az` connected on first run — agents should check and offer to help connect them.
- **McNulty:** Issue mode requires gh; should detect and prompt before attempting gh operations.
- **Herc/Kima:** Azure operations require az login; should detect and prompt before az calls.
