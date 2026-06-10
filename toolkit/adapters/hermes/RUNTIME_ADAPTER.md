---
name: secops-squad-hermes
description: "SecOps Squad agent runtime adapter for Hermes Agent. Replaces the GitHub Copilot CLI dependency with Hermes's native agent framework."
version: 1.0.0
author: JARVIS
runtime: hermes
---

# SecOps Squad — Hermes Agent Runtime Adapter

## Overview

The original SecOps Squad runs on GitHub Copilot CLI (`copilot --agent secops-squad`).
This adapter makes the same agent team, skills, and personas work on **Hermes Agent**
via its native delegation, skill, and tool systems.

No code changes to the skill files. No rewrites. The adapter translates
the Squad framework concepts into Hermes equivalents.

## Architecture Mapping

| Squad Concept | Hermes Equivalent | Notes |
|---|---|---|
| `copilot --agent secops-squad` | `hermes -s secops-squad` or gateway session | Skills load via Hermes skill system |
| `.squad/team.md` (roster) | SKILL.md frontmatter + agent delegation | Agents become delegate_task subagents |
| `.squad/routing.md` | Skill routing + delegation config | Same logic, different config format |
| `.squad/decisions.md` | fact_store + session memory | Decisions persist via Holographic Memory |
| `.squad/ceremonies.md` | Cron jobs + scheduled check-ins | Ceremonies become cron tasks |
| `.squad/agents/{name}/history.md` | session_search + fact_store | Agent knowledge persists across sessions |
| `.secops/environment.yaml` | `.secops/environment.yaml` (unchanged) | Read directly by skills |
| `.copilot/skills/*.md` | `~/.hermes/skills/secops-squad/` | Installed as Hermes skills |
| `secops-squad` CLI | `hermes` CLI + secops-squad skill | CLI commands map to Hermes slash commands |
| GitHub Actions workflows | Hermes cron + webhooks | Issue triage becomes scheduled tasks |

## Setup

### 1. Install SecOps Squad skills into Hermes

```bash
# From the secops-squad-starter-kit directory
hermes skills install ./toolkit/adapters/hermes/secops-squad-skill.md --name secops-squad
```

Or manually copy the skill directory:

```bash
cp -r toolkit/adapters/hermes/secops-squad/ ~/.hermes/skills/
```

### 2. Configure the environment

Create `.secops/environment.yaml` in your project directory (or use the
starter-kit template):

```bash
cp .secops/templates/environment.yaml /your/project/.secops/environment.yaml
# Edit to match your SOC stack
```

### 3. Configure the toolkit adapter

Set your primary SIEM adapter in `.secops/environment.yaml`:

```yaml
toolkit:
  primary_adapter: splunk  # or sentinel, elastic, qradar, generic
```

### 4. Start a session

```bash
cd /your/project
hermes -s secops-squad
```

Or via gateway (Telegram, Discord, etc.) -- the skill auto-loads when
the session is in a directory with `.secops/` present.

## Agent Delegation Pattern

Squad agents map to Hermes delegate_task subagents:

### Coordinator (Squad) → Main Hermes session

The coordinator role is the main Hermes session. It reads `.squad/team.md`,
routes tasks to the right specialist, and maintains decisions.

### Specialist Agents → delegate_task goals

Each Squad agent (McNulty, Kima, Freamon, Herc, etc.) becomes a
delegate_task call with the right skill loaded:

```
delegate_task(
  goal="Hunt for suspicious sign-ins in the last 7 days",
  context="Read .secops/environment.yaml for toolkit adapter. Use the hunt.suspicious-signins intent.",
  toolsets=["terminal", "file", "browser"],
  skills=["secops-squad-hunting"]
)
```

### Multi-Agent Parallel Execution

Squad's parallel launch pattern maps to Hermes batch delegation:

```
delegate_task(tasks=[
  {
    goal: "Hunt for lateral movement patterns",
    context: "Use hunt.lateral-movement intent. Adapter: {primary_adapter}.",
    toolsets: ["terminal", "file"]
  },
  {
    goal: "Check for compromised accounts",
    context: "Use respond.compromised-account intent. Check persistence.",
    toolsets: ["terminal", "file"]
  },
  {
    goal: "Write detection rule for this pattern",
    context: "Use detect.* intent appropriate to the finding. Map to MITRE.",
    toolsets: ["terminal", "file"]
  }
])
```

## Toolkit Resolution in Hermes

When a Hermes agent loads a secops-squad skill:

1. Read `.secops/environment.yaml` → get `toolkit.primary_adapter`
2. Load `toolkit/adapters/{primary_adapter}/adapter.yaml`
3. When a skill references an intent (e.g., `hunt.suspicious-signins`):
   - Look up the intent in the adapter's `intent_map`
   - Load the corresponding skill file
   - Use the `query_template` for the target SIEM
4. If no adapter mapping exists, fall back to `generic` adapter

## CLI Command Mapping

| SecOps Squad CLI | Hermes Equivalent |
|---|---|
| `secops-squad init` | `hermes -s secops-squad` (skill walks you through init) |
| `secops-squad doctor` | `hermes doctor` + check `.secops/` config |
| `secops-squad env validate` | Skill reads `.secops/` and reports status |
| `secops-squad skill list` | `hermes skills list` |
| `secops-squad persona list` | Read `personas/*/README.md` |
| `secops-squad persona switch X` | Update `.secops/environment.yaml` toolkit section |
| `secops-squad kql validate` | Adapter-specific: `splunk` → `| datamodel` test, etc. |
| `secops-squad playbook deploy` | delegate_task to SOAR agent |
| `secops-squad update` | `git pull` on the starter-kit repo |

## Ceremony Schedule (Cron Jobs)

Squad ceremonies translate to Hermes cron jobs:

```bash
# Daily standup (9 AM)
hermes cron create "0 9 * * *" \
  --name "squad-standup" \
  --prompt "Review .squad/ decisions and log. Check for stale items. Report status." \
  --skills secops-squad

# Weekly retrospective (Friday 4 PM)  
hermes cron create "0 16 * * 5" \
  --name "squad-retro" \
  --prompt "Review the week's orchestration-log and decisions. Summarize patterns and suggest improvements." \
  --skills secops-squad
```

## Differences from Copilot Runtime

| Aspect | Copilot CLI | Hermes |
|---|---|---|
| Agent execution | Sequential (mostly) | Parallel delegation (up to 3) |
| State persistence | `.squad/` git files | `.squad/` files + fact_store + session DB |
| Tool access | Copilot sandbox | Full system access (terminal, file, browser) |
| Multi-platform | CLI only | CLI, Telegram, Discord, Slack, etc. |
| Background tasks | None | Cron, background terminal |
| Memory | Session-only | Persistent across sessions |
