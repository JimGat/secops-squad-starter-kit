# .squad/ — Squad Runtime & Configuration

Runtime state and configuration for the AI agent team, following the [Squad SDK](https://github.com/bradygaster/squad) pattern by @bradygaster. This SecOps Squad has **8 specialized agents** plus a coordinator.

## Directory Structure

```
.squad/
├── team.md              — Agent roster (8 members + coordinator)
├── routing.md           — Work routing table (which agent handles what)
├── ceremonies.md        — Ceremony definitions (see below)
├── config.json          — Feature flags (casting, ceremonies, decision_inbox)
├── decisions/           — Decision log and inbox (ADR-style records)
│   ├── decisions.md
│   └── inbox/           — Pending decision proposals
├── agents/              — Per-agent state (charter.md + history.md each)
├── casting/             — Agent identity assignment system
├── identity/            — Squad identity and session context
├── templates/           — Squad framework templates (30+ files)
├── log/                 — Session execution logs
├── orchestration-log/   — Multi-agent orchestration logs
├── plugins/             — Plugin install directory
└── .scratch/            — Temporary working files
```

## Agents

| Agent | Codename | Specialization |
|-------|----------|----------------|
| Coordinator | Squad | Routes work to agents via routing.md |
| Lead | mcnulty | Architecture, scope, code review |
| SecOps Engineer | kima | Sentinel, Defender, MITRE ATT&CK |
| KQL Engineer | freamon | Hunting queries, analytics, query optimization |
| Automation/SOAR | herc | Logic Apps, playbooks, automation |
| Platform Dev | sydnor | Templates, CLI, CI/CD, framework |
| Tester/QA | carver | Validation, test suites, quality gates |
| Session Logger | scribe | Automatic logging (never blocks work) |
| Work Monitor | ralph | Circuit breaker, triage, health monitoring |

Each agent directory (`agents/{codename}/`) contains:
- **charter.md** — Role definition, responsibilities, boundaries
- **history.md** — Work history and session log

## Key Concepts

- **Routing** — The coordinator reads `routing.md` to dispatch work to the right agent based on task type.
- **Ceremonies** — 4 automated ceremonies run before/after certain work:
  1. Threat Model Review
  2. Detection Validation
  3. Architecture Review
  4. Retrospective
- **Casting** — How agents get their names and identities. Persistent across sessions. Managed via `casting/`.
- **Decision Inbox** — Captures architectural decisions (ADR-style) in `decisions/inbox/` for team review.

## Ephemeral vs. Persistent State

| Path | Type | Notes |
|------|------|-------|
| `team.md`, `routing.md`, `ceremonies.md` | Persistent | Core squad configuration |
| `agents/*/charter.md` | Persistent | Agent role definitions |
| `agents/*/history.md` | Persistent | Accumulates over time |
| `config.json`, `casting/`, `decisions/` | Persistent | Settings and records |
| `log/`, `orchestration-log/` | Ephemeral | Runtime execution logs |
| `identity/now.md` | Ephemeral | Current session context |
| `.scratch/` | Ephemeral | Temporary working files |

> **Note:** This directory is managed by the Squad SDK runtime. Do not manually edit files marked as ephemeral — they are overwritten each session.
