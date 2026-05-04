# Threat Hunting Persona

Pre-built team configuration for hypothesis-driven threat hunting, OSINT research, and hunt reporting across Microsoft Security.

## What This Is

The `threat-hunting` persona provides a dedicated hunt team powered by secops-squad. It models the full hunt lifecycle — hypothesis development, intelligence gathering, query execution, and findings reporting — with clear roles and handoffs. Built for teams running proactive hunts across Microsoft Sentinel, Defender XDR, and Entra ID.

## When to Use This Persona

- You're building a proactive threat hunting program
- You need structured hypothesis-driven hunts with documented outcomes
- You want OSINT research integrated into your hunt workflow
- You need hunt findings to feed your detection engineering pipeline

## Team Composition

| Agent | Role | Focus |
|-------|------|-------|
| **Omar** | Hunt Lead | Hypothesis development, hunt planning, findings triage, detection recommendations |
| **Slim Charles** | KQL Hunter | Hunt query authoring, cross-domain correlation, behavioral anomaly detection |
| **Bubbles** | OSINT Researcher | Threat intelligence, adversary profiling, IOC collection, TTP tracking |
| **Rhonda** | Reporting Analyst | Hunt reports, evidence documentation, executive briefings, recommendation tracking |

## Pre-Loaded Skills

**All agents** get `threat-hunting-foundations` and `cross-workspace-queries`.

| Agent | Skills |
|-------|--------|
| Omar | `ueba-patterns`, `detection-tuning` |
| Slim Charles | `defender-xdr-hunting`, `ueba-patterns`, `entra-signin-analysis` |
| Bubbles | `entra-signin-analysis` |
| Rhonda | `detection-tuning` |

## What's Included

- `team.md` — Agent roster with roles, expertise, and project context
- `routing.md` — Phase-based and request-type routing with escalation paths
- `ceremonies.md` — Hunt kickoff, hunt debrief, findings presentation
- `skills.json` — Skill assignments per agent
- `README.md` — This file

## Installation

```bash
npx secops-squad init
# Select "Threat Hunting team" when prompted
```

## Customization

After installation, everything lives in `.squad/` and is yours to edit:

- **Add agents** — need a dedicated malware analyst? Add a row to `team.md` and a routing entry.
- **Adjust routing** — change phase ownership, add IOC sweep routing, modify escalation triggers.
- **Tune ceremonies** — change debrief frequency, add a weekly intel briefing, modify templates.
- **Swap skills** — add custom skills for your environment, remove ones you don't use.

## Phase 2-3 Capabilities

This persona now includes API integration and tooling skills from Phases 2-3:

| Capability | Skill | Used By |
|-----------|-------|---------|
| Sentinel PowerShell API wrappers (20+ functions) | `sentinel-api-wrapper` | All agents |
| Azure MCP Server integration | `sentinel-mcp-server` | All agents |
| Sentinel REST API reference | `sentinel-api-reference` | All agents |
| Table data tiering awareness | `data-tiering-commands` | Omar |
| Log Analytics API wrapper | `log-analytics/api-wrapper` | Slim Charles |
| Cross-workspace query patterns | `log-analytics/query-patterns` | Slim Charles |
| KQL builder utility | `kql/query-builder` | Slim Charles |
| Hunt findings workbooks | `workbook-automation` | Rhonda |

### Tool Selection

- **Agents** use MCP (`sentinel-mcp-server`) for interactive KQL execution during hunts
- **Pipelines** use PowerShell wrappers (`sentinel-api-wrapper`) for batch IOC sweeps and incident context
- **Fallback** to REST API directly using `sentinel-api-reference` when MCP/PS unavailable

## Environment Assumptions

This persona assumes a Microsoft Security stack:
- **Microsoft Sentinel** for log aggregation and hunting queries (Log Analytics workspace)
- **Microsoft Defender XDR** for cross-domain advanced hunting (endpoint, identity, email, cloud apps)
- **Microsoft Entra ID** for identity signal hunting (sign-in logs, risky users, audit logs)
- **MITRE ATT&CK** as the framework for hunt hypothesis prioritization
- **Azure MCP Server** for agent-driven query execution (Phase 4+)
- **Az.SecurityInsights** PowerShell module for API automation
