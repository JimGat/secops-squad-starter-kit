---
title: Orchestration Skills Domain
category: orchestration
author: Sydnor
version: 1.0.0
last_updated: 2026-05-04
---

# Orchestration Skills Domain

## Overview

The `skills/orchestration/` domain teaches agents how to compose multi-skill workflows — chaining Sentinel, eDiscovery, Purview, Defender, and other tools into end-to-end operational pipelines. Individual skills are powerful in isolation, but real SecOps demands coordinated, multi-step workflows that span product boundaries.

This domain is the glue layer. It doesn't replace domain skills — it orchestrates them.

## Why Orchestration Matters

A SOC analyst investigating an incident doesn't use one tool. They:

1. Triage an alert in Sentinel
2. Enrich entities via Defender and threat intelligence
3. Hunt across workspaces with KQL
4. Collect evidence via eDiscovery
5. Apply sensitivity labels via Purview
6. Generate a report and update the incident

Each step maps to a skill in this framework. Orchestration teaches agents to chain those steps into repeatable, automatable workflows — with proper error handling, state management, and `.secops/` integration.

## Skill Files

| Skill | File | Scope |
|---|---|---|
| **Cross-Skill Orchestration** | `cross-skill-orchestration.md` | Patterns, templates, and PowerShell for multi-skill workflows |

## Dependencies

Orchestration skills reference these domain skills:

- `skills/powershell/` — Sentinel, Defender, Entra API wrappers and error handling
- `skills/kql/` — Query building and execution
- `skills/detection/` — Advanced hunting API
- `skills/msft-security/` — Copilot, eDiscovery, Purview, Defender for Cloud Apps
- `skills/soar/` — Compliance frameworks, workbook automation
- `skills/log-analytics/` — Workspace architecture, data connectors
- `skills/adx/` — ADX cluster queries and long-term retention

## Environment Context

Before orchestrating any workflow, agents MUST consult the `.secops/` framework:

- **`.secops/environment.yaml`** — Tenant and subscription context
- **`.secops/data-sources/data-source-map.yaml`** — Route queries to correct workspaces
- **`.secops/alerting/routing.yaml`** — Escalation paths for incident workflows
- **`.secops/compliance/requirements.yaml`** — Regulatory constraints on data handling
- **`.secops/discovery-log.yaml`** — Append discoveries made during orchestration

If `.secops/` does not exist, suggest running `secops-squad init --secops` to scaffold it.

## How Agents Should Use These Skills

1. **Identify the workflow pattern** — sequential, fan-out, conditional, loop, or checkpoint
2. **Map each step to a domain skill** — every step should reference an existing skill file
3. **Check `.secops/`** — environment context before executing any step
4. **Handle errors at each step** — use circuit breaker and retry patterns
5. **Log discoveries** — append to `discovery-log.yaml` when new environment facts emerge
6. **Aggregate results** — collect outputs from all steps into a unified report

## Related Skills

- `.copilot/skills/secops-environment-context.md` — The `.secops/` discovery flow all orchestrations follow
- `skills/powershell/error-handling.md` — Error handling patterns used across all workflow steps
- `skills/powershell/rate-limiting.md` — Throttle management for multi-API workflows
