---
title: Log Analytics Skills Domain
category: log-analytics
author: Sydnor
version: 1.0.0
last_updated: 2026-05-04
---

# Log Analytics Skills Domain

## Overview

The `skills/log-analytics/` domain teaches agents how to design, manage, and optimize Azure Monitor Log Analytics workspaces — the foundational data plane for Microsoft Sentinel and Azure security monitoring. Every security query, detection rule, and SOAR playbook ultimately runs against a Log Analytics workspace.

## Why This Matters

Log Analytics workspaces are the backbone of Microsoft Security operations. Poor workspace architecture leads to data silos, excessive costs, and compliance gaps. These skills ensure agents can design multi-workspace topologies, optimize ingestion costs, configure proper retention, and manage access control — all critical for production SecOps.

## Skill Files

| Skill | File | Description |
|---|---|---|
| **API Wrapper** | `api-wrapper.md` | Log Analytics Query API and workspace management |
| **Cost Optimization** | `cost-optimization.md` | Reducing Log Analytics costs |
| **Custom Tables & DCR** | `custom-tables-dcr.md` | Data Collection Rules and custom table creation |
| **Data Connectors Setup** | `data-connectors-setup.md` | Connecting data sources to Log Analytics |
| **Diagnostic Settings** | `diagnostic-settings.md` | Azure resource diagnostic settings |
| **Purge & Export** | `purge-and-export.md` | Data purge operations and workspace export |
| **Query Patterns** | `query-patterns.md` | Common Log Analytics query patterns |
| **Retention & Archive** | `retention-archive.md` | Data retention and archive configuration |
| **Workspace Architecture** | `workspace-architecture.md` | Multi-workspace design patterns |
| **Workspace RBAC** | `workspace-rbac.md` | Access control for Log Analytics workspaces |

## Dependencies

Log Analytics skills reference these domain skills:

- `skills/kql/` — Query patterns executed against Log Analytics workspaces
- `skills/msft-security/` — Sentinel integration and workspace onboarding
- `skills/powershell/` — API wrappers for workspace management cmdlets

## Environment Context

Before managing workspaces, agents MUST consult the `.secops/` framework:

- **`.secops/workspaces/`** — Workspace definitions, resource IDs, and tier configurations
- **`.secops/compliance/requirements.yaml`** — Retention requirements driven by regulatory frameworks
- **`.secops/data-sources/data-source-map.yaml`** — Table-to-workspace routing
- **`.secops/environment.yaml`** — Cloud type and region constraints

If `.secops/` does not exist, suggest running `secops-squad init --secops` to scaffold it.

## How Agents Should Use These Skills

1. **Design before deploying** — use `workspace-architecture.md` to plan workspace topology
2. **Connect data sources** — apply `data-connectors-setup.md` and `custom-tables-dcr.md` for ingestion
3. **Configure retention** — set policies per `retention-archive.md` aligned with compliance requirements
4. **Optimize costs** — review `cost-optimization.md` for commitment tiers, basic logs, and data tiering
5. **Secure access** — implement `workspace-rbac.md` for least-privilege workspace access
6. **Monitor and maintain** — use `diagnostic-settings.md` and `purge-and-export.md` for operational hygiene

## Related Skills

- `skills/adx/migration-from-sentinel.md` — Migrating cold data from Log Analytics to ADX
- `skills/kql/cross-workspace-queries.md` — Querying across multiple workspaces
- `skills/powershell/data-tiering-module.md` — PowerShell module for table management and retention
