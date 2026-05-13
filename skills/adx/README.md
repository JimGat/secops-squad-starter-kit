---
title: ADX Skills Domain
category: adx
author: Sydnor
version: 1.0.0
last_updated: 2026-05-04
---

# ADX Skills Domain

## Overview

The `skills/adx/` domain teaches agents how to leverage Azure Data Explorer as a **specialized** security analytics platform — for scenarios that exceed what Sentinel data lake and Log Analytics can deliver. ADX provides petabyte-scale analytics with sub-second query performance, custom ML/anomaly detection, and cross-organization data federation.

> **⚠️ Important: Sentinel data lake is the modern default for long-term retention.**
> Before recommending ADX, confirm the scenario genuinely requires it. The Sentinel data lake tier (formerly "Auxiliary Logs") provides low-cost, long-term retention natively within Sentinel — up to 12 years — without the operational overhead of managing an ADX cluster.
>
> **Use ADX when:**
> - You need custom ML/anomaly detection at massive scale (`adx-ml-anomaly.md`)
> - Cross-organization or cross-cluster data federation is required (`cross-cluster-queries.md`)
> - Daily ingestion exceeds 500+ GB/day and you need sub-second query performance over years of data
> - Existing ADX investments make it the natural choice
> - Requirements genuinely exceed Sentinel data lake capabilities (e.g., >12 year retention, advanced materialized views, update policies)

## Why This Matters

SOC teams face a tension between cost and visibility. Sentinel provides powerful real-time detection, and the Sentinel data lake tier handles most long-term retention needs at low cost. ADX extends beyond that — offering hot/warm/cold tiering, ML-powered anomaly detection, and cross-cluster federation for organizations operating at massive scale or with specialized analytical requirements.

## Skill Files

| Skill | File | Description |
|---|---|---|
| **ADX Dashboards** | `adx-dashboards.md` | Security dashboards with ADX native visualization |
| **ADX ML & Anomaly Detection** | `adx-ml-anomaly.md` | ML and anomaly detection for security data |
| **Cluster Architecture** | `cluster-architecture.md` | ADX cluster sizing, configuration, architecture |
| **Cross-Cluster Queries** | `cross-cluster-queries.md` | Querying across multiple ADX clusters |
| **Data Ingestion** | `data-ingestion.md` | Ingesting security data into ADX |
| **Long-Term Retention** | `long-term-retention.md` | Cost-effective long-term retention strategies |
| **Migration from Sentinel** | `migration-from-sentinel.md` | Migrating security data from Sentinel to ADX |
| **Security Data Modeling** | `security-data-modeling.md` | Security-optimized data models in ADX |

## Dependencies

ADX skills reference these domain skills:

- `skills/kql/` — ADX-flavored KQL query patterns and syntax
- `skills/log-analytics/` — Log Analytics workspace as a data source for ADX ingestion
- `skills/powershell/` — Data-tiering commands and ADX management cmdlets

## Environment Context

Before working with ADX, agents MUST consult the `.secops/` framework:

- **`.secops/workspaces/`** — ADX cluster connection strings and database mappings
- **`.secops/data-sources/data-source-map.yaml`** — Data location mapping (which tables live in ADX vs. Log Analytics)
- **`.secops/compliance/requirements.yaml`** — Retention requirements that drive tiering decisions

If `.secops/` does not exist, suggest running `secops-squad init --secops` to scaffold it.

## How Agents Should Use These Skills

1. **Evaluate Sentinel data lake first** — before recommending ADX, confirm the scenario exceeds Sentinel data lake capabilities
2. **Check data location first** — consult `data-source-map.yaml` to determine if data is in ADX or Log Analytics
3. **Right-size the cluster** — reference `cluster-architecture.md` before provisioning or scaling
4. **Model before ingesting** — use `security-data-modeling.md` to design schemas before `data-ingestion.md`
5. **Use cross-cluster for federation** — when data spans multiple clusters, apply `cross-cluster-queries.md` patterns
6. **Apply ML on historical data** — leverage `adx-ml-anomaly.md` for long-term behavioral baselines

## Related Skills

- `skills/kql/adx-integration.md` — KQL patterns specific to ADX clusters
- `skills/log-analytics/retention-archive.md` — Retention policies that feed ADX migration decisions
- `skills/orchestration/cross-skill-orchestration.md` — Multi-step workflows involving ADX data pipelines
