---
title: ADX Skills Domain
category: adx
author: Sydnor
version: 1.0.0
last_updated: 2026-05-04
---

# ADX Skills Domain

## Overview

The `skills/adx/` domain teaches agents how to leverage Azure Data Explorer as a security data lake — ingesting, modeling, querying, and retaining security telemetry at scale. ADX provides petabyte-scale analytics with sub-second query performance, making it the ideal platform for long-term security data retention and advanced threat hunting beyond Sentinel's 90-day interactive window.

## Why This Matters

SOC teams face a tension between cost and visibility. Sentinel provides powerful real-time detection, but retaining years of security data there is prohibitively expensive. ADX bridges that gap — offering hot/warm/cold tiering, ML-powered anomaly detection, and cross-cluster federation at a fraction of the cost.

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

1. **Check data location first** — consult `data-source-map.yaml` to determine if data is in ADX or Log Analytics
2. **Right-size the cluster** — reference `cluster-architecture.md` before provisioning or scaling
3. **Model before ingesting** — use `security-data-modeling.md` to design schemas before `data-ingestion.md`
4. **Use cross-cluster for federation** — when data spans multiple clusters, apply `cross-cluster-queries.md` patterns
5. **Apply ML on historical data** — leverage `adx-ml-anomaly.md` for long-term behavioral baselines

## Related Skills

- `skills/kql/adx-integration.md` — KQL patterns specific to ADX clusters
- `skills/log-analytics/retention-archive.md` — Retention policies that feed ADX migration decisions
- `skills/orchestration/cross-skill-orchestration.md` — Multi-step workflows involving ADX data pipelines
