---
title: KQL Skills Domain
category: kql
author: Freamon
version: 1.0.0
last_updated: 2026-05-04
---

# KQL Skills Domain

## Overview

The `skills/kql/` domain teaches agents how to write, optimize, and operationalize Kusto Query Language (KQL) — the primary query language for threat hunting, detection authoring, and incident investigation across Microsoft Sentinel, Defender XDR, and Azure Data Explorer. KQL is the lingua franca of Microsoft Security analytics.

## Why This Matters

Every security workflow in the Microsoft ecosystem — hunting, detection, investigation, reporting — is powered by KQL. Poorly written queries miss threats, time out on large datasets, or generate excessive false positives. These skills ensure agents produce KQL that is performant, accurate, and tailored to the security data model.

## Skill Files

| Skill | File | Description |
|---|---|---|
| **ADX Integration** | `adx-integration.md` | KQL patterns specific to ADX clusters |
| **Cloud Security Posture** | `cloud-security-posture.md` | Defender for Cloud KQL queries |
| **Cross-Workspace Queries** | `cross-workspace-queries.md` | Multi-workspace KQL patterns |
| **Defender XDR Hunting** | `defender-xdr-hunting.md` | Advanced hunting in Defender XDR |
| **Detection Tuning** | `detection-tuning.md` | Tuning analytics rules for false positive reduction |
| **Entra Sign-In Analysis** | `entra-signin-analysis.md` | Entra ID sign-in log analysis |
| **Incident Investigation** | `incident-investigation.md` | KQL patterns for incident investigation workflows |
| **Query Builder** | `query-builder.md` | Programmatic KQL query construction |
| **Sentinel Analytics Rules** | `sentinel-analytics-rules.md` | KQL for Sentinel scheduled/NRT rules |
| **Threat Hunting Foundations** | `threat-hunting-foundations.md` | Hypothesis-driven hunting methodology |
| **UEBA Patterns** | `ueba-patterns.md` | User and Entity Behavior Analytics KQL |

## Dependencies

KQL skills reference these domain skills:

- `skills/detection/` — Rule authoring patterns that consume KQL queries
- `skills/adx/` — ADX-specific KQL operators and functions
- `skills/msft-security/` — Product APIs that execute KQL queries
- `lib/kql-validator/` — Offline KQL syntax validation

## Environment Context

Before writing KQL queries, agents MUST consult the `.secops/` framework:

- **`.secops/data-sources/data-source-map.yaml`** — Which workspace or ADX cluster has which tables
- **`.secops/workspaces/`** — Workspace IDs for cross-workspace queries
- **`.secops/compliance/requirements.yaml`** — Data access restrictions that affect query scope

If `.secops/` does not exist, suggest running `secops-squad init --secops` to scaffold it.

## How Agents Should Use These Skills

1. **Check data location** — consult `data-source-map.yaml` to route queries to the correct workspace or ADX cluster
2. **Start with foundations** — use `threat-hunting-foundations.md` for hypothesis-driven hunting methodology
3. **Match query to product** — use `defender-xdr-hunting.md` for XDR, `sentinel-analytics-rules.md` for Sentinel
4. **Optimize for performance** — apply time filters, project early, and use `query-builder.md` for complex construction
5. **Validate before deploying** — run queries through `lib/kql-validator/` for syntax checks
6. **Tune iteratively** — use `detection-tuning.md` to reduce false positives in production rules

## Related Skills

- `skills/detection/detection-lifecycle.md` — The lifecycle that KQL-based detections follow
- `skills/log-analytics/query-patterns.md` — Common Log Analytics query patterns
- `skills/adx/cross-cluster-queries.md` — Cross-cluster KQL for federated ADX queries
