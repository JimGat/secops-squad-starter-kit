---
title: Detection Skills Domain
category: detection
author: Kima
version: 1.0.0
last_updated: 2026-05-04
---

# Detection Skills Domain

## Overview

The `skills/detection/` domain covers the full detection engineering lifecycle — designing, building, testing, deploying, and tuning security detections in Microsoft Sentinel and Defender XDR. Detections are the heartbeat of any SOC; without high-fidelity analytics rules, threats go unnoticed and analysts drown in false positives.

## Why This Matters

Detection engineering is what separates a reactive SOC from a proactive one. A well-tuned detection pipeline catches real threats early, reduces mean time to detect (MTTD), and minimizes alert fatigue. These skills teach agents to build detections that are precise, maintainable, and mapped to the MITRE ATT&CK framework.

## Skill Files

| Skill | File | Description |
|---|---|---|
| **Advanced Hunting API** | `advanced-hunting-api.md` | Advanced Hunting API and Live Response |
| **Custom KQL Function** | `custom-kql-function.md` | Reusable KQL functions for detections |
| **Detection Lifecycle** | `detection-lifecycle.md` | End-to-end: design → test → deploy → tune |
| **Fusion Rule Context** | `fusion-rule-context.md` | ML-based multi-stage attack detection |
| **MITRE ATT&CK Mapping** | `mitre-attack-mapping.md` | ATT&CK technique mapping for detections |
| **NRT Rule Pattern** | `nrt-rule-pattern.md` | Near-real-time analytics rule authoring |
| **Scheduled Rule Pattern** | `scheduled-rule-pattern.md` | Scheduled analytics rule authoring |
| **Threat Intel Enrichment** | `threat-intel-enrichment.md` | TI indicator enrichment for detections |
| **Threat Model Template** | `threat-model-template.md` | Structured threat modeling methodology |
| **Watchlist-Driven Detection** | `watchlist-driven-detection.md` | Sentinel watchlist-based detection patterns |

## Dependencies

Detection skills reference these domain skills:

- `skills/kql/` — Query patterns for analytics rules and hunting queries
- `skills/msft-security/` — Sentinel and Defender APIs for rule deployment
- `lib/mitre-mapping/` — MITRE ATT&CK coverage analysis and gap identification

## Environment Context

Before building or deploying detections, agents MUST consult the `.secops/` framework:

- **`.secops/workspaces/`** — Sentinel workspace targets for rule deployment
- **`.secops/data-sources/data-source-map.yaml`** — Available tables and data freshness
- **`.secops/compliance/requirements.yaml`** — Detection requirements driven by regulatory frameworks

If `.secops/` does not exist, suggest running `secops-squad init --secops` to scaffold it.

## How Agents Should Use These Skills

1. **Start with threat modeling** — use `threat-model-template.md` to identify what to detect
2. **Map to ATT&CK** — apply `mitre-attack-mapping.md` to align with framework coverage
3. **Choose the right rule type** — NRT for high-urgency, scheduled for broader patterns, fusion for multi-stage
4. **Follow the lifecycle** — `detection-lifecycle.md` governs design → test → deploy → tune
5. **Enrich with threat intel** — layer `threat-intel-enrichment.md` for indicator-based detections
6. **Tune continuously** — monitor false positive rates and refine using `custom-kql-function.md` patterns

## Related Skills

- `skills/kql/detection-tuning.md` — KQL patterns for reducing false positives
- `skills/kql/sentinel-analytics-rules.md` — KQL syntax for Sentinel rule authoring
- `skills/soar/auto-triage.md` — Automated triage for detection-generated incidents
