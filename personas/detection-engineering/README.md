# Detection Engineering Persona

Pre-built team configuration for detection content development, KQL authoring, threat modeling, and quality validation.

## What This Is

The `detection-engineering` persona provides a complete detection content team powered by secops-squad. It models the full detection lifecycle — from threat model through KQL authoring to QA validation — with clear ownership at every stage. Built for teams shipping analytics rules into Microsoft Sentinel and Defender XDR.

## When to Use This Persona

- You're building or maintaining a library of Sentinel analytics rules
- You need structured threat modeling before writing detection logic
- You want KQL code review and quality gates before rules hit production
- You're tracking MITRE ATT&CK coverage and prioritizing detection gaps

## Team Composition

| Agent | Role | Focus |
|-------|------|-------|
| **Daniels** | Detection Engineer | Rule design, detection logic, MITRE mapping, lifecycle management |
| **Lester** | KQL Author | Query authoring, performance optimization, cross-table correlations |
| **Prop Joe** | Threat Modeler | Adversary technique mapping, coverage gap analysis, evasion assessment |
| **Landsman** | QA Validator | Rule validation, false positive testing, regression checks, production sign-off |

## Pre-Loaded Skills

**All agents** get `mitre-attack-mapping` and `detection-lifecycle`.

| Agent | Skills |
|-------|--------|
| Daniels | `scheduled-rule-pattern`, `nrt-rule-pattern`, `sentinel-analytics-rules` |
| Lester | `threat-hunting-foundations`, `cross-workspace-queries`, `detection-tuning` |
| Prop Joe | `mitre-attack-mapping`, `detection-lifecycle` |
| Landsman | `detection-tuning`, `sentinel-analytics-rules` |

## What's Included

- `team.md` — Agent roster with roles, expertise, and project context
- `routing.md` — Request-type and lifecycle-stage routing with rules
- `ceremonies.md` — Detection review, threat model session, rule tuning review
- `skills.json` — Skill assignments per agent
- `README.md` — This file

## Installation

```bash
npx secops-squad init
# Select "Detection Engineering team" when prompted
```

## Customization

After installation, everything lives in `.squad/` and is yours to edit:

- **Add agents** — need a dedicated data engineer for log onboarding? Add a row to `team.md` and a routing entry.
- **Adjust routing** — add lifecycle stages, change ownership, modify gate criteria.
- **Tune ceremonies** — change review frequency, add a sprint planning ceremony, modify templates.
- **Swap skills** — add custom skills for your detection patterns, remove ones you don't use.

## Environment Assumptions

This persona assumes a Microsoft Security stack:
- **Microsoft Sentinel** as detection platform (scheduled rules, NRT rules, fusion rules, analytics templates)
- **Microsoft Defender XDR** for custom detection rules and advanced hunting
- **MITRE ATT&CK** as the coverage framework for gap analysis and prioritization
- **KQL CI/CD** pipeline for syntax validation and automated testing
