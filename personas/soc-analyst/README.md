# SOC Analyst Persona

Pre-built team configuration for L1/L2/L3 Security Operations Center analyst workflows.

## What This Is

The `soc-analyst` persona provides a ready-to-use SOC team powered by secops-squad. It models a tiered SOC with severity-based routing, structured escalation paths, and operational ceremonies — the same patterns used by production SOCs running Microsoft Sentinel and Defender XDR.

## Team Composition

| Agent | Role | Tier | Focus |
|-------|------|------|-------|
| **Bunk** | Triage Analyst | L1 | Alert triage, known-good/known-bad classification, playbook-driven response |
| **Kima** | Escalation Analyst | L2 | Medium-severity investigation, entity enrichment, correlation, escalation decisions |
| **Freamon** | Senior Analyst | L3 | Threat hunting, KQL engineering, cross-domain correlation, APT investigation |
| **Daniels** | Shift Lead | Lead | Incident assignment, shift handoff, stakeholder comms, escalation oversight |

## Pre-Loaded Skills

**All agents** get `incident-investigation` and `teams-notification`.

| Agent | Skills |
|-------|--------|
| Bunk | `phishing-response`, `compromised-account` |
| Kima | `sentinel-analytics-rules`, `sentinel-enrichment-ip`, `sentinel-enrichment-user` |
| Freamon | `threat-hunting-foundations`, `cross-workspace-queries`, `ueba-patterns`, `defender-xdr-hunting` |
| Daniels | `teams-notification`, `ticket-create` |

## Installation

```bash
npx secops-squad init
# Select "SOC Analyst team" when prompted
```

This installs the persona files into your `.squad/` directory:
- `team.md` — agent roster and project context
- `routing.md` — severity-based work routing and escalation rules
- `ceremonies.md` — shift handoff, incident review, standup, detection review
- `skills.json` — skill assignments per agent

## Customization

After installation, everything lives in `.squad/` and is yours to edit:

- **Add agents** — need an L1.5 for specific alert types? Add a row to `team.md` and a routing entry.
- **Adjust routing** — change severity thresholds, add work-type routes, modify escalation triggers.
- **Tune ceremonies** — change standup frequency, add a threat intel briefing, modify templates.
- **Swap skills** — add custom skills, remove ones you don't use, adjust per-agent assignments.

## Environment Assumptions

This persona assumes a Microsoft Security stack:
- **Microsoft Sentinel** as SIEM (incidents, analytics rules, watchlists, workbooks)
- **Microsoft Defender XDR** for endpoint, identity, email, and cloud app protection
- **Microsoft Entra ID** for identity and access management
- **Microsoft Defender for Cloud** for cloud security posture

If your stack differs, adjust the skills and routing rules to match your tools.
