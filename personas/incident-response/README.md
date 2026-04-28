# Incident Response Persona

Pre-built team configuration for structured incident response — triage, forensics, communications, and threat intelligence.

## What This Is

The `incident-response` persona provides a complete IR team powered by secops-squad. It models the NIST SP 800-61 incident response lifecycle with dedicated roles for incident command, forensic analysis, stakeholder communications, and threat intelligence. Built for teams responding to security incidents across Microsoft Sentinel and Defender XDR.

## When to Use This Persona

- You're building or formalizing an incident response capability
- You need structured IR with clear command authority and role separation
- You want forensic analysis, threat intelligence, and stakeholder comms coordinated during incidents
- You need post-incident lessons learned to feed your detection and process improvements

## Team Composition

| Agent | Role | Focus |
|-------|------|-------|
| **Rawls** | IR Lead | Incident command, containment decisions, escalation, post-incident review |
| **Sydnor** | Forensic Analyst | Evidence collection, timeline reconstruction, malware triage, impact assessment |
| **Beadie** | Comms Coordinator | Stakeholder updates, executive briefings, regulatory notification coordination |
| **Prez** | Threat Intel | IOC research, adversary attribution, threat feed correlation, campaign analysis |

## Pre-Loaded Skills

**All agents** get `incident-investigation` and `cross-workspace-queries`.

| Agent | Skills |
|-------|--------|
| Rawls | `malware-containment`, `microsoft-graph-security` |
| Sydnor | `malware-containment`, `data-exfiltration-response` |
| Beadie | `microsoft-graph-security` |
| Prez | `data-exfiltration-response`, `microsoft-graph-security` |

## What's Included

- `team.md` — Agent roster with roles, expertise, and project context
- `routing.md` — Phase-based IR routing with escalation paths
- `ceremonies.md` — IR kickoff, containment review, lessons learned
- `skills.json` — Skill assignments per agent
- `README.md` — This file

## Installation

```bash
npx secops-squad init
# Select "Incident Response team" when prompted
```

## Customization

After installation, everything lives in `.squad/` and is yours to edit:

- **Add agents** — need a dedicated recovery coordinator? Add a row to `team.md` and a routing entry.
- **Adjust routing** — change phase ownership, add regulatory-specific routing, modify escalation triggers.
- **Tune ceremonies** — change lessons learned cadence, add a tabletop exercise ceremony, modify templates.
- **Swap skills** — add custom skills for your IR procedures, remove ones you don't use.

## Environment Assumptions

This persona assumes a Microsoft Security stack:
- **Microsoft Sentinel** for incident management (incidents, automation rules, playbooks)
- **Microsoft Defender XDR** for unified incident queue and automated investigation
- **Microsoft Entra ID** for identity investigation and emergency access controls
- **Microsoft Graph Security API** for cross-product alert correlation and response
- **Framework:** NIST SP 800-61 Incident Response Lifecycle
