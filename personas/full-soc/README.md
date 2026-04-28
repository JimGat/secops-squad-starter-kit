# Full SOC Persona

Pre-built team configuration for a complete, mature Security Operations Center — all roles from triage through threat hunting, detection engineering, automation, and threat intelligence.

## What This Is

The `full-soc` persona provides a production-ready SOC team powered by secops-squad. It combines all SOC functions into a single team with comprehensive severity-based and domain-based routing. This is the "everything" persona — tiered analyst operations, detection engineering, threat hunting, SOAR automation, and threat intelligence, all coordinated by a SOC Manager.

## When to Use This Persona

- You're building a mature SOC that covers all security operations functions
- You want a single team configuration that handles triage, investigation, detection, hunting, and automation
- You need cross-functional coordination (hunt findings → detection rules → automated response)
- You want the complete ceremony set for SOC operations

For focused teams, consider the specialized personas instead:
- **`soc-analyst`** — L1/L2/L3 triage and investigation only
- **`detection-engineering`** — Detection content development only
- **`threat-hunting`** — Proactive threat hunting only
- **`cloud-security`** — Cloud posture and policy only
- **`incident-response`** — Structured IR only

## Team Composition

| Agent | Role | Focus |
|-------|------|-------|
| **Bunny Colvin** | SOC Manager | Strategy, shift management, metrics, stakeholder relations, coordination |
| **Bodie** | L1 Analyst | Alert triage, playbook-driven response, queue hygiene |
| **Poot** | L2 Analyst | Medium-severity investigation, entity enrichment, escalation decisions |
| **Carver** | L3 Analyst | Advanced investigation, cross-domain correlation, APT hunting |
| **Herc** | Detection Engineer | Analytics rule design, MITRE mapping, detection lifecycle |
| **Cutty** | Automation Engineer | SOAR playbooks, Logic Apps, response automation |
| **McNulty** | Hunt Lead | Hunt campaigns, hypothesis development, findings-to-detection pipeline |
| **Lester** | Threat Intel | IOC research, adversary profiling, threat feed management |

## Pre-Loaded Skills

**All agents** get `incident-investigation`, `teams-notification`, `mitre-attack-mapping`, and `cross-workspace-queries`.

| Agent | Skills |
|-------|--------|
| Bunny Colvin | `ticket-create`, `teams-notification` |
| Bodie | `phishing-response`, `compromised-account` |
| Poot | `sentinel-enrichment-ip`, `sentinel-enrichment-user`, `entra-signin-analysis` |
| Carver | `threat-hunting-foundations`, `ueba-patterns`, `defender-xdr-hunting` |
| Herc | `sentinel-analytics-rules`, `scheduled-rule-pattern`, `nrt-rule-pattern`, `detection-lifecycle`, `detection-tuning` |
| Cutty | `phishing-response`, `compromised-account`, `microsoft-graph-security` |
| McNulty | `threat-hunting-foundations`, `ueba-patterns`, `defender-xdr-hunting` |
| Lester | `entra-signin-analysis`, `data-exfiltration-response`, `malware-containment` |

## What's Included

- `team.md` — Full 8-agent roster with roles, expertise, and project context
- `routing.md` — Comprehensive severity + domain routing with cross-functional coordination
- `ceremonies.md` — Daily standup, shift handoff, incident review, detection review, hunt debrief, weekly retro
- `skills.json` — Complete skill assignments spanning all SOC functions
- `README.md` — This file

## How the Pieces Fit Together

The full SOC is designed for cross-functional flow:

```
Threat Intel (Lester) → Hunt Hypotheses (McNulty) → Hunt Findings → Detection Rules (Herc) → Production Rules
                                                                                                    ↓
                                                                              Alerts → Triage (Bodie) → Investigation (Poot/Carver)
                                                                                                    ↓
                                                                              Response Automation (Cutty) → Playbooks
                                                                                                    ↓
                                                                              Lessons Learned → Detection Improvements (Herc)
```

- **Intel feeds hunting** — Lester's intelligence drives McNulty's hunt hypotheses
- **Hunting feeds detection** — McNulty's confirmed findings become Herc's detection rules
- **Detections generate alerts** — Herc's rules feed the triage queue for Bodie/Poot/Carver
- **Incidents feed automation** — Repeated response patterns become Cutty's playbooks
- **Lessons learned close the loop** — Post-incident reviews generate detection and automation improvements

## Installation

```bash
npx secops-squad init
# Select "Full SOC team" when prompted
```

## Customization

After installation, everything lives in `.squad/` and is yours to edit:

- **Scale the team** — add L1.5 analysts, specialized detection engineers, or additional hunt roles.
- **Adjust routing** — change severity thresholds, add region-based routing, modify cross-functional flows.
- **Tune ceremonies** — change standup cadence, add tabletop exercises, modify retro format.
- **Swap skills** — add custom skills for your environment, remove functions you don't need.

## Environment Assumptions

This persona assumes a Microsoft Security stack:
- **Microsoft Sentinel** as SIEM (incidents, analytics rules, watchlists, automation rules, workbooks)
- **Microsoft Defender XDR** for endpoint, identity, email, and cloud app protection
- **Microsoft Entra ID** for identity and access management
- **Microsoft Defender for Cloud** for cloud security posture
- **Azure Logic Apps** for SOAR playbooks and response automation
- **Microsoft Graph Security API** for cross-product integration
