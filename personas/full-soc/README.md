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

**All agents** get `incident-investigation`, `teams-notification`, `mitre-attack-mapping`, `cross-workspace-queries`, `api-patterns`, `rate-limiting`, `auth-patterns`, `error-handling`, and `module-foundation`.

| Agent | Skills |
|-------|--------|
| Bunny Colvin | `ticket-create`, `teams-notification`, `compliance-framework-mappings`, `workbook-automation` |
| Bodie | `phishing-response`, `compromised-account`, `auto-triage`, `sentinel-enrichment-ip` |
| Poot | `sentinel-enrichment-ip`, `sentinel-enrichment-user`, `entra-signin-analysis`, `purview-api-wrapper`, `ediscovery-api-wrapper`, `entra-module` |
| Carver | `threat-hunting-foundations`, `ueba-patterns`, `defender-xdr-hunting`, `adx-integration`, `query-builder`, `resource-graph-module` |
| Herc | `sentinel-analytics-rules`, `scheduled-rule-pattern`, `nrt-rule-pattern`, `detection-lifecycle`, `detection-tuning`, `watchlist-driven-detection`, `fusion-rule-context`, `sentinel-api-wrapper`, `sentinel-module` |
| Cutty | `phishing-response`, `compromised-account`, `microsoft-graph-security`, `malware-containment`, `data-exfiltration-response`, `auto-triage`, `threat-intel-ingest`, `workbook-automation`, `compliance-framework-mappings`, `defender-api-wrapper`, `azure-monitor-module` |
| McNulty | `threat-hunting-foundations`, `ueba-patterns`, `defender-xdr-hunting`, `advanced-hunting-api`, `cloud-security-posture` |
| Lester | `entra-signin-analysis`, `data-exfiltration-response`, `malware-containment`, `threat-intel-ingest`, `copilot-for-security`, `defender-for-endpoint`, `purview-dlp-patterns` |

**Infrastructure skills** (available to all agents): `sentinel-mcp-server`, `defender-mcp-server`, `sentinel-workspace-setup`, `sentinel-api-reference`, `defender-api-permissions`, `data-tiering-commands`, `data-tiering-module`

## Phase 2-3 Skill Domains

The full-soc persona includes comprehensive Phase 2-3 skills across all domains:

### SOAR & Automation
- **Auto-triage** — Evidence-based L1 auto-close/assign/escalate
- **Threat intel ingestion** — TAXII/STIX scheduled feed automation
- **Workbook automation** — Dashboard lifecycle management with CI/CD
- **Compliance framework mappings** — 6 frameworks (NIST, CIS, PCI-DSS, HIPAA, SOC 2, ISO 27001)

### Microsoft Security APIs
- **eDiscovery** — Legal holds, custodian management, review set export
- **Purview data governance** — Sensitivity labels, DLP policies, data classification
- **Purview DLP patterns** — DLP policy patterns and sensitive information types
- **Copilot for Security** — AI-assisted threat analysis and incident summarization
- **Sentinel & Defender MCP servers** — Direct KQL execution and alert management via MCP protocol
- **Defender for Endpoint** — MDE device actions, vulnerability insights
- **Sentinel workspace setup** — Architecture, connectors, retention, RBAC

### PowerShell Modules
- **Sentinel module** — Az.SecurityInsights for rule and incident management
- **Defender API wrapper** — MDE REST API automation
- **Entra module** — Identity investigation and PIM automation
- **Azure Monitor module** — Action groups, alert rules, diagnostics
- **Resource Graph module** — Cross-subscription resource queries
- **Data tiering** — Hot/cool/archive lifecycle management
- **Auth, error handling, rate limiting** — Foundation patterns for all modules

### Detection & KQL
- **Watchlist-driven detection** — Dynamic allowlists/blocklists
- **Fusion rule patterns** — Multi-stage ML-driven alert correlation
- **Advanced Hunting API** — Programmatic hunt execution
- **ADX integration** — Long-term historical hunting
- **Query builder** — Programmatic KQL construction
- **Cloud security posture** — Defender for Cloud hunting queries

## What's Included

- `team.md` — Full 8-agent roster with roles, expertise, and project context
- `routing.md` — Comprehensive severity + domain routing with cross-functional coordination and compliance/automation routing
- `ceremonies.md` — Daily standup, shift handoff, incident review, detection review, hunt debrief, weekly retro
- `skills.json` — Complete skill assignments spanning all SOC functions (v2.0.0 with Phase 2-3 skills)
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
- **Microsoft Sentinel MCP Server** for agent-direct KQL execution and incident management
- **Microsoft Defender XDR** for endpoint, identity, email, and cloud app protection
- **Microsoft Defender MCP Server** for agent-direct Defender data queries and response actions
- **Microsoft Entra ID** for identity and access management
- **Microsoft Defender for Cloud** for cloud security posture and regulatory compliance
- **Microsoft Purview** for eDiscovery, legal hold, data classification, and DLP
- **Microsoft Copilot for Security** for AI-assisted threat analysis
- **Azure Logic Apps** for SOAR playbooks and response automation
- **Azure Monitor** for action groups, alert rules, and diagnostic settings
- **Azure Data Explorer** for long-term security data retention and historical hunting
- **Microsoft Graph Security API** for cross-product integration
- **PowerShell Az modules** for infrastructure automation (Sentinel, Defender, Entra, Monitor, Resource Graph)
