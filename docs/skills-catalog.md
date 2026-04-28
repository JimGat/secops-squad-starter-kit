# Skills Catalog

**The AI agents' knowledge packs.** Each skill is a markdown file with core patterns, real-world examples, and MITRE ATT&CK mappings. Load them via your persona or request specific skills on demand.

---

## Phase 1: Shipped Skills (6 Total)

### KQL Hunting & Detection (3 skills)

#### 1. Threat Hunting Foundations
| Property | Value |
|----------|-------|
| **Category** | KQL |
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | T1078 (Valid Accounts), T1566 (Phishing), T1059 (Command and Scripting Interpreter) |
| **Products** | Sentinel, Defender for Endpoint, Entra ID |
| **Use When** | Starting a proactive hunt (no incident), building behavioral baselines, entity pivoting, finding rare events |
| **Author** | Freamon |
| **Version** | 1.0.0 |

Core patterns teach hypothesis-driven threat hunting in KQL. Learn entity pivoting, building baselines, and anomaly detection across logs, authentication, and process data.

**File:** [`skills/kql/threat-hunting-foundations.md`](../skills/kql/threat-hunting-foundations.md)

---

#### 2. Sentinel Analytics Rules
| Property | Value |
|----------|-------|
| **Category** | KQL |
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | T1110 (Brute Force), T1078 (Valid Accounts), T1098 (Account Manipulation) |
| **Products** | Sentinel, Entra ID, Defender for Endpoint |
| **Use When** | Converting a threat hunt into automated detection, writing new scheduled/NRT rules, enriching alerts with entity mappings, building multi-stage detections |
| **Author** | Freamon |
| **Version** | 1.0.0 |

Core patterns for building Sentinel analytics rules — both scheduled and NRT. Learn entity mapping, alert enrichment, grouping strategies, and multi-stage correlation across time windows.

**File:** [`skills/kql/sentinel-analytics-rules.md`](../skills/kql/sentinel-analytics-rules.md)

---

#### 3. Incident Investigation
| Property | Value |
|----------|-------|
| **Category** | KQL |
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | T1021 (Remote Services), T1071 (Application Layer Protocol), T1048 (Exfiltration Over Alternative Protocol) |
| **Products** | Sentinel, Defender for Endpoint, Entra ID, Defender for Cloud Apps |
| **Use When** | Triaging a Sentinel incident, pivoting from IOCs, tracing lateral movement, building evidence timelines, assessing exfiltration risk |
| **Author** | Freamon |
| **Version** | 1.0.0 |

Reactive investigation patterns for when an alert fires. Learn query sequences for scope analysis, pivot chains (IP → user → device), authentication traces, and forensic reporting.

**File:** [`skills/kql/incident-investigation.md`](../skills/kql/incident-investigation.md)

---

### SOAR Automation (3 skills)

#### 4. Phishing Incident Auto-Triage & Remediation
| Property | Value |
|----------|-------|
| **Category** | SOAR |
| **Difficulty** | Advanced |
| **Trigger** | Sentinel incident (phishing-related analytics rules) |
| **MITRE ATT&CK** | T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link) |
| **Products** | Sentinel, Defender for Office 365, Office 365, Entra ID, Microsoft Defender Threat Intelligence |
| **Playbook Type** | Logic Apps |
| **Use When** | Phishing alerts need automated triage, enrichment, and remediation at scale |
| **Author** | Herc |
| **Version** | 1.0.0 |

Automates the full lifecycle of a phishing incident: triage via Defender for Office 365, verdict (malicious/suspicious/clean), IOC enrichment with threat intel, message removal from mailboxes, user notification, and closure.

**What it does:**
1. Triggered by Sentinel incident from phishing detection rules
2. Enriches email headers and URLs with Defender for Office 365 and VirusTotal
3. Determines verdict (malicious → remove all copies; suspicious → flag and monitor; clean → close)
4. Removes malicious mail and forwards to inbox rule for future blocks
5. Sends user notifications and trains security awareness
6. Closes incident or escalates for manual review

**Phase 1 Status:** Skill documented; playbook scaffold in Phase 2.

**File:** [`skills/soar/phishing-response.md`](../skills/soar/phishing-response.md)

---

#### 5. Compromised Account Auto-Response
| Property | Value |
|----------|-------|
| **Category** | SOAR |
| **Difficulty** | Advanced |
| **Trigger** | Sentinel incident (identity-based alerts or Entra ID Protection risk events) |
| **MITRE ATT&CK** | T1078 (Valid Accounts), T1078.004 (Cloud Accounts), T1110 (Brute Force), T1110.003 (Password Spraying) |
| **Products** | Sentinel, Entra ID, Entra ID Protection, Microsoft Graph, Teams |
| **Playbook Type** | Logic Apps |
| **Use When** | A user account is compromised (high-risk sign-in, password spray, brute force), containment is urgent |
| **Author** | Herc |
| **Version** | 1.0.0 |

Automates containment and remediation of compromised user accounts: revokes active sessions, enforces MFA re-registration, resets risky passwords, blocks sign-in risk, and escalates to incident commander.

**What it does:**
1. Triggered by Sentinel incident from identity analytics or Entra ID Protection
2. Extracts affected user(s) and risk level
3. Revokes all active sessions (forces re-auth)
4. Requires MFA re-registration on next sign-in
5. Resets password (if password spray/brute force) or marks for manual reset (if compromise suspected)
6. Blocks risky sign-ins for the user
7. Notifies incident commander via Teams with escalation buttons
8. Waits for approval before dismissing risk signals

**Phase 1 Status:** Skill documented; playbook scaffold in Phase 2.

**File:** [`skills/soar/compromised-account.md`](../skills/soar/compromised-account.md)

---

#### 6. Sentinel Incident Teams Notification (Adaptive Card)
| Property | Value |
|----------|-------|
| **Category** | SOAR |
| **Difficulty** | Beginner |
| **Trigger** | Any new Sentinel incident |
| **Products** | Sentinel, Teams |
| **Playbook Type** | Logic Apps |
| **Use When** | Incidents should notify the team immediately (don't wait for portal checks), quick triage actions needed |
| **Author** | Herc |
| **Version** | 1.0.0 |

Sends a rich Teams notification (Adaptive Card) for every new Sentinel incident. Includes severity colors, entity summaries, direct Sentinel links, and one-click triage actions (Assign to Me, Escalate, Close as FP).

**What it does:**
1. Triggered on any new Sentinel incident
2. Extracts incident metadata: title, description, severity, status, entities, tactics
3. Formats a severity-color-coded Adaptive Card
4. Routes to Teams channels by severity (critical → #security-critical, high → #security-incidents, etc.)
5. Includes entity summary with hyperlinks to data
6. Adds action buttons for quick triage: Assign to Me, Escalate, Close as False Positive
7. Posts follow-up thread with detailed entity information
8. Falls back to email if Teams delivery fails

**Business justification:** Analysts discover incidents faster, respond sooner, and spend less time in the portal.

**Phase 1 Status:** Skill documented; playbook scaffold in Phase 2.

**File:** [`skills/soar/teams-notification.md`](../skills/soar/teams-notification.md)

---

## Phase 2: Coming Next

### KQL & Detection (Planned)
- **Log Analytics Data Ingestion** — Connectors, table schemas, ingestion optimization, cost control
- **Azure Data Explorer (ADX) Hunting** — Long-term retention, cross-workspace analytics, time-series patterns
- **Detection Rule Tuning** — Threshold optimization, false positive reduction, alert fatigue analysis
- **MITRE ATT&CK Mapping for KQL** — Tactics/techniques for every detection pattern

### SOAR & Automation (Planned)
- **Sentinel Playbook Scaffolding** — Template engine for Logic Apps and Functions
- **Advanced Response Workflows** — Multi-stage containment, orchestrated across teams
- **Custom Connector Patterns** — Integration with third-party SIEM, ticketing, and communication tools

### Personas (Planned)
- **Detection Engineering** persona skills — Rule authoring workflows, tuning practices
- **Threat Hunting** persona skills — Hypothesis library, campaign tracking, persistence check patterns
- **Cloud Security** persona skills — Defender for Cloud, CSPM, cloud forensics
- **Incident Response** persona skills — IR procedures, forensic analysis workflows, containment playbooks
- **Full SOC** persona — All skills combined for multi-disciplinary teams

---

## How to Load a Skill

### By Persona (Recommended)
Personas come pre-loaded with relevant skills. Select SOC Analyst at init:

```bash
secops-squad init
```

Then all 6 Phase 1 skills load automatically.

### Individual Skill (Ad-hoc)
Load a specific skill on demand:

```bash
secops-squad skill threat-hunting-foundations
```

View what the skill teaches:

```bash
cat skills/kql/threat-hunting-foundations.md
```

### Custom Skill
Create your own by adding a markdown file to `skills/` with frontmatter (title, category, difficulty, MITRE ATT&CK, products, author). Then:

```bash
secops-squad skill my-custom-hunt
```

See [Personas Guide](personas-guide.md) for details on building custom skills and personas.

---

## Learning Path

### New to Threat Hunting?
1. Start with **Threat Hunting Foundations** (KQL) — Learn methodology, entity pivoting, anomaly detection
2. Explore **templates/kql/** — Try real hunting queries against your Sentinel workspace
3. Move to **Incident Investigation** (KQL) — Practice reactive triage scenarios

### New to SOAR?
1. Read **Sentinel Incident Teams Notification** (SOAR) — Understand playbook structure and Teams integration
2. Move to **Phishing Incident Auto-Triage** (SOAR) — See multi-step orchestration with enrichment
3. Advance to **Compromised Account Auto-Response** (SOAR) — Learn identity remediation patterns

### Building a Detection Rule?
1. Start with **Threat Hunting Foundations** — Find the signal (hunt)
2. Use **Sentinel Analytics Rules** — Formalize as an automated detection
3. Test against your workspace with `secops-squad kql validate`

---

## Contributing a Skill

Have a great KQL pattern or automation workflow? Contribute it as a skill:

1. Write a markdown file with frontmatter (copy the structure from an existing skill)
2. Include real examples, core patterns, common mistakes, and use cases
3. Tag with MITRE ATT&CK technique IDs
4. Open a PR to `skills/<category>/` with the label `skill-request`
5. The squad will review and merge

See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.

---

**Last Updated:** 2026-04-28  
**Phase 1 Release:** 6 skills across KQL and SOAR
