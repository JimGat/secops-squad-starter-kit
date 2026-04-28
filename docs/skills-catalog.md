# Skills Catalog

**The AI agents' knowledge packs.** Each skill is a markdown file with core patterns, real-world examples, and MITRE ATT&CK mappings. Load them via your persona or request specific skills on demand.

---

## Phase 3: Active Skills (36 Total)

### KQL Hunting & Detection (10 skills)

#### 1. Threat Hunting Foundations
| Property | Value |
|----------|-------|
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | T1078, T1566, T1059 |
| **Products** | Sentinel, Defender for Endpoint, Entra ID |
| **Author** | Freamon |

Hypothesis-driven threat hunting methodology: entity pivoting, behavioral baselines, anomaly detection across logs, authentication, and process data.

**File:** [`skills/kql/threat-hunting-foundations.md`](../skills/kql/threat-hunting-foundations.md)

---

#### 2. Sentinel Analytics Rules
| Property | Value |
|----------|-------|
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | T1110, T1078, T1098 |
| **Products** | Sentinel, Entra ID, Defender for Endpoint |
| **Author** | Freamon |

Core patterns for building Sentinel analytics rules — both scheduled and NRT. Entity mapping, alert enrichment, grouping strategies, and multi-stage correlation.

**File:** [`skills/kql/sentinel-analytics-rules.md`](../skills/kql/sentinel-analytics-rules.md)

---

#### 3. Entra Sign-In Analysis
| Property | Value |
|----------|-------|
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | T1078, T1110, T1556 |
| **Products** | Entra ID, Sentinel, Log Analytics |
| **Author** | Freamon |

Analyze authentication events, risk signals, and sign-in patterns to detect account compromise, brute force attacks, and authentication anomalies.

**File:** [`skills/kql/entra-signin-analysis.md`](../skills/kql/entra-signin-analysis.md)

---

#### 4. Incident Investigation
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | T1021, T1071, T1048 |
| **Products** | Sentinel, Defender for Endpoint, Entra ID, Defender for Cloud Apps |
| **Author** | Freamon |

Reactive investigation patterns for incident triage: scope analysis, pivot chains (IP → user → device), authentication traces, forensic reporting.

**File:** [`skills/kql/incident-investigation.md`](../skills/kql/incident-investigation.md)

---

#### 5. Cloud Security Posture
| Property | Value |
|----------|-------|
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | T1078, T1190, T1530, T1562 |
| **Products** | Defender for Cloud, Sentinel, Azure Resource Graph |
| **Author** | Freamon |

Analyze cloud configuration, compliance, and resource security posture. Identify misconfigurations, identity risks, and data exposure in Azure environments.

**File:** [`skills/kql/cloud-security-posture.md`](../skills/kql/cloud-security-posture.md)

---

#### 6. Detection Tuning
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | T1078, T1059, T1110 |
| **Products** | Sentinel, Defender for Endpoint, Log Analytics |
| **Author** | Freamon |

Threshold optimization, false positive reduction, alert fatigue analysis, and detection rule tuning for production environments.

**File:** [`skills/kql/detection-tuning.md`](../skills/kql/detection-tuning.md)

---

#### 7. Defender XDR Advanced Hunting
| Property | Value |
|----------|-------|
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | T1059, T1071, T1078, T1566, T1053 |
| **Products** | Defender for Endpoint, Defender for Office 365, Defender for Identity, Defender for Cloud Apps |
| **Author** | Freamon |

Cross-product hunting in the Defender XDR platform: DeviceProcessEvents, EmailEvents, IdentityLogonEvents correlation and investigation patterns.

**File:** [`skills/kql/defender-xdr-hunting.md`](../skills/kql/defender-xdr-hunting.md)

---

#### 8. Cross-Workspace Queries
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | T1078, T1059, T1071, T1021 |
| **Products** | Sentinel, Log Analytics, Azure Lighthouse |
| **Author** | Freamon |

Multi-workspace and multi-tenant queries for large-scale investigations, federated security operations, and cross-boundary threat hunting.

**File:** [`skills/kql/cross-workspace-queries.md`](../skills/kql/cross-workspace-queries.md)

---

#### 9. ADX Integration
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | T1078, T1059, T1027 |
| **Products** | Azure Data Explorer, Sentinel, Log Analytics |
| **Author** | Freamon |

Integrate Azure Data Explorer for long-term retention, time-series analysis, and large-scale data analytics alongside Sentinel and Log Analytics.

**File:** [`skills/kql/adx-integration.md`](../skills/kql/adx-integration.md)

---

#### 10. UEBA Patterns
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | T1078, T1098, T1087, T1071 |
| **Products** | Sentinel, Sentinel UEBA, Entra ID, Defender for Endpoint |
| **Author** | Freamon |

User and Entity Behavior Analytics patterns: anomaly detection, privilege escalation, impossible travel, and insider threat indicators.

**File:** [`skills/kql/ueba-patterns.md`](../skills/kql/ueba-patterns.md)

---

### SOAR Automation (10 skills)

#### 11. Sentinel Incident Teams Notification
| Property | Value |
|----------|-------|
| **Difficulty** | Beginner |
| **MITRE ATT&CK** | — |
| **Products** | Sentinel, Teams |
| **Author** | Herc |

Rich Adaptive Card notifications to Teams for all new Sentinel incidents. Severity routing, entity summaries, and one-click triage actions.

**File:** [`skills/soar/teams-notification.md`](../skills/soar/teams-notification.md)

---

#### 12. Sentinel Enrichment — User Account Context
| Property | Value |
|----------|-------|
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | T1078, T1110, T1136, T1098 |
| **Products** | Sentinel, Entra ID |
| **Author** | Herc |

Auto-enrich Sentinel incidents with user account context: risk levels, group memberships, recent sign-in activity, and compliance status from Entra ID.

**File:** [`skills/soar/sentinel-enrichment-user.md`](../skills/soar/sentinel-enrichment-user.md)

---

#### 13. Sentinel Enrichment — IP Address Threat Intelligence
| Property | Value |
|----------|-------|
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | T1071, T1090, T1573, T1105 |
| **Products** | Sentinel, Defender Threat Intelligence, VirusTotal |
| **Author** | Herc |

Auto-enrich IP entities with threat intelligence: geolocation, ASN, threat feeds, VirusTotal reputation, and malware associations.

**File:** [`skills/soar/sentinel-enrichment-ip.md`](../skills/soar/sentinel-enrichment-ip.md)

---

#### 14. Phishing Incident Auto-Triage & Remediation
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | T1566, T1566.001, T1566.002 |
| **Products** | Sentinel, Defender for Office 365, Office 365, Entra ID, Threat Intelligence |
| **Author** | Herc |

Automate phishing lifecycle: Defender for Office 365 triage, verdict determination, IOC enrichment, malicious message removal, user notification, and closure.

**File:** [`skills/soar/phishing-response.md`](../skills/soar/phishing-response.md)

---

#### 15. Compromised Account Auto-Response
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | T1078, T1078.004 |
| **Products** | Sentinel, Entra ID, Entra ID Protection, Microsoft Graph, Teams |
| **Author** | Herc |

Automate account containment: revoke sessions, enforce MFA re-registration, reset passwords, block risky sign-ins, escalate to incident commander.

**File:** [`skills/soar/compromised-account.md`](../skills/soar/compromised-account.md)

---

#### 16. L1 Auto-Triage — Evidence-Based Incident Routing
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | — |
| **Products** | Sentinel, Entra ID |
| **Author** | Herc |

Evidence-based incident classification and routing: severity assessment, alert aggregation, triage queue management, and team assignment.

**File:** [`skills/soar/auto-triage.md`](../skills/soar/auto-triage.md)

---

#### 17. Malware Containment & Evidence Collection
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | T1486, T1059 |
| **Products** | Sentinel, Defender for Endpoint, Teams |
| **Author** | Herc |

Automate device containment for malware incidents: isolate endpoints, collect forensic evidence, quarantine files, and coordinate with SOC team.

**File:** [`skills/soar/malware-containment.md`](../skills/soar/malware-containment.md)

---

#### 18. Data Exfiltration Response — DLP Alert Enrichment & Blocking
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | T1567, T1048 |
| **Products** | Sentinel, Purview DLP, Entra ID, Teams |
| **Author** | Herc |

Automate DLP incident response: data flow tracing, user risk assessment, content blocking, user notification, and escalation.

**File:** [`skills/soar/data-exfiltration-response.md`](../skills/soar/data-exfiltration-response.md)

---

#### 19. Threat Intelligence Ingest — TAXII/STIX to Sentinel TI
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | — |
| **Products** | Sentinel |
| **Author** | Herc |

Automate IOC ingestion from external TAXII 2.1 servers into Sentinel's Threat Intelligence platform with deduplication and expiration management.

**File:** [`skills/soar/threat-intel-ingest.md`](../skills/soar/threat-intel-ingest.md)

---

#### 20. ITSM Ticket Creation — ServiceNow / JIRA Bi-Directional Sync
| Property | Value |
|----------|-------|
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | — |
| **Products** | Sentinel, ServiceNow, JIRA |
| **Author** | Herc |

Bidirectional sync between Sentinel incidents and external ITSM ticketing systems. Automate ticket creation, status updates, and ticket closure.

**File:** [`skills/soar/ticket-create.md`](../skills/soar/ticket-create.md)

---

### Detection Engineering (8 skills)

#### 21. MITRE ATT&CK Mapping for Detections
| Property | Value |
|----------|-------|
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | T1110, T1078, T1566 |
| **Products** | Sentinel, Defender for Endpoint, Defender for Identity |
| **Author** | Kima |

Align detections with MITRE ATT&CK framework: technique mapping, sub-technique classification, tactic alignment, and coverage analysis.

**File:** [`skills/detection/mitre-attack-mapping.md`](../skills/detection/mitre-attack-mapping.md)

---

#### 22. Detection Lifecycle — Design → Test → Deploy → Tune
| Property | Value |
|----------|-------|
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | T1110, T1566, T1078 |
| **Products** | Sentinel, Defender for Endpoint, Defender for Identity |
| **Author** | Kima |

Complete detection engineering lifecycle: threat model, KQL authoring, testing against known threats, production deployment, and ongoing tuning.

**File:** [`skills/detection/detection-lifecycle.md`](../skills/detection/detection-lifecycle.md)

---

#### 23. Scheduled Analytics Rule Pattern
| Property | Value |
|----------|-------|
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | T1110, T1078 |
| **Products** | Sentinel |
| **Author** | Kima |

The workhorse detection pattern: KQL query, fixed cadence execution, threshold evaluation, alert creation. Includes production-ready brute force example.

**File:** [`skills/detection/scheduled-rule-pattern.md`](../skills/detection/scheduled-rule-pattern.md)

---

#### 24. Near-Real-Time (NRT) Rule Pattern
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | T1190, T1078, T1133 |
| **Products** | Sentinel |
| **Author** | Kima |

Fastest detection mechanism in Sentinel: minute-level execution, no lookback window, real-time alerting. Learn constraints and optimization patterns.

**File:** [`skills/detection/nrt-rule-pattern.md`](../skills/detection/nrt-rule-pattern.md)

---

#### 25. Threat Model Template for Detection Engineering
| Property | Value |
|----------|-------|
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | T1566, T1566.001, T1566.002, T1078, T1539 |
| **Products** | Sentinel, Defender for Office 365, Entra ID Protection |
| **Author** | Kima |

Structured threat modeling for detection design: adversary objectives, detection opportunities, evasion tactics, and coverage verification.

**File:** [`skills/detection/threat-model-template.md`](../skills/detection/threat-model-template.md)

---

#### 26. Fusion Rule Context — Understanding ML-Based Multi-Stage Attack Detection
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | T1078, T1566, T1027, T1486, T1071 |
| **Products** | Sentinel, Defender for Cloud Apps, Defender for Identity, Entra ID Protection |
| **Author** | Kima |

ML-based multi-stage attack detection: Fusion rules, correlation across data sources, investigation context, and tuning guidance.

**File:** [`skills/detection/fusion-rule-context.md`](../skills/detection/fusion-rule-context.md)

---

#### 27. Watchlist-Driven Detection
| Property | Value |
|----------|-------|
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | T1078, T1078.004, T1566 |
| **Products** | Sentinel |
| **Author** | Kima |

Bring external reference data into detections: IP allowlists, VIP user lists, critical assets. Automation patterns for keeping watchlists current.

**File:** [`skills/detection/watchlist-driven-detection.md`](../skills/detection/watchlist-driven-detection.md)

---

#### 28. Custom KQL Function Authoring
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | T1071, T1078 |
| **Products** | Sentinel, Azure Monitor, Log Analytics |
| **Author** | Kima |

Reusable KQL functions for detection libraries: function syntax, parameter passing, performance optimization, and testing patterns.

**File:** [`skills/detection/custom-kql-function.md`](../skills/detection/custom-kql-function.md)

---

### Azure Data Explorer (8 skills, Phase 3)

#### 29. ADX Cluster Architecture
| Property | Value |
|----------|-------|
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | T1526, T1087 |
| **Products** | Azure Data Explorer, Azure |
| **Author** | Freamon |

Design and configure ADX clusters for security workloads: SKU selection, scaling, failover strategies, and topology optimization.

**File:** [`skills/adx/cluster-architecture.md`](../skills/adx/cluster-architecture.md)

---

#### 30. Security Data Modeling
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | T1526 |
| **Products** | Azure Data Explorer, Azure |
| **Author** | Freamon |

Schema design for security logs, events, and time-series data. Optimize for ingestion performance, query efficiency, and retention policies.

**File:** [`skills/adx/security-data-modeling.md`](../skills/adx/security-data-modeling.md)

---

#### 31. Data Ingestion Patterns
| Property | Value |
|----------|-------|
| **Difficulty** | Intermediate |
| **MITRE ATT&CK** | — |
| **Products** | Azure Data Explorer, Azure Event Hubs, Azure IoT Hub, Azure Event Grid |
| **Author** | Freamon |

Stream security data into ADX: Event Hub, IoT Hub, and Event Grid integrations. Batch upload patterns, update policies, and error handling.

**File:** [`skills/adx/data-ingestion.md`](../skills/adx/data-ingestion.md)

---

#### 32. Long-Term Retention Strategies
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | — |
| **Products** | Azure Data Explorer, Azure Storage |
| **Author** | Freamon |

Archive security data cost-effectively: hot/cold storage strategies, purge policies, compliance retention, and transition workflows.

**File:** [`skills/adx/long-term-retention.md`](../skills/adx/long-term-retention.md)

---

#### 33. Cross-Cluster Queries
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | T1526, T1087 |
| **Products** | Azure Data Explorer |
| **Author** | Freamon |

Federated querying across multiple ADX clusters for global threat hunting and multi-region security investigations.

**File:** [`skills/adx/cross-cluster-queries.md`](../skills/adx/cross-cluster-queries.md)

---

#### 34. Migration from Sentinel to ADX
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | — |
| **Products** | Sentinel, Azure Data Explorer, Log Analytics |
| **Author** | Freamon |

Archive Sentinel/Log Analytics data to ADX for long-term retention and compliance. Ingestion patterns, query migration, cost analysis.

**File:** [`skills/adx/migration-from-sentinel.md`](../skills/adx/migration-from-sentinel.md)

---

#### 35. ML & Anomaly Detection in ADX
| Property | Value |
|----------|-------|
| **Difficulty** | Advanced |
| **MITRE ATT&CK** | — |
| **Products** | Azure Data Explorer |
| **Author** | Freamon |

Detect security anomalies: time-series forecasting, baseline learning, spike detection, and behavioral analytics.

**File:** [`skills/adx/adx-ml-anomaly.md`](../skills/adx/adx-ml-anomaly.md)

---

#### 36. ADX Dashboards & Real-Time KPIs
| Property | Value |
|----------|-------|
| **Difficulty** | Beginner |
| **MITRE ATT&CK** | — |
| **Products** | Azure Data Explorer |
| **Author** | Freamon |

Create interactive dashboards for security KPI tracking: incident rates, threat detections, compliance status, and hunting progress.

**File:** [`skills/adx/adx-dashboards.md`](../skills/adx/adx-dashboards.md)

---

## Summary by Category

| Category | Count | Phase | Status |
|----------|-------|-------|--------|
| **KQL Hunting & Detection** | 10 | 2 | ✅ Active |
| **SOAR Automation** | 10 | 2 | ✅ Active |
| **Detection Engineering** | 8 | 2 | ✅ Active |
| **Azure Data Explorer** | 8 | 3 | ✅ Active |
| **Log Analytics** | 8 | 4 | 📋 Planned |
| **Microsoft Security Products** | 8 | 4 | 📋 Planned |
| **TOTAL** | **36** | — | — |

---

## How to Load a Skill

### By Persona (Recommended)
Personas come pre-loaded with relevant skills. Select a persona at init:

```bash
secops-squad init
```

Choose from: SOC Analyst, Detection Engineering, Threat Hunting, Cloud Security, Incident Response, Full SOC. All skills for that persona load automatically.

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
2. Use **Detection Lifecycle** — Understand the full engineering process
3. Use **Scheduled Analytics Rule Pattern** — Formalize as an automated detection
4. Test against your workspace with `secops-squad kql validate`

### New to Detection Engineering?
1. Start with **Detection Lifecycle** — Understand the complete process
2. Use **Threat Model Template** — Learn adversary-centric design
3. Implement with **Scheduled Analytics Rule Pattern** or **NRT Rule Pattern**
4. Map to **MITRE ATT&CK Mapping for Detections**

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
**Phase 2 Release:** 28 shipped skills across KQL, SOAR, and Detection Engineering  
**Coming Next:** Log Analytics, Microsoft Security Products, Azure Data Explorer skills
