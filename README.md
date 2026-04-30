# secops-squad

[![Node.js](https://img.shields.io/badge/Node.js-18+-green)](https://nodejs.org/) [![MIT License](https://img.shields.io/badge/License-MIT-blue)](LICENSE) [![Phase 3 Release](https://img.shields.io/badge/Phase-3%20Active-brightgreen)](docs/getting-started.md)

**AI-powered SecOps team framework for the Microsoft Security stack.**

secops-squad gives you a team of specialized AI agents — each with deep knowledge of Microsoft Sentinel, Defender XDR, KQL, SOAR playbooks, and threat hunting — working together in your repository. Pick a persona, load your skills, and go hunting.

---

## Quick Start

```bash
npx secops-squad init
```

This walks you through persona selection, Azure workspace configuration, and deploys a `secops-squad.config.json` in your repo root. You'll have a working SOC Analyst setup with KQL hunting and phishing response automation in under 15 minutes.

## What's in the Box

### 📦 Current Phase 3 Inventory

```
secops-squad/
├── personas/                     — 6 live personas
│   ├── soc-analyst/              ✅ Phase 1
│   ├── detection-engineering/    ✅ Phase 2
│   ├── threat-hunting/           ✅ Phase 2
│   ├── cloud-security/           ✅ Phase 2
│   ├── incident-response/        ✅ Phase 2
│   └── full-soc/                 ✅ Phase 2
├── skills/                       — 36 total skills
│   ├── kql/                      ✅ 10 hunting & detection
│   ├── soar/                     ✅ 10 automation & playbook
│   ├── detection/                ✅ 8 detection engineering
│   └── adx/                      ✅ 8 Azure Data Explorer (Phase 3)
├── templates/
│   ├── threat-models/            ✅ 10 MITRE tactic templates (Phase 3)
│   ├── bicep/
│   │   ├── sentinel/             ✅ Workspace scaffolds
│   │   └── adx/                  ✅ Security data lake (Phase 3)
│   └── kql/                      ✅ Query library
├── lib/
│   └── graph-security/           ✅ Graph Security API (zero-dependency) (Phase 3)
└── cli/                          — Command-line tools
```

### 🎯 Personas (6 Live)

| Persona | Status | Focus | Load With |
|---------|--------|-------|-----------|
| **SOC Analyst** | ✅ Live | Triage, investigation, incident response | `secops-squad init` → SOC Analyst |
| **Detection Engineering** | ✅ Live | Rule authoring, KQL, MITRE ATT&CK mapping | `secops-squad init` → Detection Engineering |
| **Threat Hunting** | ✅ Live | Proactive hunting, hypothesis-driven investigations | `secops-squad init` → Threat Hunting |
| **Cloud Security** | ✅ Live | Cloud posture, Defender for Cloud, identity | `secops-squad init` → Cloud Security |
| **Incident Response** | ✅ Live | IR procedures, forensics, containment | `secops-squad init` → Incident Response |
| **Full SOC** | ✅ Live | All skills (complete, mature SOC) | `secops-squad init` → Full SOC |

See [Personas Guide](docs/personas-guide.md) for details on personas, ADX integration, and threat modeling.

### 🛠 Skills Library

**Phase 3 Active: 36 core skills** across **4 categories**:

#### KQL Hunting & Detection (10 skills)
- [**Threat Hunting Foundations**](skills/kql/threat-hunting-foundations.md) — Hypothesis-driven hunting, baseline building, entity pivoting
- [**Sentinel Analytics Rules**](skills/kql/sentinel-analytics-rules.md) — Scheduled/NRT rule patterns, entity mapping, multi-stage detection
- [**Entra Sign-In Analysis**](skills/kql/entra-signin-analysis.md) — Authentication anomalies, risk detection, account compromise
- [**Incident Investigation**](skills/kql/incident-investigation.md) — Reactive triage, pivot chains, lateral movement tracing
- [**Cloud Security Posture**](skills/kql/cloud-security-posture.md) — Cloud config audit, compliance, identity risk
- [**Detection Tuning**](skills/kql/detection-tuning.md) — Threshold optimization, false positive reduction
- [**Defender XDR Advanced Hunting**](skills/kql/defender-xdr-hunting.md) — Cross-product hunting across Defender suite
- [**Cross-Workspace Queries**](skills/kql/cross-workspace-queries.md) — Multi-workspace, multi-tenant investigations
- [**ADX Integration**](skills/kql/adx-integration.md) — Long-term retention and time-series analytics
- [**UEBA Patterns**](skills/kql/ueba-patterns.md) — User behavior analytics, anomaly detection, insider threats

#### SOAR Automation (10 skills)
- [**Sentinel Incident Teams Notification**](skills/soar/teams-notification.md) — Adaptive Card alerts, severity routing, quick actions
- [**Sentinel Enrichment — User**](skills/soar/sentinel-enrichment-user.md) — Auto-enrich with Entra ID context
- [**Sentinel Enrichment — IP**](skills/soar/sentinel-enrichment-ip.md) — Threat intelligence enrichment
- [**Phishing Incident Auto-Response**](skills/soar/phishing-response.md) — MDO triage, verdict, message removal
- [**Compromised Account Response**](skills/soar/compromised-account.md) — Entra ID containment, session revocation, MFA enforcement
- [**L1 Auto-Triage**](skills/soar/auto-triage.md) — Evidence-based incident routing
- [**Malware Containment**](skills/soar/malware-containment.md) — Endpoint isolation, evidence collection
- [**Data Exfiltration Response**](skills/soar/data-exfiltration-response.md) — DLP enrichment, content blocking, user notification
- [**Threat Intelligence Ingest**](skills/soar/threat-intel-ingest.md) — TAXII/STIX to Sentinel TI ingestion
- [**ITSM Ticket Creation**](skills/soar/ticket-create.md) — ServiceNow/JIRA bidirectional sync

#### Detection Engineering (8 skills)
- [**MITRE ATT&CK Mapping**](skills/detection/mitre-attack-mapping.md) — Technique alignment, coverage analysis
- [**Detection Lifecycle**](skills/detection/detection-lifecycle.md) — Design, test, deploy, tune workflow
- [**Scheduled Analytics Rule Pattern**](skills/detection/scheduled-rule-pattern.md) — Core pattern with production examples
- [**NRT Rule Pattern**](skills/detection/nrt-rule-pattern.md) — Minute-level real-time detection
- [**Threat Model Template**](skills/detection/threat-model-template.md) — Adversary-centric detection design
- [**Fusion Rule Context**](skills/detection/fusion-rule-context.md) — ML-based multi-stage attack detection
- [**Watchlist-Driven Detection**](skills/detection/watchlist-driven-detection.md) — Reference data integration and automation
- [**Custom KQL Function Authoring**](skills/detection/custom-kql-function.md) — Reusable function libraries and patterns

#### Azure Data Explorer (8 skills, Phase 3)
- [**ADX Cluster Architecture**](skills/adx/cluster-architecture.md) — SKU selection, scaling, failover, and topology
- [**Security Data Modeling**](skills/adx/security-data-modeling.md) — Schema design for logs, events, and time-series data
- [**Data Ingestion Patterns**](skills/adx/data-ingestion.md) — Event Hub, IoT Hub, Event Grid, and batch ingestion
- [**Long-Term Retention Strategies**](skills/adx/long-term-retention.md) — Archival, purge policies, cost optimization
- [**Cross-Cluster Queries**](skills/adx/cross-cluster-queries.md) — Federated querying across ADX clusters
- [**Migration from Sentinel**](skills/adx/migration-from-sentinel.md) — Archival and log transition workflows
- [**ML & Anomaly Detection**](skills/adx/adx-ml-anomaly.md) — Time-series anomalies, forecasting, baselines
- [**ADX Dashboards**](skills/adx/adx-dashboards.md) — Real-time visualization and KPI tracking

See [Skills Catalog](docs/skills-catalog.md) for full inventory with difficulty levels and MITRE ATT&CK mappings.

### 📐 Templates

Ready-to-deploy infrastructure and security templates:

#### Threat Model Templates (10, Phase 3)
- [**Initial Access**](templates/threat-models/initial-access.md) — T1189, T1199, T1200, T1566, T1091, T1195
- [**Persistence**](templates/threat-models/persistence.md) — T1098, T1197, T1547, T1098, T1547, T1547
- [**Privilege Escalation**](templates/threat-models/privilege-escalation.md) — T1548, T1134, T1547, T1548
- [**Defense Evasion**](templates/threat-models/defense-evasion.md) — T1548, T1197, T1134, T1562
- [**Credential Access**](templates/threat-models/credential-access.md) — T1110, T1555, T1187, T1040
- [**Lateral Movement**](templates/threat-models/lateral-movement.md) — T1210, T1570, T1570, T1021
- [**Exfiltration**](templates/threat-models/exfiltration.md) — T1020, T1030, T1048, T1041
- [**Impact**](templates/threat-models/impact.md) — T1531, T1485, T1561, T1491

See [Threat Models Guide](templates/threat-models/README.md) for detailed MITRE ATT&CK alignment and usage.

#### Infrastructure Templates
- **KQL Templates** — Hunting queries, detection rules, investigation notebooks organized by MITRE tactic (in `templates/kql/`)
- **Sentinel Bicep** — Sentinel workspace scaffolds and configuration-as-code (in `templates/bicep/sentinel/`)
- **ADX Bicep** — Security data lake deployment with cluster, database, tables, and ingestion (in `templates/bicep/adx/`). See [ADX Bicep README](templates/bicep/adx/README.md).

### 📚 Libraries

#### Graph Security API Library (Phase 3)
Zero-dependency Node.js library for Microsoft Graph Security v1.0 — alert management, incident correlation, threat intelligence, and security posture tracking. Includes 4 modules with 3 authentication flows.

**File:** [`lib/graph-security/`](lib/graph-security/README.md)

See [Graph Security API Guide](docs/graph-security-api.md) for detailed usage examples, auth patterns, and error handling.

### 🔍 KQL Validation
Built-in KQL syntax validation runs on every PR that touches query files:
```bash
secops-squad kql validate
```

## Supported Microsoft Security Products

- Microsoft Sentinel ✅
- Microsoft Defender XDR (incidents, advanced hunting) ✅
- Microsoft Defender for Endpoint ✅
- Microsoft Defender for Cloud (coming Phase 2)
- Microsoft Defender for Identity ✅
- Microsoft Defender for Office 365 ✅
- Microsoft Entra ID Protection ✅
- Microsoft Purview (coming Phase 2)
- Microsoft Intune (coming Phase 2)

## CLI Commands

```
secops-squad init          Set up a new secops-squad project
secops-squad doctor        Check environment prerequisites
secops-squad status        Show current config and loaded skills
secops-squad skill <name>  Load or inspect a skill
secops-squad persona       Switch active persona (Phase 2)
secops-squad workspace     Manage Sentinel workspace connection
secops-squad kql           KQL query tools (validate, run, explain)
secops-squad playbook      SOAR playbook tools (scaffold, deploy) — Phase 2
```

## Project Status

### Phase 1 — Foundation ✅ SHIPPED
- [x] Project structure and scaffold
- [x] **SOC Analyst persona** (fully populated)
- [x] **6 core skills** (3 KQL, 3 SOAR) with MITRE ATT&CK mapping
- [x] Config schema and validation
- [x] CLI entry point (init, doctor, status, kql)
- [x] KQL validation CI workflow
- [x] Issue templates for detection requests, playbook requests, and threat hunts
- [x] Getting Started guide with real workflows
- [x] Skills Catalog and Personas Guide

### Phase 2 — Expansion ✅ SHIPPED
- [x] Additional personas (Detection Engineering, Threat Hunting, Cloud Security, Incident Response, Full SOC)
- [x] Extended KQL skills (10 total, +7 new)
- [x] Extended SOAR skills (10 total, +7 new)
- [x] Detection Engineering skills (8 new)
- [x] Updated Skills Catalog (28 shipped skills)
- [x] Updated Personas Guide (6 active personas)
- [x] Updated README (Phase 2 inventory)
- [x] KQL validator library
- [x] SOAR playbook deployment engine
- [x] Graph Security API integration (zero-dependency)
- [x] Azure auth helper and workspace auto-discovery
- [x] Template engine for Bicep deployments
- [x] CLI interactive mode

### Phase 3 — Data & Security (🚀 ACTIVE)
- [x] **8 ADX skills** (cluster architecture, security data modeling, ingestion, long-term retention, cross-cluster queries, migration, ML/anomaly, dashboards)
- [x] **10 Threat Model templates** (Initial Access, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Lateral Movement, Exfiltration, Impact)
- [x] **Graph Security API library** (alerts, incidents, threat-intelligence, secure-score modules with 3 auth flows)
- [x] **ADX Bicep templates** (cluster, database, tables, ingestion with dev/standard/production tiers)
- [x] **ADX Setup Guide** (quick-start, ADX vs Log Analytics, integration patterns)
- [x] **Graph Security API documentation** (usage examples, auth flows, error handling)
- [ ] Threat Hunting automation workflows
- [ ] Detection rule tuning recommendations
- [ ] ADX SIEM connector for Sentinel

### Phase 4 — Optimization (Planned)
- [ ] Advanced automation workflows
- [ ] Cross-workspace federation patterns
- [ ] Compliance and audit reporting
- [ ] Performance optimization guidance

## Installation

### Quick Setup (Recommended)

```bash
# macOS / Linux
./install.sh

# Windows PowerShell
.\install.ps1
```

This downloads secops-squad, creates a standalone project in `~/secops-squad` (not linked to the upstream repo), installs dependencies, and initializes a fresh git repository. See [install.sh](install.sh) and [install.ps1](install.ps1) for advanced options.

### Via npm

```bash
npm install -g secops-squad
secops-squad init
```

See [Getting Started](docs/getting-started.md) for post-install configuration and your first hunt.

## Documentation

- [**Getting Started**](docs/getting-started.md) — Installation, init wizard, your first hunt
- [**Skills Catalog**](docs/skills-catalog.md) — All 36 skills with difficulty, MITRE ATT&CK, and coverage
- [**Personas Guide**](docs/personas-guide.md) — All 6 personas, team composition, ADX integration notes
- [**ADX Setup Guide**](docs/adx-setup.md) — Azure Data Explorer quick-start, when to use ADX vs Log Analytics
- [**Graph Security API**](docs/graph-security-api.md) — Library usage, examples, auth flows, error handling

## Contributing

Contributions welcome! The project uses a squad-based development model:

1. Check open issues — look for `detection-request`, `playbook-request`, or `hunt-request` labels
2. Fork and create a feature branch
3. Follow the persona/skill structure when adding new content
4. KQL files are validated on PR — make sure queries parse cleanly
5. Open a PR and the squad will review

## License

[MIT](LICENSE)
