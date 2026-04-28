# secops-squad

[![Node.js](https://img.shields.io/badge/Node.js-18+-green)](https://nodejs.org/) [![MIT License](https://img.shields.io/badge/License-MIT-blue)](LICENSE) [![Phase 2 Release](https://img.shields.io/badge/Phase-2%20Active-brightgreen)](docs/getting-started.md)

**AI-powered SecOps team framework for the Microsoft Security stack.**

secops-squad gives you a team of specialized AI agents — each with deep knowledge of Microsoft Sentinel, Defender XDR, KQL, SOAR playbooks, and threat hunting — working together in your repository. Pick a persona, load your skills, and go hunting.

---

## Quick Start

```bash
npx secops-squad init
```

This walks you through persona selection, Azure workspace configuration, and deploys a `secops-squad.config.json` in your repo root. You'll have a working SOC Analyst setup with KQL hunting and phishing response automation in under 15 minutes.

## What's in the Box

### 📦 Current Phase 2 Inventory

```
secops-squad/
├── personas/
│   ├── soc-analyst/              — Live (Phase 1)
│   ├── detection-engineering/    — Live (Phase 2)
│   ├── threat-hunting/           — Live (Phase 2)
│   ├── cloud-security/           — Live (Phase 2)
│   ├── incident-response/        — Live (Phase 2)
│   └── full-soc/                 — Live (Phase 2)
├── skills/
│   ├── kql/                      — 10 hunting & detection skills
│   ├── soar/                     — 10 automation & playbook skills
│   ├── detection/                — 8 detection engineering skills
│   ├── log-analytics/            — Coming Phase 3
│   ├── adx/                      — Coming Phase 3
│   └── msft-security/            — Coming Phase 3
├── templates/
│   ├── kql/                      — Hunting and detection query library
│   └── bicep/                    — Sentinel workspace scaffolds
└── cli/                          — Command-line tools
```

### 🎯 Personas

| Persona | Status | Focus | Load With |
|---------|--------|-------|-----------|
| **SOC Analyst** | ✅ Live | Triage, investigation, incident response | `secops-squad init` → Select SOC Analyst |
| **Detection Engineering** | ✅ Live | Rule authoring, KQL, MITRE ATT&CK mapping | `secops-squad init` → Select Detection Engineering |
| **Threat Hunting** | ✅ Live | Proactive hunting, hypothesis-driven investigations | `secops-squad init` → Select Threat Hunting |
| **Cloud Security** | ✅ Live | Cloud posture, Defender for Cloud, identity | `secops-squad init` → Select Cloud Security |
| **Incident Response** | ✅ Live | IR procedures, forensics, containment | `secops-squad init` → Select Incident Response |
| **Full SOC** | ✅ Live | All skills (for teams wearing every hat) | `secops-squad init` → Select Full SOC |

See [Personas Guide](docs/personas-guide.md) for details on switching personas and building custom ones.

### 🛠 Skills Library

Currently shipped with **28 core skills** across **3 categories**:

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

See [Skills Catalog](docs/skills-catalog.md) for full inventory with difficulty levels and MITRE ATT&CK mappings.

### 📐 Templates
Ready-to-deploy infrastructure and query templates:

- **KQL Templates** — Hunting queries, detection rules, investigation notebooks organized by MITRE tactic (in `templates/kql/`)
- **Bicep Templates** — ARM templates for Sentinel workspace provisioning (in `templates/bicep/`)

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

### Phase 2 — Expansion ✅ ACTIVE
- [x] Additional personas (Detection Engineering, Threat Hunting, Cloud Security, Incident Response, Full SOC)
- [x] Extended KQL skills (10 total, +7 new)
- [x] Extended SOAR skills (10 total, +7 new)
- [x] Detection Engineering skills (8 new)
- [x] Updated Skills Catalog (28 shipped skills)
- [x] Updated Personas Guide (6 active personas)
- [x] Updated README (Phase 2 inventory)
- [ ] KQL validator library
- [ ] SOAR playbook deployment engine
- [ ] Graph Security API integration
- [ ] Azure auth helper and workspace auto-discovery
- [ ] Template engine for Bicep deployments
- [ ] CLI interactive mode

### Phase 3 — Advanced (Planned)
- [ ] Log Analytics skills (8 planned)
- [ ] Microsoft Security Products skills (8 planned)
- [ ] Azure Data Explorer skills (8 planned)
- [ ] Advanced automation workflows
- [ ] Cross-workspace federation patterns
- [ ] Compliance and audit reporting

## Getting Started

See the full [Getting Started Guide](docs/getting-started.md) for prerequisites, installation, and your first run.

## Contributing

Contributions welcome! The project uses a squad-based development model:

1. Check open issues — look for `detection-request`, `playbook-request`, or `hunt-request` labels
2. Fork and create a feature branch
3. Follow the persona/skill structure when adding new content
4. KQL files are validated on PR — make sure queries parse cleanly
5. Open a PR and the squad will review

## License

[MIT](LICENSE)
