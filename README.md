# secops-squad

[![Node.js](https://img.shields.io/badge/Node.js-18+-green)](https://nodejs.org/) [![MIT License](https://img.shields.io/badge/License-MIT-blue)](LICENSE) [![Phase 1 Release](https://img.shields.io/badge/Phase-1%20GA-blueviolet)](docs/getting-started.md)

**AI-powered SecOps team framework for the Microsoft Security stack.**

secops-squad gives you a team of specialized AI agents — each with deep knowledge of Microsoft Sentinel, Defender XDR, KQL, SOAR playbooks, and threat hunting — working together in your repository. Pick a persona, load your skills, and go hunting.

---

## Quick Start

```bash
npx secops-squad init
```

This walks you through persona selection, Azure workspace configuration, and deploys a `secops-squad.config.json` in your repo root. You'll have a working SOC Analyst setup with KQL hunting and phishing response automation in under 15 minutes.

## What's in the Box

### 📦 Current Phase 1 Inventory

```
secops-squad/
├── personas/
│   └── soc-analyst/          — Live, pre-built team configuration
├── skills/
│   ├── kql/
│   │   ├── threat-hunting-foundations.md
│   │   ├── sentinel-analytics-rules.md
│   │   └── incident-investigation.md
│   └── soar/
│       ├── phishing-response.md
│       ├── compromised-account.md
│       └── teams-notification.md
├── templates/
│   ├── kql/                  — Hunting and detection query library
│   └── bicep/                — Sentinel workspace scaffolds
└── cli/                      — Command-line tools
```

### 🎯 Personas

| Persona | Status | Focus | Load With |
|---------|--------|-------|-----------|
| **SOC Analyst** | ✅ Live | Triage, investigation, incident response | `secops-squad init` → Select SOC Analyst |
| **Detection Engineering** | 📋 Coming | Rule authoring, KQL, MITRE ATT&CK mapping | Phase 2 |
| **Threat Hunting** | 📋 Coming | Proactive hunting, hypothesis-driven investigations | Phase 2 |
| **Cloud Security** | 📋 Coming | Cloud posture, Defender for Cloud, identity | Phase 2 |
| **Incident Response** | 📋 Coming | IR procedures, forensics, containment | Phase 2 |
| **Full SOC** | 📋 Coming | All skills (for teams wearing every hat) | Phase 2 |

See [Personas Guide](docs/personas-guide.md) for details on switching personas and building custom ones.

### 🛠 Skills Library

Currently shipped with **6 core skills** across **2 categories**:

#### KQL Hunting & Detection (3 skills)
- [**Threat Hunting Foundations**](skills/kql/threat-hunting-foundations.md) — Hypothesis-driven hunting methodology, baseline building, entity pivoting
- [**Sentinel Analytics Rules**](skills/kql/sentinel-analytics-rules.md) — Scheduled/NRT rule patterns, entity mapping, multi-stage detection
- [**Incident Investigation**](skills/kql/incident-investigation.md) — Reactive triage, pivot chains, lateral movement tracing, impact assessment

#### SOAR Automation (3 skills)
- [**Phishing Incident Auto-Triage & Remediation**](skills/soar/phishing-response.md) — MDO enrichment, verdict, message removal, user education
- [**Compromised Account Auto-Response**](skills/soar/compromised-account.md) — Entra ID containment, session revocation, MFA enforcement, risk sign-offs
- [**Sentinel Incident Teams Notification**](skills/soar/teams-notification.md) — Rich Adaptive Cards to Teams, severity routing, quick actions

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

### Phase 2 — Expansion (Coming Next)
- [ ] Additional personas (Detection Engineering, Threat Hunting, Cloud Security, Incident Response, Full SOC)
- [ ] KQL validator library
- [ ] SOAR playbook deployment engine
- [ ] Graph Security API integration
- [ ] Azure auth helper and workspace auto-discovery
- [ ] Template engine for Bicep deployments
- [ ] CLI interactive mode

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
