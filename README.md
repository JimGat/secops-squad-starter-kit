# secops-squad

**AI-powered SecOps team framework for the Microsoft Security stack.**

secops-squad gives you a team of specialized AI agents — each with deep knowledge of Microsoft Sentinel, Defender XDR, KQL, SOAR playbooks, and threat hunting — working together in your repository. Pick a persona that matches your role, and the squad loads the right skills, templates, and workflows automatically.

---

## Quick Start

```bash
npx secops-squad init
```

This walks you through persona selection, Azure workspace configuration, and drops a `secops-squad.config.json` in your repo root.

## What You Get

### 🎯 Personas
Each persona loads a curated set of skills and context for a specific SecOps role:

| Persona | Focus |
|---------|-------|
| **SOC Analyst** | Triage, investigation, alert handling, incident response playbooks |
| **Detection Engineering** | Detection rule authoring, KQL optimization, MITRE ATT&CK mapping |
| **Threat Hunting** | Proactive hunting queries, hypothesis-driven investigations, ADX analytics |
| **Cloud Security** | Cloud posture, Defender for Cloud, identity protection, compliance |
| **Incident Response** | IR procedures, forensics, containment, eradication, recovery |
| **Full SOC** | All skills loaded — for teams that wear every hat |

### 🛠 Skills Library
Skills are modular knowledge packs that agents use:

- **KQL** — Query authoring, optimization, common patterns for Sentinel and Defender tables
- **SOAR** — Playbook design, Logic App automation, response orchestration
- **Detection** — Analytics rule creation, scheduled/NRT/fusion rules, tuning
- **Log Analytics** — Data connector setup, table schemas, ingestion optimization
- **ADX** — Azure Data Explorer for long-term hunting and large-scale analytics
- **Microsoft Security** — Cross-product knowledge across the Defender suite and Entra

### 📐 Templates
Ready-to-deploy infrastructure and query templates:

- **Bicep** — ARM templates for Sentinel workspaces, SOAR playbooks, ADX clusters
- **KQL** — Hunting queries, detection rules, and investigation notebooks organized by MITRE tactic

### 🔍 KQL Validation
Built-in KQL syntax validation runs on every PR that touches query files:
```bash
secops-squad kql validate
```

## Supported Microsoft Security Products

- Microsoft Sentinel
- Microsoft Defender XDR (incidents, advanced hunting)
- Microsoft Defender for Endpoint
- Microsoft Defender for Cloud
- Microsoft Defender for Identity
- Microsoft Defender for Office 365
- Microsoft Entra ID Protection
- Microsoft Purview
- Microsoft Intune

## CLI Commands

```
secops-squad init          Set up a new secops-squad project
secops-squad doctor        Check environment prerequisites
secops-squad status        Show current config and loaded skills
secops-squad skill <name>  Load or inspect a skill
secops-squad persona       Switch active persona
secops-squad workspace     Manage Sentinel workspace connection
secops-squad kql           KQL query tools (validate, run, explain)
secops-squad playbook      SOAR playbook tools (scaffold, deploy)
```

## Project Status

### Phase 1 — Foundation ✅
- [x] Project structure and scaffold
- [x] Persona definitions
- [x] Core skill files (KQL, SOAR, Detection, Log Analytics, ADX, Microsoft Security)
- [x] Config schema and validation
- [x] CLI entry point
- [x] KQL validation CI workflow
- [x] Issue templates for detection requests, playbook requests, and threat hunts

### Phase 2 — Coming Next
- [ ] KQL validator library
- [ ] Graph Security API integration
- [ ] Azure auth helper
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
