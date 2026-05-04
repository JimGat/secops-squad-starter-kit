# 🛡️ SecOps Squad Starter Kit

[![Phase 3 Active](https://img.shields.io/badge/Phase-3%20Active-brightgreen)](docs/getting-started.md) [![Skills](https://img.shields.io/badge/Skills-96-blue)](SKILLS_CATALOG.md) [![Node.js](https://img.shields.io/badge/Node.js-18+-green)](https://nodejs.org/) [![MIT License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

> **Your AI SecOps team for the Microsoft Security stack. 96 skills. One command to install.**

Turns GitHub Copilot CLI into a full security operations squad — KQL hunting, SOAR automation, detection engineering, threat modeling, multi-tenant operations, and API wrappers for the entire Microsoft Security stack — all through natural conversation. Pick a persona, load your skills, go hunting.

## 🚀 Install

**Step 1:** Get a GitHub Copilot license at [aka.ms/githubcopilot](https://aka.ms/githubcopilot) (free for all Microsoft FTEs)

**Step 2:** Open a terminal and paste:

**Windows PowerShell:**
```powershell
irm "https://raw.githubusercontent.com/x3nc0n/secops-squad-starter-kit/main/install.ps1" | iex
```

**macOS / Linux:**
```bash
curl -fsSL "https://raw.githubusercontent.com/x3nc0n/secops-squad-starter-kit/main/install.sh" | bash
```

That's it. The installer clones the repo, installs dependencies, and scaffolds a working SecOps project in `~/secops-squad-starter-kit`. Total time: ~3 minutes.

> **Getting an execution policy error?** Run this first, then try the one-liner again:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```

### Prerequisites

| Requirement | How to get it |
|------------|---------------|
| **GitHub Copilot license** | [aka.ms/githubcopilot](https://aka.ms/githubcopilot) (free for Microsoft FTEs) |
| **Node.js 18+** | [nodejs.org](https://nodejs.org/) or `winget install OpenJS.NodeJS.LTS` |
| **Git** | [git-scm.com](https://git-scm.com/) or `winget install Git.Git` |

### What happens during install (~3 min)

1. Clones `x3nc0n/secops-squad-starter-kit` into `~/secops-squad-starter-kit`
2. Installs Node.js dependencies
3. Runs persona selection (SOC Analyst, Detection Engineering, Threat Hunting, etc.)
4. Configures Azure workspace connection
5. Initializes a fresh git repository — your copy, not linked to upstream

## What You Get

| Capability | What It Does |
|-----------|-------------|
| 🔍 **KQL Hunting** | 11 skills — threat hunting, Sentinel analytics, Entra sign-in analysis, UEBA, cross-workspace |
| ⚡ **SOAR Automation** | 12 skills — phishing response, compromised account, auto-triage, data exfil, TI ingest |
| 🛡️ **Detection Engineering** | 9 skills — MITRE ATT&CK mapping, rule lifecycle, NRT/scheduled patterns, watchlists |
| 📊 **Azure Data Explorer** | 8 skills — security data lake, long-term retention, ML anomaly, cross-cluster |
| 🔧 **PowerShell Modules** | 14 skills — API wrappers, auth patterns, Sentinel/Defender/Entra submodules |
| 🏢 **Microsoft Security** | 16 skills — Defender XDR, Sentinel, Entra, Purview, MCP servers, Graph API |
| 📋 **Log Analytics** | 10 skills — workspace architecture, data connectors, DCR, cost optimization |
| 🌐 **Platform** | 3 skills — multi-tenant, sovereign cloud (GCC/GCC-H/DoD), cross-cloud |
| 🔗 **Orchestration** | 3 skills — cross-skill workflows, Copilot for Security, MSSP patterns |
| 🤖 **Copilot Skills** | 9 skills — agent collaboration, git workflow, error recovery, conventions |
| ✅ **KQL Validation** | Automated syntax checks on every PR |

## 🎯 Personas

Six specialized personas, each with its own team composition, skill routing, and ceremony cadence:

| Persona | Focus | Key Skills |
|---------|-------|------------|
| **SOC Analyst** | Triage, investigation, incident response | KQL hunting, auto-triage, enrichment |
| **Detection Engineering** | Rule authoring, KQL, MITRE ATT&CK mapping | Detection lifecycle, NRT/scheduled rules, watchlists |
| **Threat Hunting** | Proactive hunting, hypothesis-driven investigations | Advanced KQL, UEBA, cross-workspace queries |
| **Cloud Security** | Cloud posture, Defender for Cloud, identity | Cloud posture KQL, Defender policies, Entra analysis |
| **Incident Response** | IR procedures, forensics, containment | Malware containment, compromised account, data exfil |
| **Full SOC** | All skills combined for a mature SOC | Complete 96-skill library |

Each persona includes `team.md`, `routing.md`, and `ceremonies.md` for structured agent collaboration. See [Personas Guide](docs/personas-guide.md) for details.

## 🛠 Skills at a Glance

**96 skills** across **11 domains:**

| Domain | Count | Examples |
|--------|-------|----------|
| **KQL Hunting & Analytics** | 11 | Threat hunting, Sentinel analytics, UEBA, Defender XDR, cross-workspace |
| **SOAR Automation** | 12 | Phishing response, compromised account, auto-triage, TI ingest, compliance |
| **Detection Engineering** | 9 | MITRE mapping, detection lifecycle, NRT rules, watchlist detection, fusion |
| **Azure Data Explorer** | 8 | Cluster architecture, data modeling, ML anomaly, dashboards, migration |
| **Microsoft Security** | 16 | Defender XDR, Sentinel, Entra, Purview DLP, MCP servers, Graph API |
| **PowerShell Modules** | 14 | Module foundation, API wrappers, auth, rate limiting, submodules |
| **Log Analytics** | 10 | Workspace architecture, DCR, data connectors, cost optimization, RBAC |
| **Platform** | 3 | Multi-tenant, GCC/GCC-H/DoD sovereign cloud, cross-cloud connectors |
| **Orchestration** | 3 | Cross-skill workflows, Copilot for Security, MSSP workflows |
| **Testing** | 1 | Integration test suites for SecOps workflows |
| **Copilot Agent Skills** | 9 | Agent collaboration, git workflow, error recovery, conventions |

See [**SKILLS_CATALOG.md**](SKILLS_CATALOG.md) for the complete inventory with every skill listed by domain.

## 🏗️ Customer Knowledge Framework (`.secops/`)

The `.secops/` directory is a customer-specific environment knowledge layer that tells agents **where** things are — not just how to do them. While skills teach agents KQL and SOAR patterns, `.secops/` maps the customer's actual infrastructure:

- **`environment.yaml`** — Primary environment descriptor (tenant, subscription, regions)
- **`workspaces/`** — Log Analytics and Sentinel workspace configurations
- **`data-sources/`** — What data lives where, active migrations, table-to-workspace mapping
- **`identity/`** — Multi-tenant topology, RBAC conventions, service principal inventory
- **`alerting/`** — Alert routing rules and notification channels
- **`compliance/`** — Regulatory boundaries, data residency, retention requirements
- **`discovery-log.yaml`** — Agent-discovered environment facts

This framework ensures agents don't guess — they know that `SecurityEvent` is in ADX (not Sentinel), that the customer is GDPR-bound to EU regions, or that `NetFlowLogs` is mid-migration.

## 🌐 Platform Skills — Multi-Tenant, Sovereign Cloud & Cross-Cloud

The `skills/platform/` domain handles enterprise-scale deployment patterns:

- **Multi-Tenant Support** — Azure Lighthouse, cross-tenant KQL queries, tenant-scoped RBAC for MSSPs and multi-org environments
- **Sovereign Cloud (GCC/GCC-H/DoD)** — Endpoint mappings, API differences, feature parity matrices for Azure Government clouds
- **Cross-Cloud Connectors** — Ingesting AWS CloudTrail, GCP Security Command Center, and other cloud provider data into Sentinel

## 🔌 API Wrappers & MCP Servers

The kit includes production-ready API integration skills:

| Type | Skills | What They Cover |
|------|--------|-----------------|
| **PowerShell API Wrappers** | `sentinel-api-wrapper`, `defender-api-wrapper` | Full REST API coverage with auth, pagination, rate limiting |
| **MCP Servers** | `sentinel-mcp-server`, `defender-mcp-server` | Model Context Protocol servers for Copilot tool integration |
| **Graph Security API** | `microsoft-graph-security` | Alerts, incidents, threat intel, secure score via Graph |
| **Purview / eDiscovery** | `purview-api-wrapper`, `ediscovery-api-wrapper` | Compliance and legal hold automation |
| **Log Analytics** | `api-wrapper` | Query API, workspace management, data export |

## Supported Microsoft Security Products

- ✅ Microsoft Sentinel
- ✅ Microsoft Defender XDR (incidents, advanced hunting)
- ✅ Microsoft Defender for Endpoint
- ✅ Microsoft Defender for Identity
- ✅ Microsoft Defender for Office 365
- ✅ Microsoft Defender for Cloud / Cloud Apps
- ✅ Microsoft Entra ID Protection
- ✅ Microsoft Graph Security API
- ✅ Microsoft Purview (DLP, eDiscovery)
- ✅ Microsoft Copilot for Security
- ✅ Azure Data Explorer (security data lake)
- ✅ Azure Monitor / Log Analytics

## ❓ FAQ

<details>
<summary><b>What's the difference between this and a regular Sentinel deployment?</b></summary>
SecOps Squad Starter Kit is an AI-assisted overlay — it doesn't replace your Sentinel workspace. It gives your Copilot CLI deep knowledge of KQL, detection engineering, SOAR patterns, and your security stack so you can hunt, build detections, and automate response through natural conversation.
</details>

<details>
<summary><b>Do I need an Azure subscription?</b></summary>
For KQL hunting and SOAR skills, yes — you need a Sentinel workspace. For detection engineering skills, threat model templates, and learning KQL patterns, no Azure subscription is required.
</details>

<details>
<summary><b>Can I use this with an existing Sentinel workspace?</b></summary>
Yes. During <code>init</code>, you connect to your existing workspace. The starter kit reads from your environment — it never writes to Sentinel unless you explicitly deploy a playbook or analytics rule.
</details>

<details>
<summary><b>Mac support?</b></summary>
Yes. Use the <code>install.sh</code> one-liner above. Requires Node.js 18+ and Git.
</details>

## 🔧 Troubleshooting

| Issue | Fix |
|-------|-----|
| Script won't run | `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` then retry |
| Node.js not found | Install from [nodejs.org](https://nodejs.org/) or `winget install OpenJS.NodeJS.LTS` |
| KQL validation fails | Run `npm test` locally to see syntax errors before pushing |
| Auth expired | Re-run `az login` for Azure, `gh auth login` for GitHub |
| Persona not loading | Check `secops-squad.config.json` exists in your project root |

## 📚 Documentation

- [**Getting Started**](docs/getting-started.md) — Installation, init wizard, your first hunt
- [**Architecture Guide**](docs/ARCHITECTURE.md) — Full platform architecture, skills system, orchestration patterns
- [**Integration Guide**](docs/INTEGRATION.md) — Connect to real Azure environments, multi-tenant, gov cloud
- [**`.secops/` Schema Reference**](docs/SECOPS_SCHEMA.md) — Complete field-level docs for customer knowledge framework
- [**Skills Catalog**](SKILLS_CATALOG.md) — All 96 skills organized by domain
- [**Personas Guide**](docs/personas-guide.md) — All 6 personas, team composition, ceremony cadence
- [**ADX Setup Guide**](docs/adx-setup.md) — Azure Data Explorer quick-start, ADX vs Log Analytics
- [**Graph Security API**](docs/graph-security-api.md) — Library usage, auth flows, error handling
- [**MITRE Coverage**](docs/mitre-coverage.md) — ATT&CK technique coverage map
- [**Customer Knowledge**](.secops/README.md) — `.secops/` environment framework docs

## 🙏 Built On

- **[@bradygaster/squad-sdk](https://github.com/bradygaster/squad-sdk)** — Brady Gaster's Squad SDK that powers the agent team architecture
- **[GitHub Copilot CLI](https://githubnext.com/projects/copilot-cli)** — The runtime that makes it all work

## License

[MIT](LICENSE)
