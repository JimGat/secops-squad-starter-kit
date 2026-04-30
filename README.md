# 🛡️ SecOps Squad Starter Kit

[![Phase 3 Active](https://img.shields.io/badge/Phase-3%20Active-brightgreen)](docs/getting-started.md) [![Node.js](https://img.shields.io/badge/Node.js-18+-green)](https://nodejs.org/) [![MIT License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

> **Your AI SecOps team for the Microsoft Security stack. One command to install.**

Turns GitHub Copilot CLI into a full security operations squad — KQL hunting, SOAR automation, detection engineering, and threat modeling — all through natural conversation. Pick a persona, load your skills, go hunting.

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
| 🔍 **KQL Hunting** | Threat hunting, Sentinel analytics, Entra sign-in analysis, UEBA |
| ⚡ **SOAR Automation** | Phishing response, compromised account containment, auto-triage |
| 🛡️ **Detection Engineering** | MITRE ATT&CK mapping, rule lifecycle, NRT/scheduled patterns |
| 📊 **Azure Data Explorer** | Security data lake, long-term retention, ML anomaly detection |
| 📐 **Threat Models** | 10 MITRE tactic templates from Initial Access to Impact |
| 🔌 **Graph Security API** | Zero-dependency library for alerts, incidents, threat intel, secure score |
| 📋 **Bicep Templates** | Sentinel workspace scaffolds and ADX cluster deployments |
| ✅ **KQL Validation** | Automated syntax checks on every PR |

## 🎯 Personas

| Persona | Focus |
|---------|-------|
| **SOC Analyst** | Triage, investigation, incident response |
| **Detection Engineering** | Rule authoring, KQL, MITRE ATT&CK mapping |
| **Threat Hunting** | Proactive hunting, hypothesis-driven investigations |
| **Cloud Security** | Cloud posture, Defender for Cloud, identity |
| **Incident Response** | IR procedures, forensics, containment |
| **Full SOC** | All skills combined for a mature SOC |

See [Personas Guide](docs/personas-guide.md) for details.

## 🛠 Skills at a Glance

**36 skills** across **4 categories:**

| Category | Count | Examples |
|----------|-------|----------|
| **KQL Hunting & Detection** | 10 | Threat hunting, Sentinel analytics, UEBA, cross-workspace queries |
| **SOAR Automation** | 10 | Phishing response, compromised account, auto-triage, TI ingest |
| **Detection Engineering** | 8 | MITRE mapping, detection lifecycle, NRT rules, watchlist detection |
| **Azure Data Explorer** | 8 | Cluster architecture, data modeling, ML anomaly, dashboards |

See [Skills Catalog](docs/skills-catalog.md) for the full inventory with difficulty levels and MITRE ATT&CK mappings.

## Supported Microsoft Security Products

- ✅ Microsoft Sentinel
- ✅ Microsoft Defender XDR (incidents, advanced hunting)
- ✅ Microsoft Defender for Endpoint
- ✅ Microsoft Defender for Identity
- ✅ Microsoft Defender for Office 365
- ✅ Microsoft Entra ID Protection
- ✅ Microsoft Defender for Cloud
- ✅ Microsoft Graph Security API

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
- [**Skills Catalog**](docs/skills-catalog.md) — All 36 skills with difficulty, MITRE ATT&CK, and coverage
- [**Personas Guide**](docs/personas-guide.md) — All 6 personas, team composition, ADX integration
- [**ADX Setup Guide**](docs/adx-setup.md) — Azure Data Explorer quick-start, ADX vs Log Analytics
- [**Graph Security API**](docs/graph-security-api.md) — Library usage, auth flows, error handling
- [**MITRE Coverage**](docs/mitre-coverage.md) — ATT&CK technique coverage map

## 🙏 Built On

- **[@bradygaster/squad-sdk](https://github.com/bradygaster/squad-sdk)** — Brady Gaster's Squad SDK that powers the agent team architecture
- **[GitHub Copilot CLI](https://githubnext.com/projects/copilot-cli)** — The runtime that makes it all work

## License

[MIT](LICENSE)
