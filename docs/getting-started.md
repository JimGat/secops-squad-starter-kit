# Getting Started with secops-squad

## Prerequisites

| Tool | Version | Required? | Purpose |
|------|---------|-----------|---------|
| **Node.js** | 18+ | ✅ Yes | Runtime for CLI and skill engine |
| **Git** | 2.x+ | ✅ Yes | Version control |
| **GitHub CLI** (`gh`) | 2.x+ | Recommended | Issue creation, PR workflows |
| **Azure CLI** (`az`) | 2.x+ | Optional | Sentinel workspace access, deployments |

Verify your environment:

```bash
node --version    # v18.0.0 or later
git --version     # any recent version
gh --version      # recommended
az --version      # optional, needed for Azure features
```

## Installation

### Option 1: Initialize in an existing repo

```bash
npx secops-squad init
```

### Option 2: Clone and set up

```bash
git clone https://github.com/jospaid/secops-squad.git
cd secops-squad
npm install
```

### Option 3: Global install

```bash
npm install -g @secops-squad/secops-squad
secops-squad init
```

## First Run

Running `secops-squad init` walks you through setup:

### 1. Choose a Persona

The init wizard asks you to pick a persona. This determines which skills load by default:

```
? Select your persona:
  ❯ SOC Analyst         — Triage, investigation, incident response
    Detection Engineer   — Rule authoring, KQL, MITRE mapping
    Threat Hunter        — Proactive hunting, hypothesis-driven analysis
    Cloud Security       — Posture management, Defender for Cloud
    Incident Response    — IR procedures, forensics, containment
    Full SOC             — All skills (for teams wearing every hat)
```

**Not sure?** Start with **SOC Analyst** — it covers the most common workflows. You can switch anytime with `secops-squad persona`.

### 2. Connect Your Workspace (Optional)

If you have a Microsoft Sentinel workspace, the wizard can connect to it:

```
? Azure Subscription ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
? Sentinel Workspace Name: my-sentinel-workspace
? Resource Group: rg-security
```

This enables live query execution, detection deployment, and playbook management. You can skip this and add it later.

### 3. Select Products

Choose which Microsoft Security products you work with:

```
? Select enabled products:
  ◉ Microsoft Sentinel
  ◉ Defender XDR
  ◯ Defender for Endpoint
  ◯ Defender for Cloud
  ◯ Defender for Identity
  ◯ Defender for Office 365
  ◯ Entra ID Protection
```

This controls which tables, schemas, and templates are surfaced by your skills.

### 4. Configuration File

After setup, you'll have a `secops-squad.config.json` in your repo root:

```json
{
  "teamName": "my-security-team",
  "persona": "soc-analyst",
  "azure": {
    "subscriptionId": "...",
    "tenantId": "..."
  },
  "sentinel": {
    "workspaceId": "...",
    "workspaceName": "my-sentinel-workspace",
    "resourceGroup": "rg-security"
  },
  "products": ["sentinel", "defender-xdr"],
  "skills": {
    "loaded": ["kql", "soar", "detection", "log-analytics"],
    "custom": []
  }
}
```

## Persona Selection Guide

| If you... | Choose |
|-----------|--------|
| Handle alerts and triage incidents daily | **SOC Analyst** |
| Write and tune detection rules (analytics rules, KQL) | **Detection Engineering** |
| Run proactive threat hunts across your data | **Threat Hunting** |
| Manage cloud security posture and Defender for Cloud | **Cloud Security** |
| Lead incident response and forensic analysis | **Incident Response** |
| Do a bit of everything on a small team | **Full SOC** |

## Verify Setup

After init, run the doctor command to verify everything is configured correctly:

```bash
secops-squad doctor
```

This checks:
- Node.js version
- Azure CLI authentication (if configured)
- Sentinel workspace connectivity (if configured)
- Loaded skills integrity
- Template availability

## Next Steps

- Run `secops-squad status` to see your current configuration
- Run `secops-squad kql validate` to test KQL validation on any `.kql` files
- Browse `templates/kql/` for ready-to-use hunting and detection queries
- Check `skills/` to see what knowledge packs are loaded
- Read the skill files to understand what your AI agents know
