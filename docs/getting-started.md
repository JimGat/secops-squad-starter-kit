# Getting Started with secops-squad

**Get a working SecOps team with KQL hunting and phishing response in ≤ 15 minutes.**

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

### Option 1: Initialize in an existing repo ⭐ Fastest

```bash
npx secops-squad init
```

### Option 2: Clone and set up

```bash
git clone https://github.com/jospaid/secops-squad.git
cd secops-squad
npm install
node cli/index.js init
```

### Option 3: Global install

```bash
npm install -g secops-squad
secops-squad init
```

## Your First Run — 15-Minute Walkthrough

### 1. Initialize Your Team (2 min)

Run the init wizard:

```bash
secops-squad init
```

### 2. Select Your Persona (1 min)

The init wizard asks you to pick a persona. For this walkthrough, choose **SOC Analyst** — it gives you the full toolkit:

```
? Select your persona:
  ❯ SOC Analyst         — Triage, investigation, incident response
    Detection Engineer   — (Coming Phase 2)
    Threat Hunter        — (Coming Phase 2)
    Cloud Security       — (Coming Phase 2)
    Incident Response    — (Coming Phase 2)
    Full SOC             — (Coming Phase 2)
```

**Why SOC Analyst?** It includes all Phase 1 skills: 3 KQL hunting/detection skills + 3 SOAR automation skills. Perfect for a first run.

### 3. Connect Your Workspace (Optional, 2 min)

If you have a Microsoft Sentinel workspace, add it now:

```
? Do you have a Sentinel workspace? (y/n) y
? Azure Subscription ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
? Sentinel Workspace Name: my-sentinel-workspace
? Resource Group: rg-security
```

**Skip it?** No problem — you can add it later with `secops-squad workspace connect`. The squad works offline too.

### 4. Verify Your Setup (1 min)

After init completes, run the doctor command to check everything:

```bash
secops-squad doctor
```

This verifies:
- ✅ Node.js version
- ✅ Config file integrity
- ✅ Loaded skills
- ✅ Azure CLI authentication (if configured)
- ✅ Sentinel workspace connectivity (if configured)

### 5. Check Your Configuration (1 min)

View what you just set up:

```bash
secops-squad status
```

You'll see something like:

```
secops-squad Configuration
─────────────────────────────
Team Name:    my-security-team
Persona:      soc-analyst
Config File:  ./secops-squad.config.json

Loaded Skills:
  ✓ Threat Hunting Foundations (kql)
  ✓ Sentinel Analytics Rules (kql)
  ✓ Incident Investigation (kql)
  ✓ Phishing Incident Auto-Triage & Remediation (soar)
  ✓ Compromised Account Auto-Response (soar)
  ✓ Sentinel Incident Teams Notification (soar)

Workspace Connection:
  Status: Connected to my-sentinel-workspace
```

### 6. Browse the Skills Library (3 min)

Now explore what you have. Look at the skills catalog:

```bash
cat docs/skills-catalog.md
```

Or read a skill directly:

```bash
cat skills/kql/threat-hunting-foundations.md
```

Each skill includes:
- **Use cases** — When to apply this skill
- **Core patterns** — Query structures and KQL examples
- **Common mistakes** — What not to do
- **Real-world example** — End-to-end walkthrough

### 7. Your First Hunt — Threat Hunting (4 min)

Let's run a real threat hunt. Open the threat hunting foundations skill:

```bash
cat skills/kql/threat-hunting-foundations.md
```

Pick a scenario from the **Core Patterns** section (e.g., "Rare Process Executions"). Try one of the KQL queries against your Sentinel workspace:

```bash
secops-squad kql run --query "your-query.kql" --workspace my-sentinel-workspace
```

Or copy a hunting query from `templates/kql/` and adapt it.

### 8. Your First Automation — Phishing Response (2 min)

Now see how SOAR works. Read the phishing response skill:

```bash
cat skills/soar/phishing-response.md
```

This skill describes a Logic Apps playbook that:
1. Triggers on phishing-related Sentinel incidents
2. Enriches them with threat intel
3. Removes malicious mail from inboxes
4. Notifies your incident commander

**Next step:** In Phase 2, you'll deploy this playbook to your environment with a single command.

## Persona Selection Guide

| If you... | Choose | Get |
|-----------|--------|-----|
| **Handle alerts and triage incidents daily** | SOC Analyst | KQL hunting, incident investigation, phishing & account response automation |
| **Write and tune detection rules** | Detection Engineer | _(Coming Phase 2)_ |
| **Run proactive threat hunts** | Threat Hunter | _(Coming Phase 2)_ |
| **Manage cloud security posture** | Cloud Security | _(Coming Phase 2)_ |
| **Lead incident response** | Incident Response | _(Coming Phase 2)_ |
| **Do a bit of everything** | Full SOC | _(Coming Phase 2)_ |

## Configuration File

After init, you have a `secops-squad.config.json`:

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
  "enabledProducts": [
    "sentinel",
    "defender-xdr",
    "defender-endpoint",
    "entra-id"
  ],
  "skills": {
    "loaded": [
      "threat-hunting-foundations",
      "sentinel-analytics-rules",
      "incident-investigation",
      "phishing-response",
      "compromised-account",
      "teams-notification"
    ]
  }
}
```

You can edit this by hand to switch personas, add/remove products, or load custom skills.

## Next Steps

✅ **Explore templates:** Browse `templates/kql/` for pre-built hunting and detection queries.

✅ **Switch personas:** When Phase 2 lands, switch with `secops-squad persona` and load new skills.

✅ **Build custom skills:** See [Personas Guide](personas-guide.md) for how to create your own skill packs.

✅ **Contribute:** Found a great hunt? See [CONTRIBUTING.md](../CONTRIBUTING.md) to submit it as a skill.

✅ **File issues:** Need a skill that doesn't exist? Open a [skill request issue](https://github.com/jospaid/secops-squad/issues/new?labels=skill-request).

## Troubleshooting

**Q: `secops-squad` command not found**

A: Make sure Node.js 18+ is installed and the npm package was installed globally or via npx:
```bash
node --version  # should be v18.0.0 or later
npx secops-squad status  # if not globally installed
```

**Q: Sentinel workspace connection fails**

A: Run `az login` to authenticate with Azure, then try `secops-squad doctor` to diagnose the issue.

**Q: I want to switch to a different persona**

A: In Phase 2, use `secops-squad persona` to switch. For now, edit `secops-squad.config.json` and run `secops-squad status` to reload.

**Q: Where are the KQL templates?**

A: Check `templates/kql/` in your repo root. They're organized by MITRE ATT&CK tactic.

---

**Ready to hunt?** Let's go. Start with `secops-squad status` and pick your first skill from the Skills Catalog.
