# Cost Transparency

This document provides transparency on the costs associated with building and
using the SecOps Squad Starter Kit.

---

## AI-Assisted Development Cost (One-Time)

The SecOps Squad Starter Kit was built iteratively across multiple GitHub Copilot
CLI sessions using the Squad framework itself (dogfooding). The estimates below
cover the cumulative AI cost of developing the 96 skills, 6 personas, CLI tooling,
and documentation.

### Estimated Development Tokens

| Phase | Model(s) Used | Est. Input Tokens | Est. Output Tokens |
|-------|--------------|------------------:|-------------------:|
| Core framework (CLI, lib, templates) | Claude Sonnet 4.x | ~300,000 | ~150,000 |
| Security skills (96 across 11 domains) | Claude Sonnet 4.x / Haiku 4.5 | ~500,000 | ~250,000 |
| Personas & charters (6 SOC roles) | Claude Sonnet 4.x | ~80,000 | ~40,000 |
| Documentation (README, catalog, docs/) | Claude Haiku 4.5 | ~100,000 | ~60,000 |
| Iteration & refinement | Mixed | ~200,000 | ~100,000 |
| **Total (estimated)** | | **~1,180,000** | **~600,000** |

### Estimated API-Equivalent Cost

| Model Tier | Input Cost | Output Cost | Subtotal |
|-----------|-----------|------------|----------|
| Sonnet-tier work | ~$2.64 | ~$8.10 | ~$10.74 |
| Haiku-tier work | ~$0.25 | ~$1.50 | ~$1.75 |
| **Total** | | | **~$12–15** |

> **Note:** This is the estimated equivalent cost if the work had been done via
> direct API calls. Under a GitHub Copilot subscription, this is included in the
> subscription fee — no additional cost to the developer.

---

## Runtime Cost (Using SecOps Squad)

SecOps Squad is a **local developer tool** — it runs on your machine via GitHub
Copilot CLI. There is no Azure infrastructure to deploy for the tool itself.

### What You Pay

| Component | Cost | Notes |
|-----------|------|-------|
| **GitHub Copilot subscription** | Included for Microsoft FTEs | [aka.ms/githubcopilot](https://aka.ms/githubcopilot) |
| **Node.js runtime** | Free | Local execution |
| **Git** | Free | Local version control |
| **SecOps Squad itself** | Free | Open-source starter kit |

### Per-Session Token Usage (Typical)

When you use SecOps Squad, each Copilot session consumes tokens. Typical usage:

| Session Type | Est. Tokens (In/Out) | API-Equivalent Cost |
|-------------|---------------------:|--------------------:|
| Quick skill lookup / single agent task | ~20K / ~10K | ~$0.15–0.30 |
| Multi-agent investigation (3–4 agents) | ~100K / ~50K | ~$1.00–2.00 |
| Full team session (all agents, ceremony) | ~250K / ~120K | ~$3.00–5.00 |
| Heavy session (incident response, hunting) | ~500K / ~200K | ~$5.00–10.00 |

These are covered by your Copilot subscription — shown for transparency only.

---

## Microsoft Security Stack Costs (Separate)

SecOps Squad **integrates with** the Microsoft Security stack but does not replace
or provision it. The following services have their own licensing and are **not part
of SecOps Squad's cost**:

| Service | Licensing | Used By SecOps Squad For |
|---------|-----------|-------------------------|
| Microsoft Sentinel | Pay-as-you-go (per GB ingested) | KQL hunting, detection rules, SOAR playbooks |
| Microsoft Defender XDR | M365 E5 / E5 Security add-on | Advanced hunting, incident correlation |
| Microsoft Entra ID | P1/P2 (included in M365 E5) | Identity protection, Conditional Access |
| Azure Monitor / Log Analytics | Pay-as-you-go | Log queries, workbook generation |
| Microsoft Purview | M365 E5 Compliance | Data classification, DLP policies |

> SecOps Squad generates KQL, detection rules, and playbook scaffolds. It does not
> deploy infrastructure or incur Azure charges on its own.

---

*Last updated: 2026-06-08*
