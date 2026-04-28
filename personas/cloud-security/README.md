# Cloud Security Persona

Pre-built team configuration for cloud security posture management, policy enforcement, and Defender for Cloud operations.

## What This Is

The `cloud-security` persona provides a focused cloud security team powered by secops-squad. It covers the full posture management lifecycle — assessment, policy enforcement, remediation, and verification — with clear role separation. Built for teams managing Microsoft Defender for Cloud, Azure Policy, and cloud security hardening.

## When to Use This Persona

- You're managing cloud security posture across Azure subscriptions
- You need structured policy management with compliance framework alignment
- You want regular posture assessments with tracked remediation
- You're configuring Defender for Cloud plans and diagnostic settings

## Team Composition

| Agent | Role | Focus |
|-------|------|-------|
| **Avon** | Cloud Security Engineer | Remediation, Defender for Cloud configuration, RBAC, hardening |
| **Stringer** | Policy Analyst | Azure Policy, compliance frameworks, governance, exemption management |
| **D'Angelo** | Posture Reviewer | CSPM assessments, Secure Score, misconfiguration detection, trend analysis |

## Pre-Loaded Skills

**All agents** get `cloud-security-posture` and `defender-for-cloud-policies`.

| Agent | Skills |
|-------|--------|
| Avon | `defender-xdr-configuration`, `workspace-rbac`, `diagnostic-settings` |
| Stringer | `defender-for-cloud-policies` |
| D'Angelo | `cloud-security-posture` |

## What's Included

- `team.md` — Agent roster with roles, expertise, and project context
- `routing.md` — Domain-based routing with workflow stages and escalation
- `ceremonies.md` — Posture review, policy review, cloud threat model
- `skills.json` — Skill assignments per agent
- `README.md` — This file

## Installation

```bash
npx secops-squad init
# Select "Cloud Security team" when prompted
```

## Customization

After installation, everything lives in `.squad/` and is yours to edit:

- **Add agents** — need a dedicated compliance officer? Add a row to `team.md` and a routing entry.
- **Adjust routing** — change domain ownership, add multi-cloud routing, modify escalation triggers.
- **Tune ceremonies** — change posture review frequency, add a monthly compliance report, modify templates.
- **Swap skills** — add custom skills for your compliance frameworks, remove ones you don't use.

## Environment Assumptions

This persona assumes a Microsoft Security stack:
- **Microsoft Defender for Cloud** for CSPM, CWP, and security recommendations
- **Azure Policy** for governance, compliance, and enforcement
- **Microsoft Entra ID** for RBAC and identity governance
- **Microsoft Defender XDR** for unified alert integration
- **Compliance Frameworks:** CIS Azure Benchmarks, NIST 800-53, PCI-DSS, SOC 2, ISO 27001
