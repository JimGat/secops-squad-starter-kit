# Threat Model Template Library

> **Author:** Kima (SecOps Engineer)
> **Version:** 1.0 | **Last Updated:** 2026-04-28
> **Team Decision:** #7 — Threat model required before detection rules merge

## Why Threat Models

Detection rules that ship without a threat model are guesses. A threat model documents *why* a detection exists, *what* it catches, *what it misses*, and *how to tune it*. Every detection in this framework starts here — not optional.

This library provides tactic-level threat models covering the most common MITRE ATT&CK tactics seen in Microsoft 365 / Azure / hybrid environments. Each template is pre-populated with techniques, attack flows, data sources, detection opportunities, and gap analysis so detection engineers don't start from zero.

## How This Library Connects to Skills

```
┌──────────────────────────────────────────────────────────────┐
│                    DETECTION ENGINEERING WORKFLOW            │
│                                                              │
│  1. Pick a threat model template (this library)              │
│     └─ Identify techniques, data sources, gaps               │
│                                                              │
│  2. Write the detection (detection/ skills)                  │
│     ├─ skills/detection/scheduled-rule-pattern.md            │
│     ├─ skills/detection/nrt-rule-pattern.md                  │
│     ├─ skills/detection/custom-kql-function.md               │
│     └─ skills/detection/watchlist-driven-detection.md        │
│                                                              │
│  3. Map to ATT&CK (skills/detection/mitre-attack-mapping.md)│
│                                                              │
│  4. Lifecycle management                                     │
│     └─ skills/detection/detection-lifecycle.md               │
│                                                              │
│  5. Product configuration (msft-security/ skills)            │
│     ├─ skills/msft-security/sentinel-workspace-setup.md      │
│     ├─ skills/msft-security/defender-xdr-configuration.md    │
│     ├─ skills/msft-security/defender-for-identity.md         │
│     ├─ skills/msft-security/defender-for-endpoint.md         │
│     └─ skills/msft-security/entra-id-protection.md           │
└──────────────────────────────────────────────────────────────┘
```

## Templates in This Library

| Template | Tactic ID | Tactic | Key Techniques |
|---|---|---|---|
| [credential-access.md](credential-access.md) | TA0006 | Credential Access | Brute force, credential dumping, MFA fatigue, token theft, Kerberoasting |
| [initial-access.md](initial-access.md) | TA0001 | Initial Access | Phishing, exploit public-facing app, valid accounts, trusted relationship |
| [lateral-movement.md](lateral-movement.md) | TA0008 | Lateral Movement | Remote services, internal spearphishing, exploitation of remote services |
| [persistence.md](persistence.md) | TA0003 | Persistence | Account manipulation, create account, scheduled task, implant container image |
| [privilege-escalation.md](privilege-escalation.md) | TA0004 | Privilege Escalation | Abuse elevation control, access token manipulation, domain policy modification |
| [exfiltration.md](exfiltration.md) | TA0010 | Exfiltration | Exfil over C2, web service, alternative protocol, automated exfiltration |
| [defense-evasion.md](defense-evasion.md) | TA0005 | Defense Evasion | Indicator removal, obfuscated files, impair defenses, modify cloud compute |
| [impact.md](impact.md) | TA0040 | Impact | Data destruction, ransomware, resource hijacking, account access removal |
| [template-blank.md](template-blank.md) | — | Any | Blank reusable template for any tactic |

## When to Use Each Template

### Starting a new detection project
Pick the template matching the tactic you're targeting. If your detection spans multiple tactics (e.g., phishing → credential theft → lateral movement), start with the initial access template and cross-reference the others.

### Reviewing an existing detection
Use the relevant template's gap analysis section to check if your detection covers all sub-techniques and data sources.

### Assessing coverage
Compare your deployed analytics rules against each template's "Detection Opportunities" sections. Gaps = risk acceptance decisions or new detection work.

### Building a new template
Copy `template-blank.md`, fill in the YAML frontmatter, and follow the section structure. Every technique needs an attack flow diagram, data sources, detection opportunities, false positive analysis, and gap assessment.

## Template Structure

Each threat model follows this structure:

1. **YAML Frontmatter** — Machine-readable metadata (tactic ID, techniques, products, data sources)
2. **Executive Summary** — One-paragraph threat overview for stakeholders
3. **Per-Technique Sections** — Each containing:
   - Attack flow (Mermaid diagram)
   - Data sources (specific log tables)
   - Detection opportunities (KQL stubs)
   - False positive scenarios and tuning
   - Microsoft product coverage
   - Detection gap analysis
   - Related skills cross-references
4. **Coverage Matrix** — Summary table of what's detected vs. gaps
5. **References** — MITRE ATT&CK links, Microsoft docs, threat intel sources

## Process

1. **Before writing any detection rule**, select or create a threat model
2. **Fill in all sections** — incomplete models block review
3. **Submit for review** — McNulty gates architecture, Carver gates quality
4. **Attach to the detection PR** — the model lives alongside the rule
5. **Maintain over time** — update when new sub-techniques emerge or data sources change

## Related Skills

- `skills/detection/threat-model-template.md` — The original skill with process and example
- `skills/detection/mitre-attack-mapping.md` — ATT&CK mapping methodology
- `skills/detection/detection-lifecycle.md` — End-to-end detection workflow
- `skills/detection/scheduled-rule-pattern.md` — Analytics rule implementation
- `skills/detection/nrt-rule-pattern.md` — Near-real-time rule patterns
- `skills/msft-security/sentinel-workspace-setup.md` — Workspace and data connector setup
