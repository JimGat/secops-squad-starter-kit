# templates/ — Deployment & Content Templates

Three categories of templates for infrastructure deployment, query authoring, and threat modeling.

## Directory Structure

```
templates/
├── bicep/              — Azure infrastructure deployment
│   ├── README.md       — Detailed Bicep template reference ✱
│   ├── soar/           — 5 SOAR playbook Logic App templates
│   │   ├── main.bicep
│   │   ├── phishing-response.bicep
│   │   ├── compromised-account.bicep
│   │   ├── malware-containment.bicep
│   │   ├── ip-enrichment.bicep
│   │   └── teams-notification.bicep
│   └── adx/            — ADX security data lake templates
│       ├── main.bicep, cluster.bicep, database.bicep
│       ├── tables.bicep, ingestion.bicep
├── kql/                — KQL query templates by use case
│   ├── detection/      — Detection rule templates
│   ├── hunting/        — Threat hunting query templates
│   └── investigation/  — Incident investigation query templates
└── threat-models/      — STRIDE threat model templates
    ├── README.md       — Threat model template guide ✱
    ├── template-blank.md
    └── 8 tactic-specific templates (credential-access, defense-evasion,
        exfiltration, impact, initial-access, lateral-movement,
        persistence, privilege-escalation)
```

✱ = Existing detailed README — see those files for comprehensive reference.

## Template Categories

| Category | Templates | Purpose |
|----------|-----------|---------|
| [Bicep](bicep/README.md) | SOAR playbooks, ADX data lake | Deploy Azure infrastructure for security operations |
| KQL | Detection, hunting, investigation | Query templates for Sentinel / Log Analytics / ADX |
| [Threat Models](threat-models/README.md) | Blank + 8 MITRE tactic templates | STRIDE-based threat modeling aligned to ATT&CK |

## Usage

- **Bicep**: Deploy with `az deployment group create` — see [bicep/README.md](bicep/README.md)
- **KQL**: Copy and customize queries for your environment — reference `.secops/` for workspace context
- **Threat Models**: Start from `template-blank.md` or pick a tactic-specific template
