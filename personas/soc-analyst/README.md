# SOC Analyst Persona

Pre-built team configuration for L1/L2/L3 Security Operations Center analyst workflows — enhanced with Phase 2-3 tool integrations.

## What This Is

The `soc-analyst` persona provides a ready-to-use SOC team powered by secops-squad. It models a tiered SOC with severity-based routing, structured escalation paths, and operational ceremonies — the same patterns used by production SOCs running Microsoft Sentinel and Defender XDR.

**Phase 2-3 enhancements** add programmatic API access, KQL query construction and validation, workbook automation, and integrated tool chains that connect the full incident lifecycle.

## Incident Lifecycle

The SOC analyst workflow follows five stages, each powered by specific tools:

```
Detect → Hunt → Investigate → Respond → Report
```

### 1. Detect
Sentinel analytics rules and Defender XDR generate alerts. Alert routing follows `.secops/alerting/routing.yaml` severity mappings to assign the right analyst tier.

### 2. Hunt
Freamon (L3) drives proactive threat hunting using the **KQL builder** (`skills/kql/query-builder.md`) to construct, validate, and optimize queries. Validated queries execute via the **Advanced Hunting API** (`skills/detection/advanced-hunting-api.md`) against MDE/XDR unified schema or Sentinel workspaces.

### 3. Investigate
Kima (L2) and Freamon (L3) investigate using the **Sentinel API wrapper** (`skills/powershell/sentinel-api-wrapper.md`) for incident details and the **Defender API wrapper** (`skills/powershell/defender-api-wrapper.md`) for endpoint/identity context. **Log Analytics** (`skills/log-analytics/api-wrapper.md`) provides cross-workspace correlation. **Copilot for Security** (`skills/msft-security/copilot-for-security.md`) adds natural-language enrichment.

### 4. Respond
Bunk (L1) and Kima (L2) execute playbooks (phishing response, compromised account) via API wrappers. Containment actions flow through Defender API (isolate device, restrict app execution) and Sentinel API (update incident status, add evidence).

### 5. Report
Daniels (Shift Lead) and Kima (L2) manage SOC dashboards via **workbook automation** (`skills/soar/workbook-automation.md`). Detection coverage, alert trends, and SLA metrics are deployed as Sentinel workbooks.

## Tool Chain

The primary tool chain connects four core capabilities:

```
KQL Builder → Advanced Hunting → Sentinel API → Workbook
   (build)       (execute)        (manage)      (report)
```

| Stage | Tool | Skill Reference | Used By |
|-------|------|-----------------|---------|
| Build queries | KQL builder | `skills/kql/query-builder.md` | Freamon |
| Execute queries | Advanced Hunting API | `skills/detection/advanced-hunting-api.md` | Freamon |
| Query workspaces | Log Analytics API | `skills/log-analytics/api-wrapper.md` | Freamon |
| Cross-workspace | Log Analytics patterns | `skills/log-analytics/query-patterns.md` | Freamon |
| Manage incidents | Sentinel API wrapper | `skills/powershell/sentinel-api-wrapper.md` | All |
| Endpoint actions | Defender API wrapper | `skills/powershell/defender-api-wrapper.md` | Kima, Freamon |
| SOC dashboards | Workbook automation | `skills/soar/workbook-automation.md` | Kima, Daniels |
| AI enrichment | Copilot for Security | `skills/msft-security/copilot-for-security.md` | All |
| API safety | Rate limiting | `skills/powershell/rate-limiting.md` | All |

## Team Composition

| Agent | Role | Tier | Focus |
|-------|------|------|-------|
| **Bunk** | Triage Analyst | L1 | Alert triage, known-good/known-bad classification, playbook-driven response |
| **Kima** | Escalation Analyst | L2 | Medium-severity investigation, entity enrichment, correlation, escalation decisions |
| **Freamon** | Senior Analyst | L3 | Threat hunting, KQL engineering, cross-domain correlation, APT investigation |
| **Daniels** | Shift Lead | Lead | Incident assignment, shift handoff, stakeholder comms, escalation oversight |

## Pre-Loaded Skills

**All agents** get `incident-investigation`, `teams-notification`, `rate-limiting`, and `copilot-for-security`.

| Agent | Core Skills | Phase 2-3 Skills |
|-------|-------------|------------------|
| Bunk | `phishing-response`, `compromised-account` | `sentinel-api-wrapper` |
| Kima | `sentinel-analytics-rules`, `sentinel-enrichment-ip`, `sentinel-enrichment-user` | `sentinel-api-wrapper`, `defender-api-wrapper`, `workbook-automation` |
| Freamon | `threat-hunting-foundations`, `cross-workspace-queries`, `ueba-patterns`, `defender-xdr-hunting` | `advanced-hunting-api`, `query-builder`, `log-analytics-api-wrapper`, `log-analytics-query-patterns`, `sentinel-api-wrapper`, `defender-api-wrapper` |
| Daniels | `teams-notification`, `ticket-create` | `workbook-automation` |

## Installation

```bash
npx secops-squad init
# Select "SOC Analyst team" when prompted
```

This installs the persona files into your `.squad/` directory:
- `team.md` — agent roster and project context
- `routing.md` — severity-based work routing, tool-chain routing, and escalation rules
- `ceremonies.md` — shift handoff, incident review, standup, detection review
- `skills.json` — skill assignments per agent (v2.0.0 with Phase 2-3 tools)

## Customization

After installation, everything lives in `.squad/` and is yours to edit:

- **Add agents** — need an L1.5 for specific alert types? Add a row to `team.md` and a routing entry.
- **Adjust routing** — change severity thresholds, add work-type routes, modify escalation triggers and tool-chain mappings.
- **Tune ceremonies** — change standup frequency, add a threat intel briefing, modify templates.
- **Swap skills** — add custom skills, remove ones you don't use, adjust per-agent assignments.
- **Configure `.secops/`** — set up `alerting/routing.yaml` for environment-specific alert routing rules.

## Environment Assumptions

This persona assumes a Microsoft Security stack:
- **Microsoft Sentinel** as SIEM (incidents, analytics rules, watchlists, workbooks)
- **Microsoft Defender XDR** for endpoint, identity, email, and cloud app protection
- **Microsoft Entra ID** for identity and access management
- **Microsoft Defender for Cloud** for cloud security posture
- **`.secops/` framework** for environment-specific configuration (workspace IDs, alerting rules, compliance requirements)

If your stack differs, adjust the skills and routing rules to match your tools.
