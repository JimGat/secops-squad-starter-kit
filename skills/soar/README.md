---
title: SOAR Skills Domain
category: soar
author: Herc
version: 1.0.0
last_updated: 2026-05-04
---

# SOAR Skills Domain

## Overview

The `skills/soar/` domain covers Security Orchestration, Automation, and Response — the playbooks, enrichment logic, and automated workflows that turn security alerts into resolved incidents. SOAR skills teach agents how to build end-to-end response pipelines: from automated triage and entity enrichment to containment actions, notification, and ticket creation.

## Why This Matters

SOC teams face thousands of alerts daily. Without automation, analysts spend most of their time on repetitive triage and enrichment tasks instead of investigating real threats. SOAR skills enable agents to automate the predictable parts of incident response — reducing mean time to respond (MTTR), ensuring consistent playbook execution, and freeing analysts for high-judgment work.

## Skill Files

| Skill | File | Description |
|---|---|---|
| **Auto-Triage** | `auto-triage.md` | Automated incident triage and classification |
| **Compliance Framework Mappings** | `compliance-framework-mappings.md` | Mapping incidents to compliance frameworks |
| **Compromised Account** | `compromised-account.md` | Compromised account response playbook |
| **Data Exfiltration Response** | `data-exfiltration-response.md` | Data exfiltration detection and response |
| **Malware Containment** | `malware-containment.md` | Malware containment and remediation |
| **Phishing Response** | `phishing-response.md` | Phishing triage and response automation |
| **Sentinel Enrichment - IP** | `sentinel-enrichment-ip.md` | IP address enrichment via Sentinel |
| **Sentinel Enrichment - User** | `sentinel-enrichment-user.md` | User entity enrichment via Sentinel |
| **Teams Notification** | `teams-notification.md` | Teams notification for security alerts |
| **Threat Intel Ingest** | `threat-intel-ingest.md` | Threat intelligence indicator ingestion |
| **Ticket Create** | `ticket-create.md` | ServiceNow/Jira ticket creation automation |
| **Workbook Automation** | `workbook-automation.md` | SOC dashboard and workbook lifecycle |

## Dependencies

SOAR skills reference these domain skills:

- `skills/msft-security/` — Sentinel and Defender APIs for alert ingestion and response actions
- `skills/powershell/` — API wrappers for orchestrating response steps
- `templates/bicep/soar/` — Bicep templates for deploying Logic Apps and Function Apps

## Environment Context

Before building or executing playbooks, agents MUST consult the `.secops/` framework:

- **`.secops/alerting/routing.yaml`** — Alert routing rules and escalation paths
- **`.secops/workspaces/`** — Sentinel workspace targets for playbook deployment
- **`.secops/compliance/requirements.yaml`** — Regulatory constraints on automated response actions
- **`.secops/environment.yaml`** — Cloud type and subscription context

If `.secops/` does not exist, suggest running `secops-squad init --secops` to scaffold it.

## How Agents Should Use These Skills

1. **Start with triage** — use `auto-triage.md` to classify and prioritize incoming incidents
2. **Enrich entities** — apply `sentinel-enrichment-ip.md` and `sentinel-enrichment-user.md` for context
3. **Match the response playbook** — select `phishing-response.md`, `compromised-account.md`, `malware-containment.md`, or `data-exfiltration-response.md` based on incident type
4. **Notify stakeholders** — use `teams-notification.md` for real-time SOC alerting
5. **Create tickets** — apply `ticket-create.md` for ITSM integration
6. **Map to compliance** — use `compliance-framework-mappings.md` for regulatory reporting

## Related Skills

- `skills/msft-security/sentinel-api-reference.md` — Sentinel APIs consumed by SOAR playbooks
- `skills/detection/detection-lifecycle.md` — Detections that trigger SOAR workflows
- `skills/orchestration/cross-skill-orchestration.md` — Multi-step workflow patterns used by playbooks
