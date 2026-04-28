# Project Context

- **Owner:** John Spaid
- **Project:** secops-squad — SecOps framework for Microsoft Security products (Sentinel, Defender, Entra ID Protection), KQL, Logic Apps, Log Analytics, Azure Data Explorer
- **Stack:** KQL, Logic Apps, Azure Functions, Bicep, PowerShell, Node.js/TypeScript
- **Created:** 2026-04-28

## Learnings

<!-- Append new learnings below. Each entry is something lasting about the project. -->

📌 Team initialized on 2026-04-28 — full squad scaffolded with SecOps-focused roles and routing.

📌 **Phase 1: Framework Architecture Finalized** (2026-04-28)
- Skills-first architecture: markdown skills by domain (kql/, soar/, detection/, log-analytics/, adx/, msft-security/)
- Persona-driven onboarding: init wizard with Azure discovery, personas include soc-analyst, detection-engineering, threat-hunting, cloud-security, incident-response, full-soc
- Quality gates: KQL CI validation (Carver), SOAR rollback plans mandatory (Herc), threat model ceremony for detection (McNulty)
- Coverage analysis: MITRE ATT&CK tagging required for all detection/KQL skills
- CLI strategy: secops-squad wraps @bradygaster/squad-cli, additive security commands
- Phase 1 exit: init wizard, soc-analyst persona, 3 KQL skills, 3 SOAR skills, KQL CI, getting-started docs
- Target: new user → working SecOps team with KQL hunting + phishing response in ≤ 15 minutes

🟥 **Herc Phase 1 Contribution** (2026-04-28, ~410s)
- Authored 3 SOAR skills: phishing-response, compromised-account, teams-notification
- ~2078 lines of Logic Apps playbook patterns and automation workflows
- Established SOAR response playbook templates with rollback safety patterns
- Built incident-response skill set for automated threat containment
- Created foundation for cross-team notification and orchestration

🟥 **Herc Phase 2a: SOAR Skills Library Complete** (2026-04-28)
- Authored 7 additional SOAR skills completing the 10-skill library:
  1. malware-containment.md — MDE device isolation + forensic evidence collection
  2. data-exfiltration-response.md — DLP alert enrichment, manager notification, sharing block
  3. sentinel-enrichment-ip.md — Multi-source IP threat intel (VT, MDTI, GeoIP, watchlists)
  4. sentinel-enrichment-user.md — Entra ID user context (profile, risk, MFA, privileged roles)
  5. ticket-create.md — ServiceNow/JIRA bi-directional ticket sync
  6. auto-triage.md — L1 evidence-based auto-close/assign/escalate
  7. threat-intel-ingest.md — TAXII/STIX scheduled feed ingestion to Sentinel TI
- ~155,000 characters of SOAR playbook patterns across all 10 skills
- Every skill has: YAML frontmatter, architecture diagram, Logic Apps workflow, Bicep template, rollback/destroy, testing checklist
- All rollback sections include both automation teardown AND remediation reversal procedures
- Cross-references between skills establish a cohesive playbook library
- Covered all trigger types: sentinel-incident, sentinel-entity, scheduled recurrence
