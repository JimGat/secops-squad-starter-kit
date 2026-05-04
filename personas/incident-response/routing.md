# Work Routing

How incident response work routes across the team, by IR phase and request type.

## Phase-Based Routing

| Phase | Route To | Action |
|-------|----------|--------|
| Initial triage | Rawls (IR Lead) | Classify severity, assess scope, declare incident level, assign initial tasks |
| Evidence collection | Sydnor (Forensic Analyst) | Preserve evidence, collect artifacts, begin timeline reconstruction |
| IOC research | Prez (Threat Intel) | Research indicators, check threat feeds, assess adversary attribution |
| Containment decision | Rawls (IR Lead) | Decide containment strategy based on evidence and intel, authorize actions |
| Stakeholder notification | Beadie (Comms Coordinator) | Draft and send status updates, brief leadership, coordinate regulatory needs |
| Forensic analysis | Sydnor (Forensic Analyst) | Deep-dive analysis, malware triage, impact assessment, root cause determination |
| Eradication | Rawls (IR Lead) + Sydnor (Forensic) | Remove attacker persistence, verify clean state, coordinate with IT ops |
| Recovery | Rawls (IR Lead) | Coordinate system restoration, verify clean state, monitor for re-compromise |
| Lessons learned | Rawls (IR Lead) | Facilitate post-incident review, document findings, assign improvement actions |

## Request-Type Routing

| Request Type | Route To | Examples |
|-------------|----------|----------|
| New incident triage | Rawls | Sentinel incident, Defender XDR alert, reported compromise |
| Evidence preservation | Sydnor | Disk image request, memory capture, log snapshot, email export |
| Malware sample analysis | Sydnor | Suspicious file triage, payload detonation, artifact extraction |
| IOC lookup / enrichment | Prez | IP/domain/hash reputation, threat actor profiling, campaign correlation |
| Status update request | Beadie | Leadership briefing, legal update, customer notification, regulatory report |
| Containment action | Rawls | Account disable, network isolation, endpoint quarantine, firewall block |
| Data exfiltration assessment | Sydnor + Prez | Determine what data was accessed/exfiltrated, assess regulatory impact |

## Incident Workflow

```
Detection → Rawls (triage) → Sydnor (evidence) + Prez (intel) → Rawls (containment) → Beadie (comms) → Sydnor (eradication) → Rawls (recovery) → All (lessons learned)
```

## Escalation Path

| From | To | When |
|------|----|------|
| Rawls → Executive Leadership | Major incident declaration, significant business impact, regulatory exposure |
| Rawls → Legal/Compliance | Data breach confirmed, regulatory notification required |
| Sydnor → Rawls | Evidence confirms active attacker presence or lateral movement |
| Prez → Rawls | Intelligence indicates nation-state actor or coordinated campaign |
| Beadie → Rawls | Stakeholder requests information beyond current disclosure authorization |

## Compliance & Automation Routing

| Request Type | Route To | Skill | Examples |
|-------------|----------|-------|----------|
| Compliance check | Beadie (Comms) | `compliance-framework-mappings` | Map incident to NIST 800-53, PCI-DSS, HIPAA, SOC 2 controls; assess regulatory notification obligations |
| Evidence preservation / legal hold | Sydnor (Forensic) | `ediscovery-api-wrapper` | Place custodian legal hold, create eDiscovery case, export review set for legal proceedings |
| Data classification assessment | Sydnor (Forensic) | `purview-api-wrapper` | Determine sensitivity of exposed data, check DLP policy violations, assess data classification labels |
| Data retention / tiering | Sydnor (Forensic) | `data-tiering-commands` | Tier forensic evidence to appropriate storage, enforce retention policies for legal holds |
| Post-incident reporting | Rawls (IR Lead) | `workbook-automation` | Deploy incident summary dashboard, generate compliance audit workbook, executive briefing visuals |
| Regulatory reporting | Beadie (Comms) | `compliance-framework-mappings` | Generate framework-specific compliance reports, map findings to control families |

## Rules

1. **Rawls commands the incident** — all containment and escalation decisions go through IR Lead. No freelancing.
2. **Evidence first, then conclusions** — Sydnor collects before anyone speculates. Preserve evidence integrity.
3. **Prez feeds intel in real-time** — IOC research happens in parallel with forensics, not after.
4. **Beadie owns all external comms** — nobody talks to stakeholders, legal, or press without Beadie coordinating.
5. **Containment before eradication** — stop the bleeding, then clean up. Don't tip off the attacker by cleaning too early.
6. **Every incident gets lessons learned** — no incident closes without a post-incident review, regardless of severity.
7. **Major incidents get Rawls immediately** — critical severity bypasses any queue or routing logic.
8. **Chain of custody is sacred** — Sydnor maintains forensic integrity. No evidence handling without documentation.
9. **Compliance assessment before closure** — Beadie maps every High/Critical incident to applicable compliance frameworks before Rawls closes it.
10. **Legal holds before evidence collection** — Sydnor places eDiscovery legal holds before collecting mailbox or document evidence to ensure admissibility.
11. **Post-incident dashboards are mandatory** — Rawls deploys an incident summary workbook for every High/Critical incident using workbook-automation.
