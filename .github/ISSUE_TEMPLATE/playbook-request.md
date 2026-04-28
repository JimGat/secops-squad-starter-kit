---
name: Playbook Request
about: Request a new SOAR playbook for automated response
title: "[Playbook] "
labels: playbook-request
assignees: ""
---

## SOAR Playbook Request

### Trigger
<!-- What event or alert should kick off this playbook? -->
- **Trigger type:** (e.g., Sentinel alert, Sentinel incident, scheduled, manual)
- **Alert/Rule name:** (if triggered by a specific analytics rule)

### Automated Actions
<!-- What should the playbook do? List the steps in order. -->
1.
2.
3.

### Enrichment Sources
<!-- What external data should the playbook pull? -->
- [ ] Threat intelligence lookup (IP, domain, hash)
- [ ] User details from Entra ID
- [ ] Device info from Defender for Endpoint
- [ ] Geo-IP lookup
- [ ] VirusTotal / other TI provider
- [ ] Other: ___

### Response Actions
<!-- What containment or remediation actions should be taken? -->
- [ ] Isolate device (Defender for Endpoint)
- [ ] Disable user account (Entra ID)
- [ ] Block IP/domain (firewall / NSG)
- [ ] Revoke user sessions
- [ ] Send notification (Teams / email)
- [ ] Create ticket (ServiceNow / Jira)
- [ ] Other: ___

### Approval Requirements
- [ ] Fully automated (no human approval needed)
- [ ] Semi-automated (human approves critical actions)
- [ ] Human-triggered only

### Target Products
<!-- Which Microsoft Security products does this playbook interact with? -->
- [ ] Microsoft Sentinel
- [ ] Defender for Endpoint
- [ ] Defender for Cloud
- [ ] Defender for Identity
- [ ] Entra ID
- [ ] Other: ___

### Additional Context
<!-- Runbook references, SLA requirements, escalation paths, etc. -->
