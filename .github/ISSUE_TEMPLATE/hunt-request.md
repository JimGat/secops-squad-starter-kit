---
name: Threat Hunt Request
about: Request a proactive threat hunt
title: "[Hunt] "
labels: hunt-request
assignees: ""
---

## Threat Hunt Request

### Hypothesis
<!-- What do you suspect might be happening in the environment? State as a testable hypothesis. -->

### Hunt Objective
<!-- What question are you trying to answer? What would a positive finding look like? -->

### MITRE ATT&CK Mapping
<!-- Which tactic(s) and technique(s) are you hunting for? -->
- **Tactic:**
- **Technique ID:**
- **Technique Name:**

### Data Sources
<!-- Which tables and time ranges should be searched? -->
- **Table(s):** (e.g., DeviceProcessEvents, CommonSecurityLog, AADSignInEventsBeta)
- **Time range:** (e.g., last 30 days, specific date range)
- **Platform:** (e.g., Sentinel, Defender XDR advanced hunting, ADX)

### Threat Intelligence
<!-- Any IOCs, threat actor references, or campaign context? -->
- **IOCs:** (hashes, IPs, domains — if applicable)
- **Threat actor / campaign:**
- **Reference reports:**

### Scope
- [ ] Organization-wide
- [ ] Specific tenant / subscription
- [ ] Specific device group
- [ ] Specific user population
- **Scope details:**

### Hunt Type
- [ ] IOC sweep (searching for known indicators)
- [ ] TTP-based (looking for behavioral patterns)
- [ ] Anomaly detection (statistical outliers)
- [ ] Baseline deviation (comparing against known-good)

### Expected Output
<!-- What deliverables should the hunt produce? -->
- [ ] KQL hunting query (reusable)
- [ ] Findings report
- [ ] New detection rule (if positive findings)
- [ ] Watchlist updates
- [ ] Threat intel enrichment

### Priority
- [ ] Urgent (active threat suspected)
- [ ] High (recent threat intel, no active indicators yet)
- [ ] Normal (proactive / scheduled hunt)

### Additional Context
<!-- Incident references, management requests, compliance drivers, etc. -->
