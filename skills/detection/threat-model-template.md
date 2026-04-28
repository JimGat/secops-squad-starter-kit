---
title: Threat Model Template for Detection Engineering
category: detection
difficulty: intermediate
mitre_attack:
  - T1566  # Phishing
  - T1566.001  # Spearphishing Attachment
  - T1566.002  # Spearphishing Link
  - T1078  # Valid Accounts
  - T1078.004  # Cloud Accounts
  - T1539  # Steal Web Session Cookie
  - T1056.004  # Credential API Hooking
  - T1114  # Email Collection
  - T1114.003  # Email Forwarding Rule
products:
  - Microsoft Sentinel
  - Microsoft Defender for Office 365
  - Azure Active Directory Identity Protection
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# Threat Model Template for Detection Engineering

## Overview

Every detection in this framework starts with a threat model. Not optional — it's team decision #7. The threat model answers *why* this detection exists before you write a single line of KQL. It documents the threat actor, their goals, the attack path, and your detection approach so reviewers and future maintainers understand the intent.

This skill provides the template, the process, and a complete example.

Use this skill when:
- Starting a new detection (Phase 1 of the [Detection Lifecycle](detection-lifecycle.md))
- Reviewing a detection for approval (threat model is a gate requirement)
- Documenting an existing detection that lacks a threat model
- Onboarding a new detection engineer to the team's process

## Prerequisites

| Requirement | Detail |
|---|---|
| **MITRE ATT&CK** | Familiarity with the Enterprise ATT&CK matrix |
| **Threat intelligence** | Access to threat reports, intel feeds, or adversary profiles |
| **Data source knowledge** | Understanding of what telemetry your environment collects |
| **Review process** | Defined approval workflow (detection lead or team review) |

## The Template

Copy this template for every new detection. Store it in your detection repository alongside the analytics rule ARM/Bicep template.

File naming convention: `threat-models/{detection-slug}.md`

---

### Threat Model Document

````markdown
# Threat Model: {Detection Name}

**Detection ID:** {unique-identifier}
**Author:** {name}
**Date:** {YYYY-MM-DD}
**Status:** Draft | In Review | Approved | Deprecated
**Reviewer:** {name}
**Approval Date:** {YYYY-MM-DD or N/A}

---

## 1. Threat Actor Profile

| Field | Detail |
|---|---|
| **Actor type** | {Nation-state / Financially motivated / Insider / Hacktivist / Opportunistic} |
| **Motivation** | {What does the attacker want? Espionage, financial gain, disruption, data theft} |
| **Capability level** | {Low / Medium / High / Advanced} |
| **Known groups** | {APT29, FIN7, etc. or "Generic" for commodity threats} |
| **Target** | {What are they targeting? Users, systems, data, infrastructure} |

## 2. Attack Path

Describe the step-by-step attack sequence this detection is designed to catch.

| Step | Action | MITRE Technique | Data Source |
|---|---|---|---|
| 1 | {Description of first action} | {T####} | {Table/log name} |
| 2 | {Description of second action} | {T####} | {Table/log name} |
| 3 | {Description of third action} | {T####} | {Table/log name} |

### Attack Diagram (Optional)

```
Attacker → [Phishing Email] → User clicks link → [Credential Harvest]
         → Attacker signs in → [Anomalous Sign-in] → Data access
```

## 3. Data Sources

| Data Source | Table | Required Fields | Retention Needed |
|---|---|---|---|
| {Source name} | {KQL table} | {Key columns} | {Min retention} |

### Data Availability Confirmation

- [ ] Data source is connected and ingesting
- [ ] Required fields are populated (not null/empty)
- [ ] Retention covers the detection's lookback window
- [ ] Ingestion latency is acceptable for the detection type (NRT vs scheduled)

## 4. Detection Approach

**Detection type:** {Scheduled rule / NRT rule / Hunting query / Fusion supplement}

**Logic summary:** {One paragraph describing what the detection does — in plain language, not KQL}

**Key thresholds:**
| Parameter | Value | Rationale |
|---|---|---|
| {e.g., FailureThreshold} | {50} | {Based on testing — below this, FP rate exceeds 50%} |

**Entity mappings:**
| Entity Type | Column | Purpose |
|---|---|---|
| {Account / IP / Host} | {Column name} | {Why this entity matters for investigation} |

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Confidence |
|---|---|---|---|
| {Tactic name} | {T####} | {T####.###} | {High / Medium / Low} |

## 6. Expected Outcomes

| Metric | Target |
|---|---|
| True positive rate | {≥ 80%} |
| False positive rate | {≤ 20%} |
| Expected alert volume | {< X per day} |
| Mean time to response | {< Y hours} |

## 7. False Positive Sources

| FP Source | Mitigation |
|---|---|
| {Known FP cause} | {How to tune it out} |

## 8. Limitations and Blind Spots

- {What this detection will NOT catch}
- {Evasion techniques an attacker could use}
- {Dependencies that could cause the detection to fail}

## 9. Review and Approval

| Step | Owner | Status |
|---|---|---|
| Threat model drafted | {Author} | {Done / Pending} |
| Peer review | {Reviewer name} | {Done / Pending} |
| MITRE mapping verified | {Kima or detection lead} | {Done / Pending} |
| Data availability confirmed | {Author} | {Done / Pending} |
| Approved for development | {Detection lead} | {Done / Pending} |
````

---

## Process: How to Write a Threat Model

### Step 1 — Identify the Threat

Start with one of:
- A threat intelligence report describing a technique used against your industry
- A gap identified in your MITRE ATT&CK coverage analysis
- A real incident that your existing detections missed
- A request from the SOC team based on observed attack patterns

### Step 2 — Research the Attack Path

- Read MITRE ATT&CK documentation for the technique
- Review threat intelligence for real-world examples
- Identify the data sources that would record this activity
- Map each step to a tactic and technique

### Step 3 — Validate Data Availability

Before committing to development:

```kql
// Check if the required table has data
SignInLogs
| where TimeGenerated > ago(1d)
| summarize Count = count(), LastEvent = max(TimeGenerated)
```

```kql
// Check if required fields are populated
SignInLogs
| where TimeGenerated > ago(1d)
| summarize
    TotalRows = count(),
    NullIP = countif(isempty(IPAddress)),
    NullUPN = countif(isempty(UserPrincipalName)),
    NullResult = countif(isempty(ResultType))
| extend
    IPCoverage = round(100.0 * (TotalRows - NullIP) / TotalRows, 1),
    UPNCoverage = round(100.0 * (TotalRows - NullUPN) / TotalRows, 1),
    ResultCoverage = round(100.0 * (TotalRows - NullResult) / TotalRows, 1)
```

### Step 4 — Document the Detection Approach

Write the logic in plain language first. If you can't explain it without KQL, you don't understand it well enough.

**Good:** "Alert when a single IP address produces 50+ failed sign-in attempts against 5 or more distinct accounts within 10 minutes."

**Bad:** "Summarize SignInLogs by IPAddress and count where count > 50."

### Step 5 — Submit for Review

- Post the threat model as a PR in the detection repository
- Tag the detection lead and a peer reviewer
- Address feedback before proceeding to Phase 2 (query development)

## Example: Credential Theft via Phishing

```markdown
# Threat Model: Credential Theft via Phishing Link

**Detection ID:** phishing-credential-harvest
**Author:** Kima
**Date:** 2026-04-28
**Status:** Approved
**Reviewer:** McNulty
**Approval Date:** 2026-04-28

---

## 1. Threat Actor Profile

| Field | Detail |
|---|---|
| **Actor type** | Financially motivated / Opportunistic |
| **Motivation** | Steal credentials to access corporate email, OneDrive, SharePoint for BEC or data theft |
| **Capability level** | Medium — uses commodity phishing kits with AiTM (adversary-in-the-middle) capability |
| **Known groups** | Storm-1167, DEV-1101 operators, commodity AiTM kit users |
| **Target** | All users, with preference for finance, HR, and executive roles |

## 2. Attack Path

| Step | Action | MITRE Technique | Data Source |
|---|---|---|---|
| 1 | Attacker sends phishing email with credential harvest link | T1566.002 (Spearphishing Link) | EmailEvents (Defender for Office 365) |
| 2 | User clicks link and enters credentials on fake sign-in page | T1056.004 (Credential API Hooking) | UrlClickEvents (Defender for Office 365) |
| 3 | Attacker replays stolen credentials (and possibly session token) | T1078 (Valid Accounts) | SignInLogs (Azure AD) |
| 4 | Attacker accesses mailbox, sets forwarding rule | T1114.003 (Email Collection: Email Forwarding Rule) | OfficeActivity |
| 5 | Attacker exfiltrates data or launches BEC from compromised mailbox | T1566 (Phishing — internal) | EmailEvents |

### Attack Diagram

```
Attacker → [Phishing email with link] → User clicks → [Credential harvest page]
         → Attacker gets creds/token → [Sign-in from attacker IP]
         → [Mail forwarding rule created] → [BEC or data exfiltration]
```

## 3. Data Sources

| Data Source | Table | Required Fields | Retention Needed |
|---|---|---|---|
| Azure AD Sign-ins | SignInLogs | UserPrincipalName, IPAddress, ResultType, RiskLevelDuringSignIn | 30 days |
| Defender for Office 365 | EmailEvents | SenderFromAddress, RecipientEmailAddress, DeliveryAction | 30 days |
| Defender for Office 365 | UrlClickEvents | Url, AccountUpn, ActionType | 30 days |
| Office 365 Audit | OfficeActivity | Operation, UserId, ClientIP | 90 days |

### Data Availability Confirmation

- [x] SignInLogs connected and ingesting
- [x] EmailEvents connected via M365 Defender connector
- [x] UrlClickEvents populated
- [x] OfficeActivity connected
- [x] All retention requirements met

## 4. Detection Approach

**Detection type:** Scheduled rule (1-hour frequency)

**Logic summary:** Detect when a user clicks a URL delivered via email (UrlClickEvents), followed by a sign-in from a new IP address flagged as risky (SignInLogs with RiskLevel medium/high), followed by a mail forwarding rule creation (OfficeActivity) — all within a 4-hour window. This catches the credential-harvest-to-mailbox-takeover chain.

**Key thresholds:**
| Parameter | Value | Rationale |
|---|---|---|
| CorrelationWindow | 4 hours | Attackers typically act within 1-2 hours; 4 hours provides margin |
| RiskLevel | medium or high | Filters out low-risk sign-ins that are likely legitimate |

**Entity mappings:**
| Entity Type | Column | Purpose |
|---|---|---|
| Account | UserPrincipalName | The compromised user — primary investigation target |
| IP | AttackerIP | The IP used for the malicious sign-in |
| URL | PhishingUrl | The credential harvest URL for blocking |

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Confidence |
|---|---|---|---|
| Initial Access | T1566 | T1566.002 (Spearphishing Link) | High |
| Credential Access | T1078 | T1078.004 (Cloud Accounts) | High |
| Collection | T1114 | T1114.003 (Email Forwarding Rule) | Medium |

## 6. Expected Outcomes

| Metric | Target |
|---|---|
| True positive rate | ≥ 85% |
| False positive rate | ≤ 15% |
| Expected alert volume | 1-5 per day |
| Mean time to response | < 2 hours |

## 7. False Positive Sources

| FP Source | Mitigation |
|---|---|
| Legitimate new IP after VPN change | Check if IP is from a known corporate VPN range (watchlist) |
| URL rewrite services triggering UrlClickEvents | Exclude known URL rewrite domains |
| IT admin creating mail rules on behalf of users | Exclude accounts in ServiceAccounts watchlist |

## 8. Limitations and Blind Spots

- Does NOT detect credential theft via attachment-based phishing (T1566.001) — separate detection needed
- AiTM attacks that steal session tokens may bypass the RiskLevel filter if Conditional Access doesn't flag them
- If UrlClickEvents has ingestion delays > 2 hours, the correlation window may miss the chain
- Attacker who waits > 4 hours between credential theft and mailbox access will evade this detection
```

## Review and Approval Workflow

```
Author writes          Peer reviews         Detection lead        Detection enters
threat model    ──►    and comments   ──►   approves or    ──►   Phase 2
(1-2 hours)           (1 hour)              requests changes     (KQL development)
                                            (Gate 1)
```

### Review Checklist (for Reviewers)

- [ ] Threat actor profile is realistic and specific (not "any attacker")
- [ ] Attack path steps are concrete and mapped to MITRE techniques
- [ ] Data sources exist and are confirmed available
- [ ] Detection approach is described in plain language
- [ ] Thresholds have documented rationale
- [ ] False positive sources are identified with mitigations
- [ ] Limitations are honest — no detection catches everything
- [ ] MITRE mapping confidence levels are justified

## Best Practices

1. **Write the threat model before the KQL.** This prevents building detections in search of a problem.
2. **Be honest about limitations.** A threat model that claims no blind spots is a threat model that hasn't been thought through.
3. **Keep it concise.** The template is comprehensive, but each section should be 2-5 lines. If it takes more than an hour to write, you're over-thinking it.
4. **Link to threat intelligence.** Reference the report, advisory, or incident that motivated this detection. Future readers need context.
5. **Update when tuning.** When you change thresholds or exclusions in Phase 4, update the threat model to reflect the current state.
6. **Store alongside the rule.** The threat model lives in the same Git repo as the analytics rule ARM template — they're a unit.

## Related Skills

- **[Detection Lifecycle](detection-lifecycle.md)** — The threat model is a Phase 1 deliverable and Gate 1 requirement.
- **[MITRE ATT&CK Mapping](mitre-attack-mapping.md)** — How to fill in the MITRE mapping section.
- **[Scheduled Rule Pattern](scheduled-rule-pattern.md)** — Build the rule after the threat model is approved.
- **[Watchlist-Driven Detection](watchlist-driven-detection.md)** — Watchlists support the false positive mitigations documented here.
