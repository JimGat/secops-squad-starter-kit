---
title: Fusion Rule Context — Understanding ML-Based Multi-Stage Attack Detection
category: detection
difficulty: advanced
mitre_attack:
  - T1078  # Valid Accounts
  - T1566  # Phishing
  - T1027  # Obfuscated Files or Information
  - T1486  # Data Encrypted for Impact
  - T1071  # Application Layer Protocol
products:
  - Microsoft Sentinel
  - Microsoft Defender for Cloud Apps
  - Microsoft Defender for Identity
  - Azure Active Directory Identity Protection
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# Fusion Rule Context — Understanding ML-Based Multi-Stage Attack Detection

## Overview

Fusion is Sentinel's built-in ML engine that correlates low-fidelity alerts across multiple Microsoft security products to detect multi-stage attacks. You can't write Fusion rules — Microsoft manages the ML models. But you *can* understand what Fusion detects, interpret its incidents, and build supplementary detections for its blind spots.

This skill is about working *with* Fusion, not replacing it.

Use this skill when:
- A Fusion incident lands in your queue and you need to interpret it
- You're assessing your detection coverage and need to understand what Fusion handles
- You want to build custom detections that complement Fusion's coverage
- You're tuning Fusion's behavior (what limited tuning is available)

## Prerequisites

| Requirement | Detail |
|---|---|
| **Data connectors** | Azure AD Identity Protection, Microsoft Defender for Cloud Apps, Defender for Endpoint, Defender for Identity, Defender for Office 365 |
| **Sentinel** | Fusion rule enabled (enabled by default — check **Analytics** → **Rule templates** → **Advanced Multistage Attack Detection**) |
| **Permissions** | `Microsoft Sentinel Reader` to view incidents; `Contributor` to tune |
| **Threat model** | Fusion covers scenarios that should be documented in your threat model library |

## What Fusion Detects

Fusion correlates alerts from multiple sources to identify multi-stage attack patterns. It operates on the premise that individual alerts may be low-confidence, but their *combination* in sequence indicates a real attack.

### Supported Attack Scenarios

| Scenario | Typical Kill Chain | Data Sources |
|---|---|---|
| **Credential theft → data exfiltration** | Phishing → compromised sign-in → mass file download | Azure AD Identity Protection + Defender for Cloud Apps |
| **Credential theft → lateral movement** | Password spray → new inbox rule → internal phishing | Azure AD Identity Protection + Defender for Office 365 |
| **Ransomware** | Suspicious sign-in → endpoint alert → mass encryption | Azure AD Identity Protection + Defender for Endpoint |
| **Cloud resource abuse** | Compromised admin account → new compute deployment → crypto mining | Azure AD Identity Protection + Azure Activity |
| **Supply chain compromise** | Suspicious OAuth consent → data access from unusual app | Azure AD Identity Protection + Defender for Cloud Apps |

### How Fusion Works (Simplified)

```
Alert Source A          Alert Source B          Alert Source C
(Identity Protection)   (Defender for Endpoint) (Cloud Apps)
      │                       │                       │
      ▼                       ▼                       ▼
  ┌─────────────────────────────────────────────────────┐
  │              Fusion ML Correlation Engine            │
  │                                                     │
  │  1. Collects alerts across products                 │
  │  2. Correlates by entity (user, IP, device)         │
  │  3. Evaluates temporal proximity                    │
  │  4. Scores kill-chain likelihood                    │
  │  5. Creates Sentinel incident if threshold met      │
  └─────────────────────────────────────────────────────┘
                          │
                          ▼
                  Fusion Incident
                  (High severity, multi-alert)
```

## Reading and Interpreting Fusion Incidents

### Anatomy of a Fusion Incident

| Field | What to Look For |
|---|---|
| **Title** | Describes the attack scenario (e.g., "Suspicious sign-in followed by anomalous Office 365 activity") |
| **Severity** | Almost always **High** — Fusion fires conservatively |
| **Alerts** | Multiple alerts from different products, correlated by entity |
| **Entities** | The user, IP, device, or application at the center of the correlation |
| **Timeline** | Chronological sequence of the correlated alerts — this tells the attack story |
| **MITRE ATT&CK** | Auto-mapped to tactics (e.g., Initial Access → Execution → Exfiltration) |

### Triage Workflow for Fusion Incidents

1. **Read the timeline.** Fusion incidents are stories — read the alerts in chronological order to understand the kill chain.

2. **Validate the anchor alert.** The first alert in the chain is usually the initial access event (sign-in anomaly, phishing detection). If this is a known false positive, the entire chain may be benign.

3. **Check entity context.** Use entity pages (click the user/IP entity in the incident) to see:
   - Is this a VIP user? (Check your `VIP-Users` watchlist)
   - Is this IP from a known corporate location?
   - Has this device shown other suspicious behavior?

4. **Correlate with custom detections.** Run your own KQL queries for the entities involved:

   ```kql
   // Check user activity around the Fusion incident
   let TargetUser = "compromised.user@contoso.com";
   let IncidentTime = datetime(2026-04-28T10:30:00Z);
   let Window = 2h;
   SignInLogs
   | where TimeGenerated between ((IncidentTime - Window) .. (IncidentTime + Window))
   | where UserPrincipalName =~ TargetUser
   | project TimeGenerated, IPAddress, AppDisplayName, ResultType,
       Country = tostring(LocationDetails.countryOrRegion),
       RiskLevel = RiskLevelDuringSignIn
   | order by TimeGenerated asc
   ```

5. **Classify and close.** Fusion incidents should be classified within 4 hours:
   - **True Positive** — Escalate to incident response, begin containment
   - **Benign Positive** — Real activity, not malicious (e.g., employee traveling)
   - **False Positive** — Incorrect correlation, add tuning notes

## What You Can and Can't Control

### What You Can Tune

| Control | How | Location |
|---|---|---|
| **Enable/disable Fusion** | Toggle the Fusion analytics rule | Sentinel → Analytics → Active rules |
| **Exclude specific alert types** | Configure source signal exclusions | Fusion rule → Edit → Source signal settings |
| **Suppress by entity** | Add users/IPs to exclusions | Sentinel → Analytics → Fusion rule → Exclusions |
| **Automation rules** | Auto-close or auto-assign Fusion incidents matching criteria | Sentinel → Automation → Automation rules |

### What You Can't Tune

| Aspect | Detail |
|---|---|
| **ML models** | Microsoft manages the correlation logic — you can't adjust thresholds or weights |
| **Alert combinations** | You can't define which alert pairs Fusion should correlate |
| **Severity** | Fusion incidents are always High severity |
| **Detection logic** | The internal scoring algorithm is opaque |

## Building Supplementary Detections

Fusion has blind spots. Build custom detections for scenarios Fusion doesn't cover:

### Blind Spot 1 — Single-Source Multi-Stage Attacks

Fusion requires alerts from *multiple* products. An attack that stays within a single data source won't trigger Fusion.

**Supplementary detection:** Build scheduled rules that correlate events within `SignInLogs` or `SecurityEvent` over time.

```kql
// Single-source kill chain: failed MFA → successful sign-in → risky activity
// MITRE: T1078 (Valid Accounts)
let MFAFailures = SignInLogs
    | where TimeGenerated > ago(1h)
    | where ResultType == "50074" // MFA required but not completed
    | distinct UserPrincipalName, IPAddress;
let SubsequentSuccess = SignInLogs
    | where TimeGenerated > ago(1h)
    | where ResultType == 0
    | where UserPrincipalName in (MFAFailures)
    | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName;
SubsequentSuccess
| join kind=inner (
    AuditLogs
    | where TimeGenerated > ago(1h)
    | where OperationName in ("Add member to role", "Add app role assignment")
    | extend Actor = tostring(InitiatedBy.user.userPrincipalName)
) on $left.UserPrincipalName == $right.Actor
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, OperationName
```

### Blind Spot 2 — Third-Party Product Alerts

Fusion primarily correlates Microsoft product alerts. Third-party SIEM data, custom alerts, and non-Microsoft security tools aren't included.

**Supplementary detection:** Build custom analytics rules that correlate third-party alerts with Azure AD sign-in anomalies.

### Blind Spot 3 — Slow-Burn Attacks

Fusion looks for temporal proximity. An attacker who waits days between stages may not trigger correlation.

**Supplementary detection:** Use longer lookback windows (7–14 days) in scheduled rules with baseline deviation patterns.

## Common Fusion Scenarios and Response

| Fusion Scenario | First Response | Containment Action | Related Playbook |
|---|---|---|---|
| Suspicious sign-in → mail forwarding rule | Check if forwarding rule is to external domain | Disable forwarding rule, revoke sessions | Email compromise response |
| Anomalous travel → mass download | Verify if user is actually traveling | Block sign-in, revoke sessions, check downloaded files | Data exfiltration response |
| Impossible travel → admin privilege escalation | Check if admin action was authorized | Remove added privileges, revoke sessions | Privilege escalation response |
| Suspicious sign-in → ransomware indicators | Immediately isolate endpoint | Isolate device, revoke sessions, begin IR | Ransomware response |

## Best Practices

1. **Don't disable Fusion.** It catches multi-stage attacks that individual rules miss. If it's noisy, tune the source signal exclusions rather than turning it off.
2. **Classify every Fusion incident.** The ML improves with feedback — marking true/false positives helps Microsoft tune the models for your tenant.
3. **Build around Fusion, not against it.** Custom detections should cover what Fusion *can't* see (single-source attacks, slow-burn campaigns, third-party data). Don't duplicate Fusion's coverage.
4. **Document Fusion scenarios in your threat model library.** Even though you can't control the logic, document the attack scenarios Fusion is expected to catch.
5. **Set up automation rules for Fusion incidents.** Auto-assign Fusion incidents to senior analysts and auto-run enrichment playbooks (see SOAR skills).
6. **Review Fusion incident trends quarterly.** If Fusion is producing mostly benign positives for a specific scenario, add source signal exclusions.

## Related Skills

- **[Detection Lifecycle](detection-lifecycle.md)** — Fusion detections follow a modified lifecycle (no Phase 2/3, focus on Phase 4 tuning).
- **[MITRE ATT&CK Mapping](mitre-attack-mapping.md)** — Fusion auto-maps to tactics; verify and supplement.
- **[Scheduled Rule Pattern](scheduled-rule-pattern.md)** — Build supplementary detections for Fusion blind spots.
- **[Threat Model Template](threat-model-template.md)** — Document Fusion-covered scenarios in your threat model library.
