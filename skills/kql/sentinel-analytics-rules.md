---
title: Sentinel Analytics Rules
category: kql
difficulty: intermediate
mitre_attack:
  - T1110  # Brute Force
  - T1078  # Valid Accounts
  - T1098  # Account Manipulation
products:
  - Microsoft Sentinel
  - Azure Active Directory
  - Microsoft Defender for Endpoint
author: Freamon
version: 1.0.0
---

# Sentinel Analytics Rules

## Overview

This skill covers the KQL patterns and structural requirements for writing Microsoft Sentinel analytics rules — both scheduled and NRT (near-real-time). Analytics rules are the automated detection engine of a SOC: they run on a schedule, evaluate KQL queries against ingested data, and generate alerts (grouped into incidents) when conditions are met.

Use this skill when:
- Converting a validated threat hunt into an automated detection
- Writing a new scheduled or NRT analytics rule from scratch
- Enriching alerts with entity mappings and custom details
- Building multi-stage detections that correlate events across time windows

## Prerequisites

| Requirement | Detail |
|---|---|
| **Tables** | `SignInLogs`, `AuditLogs`, `SecurityEvent`, `DeviceProcessEvents`, `SecurityAlert` |
| **Workspace** | Sentinel-enabled Log Analytics workspace |
| **Permissions** | `Microsoft Sentinel Contributor` to create and modify rules |
| **Knowledge** | Familiarity with [Threat Hunting Foundations](threat-hunting-foundations.md) patterns |

## Core Patterns

### Pattern 1 — Scheduled Rule: Brute Force Detection

Scheduled rules run on a fixed cadence (e.g., every 5 minutes) and query a defined look-back window. The KQL must be deterministic within that window — it should produce the same results if re-run against the same data.

```kql
// Brute Force Detection — Scheduled Rule
// Frequency: every 5 minutes | Lookback: 1 hour
// Fires when a single IP generates ≥ FailureThreshold failed sign-ins
// followed by at least one success against any account.
let FailureThreshold = 10;
let TimeWindow = 1h;
let FailedSignIns = SignInLogs
    | where TimeGenerated > ago(TimeWindow)
    | where ResultType != 0 // Non-zero = failure
    | summarize
        FailureCount = count(),
        TargetAccounts = make_set(UserPrincipalName, 50),
        FailureCodes = make_set(ResultType, 10)
        by IPAddress;
let SuccessfulSignIns = SignInLogs
    | where TimeGenerated > ago(TimeWindow)
    | where ResultType == 0
    | project IPAddress, SuccessUser = UserPrincipalName, SuccessTime = TimeGenerated,
        AppDisplayName, Location = tostring(LocationDetails.countryOrRegion);
FailedSignIns
| where FailureCount >= FailureThreshold
| join kind=inner SuccessfulSignIns on IPAddress
// Enrich for entity mapping
| extend
    AccountName = tostring(split(SuccessUser, "@")[0]),
    AccountUPNSuffix = tostring(split(SuccessUser, "@")[1])
| project
    IPAddress,
    FailureCount,
    TargetAccounts,
    FailureCodes,
    SuccessUser,
    SuccessTime,
    AppDisplayName,
    Location,
    AccountName,
    AccountUPNSuffix
```

**Rule configuration:**
- **Frequency:** 5 minutes
- **Lookback:** 1 hour (overlap ensures no events are missed between runs)
- **Entity mappings:** `Account` → `AccountName` + `AccountUPNSuffix`; `IP` → `IPAddress`
- **Severity:** Medium (escalate to High if `FailureCount > 50`)

**Parameters to customize:**
- `FailureThreshold` — Start at 10; raise for environments with frequent password resets or SSO retries.
- `TimeWindow` — Must match or exceed the rule's configured lookback.

**Performance notes:**
- Two parallel scans of `SignInLogs` (failures and successes), joined on `IPAddress`. The `where` filters run first, so only rows within the time window are scanned.
- Estimated cost: Low — sign-in logs are typically 1-5 GB/day for mid-size tenants.

---

### Pattern 2 — NRT Rule: Privilege Escalation

NRT rules have a near-zero-latency response. They ingest data as it arrives and evaluate the query continuously. Constraints: no `ago()` time filters (NRT handles the window), no `join` across tables, simpler queries preferred.

```kql
// NRT Rule: Sensitive Role Assignment
// Fires immediately when a high-privilege Azure AD role is assigned.
let SensitiveRoles = dynamic([
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator"
]);
AuditLogs
| where OperationName == "Add member to role"
| where Result == "success"
| mv-expand TargetResource = TargetResources
| extend RoleName = tostring(TargetResource.displayName)
| where RoleName in (SensitiveRoles)
| mv-expand ModifiedProperty = TargetResource.modifiedProperties
| extend TargetUser = tostring(parse_json(tostring(ModifiedProperty.newValue)))
| extend
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress)
| project
    TimeGenerated,
    RoleName,
    TargetUser,
    InitiatedByUser,
    InitiatedByApp,
    InitiatedByIP,
    CorrelationId
```

**Rule configuration:**
- **Type:** NRT (no frequency/lookback — processes data as ingested)
- **Entity mappings:** `Account` → `InitiatedByUser`; `IP` → `InitiatedByIP`
- **Severity:** High

**Parameters to customize:**
- `SensitiveRoles` — Add or remove roles per your organization's privilege model.

**Performance notes:**
- NRT rules must be lightweight. Avoid `join`, `union`, or wide `summarize` aggregations.
- This query scans only `AuditLogs` and applies tight `where` filters immediately.

---

### Pattern 3 — Dynamic Severity Mapping

Not all alerts deserve the same severity. This pattern uses `case()` to dynamically assign severity based on the evidence in the query results.

```kql
// Impossible Travel Detection with Dynamic Severity
let TimeWindow = 1d;
let MinTimeBetweenSignIns = 30m; // Minimum time to consider "impossible"
let MinDistanceKm = 500;
SignInLogs
| where TimeGenerated > ago(TimeWindow)
| where ResultType == 0
| extend
    Latitude = toreal(LocationDetails.geoCoordinates.latitude),
    Longitude = toreal(LocationDetails.geoCoordinates.longitude),
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city)
| where isnotempty(Latitude) and isnotempty(Longitude)
| order by UserPrincipalName asc, TimeGenerated asc
| extend
    PrevTime = prev(TimeGenerated),
    PrevLat = prev(Latitude),
    PrevLon = prev(Longitude),
    PrevCountry = prev(Country),
    PrevUser = prev(UserPrincipalName)
// Only compare sequential events for the same user
| where UserPrincipalName == PrevUser
| extend TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDiffMinutes > 0 and TimeDiffMinutes < toint(MinTimeBetweenSignIns / 1m)
// Haversine-approximated distance
| extend DistanceKm = geo_distance_2points(Longitude, Latitude, PrevLon, PrevLat) / 1000.0
| where DistanceKm > MinDistanceKm
// Dynamic severity based on evidence strength
| extend AlertSeverity = case(
    DistanceKm > 5000 and TimeDiffMinutes < 10, "High",    // Intercontinental in minutes
    DistanceKm > 2000 and TimeDiffMinutes < 60, "High",    // Cross-continent in an hour
    Country != PrevCountry, "Medium",                       // Different country
    "Low"                                                   // Same country, far distance
)
| project
    TimeGenerated,
    UserPrincipalName,
    City, Country,
    PrevCountry,
    DistanceKm = round(DistanceKm, 0),
    TimeDiffMinutes,
    AlertSeverity,
    IPAddress
```

**Parameters to customize:**
- `MinTimeBetweenSignIns` — Reduce for tighter detection; increase to allow VPN-based location switching.
- `MinDistanceKm` — 500 km works for most geographies; increase for countries with wide-area VPN exits.

**Performance notes:**
- `prev()` window functions require sorted data. The `order by` before `extend` is mandatory.
- `geo_distance_2points()` is a built-in KQL function — no UDFs needed.

---

### Pattern 4 — Multi-Stage Attack Detection

Correlate events across time stages to detect attack sequences that no single event would trigger. This pattern detects a reconnaissance → credential spray → data access chain.

```kql
// Multi-stage: Reconnaissance → Brute Force → Mailbox Access
let Stage1Window = 7d;
let Stage2Window = 2d;
let Stage3Window = 1d;
// Stage 1: Reconnaissance — enumeration of user accounts
let ReconIPs = SignInLogs
    | where TimeGenerated > ago(Stage1Window)
    | where ResultType == 50034 // User account not found
    | summarize NonExistentAttempts = count() by IPAddress
    | where NonExistentAttempts > 20
    | project IPAddress;
// Stage 2: Brute force from the same IPs
let BruteForceIPs = SignInLogs
    | where TimeGenerated > ago(Stage2Window)
    | where IPAddress in (ReconIPs)
    | where ResultType in (50126, 50053, 50055) // Wrong password, locked, expired
    | summarize FailedAttempts = count(), TargetedUsers = dcount(UserPrincipalName) by IPAddress
    | where FailedAttempts > 10 and TargetedUsers > 3
    | project IPAddress;
// Stage 3: Successful sign-in and mailbox/data access from brute-forced IPs
SignInLogs
| where TimeGenerated > ago(Stage3Window)
| where IPAddress in (BruteForceIPs)
| where ResultType == 0
| where AppDisplayName in ("Microsoft Exchange Online", "Microsoft Office 365", "Microsoft Teams")
| extend
    AccountName = tostring(split(UserPrincipalName, "@")[0]),
    AccountUPNSuffix = tostring(split(UserPrincipalName, "@")[1])
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    Location = tostring(LocationDetails.countryOrRegion),
    AccountName,
    AccountUPNSuffix
```

**Parameters to customize:**
- `Stage1Window` through `Stage3Window` — Adjust based on expected attack tempo.
- `ResultType` codes — Add relevant Azure AD error codes for your tenant.
- `AppDisplayName` filter — Add apps that hold sensitive data in your organization.

**Performance notes:**
- Each stage feeds into the next via `let` + `in()`, progressively narrowing the data. This is far cheaper than a single multi-join query.
- Total scan: 3 passes over `SignInLogs` with different time windows, each heavily filtered.

---

### Pattern 5 — Alert Enrichment with Custom Details

Enrich alerts with contextual information so analysts don't need to re-query during triage. Use `extend` to compute fields and map them to Sentinel's entity model.

```kql
// Account Manipulation Detection with Rich Enrichment
let TimeWindow = 1h;
AuditLogs
| where TimeGenerated > ago(TimeWindow)
| where OperationName has_any (
    "Add member to group",
    "Add owner to group",
    "Add member to role",
    "Update user",
    "Reset user password"
)
| where Result == "success"
| extend
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
    InitiatedByApp = tostring(InitiatedBy.app.displayName)
| mv-expand TargetResource = TargetResources
| extend
    TargetDisplayName = tostring(TargetResource.displayName),
    TargetType = tostring(TargetResource.type),
    TargetUPN = tostring(TargetResource.userPrincipalName)
// Enrichment: tag operations by risk level
| extend OperationRisk = case(
    OperationName has "role", "High",
    OperationName has "owner", "Medium",
    OperationName has "password", "Medium",
    "Low"
)
// Enrichment: is this a self-service action or admin-on-behalf?
| extend IsSelfService = (InitiatedByUser =~ TargetUPN)
| project
    TimeGenerated,
    OperationName,
    InitiatedByUser,
    InitiatedByIP,
    TargetDisplayName,
    TargetUPN,
    TargetType,
    OperationRisk,
    IsSelfService,
    CorrelationId
```

**Entity mappings for rule YAML:**
```yaml
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: InitiatedByUser
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: InitiatedByIP
customDetails:
  OperationRisk: OperationRisk
  TargetUser: TargetUPN
  ActionType: OperationName
```

**Performance notes:**
- `has_any()` is faster than multiple `==` checks with `or` for string matching.
- `mv-expand` on `TargetResources` may multiply rows; the downstream `project` keeps the result set small.

## Analytics Rule YAML Structure Reference

When deploying rules as code (ARM templates, Bicep, or Sentinel Repositories), use this structure:

```yaml
kind: Scheduled   # or NRT
properties:
  displayName: "Brute Force Followed by Successful Sign-In"
  description: |
    Detects IPs generating excessive failed sign-ins followed
    by a successful authentication, indicating credential compromise.
  severity: Medium               # Informational | Low | Medium | High
  enabled: true
  query: |
    // ... KQL query here ...
  queryFrequency: PT5M           # ISO 8601 duration — how often the rule runs
  queryPeriod: PT1H              # ISO 8601 duration — how far back each run looks
  triggerOperator: GreaterThan
  triggerThreshold: 0            # Alert if query returns > 0 results
  suppressionDuration: PT1H      # Suppress duplicate alerts for this window
  suppressionEnabled: true
  tactics:
    - CredentialAccess
    - InitialAccess
  techniques:
    - T1110
    - T1078
  entityMappings:
    - entityType: Account
      fieldMappings:
        - identifier: Name
          columnName: AccountName
        - identifier: UPNSuffix
          columnName: AccountUPNSuffix
    - entityType: IP
      fieldMappings:
        - identifier: Address
          columnName: IPAddress
  customDetails:
    FailureCount: FailureCount
    TargetAccounts: TargetAccounts
  incidentConfiguration:
    createIncident: true
    groupingConfiguration:
      enabled: true
      lookbackDuration: PT5H
      matchingMethod: Selected
      groupByEntities:
        - Account
        - IP
```

**Key constraints:**
- `queryPeriod` must be ≥ `queryFrequency` to avoid gaps.
- For NRT rules: omit `queryFrequency` and `queryPeriod` — the engine manages the window.
- `triggerThreshold: 0` with `triggerOperator: GreaterThan` fires on any result row.

## MITRE ATT&CK Context

| Technique | ID | Detection Pattern |
|---|---|---|
| Brute Force | T1110 | Pattern 1 detects password-spray and credential-stuffing attacks via failed→success correlation. Pattern 4 chains reconnaissance into brute force. |
| Valid Accounts | T1078 | Pattern 3 (impossible travel) identifies stolen credentials used from new locations. Pattern 1 catches accounts compromised via brute force. |
| Account Manipulation | T1098 | Pattern 2 (NRT role assignment) catches privilege escalation in near-real-time. Pattern 5 enriches account modification events with risk scoring. |

## False Positive Guidance

| Pattern | Common False Positives | Tuning Advice |
|---|---|---|
| Brute force | Legacy applications with expired cached credentials, misconfigured service principals | Exclude known service principal IPs. Filter `AppDisplayName` for legacy auth clients. |
| Impossible travel | VPN services that rotate exit nodes, mobile users on airline Wi-Fi | Add corporate VPN egress IP ranges to an exclusion watchlist. Increase `MinTimeBetweenSignIns`. |
| Privilege escalation (NRT) | Planned PIM (Privileged Identity Management) activations, break-glass procedures | Correlate with PIM activation logs; suppress alerts for PIM-eligible users during activation windows. |
| Account manipulation | Automated provisioning systems (SCIM, HR sync), helpdesk password resets | Exclude service accounts used by identity governance tools. Filter on `InitiatedBy.app.displayName`. |

## Tuning Guide

### Rule Frequency vs. Lookback

| Detection Goal | Frequency | Lookback | Notes |
|---|---|---|---|
| Near-real-time alerting | 5 min | 15 min | High cost; use only for critical detections |
| Standard SOC alerting | 5 min | 1 hr | Recommended default — balances speed and cost |
| Low-priority/noisy detections | 1 hr | 6 hr | Reduces alert fatigue for informational rules |
| Daily compliance checks | 24 hr | 25 hr | 1-hour overlap ensures no gaps across days |

### Threshold Calibration Process

1. **Deploy disabled** — Create the rule as disabled, run the query manually for 7 days.
2. **Count daily alerts** — If > 20/day, the threshold is too sensitive for a scheduled rule.
3. **Review false positives** — Categorize FP sources and add exclusions to the query.
4. **Enable at Medium severity** — Monitor for one sprint cycle.
5. **Promote or tune** — Increase severity if signal is clean; add `suppressionDuration` if duplicates appear.

### NRT vs. Scheduled Decision Matrix

| Factor | Choose NRT | Choose Scheduled |
|---|---|---|
| Detection latency requirement | < 1 minute | 5+ minutes acceptable |
| Query complexity | Simple (single table, few operators) | Complex (joins, multi-stage) |
| Cross-table correlation | Not supported | Supported |
| Alert volume expectation | Low (< 5/day) | Any |
| `ago()` time filtering | Not supported | Required |

## Related Skills

- **[Threat Hunting Foundations](threat-hunting-foundations.md)** — Build and validate the hunt before promoting it to a rule.
- **[Incident Investigation](incident-investigation.md)** — Query patterns for investigating the alerts this rule generates.
