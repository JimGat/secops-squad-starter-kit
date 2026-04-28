---
title: UEBA Patterns
category: kql
difficulty: advanced
mitre_attack:
  - T1078  # Valid Accounts
  - T1098  # Account Manipulation
  - T1087  # Account Discovery
  - T1071  # Application Layer Protocol
products:
  - Microsoft Sentinel
  - Microsoft Sentinel UEBA
  - Microsoft Entra ID
  - Microsoft Defender for Endpoint
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# UEBA Patterns

## Overview

User and Entity Behavior Analytics (UEBA) uses machine learning to build behavioral baselines for users, devices, and IP addresses, then flags deviations as anomalies. Sentinel's UEBA engine populates the `BehaviorAnalytics` and `Anomalies` tables with enriched, scored anomaly data. This skill covers patterns for querying UEBA data, building custom behavioral analytics, and integrating UEBA scores into detection and investigation workflows.

Use this skill when:
- You want to detect insider threats through behavioral deviation
- You need to prioritize incidents based on anomaly scores rather than static rules
- You are building "first-time" or "rare activity" detections that adapt to each entity
- You want to compare a user's behavior to their peer group
- You need to detect account takeover through behavioral shifts

## Prerequisites

| Requirement | Detail |
|---|---|
| **Tables** | `BehaviorAnalytics`, `Anomalies`, `IdentityInfo`, `SignInLogs`, `AuditLogs` |
| **Workspace** | Sentinel workspace with UEBA enabled (Settings → Entity Behavior) |
| **Permissions** | `Microsoft Sentinel Reader` or higher |
| **Configuration** | UEBA data sources enabled: Azure AD, Defender for Endpoint, Azure Activity. Minimum 14 days of data for baselines. |

## Core Patterns

### Pattern 1 — High-Anomaly-Score Users

Query the `BehaviorAnalytics` table for users with the highest anomaly investigation priority scores. This surfaces the users most likely to be compromised or acting maliciously.

```kql
// Surface users with the highest UEBA investigation priority scores.
let LookbackPeriod = 7d;
BehaviorAnalytics
| where TimeGenerated > ago(LookbackPeriod)
| where isnotempty(UserPrincipalName)
| summarize
    MaxInvestigationPriority = max(InvestigationPriority),
    AvgInvestigationPriority = avg(InvestigationPriority),
    AnomalyCount = count(),
    ActivityTypes = make_set(ActivityType, 20),
    SourceIPs = make_set(SourceIPAddress, 10),
    SourceLocations = make_set(SourceIPLocation, 10),
    Devices = make_set(DevicesInsights, 5)
    by UserPrincipalName
| where MaxInvestigationPriority > 3  // Score 1-10; >3 is notable
| order by MaxInvestigationPriority desc
| extend
    RiskTier = case(
        MaxInvestigationPriority >= 8, "🔴 Critical",
        MaxInvestigationPriority >= 5, "🟠 High",
        MaxInvestigationPriority >= 3, "🟡 Medium",
        "🟢 Low")
```

**Parameters to customize:**
- `MaxInvestigationPriority > 3` — Lower to 1 for comprehensive reviews; raise to 7 for critical-only triage.
- `LookbackPeriod` — 7 days for daily triage; 30 days for trend analysis.

**Performance notes:**
- `BehaviorAnalytics` is pre-computed by Sentinel's ML engine — queries are fast.
- `InvestigationPriority` is a composite score (1-10) combining multiple anomaly signals. It is the most efficient single metric for user risk ranking.

---

### Pattern 2 — Peer Comparison: User vs. Peer Group

Detect when a user's behavior deviates from their peer group (same department, job title, or manager). This catches lateral movement and privilege escalation where the user's individual baseline is bypassed.

```kql
// Compare a user's sign-in behavior against their departmental peers.
let LookbackPeriod = 14d;
let TargetUser = "suspect.user@contoso.com";
// Get the target user's department from IdentityInfo
let UserDepartment = toscalar(
    IdentityInfo
    | where TimeGenerated > ago(30d)
    | where AccountUPN =~ TargetUser
    | summarize arg_max(TimeGenerated, Department)
    | project Department);
// Peer group: all users in the same department
let PeerGroup = (IdentityInfo
    | where TimeGenerated > ago(30d)
    | where Department == UserDepartment
    | where AccountUPN != TargetUser
    | distinct AccountUPN);
// Peer group baseline: apps accessed and sign-in patterns
let PeerBaseline = (SignInLogs
    | where TimeGenerated > ago(LookbackPeriod)
    | where UserPrincipalName in (PeerGroup)
    | where ResultType == 0
    | summarize
        PeerAvgSignIns = todouble(count()) / todouble(dcount(UserPrincipalName)),
        PeerApps = make_set(AppDisplayName, 100),
        PeerIPs = make_set(IPAddress, 100),
        PeerCountries = make_set(tostring(LocationDetails.countryOrRegion), 20));
// Target user activity
let UserActivity = (SignInLogs
    | where TimeGenerated > ago(LookbackPeriod)
    | where UserPrincipalName =~ TargetUser
    | where ResultType == 0
    | summarize
        UserSignIns = count(),
        UserApps = make_set(AppDisplayName, 100),
        UserIPs = make_set(IPAddress, 100),
        UserCountries = make_set(tostring(LocationDetails.countryOrRegion), 20));
// Compare
UserActivity
| join kind=inner PeerBaseline on 1==1
| extend
    AppsNotUsedByPeers = set_difference(UserApps, PeerApps),
    CountriesNotUsedByPeers = set_difference(UserCountries, PeerCountries),
    SignInRatioVsPeers = round(todouble(UserSignIns) / PeerAvgSignIns, 2)
| project
    UserPrincipalName = TargetUser,
    Department = UserDepartment,
    UserSignIns,
    PeerAvgSignIns = round(PeerAvgSignIns, 1),
    SignInRatioVsPeers,
    AppsNotUsedByPeers,
    CountriesNotUsedByPeers,
    UniqueAppCount = array_length(AppsNotUsedByPeers),
    UniqueCountryCount = array_length(CountriesNotUsedByPeers)
```

**Parameters to customize:**
- `TargetUser` — The user under investigation.
- `Department` — Change the peer grouping dimension to `JobTitle`, `ManagerUpn`, or `City` depending on your organizational structure.

**Performance notes:**
- `IdentityInfo` is synced from Entra ID periodically. Use `arg_max(TimeGenerated, *)` to get the latest record per user.
- `set_difference()` efficiently computes what the user does that peers don't — it's the key function for peer comparison.

---

### Pattern 3 — First-Time Activity Detection

Detect when a user performs an activity for the first time — accessing a new app, signing in from a new country, or using a new device. First-time activities can indicate account compromise.

```kql
// Detect first-time application access per user.
let DetectionWindow = 1d;
let BaselinePeriod = 90d;
// Historical app usage per user
let HistoricalApps = (SignInLogs
    | where TimeGenerated between (ago(BaselinePeriod) .. ago(DetectionWindow))
    | where ResultType == 0
    | summarize KnownApps = make_set(AppDisplayName, 500) by UserPrincipalName);
// Current app usage
let CurrentApps = (SignInLogs
    | where TimeGenerated > ago(DetectionWindow)
    | where ResultType == 0
    | summarize
        NewApps = make_set(AppDisplayName, 100),
        IPs = make_set(IPAddress, 10),
        Locations = make_set(tostring(LocationDetails.countryOrRegion), 10)
        by UserPrincipalName);
// Find users accessing apps they've never used before
CurrentApps
| join kind=inner HistoricalApps on UserPrincipalName
| extend FirstTimeApps = set_difference(NewApps, KnownApps)
| where array_length(FirstTimeApps) > 0
| project
    UserPrincipalName,
    FirstTimeApps,
    FirstTimeAppCount = array_length(FirstTimeApps),
    SignInIPs = IPs,
    SignInLocations = Locations
| order by FirstTimeAppCount desc
```

```kql
// Detect first-time country sign-ins (potential credential theft or VPN abuse).
let DetectionWindow = 1d;
let BaselinePeriod = 90d;
let KnownCountries = (SignInLogs
    | where TimeGenerated between (ago(BaselinePeriod) .. ago(DetectionWindow))
    | where ResultType == 0
    | where isnotempty(tostring(LocationDetails.countryOrRegion))
    | summarize Countries = make_set(tostring(LocationDetails.countryOrRegion), 50)
        by UserPrincipalName);
SignInLogs
| where TimeGenerated > ago(DetectionWindow)
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Country)
| summarize
    CurrentCountries = make_set(Country),
    IPs = make_set(IPAddress, 10),
    Apps = make_set(AppDisplayName, 10)
    by UserPrincipalName
| join kind=inner KnownCountries on UserPrincipalName
| extend NewCountries = set_difference(CurrentCountries, Countries)
| where array_length(NewCountries) > 0
| project
    UserPrincipalName,
    NewCountries,
    SignInIPs = IPs,
    AppsAccessed = Apps
| order by UserPrincipalName asc
```

**Parameters to customize:**
- `BaselinePeriod` — 90 days captures most cyclical behavior. Shorten for new hires (30d).
- `DetectionWindow` — 1 day for daily detection; 1h for near-real-time.

**Performance notes:**
- `make_set()` with a high limit (500) captures complete app catalogs for baseline comparison. Keep the limit proportional to your app count.
- `set_difference()` is the core of first-time detection — O(n) comparison of dynamic arrays.

---

### Pattern 4 — Rare Activity Scoring

Score activities based on how rare they are across the organization. Rare activities are more likely to be malicious or warrant investigation.

```kql
// Score process executions by organizational rarity.
// Rarer processes get higher scores.
let LookbackPeriod = 14d;
let MinimumExecutions = 1; // Include even single executions
// Global process popularity
let GlobalPopularity = (DeviceProcessEvents
    | where TimeGenerated > ago(LookbackPeriod)
    | where isnotempty(FileName)
    | summarize
        GlobalDeviceCount = dcount(DeviceName),
        GlobalUserCount = dcount(AccountName),
        GlobalExecCount = count()
        by FileName);
let TotalDevices = toscalar(
    DeviceProcessEvents
    | where TimeGenerated > ago(LookbackPeriod)
    | summarize dcount(DeviceName));
// Per-user process usage
DeviceProcessEvents
| where TimeGenerated > ago(LookbackPeriod)
| where isnotempty(FileName)
| summarize
    UserExecCount = count(),
    UserDevices = make_set(DeviceName, 10),
    SampleCommandLine = arg_min(TimeGenerated, ProcessCommandLine)
    by AccountName, FileName, FolderPath
| join kind=inner GlobalPopularity on FileName
| extend
    // Rarity score: inverse of prevalence (0-100, higher = rarer)
    PrevalencePercent = round(todouble(GlobalDeviceCount) / todouble(TotalDevices) * 100, 2),
    RarityScore = round((1.0 - todouble(GlobalDeviceCount) / todouble(TotalDevices)) * 100, 2)
| where RarityScore > 95  // Top 5% rarest
| project
    AccountName,
    FileName,
    FolderPath,
    RarityScore,
    PrevalencePercent,
    UserExecCount,
    GlobalDeviceCount,
    GlobalExecCount,
    SampleCommandLine = SampleCommandLine_ProcessCommandLine
| order by RarityScore desc, UserExecCount asc
```

**Parameters to customize:**
- `RarityScore > 95` — Top 5% rarest processes. Lower to 90 for broader coverage; raise to 99 for focused hunting.
- `TotalDevices` — Used as the denominator for prevalence. This adjusts automatically to your environment size.

**Performance notes:**
- The `toscalar()` call computes the total device count once and reuses it. Without this, you would need a more expensive join.
- `dcount()` is approximate (HyperLogLog) — acceptable for rarity scoring where exact counts are unnecessary.

---

### Pattern 5 — Activity Volume Anomaly Detection

Detect users or devices with abnormal activity volumes using Sentinel's built-in Anomalies table and custom volume analysis.

```kql
// Query Sentinel's built-in anomaly detections from the Anomalies table.
let LookbackPeriod = 7d;
Anomalies
| where TimeGenerated > ago(LookbackPeriod)
| where AnomalyTemplateName has_any (
    "Anomalous sign-in",
    "Anomalous resource access",
    "Anomalous privilege grant",
    "Anomalous account creation",
    "Anomalous data access")
| extend
    Score = AnomalyReasons,
    Entity = UserPrincipalName
| project
    TimeGenerated,
    AnomalyTemplateName,
    Entity,
    Description,
    Score,
    Tactics,
    Techniques,
    SourceIPAddress,
    SourceDevice = DeviceName
| order by TimeGenerated desc
```

```kql
// Custom volume anomaly: detect users generating abnormally high event volume.
// Uses IQR (interquartile range) method for robust outlier detection.
let LookbackPeriod = 14d;
let DetectionWindow = 1d;
// Compute per-user daily activity counts for the baseline period
let DailyActivity = (AuditLogs
    | where TimeGenerated between (ago(LookbackPeriod) .. ago(DetectionWindow))
    | summarize DailyCount = count() by UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName), bin(TimeGenerated, 1d)
    | where isnotempty(UserPrincipalName));
// Compute IQR per user
let UserIQR = (DailyActivity
    | summarize
        Q1 = percentile(DailyCount, 25),
        Q3 = percentile(DailyCount, 75),
        Median = percentile(DailyCount, 50)
        by UserPrincipalName
    | extend
        IQR = Q3 - Q1,
        UpperFence = Q3 + 1.5 * (Q3 - Q1));
// Current activity
let CurrentActivity = (AuditLogs
    | where TimeGenerated > ago(DetectionWindow)
    | summarize CurrentCount = count() by UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
    | where isnotempty(UserPrincipalName));
// Detect outliers
CurrentActivity
| join kind=inner UserIQR on UserPrincipalName
| where CurrentCount > UpperFence
| where IQR > 0  // Exclude users with constant activity
| extend OutlierFactor = round(todouble(CurrentCount - UpperFence) / todouble(IQR), 2)
| project
    UserPrincipalName,
    CurrentCount,
    Median = round(Median, 0),
    UpperFence = round(UpperFence, 0),
    OutlierFactor,
    Severity = case(
        OutlierFactor > 5, "🔴 Extreme",
        OutlierFactor > 3, "🟠 High",
        OutlierFactor > 1, "🟡 Moderate",
        "🟢 Mild")
| order by OutlierFactor desc
```

**Parameters to customize:**
- `AnomalyTemplateName has_any(...)` — Filter to specific anomaly types relevant to your current investigation.
- `UpperFence` multiplier — The standard 1.5× IQR catches moderate outliers. Use 3.0× IQR for extreme outliers only.

**Performance notes:**
- The `Anomalies` table is pre-computed by Sentinel — queries are fast and cost-efficient.
- The custom IQR-based approach uses `percentile()` which needs the full dataset in memory. Pre-aggregate to daily counts before computing IQR.
- IQR is more robust than standard deviation for outlier detection because it is not distorted by extreme values.

## MITRE ATT&CK Context

| Technique | ID | How This Skill Helps |
|---|---|---|
| Valid Accounts | T1078 | Investigation priority scoring (Pattern 1) and first-time activity (Pattern 3) detect compromised accounts through behavioral deviation. Peer comparison (Pattern 2) catches accounts used outside their normal context. |
| Account Manipulation | T1098 | Volume anomaly detection (Pattern 5) surfaces bulk permission changes or role assignments. First-time activity (Pattern 3) catches newly granted privileges being used. |
| Account Discovery | T1087 | Rare activity scoring (Pattern 4) detects enumeration tools that are uncommon in the environment. LDAP query volume anomalies flag reconnaissance. |
| Application Layer Protocol | T1071 | Peer comparison (Pattern 2) identifies users accessing applications outside their peer group norm — a signal for C2 or data exfiltration via cloud apps. |

## False Positive Guidance

| Pattern | Common False Positives | Tuning Advice |
|---|---|---|
| High investigation priority | Users starting new roles or projects (temporary behavioral shift) | Cross-reference with HR data (role changes, department transfers) via `IdentityInfo`. Allow a 2-week grace period after role changes. |
| Peer comparison | Specialized roles with no true peers (CTO, solo security engineer) | Set minimum peer group size (e.g., ≥5 peers). Fall back to organization-wide baseline for small groups. |
| First-time app access | Legitimate new app rollouts (org deploys a new SaaS tool) | Cross-reference with Entra ID audit logs for admin-consented app registrations. Exclude apps with > N users in the detection window. |
| Rare process execution | IT admin tools used legitimately but infrequently | Maintain an approved admin tools watchlist. Score rare processes higher if the executing user is not in an admin group. |
| Volume anomaly | Automated batch jobs, month-end processing, data migrations | Exclude known service accounts. Add calendar-awareness (exclude known batch processing windows). |

## Tuning Guide

### UEBA Configuration Checklist

| Setting | Recommendation | Impact |
|---|---|---|
| UEBA data sources | Enable Azure AD, Defender for Endpoint, Azure Activity, Office 365 | More data sources = richer behavioral baselines |
| Baseline period | Minimum 14 days; optimal 30 days | Shorter baselines produce more false positives |
| Anomaly rule thresholds | Start with defaults; adjust after 2-week burn-in | Aggressive tuning before baseline stabilization creates blind spots |
| Entity pages | Enable for User, IP, Host | Provides investigation context for high-priority entities |

### Investigation Priority Score Guide

| Score | Meaning | Recommended Action |
|---|---|---|
| 8-10 | Critical anomaly — high confidence behavioral deviation | Immediate investigation; open incident |
| 5-7 | Notable anomaly — warrants analyst review | Triage within 24 hours; enrich with entity page |
| 3-4 | Mild anomaly — monitor for pattern escalation | Add to watchlist; review if recurring |
| 1-2 | Low anomaly — likely normal variation | No action unless corroborated by other signals |

### Performance Optimization Checklist

- [ ] `BehaviorAnalytics` and `Anomalies` tables used as primary UEBA data sources (pre-computed, fast)
- [ ] Custom behavioral queries use `set_difference()` for first-time detection (efficient array comparison)
- [ ] Peer group computed from `IdentityInfo` with `arg_max()` for latest attributes
- [ ] `toscalar()` used for single-value denominators (total device count, total user count)
- [ ] IQR method preferred over standard deviation for outlier detection (robust to skew)
- [ ] Rarity scoring uses `dcount()` for approximate prevalence (fast on large datasets)

## Related Skills

- **[Threat Hunting Foundations](threat-hunting-foundations.md)** — Baseline deviation and rare event analysis patterns that UEBA extends.
- **[Entra Sign-In Analysis](entra-signin-analysis.md)** — Sign-in data is a primary input to UEBA behavioral models.
- **[Detection Tuning](detection-tuning.md)** — UEBA scores can replace static thresholds for adaptive detection tuning.
- **[Defender XDR Advanced Hunting](defender-xdr-hunting.md)** — Endpoint telemetry feeds the process rarity and device behavior models.
- **[Incident Investigation](incident-investigation.md)** — UEBA entity pages provide investigation context during incident response.
