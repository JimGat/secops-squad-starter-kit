---
title: Entra Sign-In Analysis
category: kql
difficulty: intermediate
mitre_attack:
  - T1078  # Valid Accounts
  - T1110  # Brute Force
  - T1556  # Modify Authentication Process
products:
  - Microsoft Entra ID
  - Microsoft Sentinel
  - Azure Monitor Log Analytics
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Entra Sign-In Analysis

## Overview

Entra ID (formerly Azure AD) sign-in logs are the foundation of identity threat detection. This skill covers deep analysis of both interactive and non-interactive sign-in patterns, risk score queries, conditional access gap analysis, MFA failure investigation, and impossible travel detection.

Use this skill when:
- Investigating account compromise or suspicious authentication activity
- Auditing conditional access policy effectiveness
- Hunting for credential attacks (brute force, password spray, token replay)
- Detecting impossible travel or anomalous geolocations
- Analyzing MFA fatigue attacks or MFA bypass attempts

## Prerequisites

| Requirement | Detail |
|---|---|
| **Tables** | `SignInLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs` |
| **Workspace** | Sentinel-connected Log Analytics workspace with Entra ID diagnostic settings configured |
| **Permissions** | `Microsoft Sentinel Reader` or `Global Reader` in Entra ID |
| **Data connectors** | Azure Active Directory connector (sign-in logs and audit logs) |

## Core Patterns

### Pattern 1 — Risk-Based Sign-In Analysis

Query Entra ID Protection risk signals to surface sign-ins flagged as risky by Microsoft's ML models. Correlate risk levels with authentication outcomes.

```kql
// Surface high and medium risk sign-ins with contextual detail.
let LookbackPeriod = 14d;
let RiskLevels = dynamic(["high", "medium"]);
SignInLogs
| where TimeGenerated > ago(LookbackPeriod)
| where RiskLevelDuringSignIn in (RiskLevels) or RiskLevelAggregated in (RiskLevels)
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    Latitude = toreal(LocationDetails.geoCoordinates.latitude),
    Longitude = toreal(LocationDetails.geoCoordinates.longitude),
    OS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    TrustType = tostring(DeviceDetail.trustType),
    // Parse conditional access results
    CAResults = parse_json(ConditionalAccessPolicies)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Country, City,
    AppDisplayName,
    ResultType,
    ResultDescription,
    RiskLevelDuringSignIn,
    RiskLevelAggregated,
    RiskState,
    RiskDetail,
    OS, Browser, TrustType,
    AuthenticationRequirement,
    MfaDetail = tostring(MfaDetail.authMethod)
| order by TimeGenerated desc
```

**Parameters to customize:**
- `RiskLevels` — Include `"low"` for comprehensive audits; use `"high"` only for focused triage.
- `LookbackPeriod` — 14 days covers most active investigations; extend to 30d for slow-burn compromises.

**Performance notes:**
- `RiskLevelDuringSignIn` is evaluated at sign-in time; `RiskLevelAggregated` includes post-sign-in signals. Query both for completeness.
- `ConditionalAccessPolicies` is a JSON array — use `mv-expand` if you need to analyze individual CA policy outcomes.

---

### Pattern 2 — Conditional Access Gap Analysis

Identify sign-ins that were not evaluated by any conditional access policy — these represent gaps in your Zero Trust posture.

```kql
// Find successful sign-ins that bypassed all conditional access policies.
let LookbackPeriod = 30d;
SignInLogs
| where TimeGenerated > ago(LookbackPeriod)
| where ResultType == 0  // Successful sign-ins only
| where ConditionalAccessStatus == "notApplied"
| where IsInteractive == true  // Focus on human sign-ins
// Exclude managed apps that legitimately bypass CA
| where AppDisplayName !in ("Microsoft Authentication Broker", "Microsoft Account Controls V2")
| summarize
    SignInCount = count(),
    DistinctUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 20),
    DistinctIPs = dcount(IPAddress),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 10)
    by AppDisplayName, ResourceDisplayName
| where SignInCount > 10
| order by SignInCount desc
```

```kql
// Analyze per-policy conditional access outcomes to find policies with high failure rates.
let LookbackPeriod = 14d;
SignInLogs
| where TimeGenerated > ago(LookbackPeriod)
| where ResultType == 0
| mv-expand CAPolicy = parse_json(ConditionalAccessPolicies)
| extend
    PolicyName = tostring(CAPolicy.displayName),
    PolicyResult = tostring(CAPolicy.result),
    GrantControls = tostring(CAPolicy.enforcedGrantControls),
    SessionControls = tostring(CAPolicy.enforcedSessionControls)
| summarize
    TotalEvaluations = count(),
    Successes = countif(PolicyResult == "success"),
    Failures = countif(PolicyResult == "failure"),
    NotApplied = countif(PolicyResult == "notApplied")
    by PolicyName
| extend FailureRate = round(todouble(Failures) / todouble(TotalEvaluations) * 100, 2)
| order by Failures desc
```

**Parameters to customize:**
- `AppDisplayName !in (...)` — Extend the exclusion list with your organization's known-good apps that legitimately bypass CA.
- `SignInCount > 10` — Lower for audits; raise to reduce noise in large environments.

**Performance notes:**
- `mv-expand` on `ConditionalAccessPolicies` multiplies rows — one row per policy per sign-in. Filter the `SignInLogs` heavily before the expansion.
- This query can be expensive on large tenants; run during off-peak hours or restrict to specific users/apps.

---

### Pattern 3 — MFA Failure and Fatigue Analysis

Detect MFA fatigue attacks (repeated push notifications to wear down the user) and analyze MFA method effectiveness.

```kql
// Detect potential MFA fatigue attacks: many MFA prompts followed by a successful sign-in.
let LookbackPeriod = 7d;
let MfaFailureThreshold = 5;
let TimeWindowMinutes = 30; // MFA attempts within this window
// Find users with repeated MFA failures
let MfaFailures = (SignInLogs
    | where TimeGenerated > ago(LookbackPeriod)
    | where ResultType == 50074   // MFA required
        or ResultType == 50076    // MFA required (strong auth)
        or ResultType == 500121   // MFA failed
    | summarize
        FailureCount = count(),
        FailureStart = min(TimeGenerated),
        FailureEnd = max(TimeGenerated),
        IPs = make_set(IPAddress, 10)
        by UserPrincipalName, bin(TimeGenerated, TimeWindowMinutes * 1m)
    | where FailureCount >= MfaFailureThreshold);
// Check if any of those users eventually succeeded
let CompromisedUsers = MfaFailures | distinct UserPrincipalName;
SignInLogs
| where TimeGenerated > ago(LookbackPeriod)
| where UserPrincipalName in (CompromisedUsers)
| where ResultType == 0  // Successful sign-in after failures
| join kind=inner (MfaFailures) on UserPrincipalName
| where TimeGenerated > FailureEnd  // Success after the failures
| where datetime_diff('minute', TimeGenerated, FailureEnd) <= 60
| project
    UserPrincipalName,
    SuccessTime = TimeGenerated,
    FailureStart,
    FailureEnd,
    MfaFailureCount = FailureCount,
    SuccessIP = IPAddress,
    FailureIPs = IPs,
    AppDisplayName,
    AuthenticationMethod = tostring(MfaDetail.authMethod)
| order by SuccessTime desc
```

**Parameters to customize:**
- `MfaFailureThreshold` — 5 is a good starting point; lower for high-security accounts.
- `TimeWindowMinutes` — 30 minutes captures most fatigue attack patterns; extend for patient adversaries.

**Performance notes:**
- The `bin()` function groups failures into time windows — essential for detecting bursts vs. spread-out failures.
- Use `ResultType` codes precisely: 50074 = MFA required, 50076 = strong auth required, 500121 = MFA auth failed.

---

### Pattern 4 — Impossible Travel Detection

Detect sign-ins from geographically distant locations within a time window that makes physical travel impossible.

```kql
// Detect impossible travel: sign-ins from locations too far apart to be the same person.
let LookbackPeriod = 14d;
let MaxTravelSpeedKmh = 900; // Max realistic speed (commercial flight)
SignInLogs
| where TimeGenerated > ago(LookbackPeriod)
| where ResultType == 0
| where isnotempty(tostring(LocationDetails.geoCoordinates.latitude))
| extend
    Lat = toreal(LocationDetails.geoCoordinates.latitude),
    Lon = toreal(LocationDetails.geoCoordinates.longitude),
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city)
| project TimeGenerated, UserPrincipalName, IPAddress, Lat, Lon, Country, City, AppDisplayName
| order by UserPrincipalName asc, TimeGenerated asc
// Compare each sign-in to the previous sign-in for the same user
| extend
    PrevTime = prev(TimeGenerated),
    PrevLat = prev(Lat),
    PrevLon = prev(Lon),
    PrevCountry = prev(Country),
    PrevCity = prev(City),
    PrevIP = prev(IPAddress),
    PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser  // Only compare within the same user
| where isnotempty(PrevLat)
// Calculate distance using Haversine approximation
| extend
    DeltaLatRad = (Lat - PrevLat) * pi() / 180.0,
    DeltaLonRad = (Lon - PrevLon) * pi() / 180.0,
    Lat1Rad = PrevLat * pi() / 180.0,
    Lat2Rad = Lat * pi() / 180.0
| extend
    A = sin(DeltaLatRad / 2) * sin(DeltaLatRad / 2)
        + cos(Lat1Rad) * cos(Lat2Rad)
        * sin(DeltaLonRad / 2) * sin(DeltaLonRad / 2)
| extend DistanceKm = 2 * 6371 * atan2(sqrt(A), sqrt(1 - A))
| extend
    TimeDiffHours = datetime_diff('second', TimeGenerated, PrevTime) / 3600.0,
    RequiredSpeedKmh = iff(datetime_diff('second', TimeGenerated, PrevTime) > 0,
        DistanceKm / (datetime_diff('second', TimeGenerated, PrevTime) / 3600.0),
        real(0))
| where DistanceKm > 500 and RequiredSpeedKmh > MaxTravelSpeedKmh
| project
    UserPrincipalName,
    SignIn1_Time = PrevTime, SignIn1_IP = PrevIP, SignIn1_Location = strcat(PrevCity, ", ", PrevCountry),
    SignIn2_Time = TimeGenerated, SignIn2_IP = IPAddress, SignIn2_Location = strcat(City, ", ", Country),
    DistanceKm = round(DistanceKm, 0),
    TimeDiffHours = round(TimeDiffHours, 2),
    RequiredSpeedKmh = round(RequiredSpeedKmh, 0)
| order by RequiredSpeedKmh desc
```

**Parameters to customize:**
- `MaxTravelSpeedKmh` — 900 km/h covers commercial flights. Lower to 120 km/h for same-region suspicious travel.
- `DistanceKm > 500` — Minimum distance to trigger. Filters out VPN IP changes within the same metro area.

**Performance notes:**
- The `prev()` window function requires data to be sorted by user then time. The `order by` before `prev()` is mandatory.
- Haversine calculation in KQL is CPU-intensive — filter by `ResultType == 0` and non-empty coordinates first to minimize rows.
- For large tenants (100k+ users), partition the query by user group or run as a scheduled rule rather than interactive.

---

### Pattern 5 — Non-Interactive Sign-In Monitoring

Non-interactive sign-ins (service tokens, app tokens, cached credentials) often fly under the radar. Attackers exploit stolen refresh tokens that generate non-interactive sign-ins.

```kql
// Detect anomalous non-interactive sign-in patterns that may indicate token theft.
let LookbackPeriod = 7d;
let BaselinePeriod = 30d;
// Build baseline of normal non-interactive sign-in apps per user
let Baselines = (AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (ago(BaselinePeriod) .. ago(LookbackPeriod))
    | where ResultType == 0
    | summarize BaselineApps = make_set(AppDisplayName, 100) by UserPrincipalName);
// Current non-interactive sign-ins
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(LookbackPeriod)
| where ResultType == 0
| summarize
    CurrentApps = make_set(AppDisplayName, 100),
    CurrentIPs = make_set(IPAddress, 50),
    SignInCount = count()
    by UserPrincipalName
| join kind=leftouter Baselines on UserPrincipalName
// Find apps in current that were never in baseline
| extend NewApps = set_difference(CurrentApps, BaselineApps)
| where array_length(NewApps) > 0
| project
    UserPrincipalName,
    SignInCount,
    NewApps,
    NewAppCount = array_length(NewApps),
    CurrentIPs
| order by NewAppCount desc
```

**Parameters to customize:**
- `BaselinePeriod` — 30 days captures most cyclical app usage. Extend for infrequently used apps.
- `array_length(NewApps) > 0` — Raise to `> 2` in noisy environments to focus on significant deviations.

**Performance notes:**
- `AADNonInteractiveUserSignInLogs` can be 10-50× the volume of `SignInLogs`. Always filter by `ResultType` and time first.
- `set_difference()` is a powerful KQL function for detecting first-time activity — it compares two dynamic arrays and returns elements in the first but not the second.
- Non-interactive sign-in logs have a separate table from interactive logs; query both for complete coverage.

## MITRE ATT&CK Context

| Technique | ID | How This Skill Helps |
|---|---|---|
| Valid Accounts | T1078 | Risk-based analysis (Pattern 1) and impossible travel (Pattern 4) detect compromised credential usage. Non-interactive monitoring (Pattern 5) catches token theft. |
| Brute Force | T1110 | MFA fatigue detection (Pattern 3) identifies password spray and MFA fatigue attacks by correlating failure bursts with subsequent success. |
| Modify Authentication Process | T1556 | Conditional access gap analysis (Pattern 2) reveals sign-ins that bypass expected authentication controls. |

## False Positive Guidance

| Pattern | Common False Positives | Tuning Advice |
|---|---|---|
| Risk-based sign-ins | VPN IP changes triggering "unfamiliar location" risk | Exclude known VPN exit IPs by adding them as named locations in Entra ID. |
| CA gap analysis | Legacy apps that don't support modern auth | Inventory legacy apps; plan migration to modern auth. Tag known legacy apps in exclusions. |
| MFA fatigue | Users genuinely entering wrong MFA codes repeatedly | Correlate with helpdesk tickets; if user self-reported, mark as false positive. |
| Impossible travel | VPN switching (user connects to different VPN regions) | Filter out known VPN provider IP ranges. Check if both IPs belong to the same VPN service. |
| Non-interactive anomaly | App registration changes, new app deployments | Cross-reference with Entra ID audit logs for recent app consent or app registration events. |

## Tuning Guide

### Sign-In Log ResultType Reference

| Code | Meaning | Relevance |
|---|---|---|
| 0 | Success | Baseline for normal activity |
| 50074 | MFA required | Indicates MFA was triggered |
| 50076 | Strong auth required | Stricter MFA requirement |
| 50126 | Invalid username or password | Brute force indicator |
| 500121 | MFA auth failed | Failed MFA challenge |
| 53003 | Blocked by CA policy | CA enforcement working |
| 530032 | Blocked by security defaults | Security defaults enforcement |

### Performance Optimization Checklist

- [ ] `ResultType` filter applied early (0 for success, specific codes for failure analysis)
- [ ] `LocationDetails` parsed with `tostring()` / `toreal()` before use in `extend`
- [ ] `mv-expand` on `ConditionalAccessPolicies` follows heavy pre-filtering
- [ ] Non-interactive logs queried from `AADNonInteractiveUserSignInLogs` (not `SignInLogs`)
- [ ] Impossible travel query uses `order by` before `prev()` to ensure correct windowing
- [ ] `set_difference()` used instead of `join` for first-time activity detection

## Related Skills

- **[Threat Hunting Foundations](threat-hunting-foundations.md)** — Baseline deviation and rare event patterns applicable to sign-in analysis.
- **[Defender XDR Advanced Hunting](defender-xdr-hunting.md)** — Identity tables in Defender complement Entra sign-in logs.
- **[UEBA Patterns](ueba-patterns.md)** — Behavioral analytics patterns that build on sign-in data for anomaly detection.
- **[Detection Tuning](detection-tuning.md)** — Techniques for reducing false positives in sign-in-based detections.
