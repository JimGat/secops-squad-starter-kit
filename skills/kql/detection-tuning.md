---
title: Detection Tuning
category: kql
difficulty: advanced
mitre_attack:
  - T1078  # Valid Accounts (example tuning target)
  - T1059  # Command and Scripting Interpreter (example tuning target)
  - T1110  # Brute Force (example tuning target)
products:
  - Microsoft Sentinel
  - Microsoft Defender for Endpoint
  - Azure Monitor Log Analytics
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Detection Tuning

## Overview

Detection tuning is the discipline of reducing false positives while maintaining true positive sensitivity. Raw detection rules almost always produce noise — the craft is in systematic refinement. This skill provides KQL patterns for baselining normal behavior, designing exclusion lists, analyzing thresholds, trending alert volumes, and building dynamic thresholds that adapt to your environment.

Use this skill when:
- A detection rule is generating too many false positives for the SOC to triage
- You need to establish what "normal" looks like before writing a detection
- You want to build exclusion patterns that are auditable and maintainable
- You need to set thresholds that balance sensitivity with alert fatigue
- You are measuring detection program health (signal-to-noise ratio)

## Prerequisites

| Requirement | Detail |
|---|---|
| **Tables** | `SecurityAlert`, `SecurityIncident`, `SignInLogs`, `DeviceProcessEvents`, `_SentinelWatchlist` (for watchlist-driven exclusions) |
| **Workspace** | Sentinel workspace with active analytics rules generating alerts |
| **Permissions** | `Microsoft Sentinel Contributor` (to modify rules after tuning) |
| **Data connectors** | Any connectors feeding the rules under tuning |

## Core Patterns

### Pattern 1 — Baseline Deviation for Threshold Discovery

Before setting a threshold, measure the actual distribution of the metric you are detecting on. This pattern builds a statistical profile of any countable behavior to inform threshold selection.

```kql
// Profile a metric's distribution to set an evidence-based threshold.
// Example: failed sign-in attempts per user per day.
let BaselinePeriod = 30d;
let MetricGranularity = 1d;
SignInLogs
| where TimeGenerated > ago(BaselinePeriod)
| where ResultType != 0  // Failed sign-ins
| summarize DailyFailures = count() by UserPrincipalName, bin(TimeGenerated, MetricGranularity)
| summarize
    P50 = percentile(DailyFailures, 50),
    P75 = percentile(DailyFailures, 75),
    P90 = percentile(DailyFailures, 90),
    P95 = percentile(DailyFailures, 95),
    P99 = percentile(DailyFailures, 99),
    Mean = avg(DailyFailures),
    StdDev = stdev(DailyFailures),
    MaxValue = max(DailyFailures),
    DistinctUsers = dcount(UserPrincipalName),
    TotalDataPoints = count()
| extend
    // Threshold recommendations based on the distribution
    ConservativeThreshold = round(P99, 0),          // ~1% alert rate
    BalancedThreshold = round(P95, 0),               // ~5% alert rate
    AggressiveThreshold = round(P90, 0),             // ~10% alert rate
    ZScore3Threshold = round(Mean + 3 * StdDev, 0)  // Statistical outlier
```

**Parameters to customize:**
- `BaselinePeriod` — 30 days is the minimum for stable statistics. Use 90 days if available.
- `MetricGranularity` — `1d` for daily patterns, `1h` for high-frequency detections.
- Change the source table and metric to profile any behavior (process counts, file modifications, API calls).

**Performance notes:**
- `percentile()` requires all data points in memory. For very high-cardinality datasets, pre-aggregate with `summarize` first.
- Running this over 90 days on large tables may take 30-60 seconds. Cache results for iterative analysis.

---

### Pattern 2 — Watchlist-Driven Exclusion Patterns

Use Sentinel watchlists as named exclusion lists. This keeps exclusions out of query text, makes them auditable, and allows non-KQL users to manage them.

```kql
// Exclude known service accounts and approved admin tools using Sentinel watchlists.
// Watchlist: "ExcludedServiceAccounts" with column "UPN"
// Watchlist: "ApprovedAdminTools" with column "ProcessName"
let ExcludedAccounts = _GetWatchlist('ExcludedServiceAccounts') | project UPN;
let ApprovedTools = _GetWatchlist('ApprovedAdminTools') | project ProcessName;
let LookbackPeriod = 1d;
DeviceProcessEvents
| where TimeGenerated > ago(LookbackPeriod)
| where AccountUpn !in (ExcludedAccounts)
| where FileName !in (ApprovedTools)
// Core detection logic: unsigned processes executing from temp directories
| where FolderPath has_any ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\")
| where isempty(ProcessVersionInfoCompanyName)  // Unsigned
| summarize
    ExecutionCount = count(),
    Devices = make_set(DeviceName, 10),
    Users = make_set(AccountName, 10)
    by FileName, FolderPath
| order by ExecutionCount desc
```

```kql
// Audit your exclusion lists: detect when an excluded entity exhibits suspicious behavior
// that the exclusion would have hidden.
let LookbackPeriod = 7d;
let ExcludedAccounts = _GetWatchlist('ExcludedServiceAccounts') | project UPN;
SignInLogs
| where TimeGenerated > ago(LookbackPeriod)
| where UserPrincipalName in (ExcludedAccounts)
| where RiskLevelDuringSignIn in ("high", "medium")
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    RiskLevelDuringSignIn,
    AppDisplayName,
    ResultType
| summarize
    RiskySignIns = count(),
    RiskLevels = make_set(RiskLevelDuringSignIn),
    IPs = make_set(IPAddress, 10)
    by UserPrincipalName
| order by RiskySignIns desc
```

**Parameters to customize:**
- `ExcludedServiceAccounts` — Name of your Sentinel watchlist. Create with columns: `UPN`, `Justification`, `AddedBy`, `ExpirationDate`.
- `ApprovedAdminTools` — Watchlist of approved process names with business justification.

**Performance notes:**
- `_GetWatchlist()` loads the watchlist into memory at query time. Keep watchlists under 10,000 rows for interactive performance.
- The audit query (second pattern) should run weekly to ensure exclusions aren't hiding real attacks.

---

### Pattern 3 — Dynamic Thresholds Based on Time-of-Day and Day-of-Week

Static thresholds fail when behavior varies by time. This pattern builds time-aware baselines that automatically adjust detection sensitivity.

```kql
// Build dynamic thresholds that account for business-hour vs. off-hour patterns.
let BaselinePeriod = 30d;
let DetectionWindow = 1d;
let Sensitivity = 3.0; // Z-score threshold
// Build per-hour-of-day, per-day-of-week baselines
let TimeBasedBaseline = (SignInLogs
    | where TimeGenerated between (ago(BaselinePeriod) .. ago(DetectionWindow))
    | where ResultType == 0
    | extend
        HourOfDay = hourofday(TimeGenerated),
        DayOfWeek = dayofweek(TimeGenerated) / 1d  // 0=Sunday, 1=Monday, etc.
    | summarize HourlyCount = count() by UserPrincipalName, HourOfDay, DayOfWeek, bin(TimeGenerated, 1d)
    | summarize
        AvgCount = avg(HourlyCount),
        StdDevCount = stdev(HourlyCount)
        by UserPrincipalName, HourOfDay, DayOfWeek);
// Current activity
let CurrentActivity = (SignInLogs
    | where TimeGenerated > ago(DetectionWindow)
    | where ResultType == 0
    | extend
        HourOfDay = hourofday(TimeGenerated),
        DayOfWeek = dayofweek(TimeGenerated) / 1d
    | summarize CurrentCount = count() by UserPrincipalName, HourOfDay, DayOfWeek);
// Compare current vs. baseline for each time slot
CurrentActivity
| join kind=inner TimeBasedBaseline on UserPrincipalName, HourOfDay, DayOfWeek
| where StdDevCount > 0
| extend ZScore = (CurrentCount - AvgCount) / StdDevCount
| where ZScore > Sensitivity
| project
    UserPrincipalName,
    HourOfDay,
    DayOfWeek = case(
        DayOfWeek == 0, "Sunday", DayOfWeek == 1, "Monday",
        DayOfWeek == 2, "Tuesday", DayOfWeek == 3, "Wednesday",
        DayOfWeek == 4, "Thursday", DayOfWeek == 5, "Friday",
        DayOfWeek == 6, "Saturday", "Unknown"),
    CurrentCount,
    ExpectedAvg = round(AvgCount, 1),
    StdDev = round(StdDevCount, 1),
    ZScore = round(ZScore, 2)
| order by ZScore desc
```

**Parameters to customize:**
- `Sensitivity` — Start at 3.0 (conservative). Lower to 2.0 for environments where subtle anomalies matter.
- The time decomposition — Add `weekofyear()` for monthly-cycle-aware baselines (finance teams at month-end).

**Performance notes:**
- The baseline is multi-dimensional (user × hour × day-of-week × day), producing many rows. Pre-filter users to a target group if needed.
- For large tenants, build the baseline as a materialized view or scheduled query that stores results in a custom log table.

---

### Pattern 4 — Alert Volume Trending and Signal-to-Noise Measurement

Measure the health of your detection program by trending alert volumes, close reasons, and true/false positive ratios.

```kql
// Weekly alert volume and disposition analysis.
let LookbackPeriod = 90d;
SecurityIncident
| where TimeGenerated > ago(LookbackPeriod)
| extend
    Week = startofweek(TimeGenerated),
    Classification = tostring(Classification),
    Severity = tostring(Severity)
| summarize
    TotalIncidents = count(),
    TruePositives = countif(Classification == "TruePositive"),
    FalsePositives = countif(Classification == "FalsePositive"),
    BenignPositives = countif(Classification == "BenignPositive"),
    Undetermined = countif(Classification == "Undetermined" or isempty(Classification))
    by Week, Severity
| extend
    FPRate = round(todouble(FalsePositives) / todouble(TotalIncidents) * 100, 2),
    TPRate = round(todouble(TruePositives) / todouble(TotalIncidents) * 100, 2)
| order by Week desc, Severity asc
```

```kql
// Identify the noisiest analytics rules — candidates for tuning.
let LookbackPeriod = 30d;
SecurityAlert
| where TimeGenerated > ago(LookbackPeriod)
| where ProviderName == "Azure Sentinel"
| summarize
    AlertCount = count(),
    DistinctEntities = dcount(CompromisedEntity),
    FirstAlert = min(TimeGenerated),
    LastAlert = max(TimeGenerated)
    by AlertName, AlertSeverity
| join kind=leftouter (
    SecurityIncident
    | where TimeGenerated > ago(LookbackPeriod)
    | mv-expand AlertId = parse_json(AlertIds)
    | extend AlertId = tostring(AlertId)
    | join kind=inner (SecurityAlert | project AlertId = SystemAlertId, AlertName) on AlertId
    | summarize
        IncidentCount = dcount(IncidentNumber),
        FPCount = dcountif(IncidentNumber, Classification == "FalsePositive"),
        TPCount = dcountif(IncidentNumber, Classification == "TruePositive")
        by AlertName
) on AlertName
| extend
    FPRate = iff(IncidentCount > 0, round(todouble(FPCount) / todouble(IncidentCount) * 100, 1), real(null)),
    AlertsPerDay = round(todouble(AlertCount) / todouble(datetime_diff('day', LastAlert, FirstAlert) + 1), 1)
| project
    AlertName,
    AlertSeverity,
    AlertCount,
    AlertsPerDay,
    IncidentCount,
    TPCount,
    FPCount,
    FPRate,
    TuningPriority = case(
        FPRate > 80, "🔴 Critical — consider disabling",
        FPRate > 50, "🟠 High — needs exclusions",
        FPRate > 20, "🟡 Moderate — review thresholds",
        "🟢 Healthy")
| order by AlertCount desc
```

**Parameters to customize:**
- `LookbackPeriod` — 30 days for operational tuning; 90 days for program maturity assessment.
- `FPRate` thresholds in `TuningPriority` — Adjust based on your SOC's tolerance.

**Performance notes:**
- The join between `SecurityAlert` and `SecurityIncident` via `AlertIds` requires `mv-expand` because `AlertIds` is a JSON array. This can be expensive on high-volume workspaces.
- Run the noisiest-rules query weekly as a scheduled workbook refresh, not interactively during hunts.

---

### Pattern 5 — A/B Testing Detection Rule Changes

Before deploying a tuned rule to production, run the old and new logic side-by-side to compare detection rates and false positive counts.

```kql
// A/B test: compare original rule logic vs. tuned rule logic on the same data.
let TestWindow = 14d;
let FailureThreshold_Original = 5;
let FailureThreshold_Tuned = 10;
let ExcludedAccounts = dynamic(["svc-backup@contoso.com", "svc-monitor@contoso.com"]);
// Original rule (v1): simple threshold
let OriginalDetections = (SignInLogs
    | where TimeGenerated > ago(TestWindow)
    | where ResultType != 0
    | summarize FailedCount = count() by UserPrincipalName
    | where FailedCount > FailureThreshold_Original
    | extend RuleVersion = "Original (threshold=5)");
// Tuned rule (v2): higher threshold + exclusions + time-scoped
let TunedDetections = (SignInLogs
    | where TimeGenerated > ago(TestWindow)
    | where ResultType != 0
    | where UserPrincipalName !in (ExcludedAccounts)
    | summarize FailedCount = count() by UserPrincipalName, bin(TimeGenerated, 1h)
    | where FailedCount > FailureThreshold_Tuned
    | summarize HourlyBursts = count(), MaxHourlyCount = max(FailedCount) by UserPrincipalName
    | extend RuleVersion = "Tuned (threshold=10, hourly, excl)");
// Compare results
let OriginalUsers = OriginalDetections | distinct UserPrincipalName;
let TunedUsers = TunedDetections | distinct UserPrincipalName;
print
    OriginalDetectionCount = toscalar(OriginalDetections | count),
    TunedDetectionCount = toscalar(TunedDetections | count),
    UsersOnlyInOriginal = toscalar(
        OriginalUsers | where UserPrincipalName !in (TunedUsers) | count),
    UsersOnlyInTuned = toscalar(
        TunedUsers | where UserPrincipalName !in (OriginalUsers) | count),
    SharedDetections = toscalar(
        OriginalUsers | where UserPrincipalName in (TunedUsers) | count)
```

**Parameters to customize:**
- `FailureThreshold_Original` / `FailureThreshold_Tuned` — Set to your current and proposed thresholds.
- `ExcludedAccounts` — The exclusion list you plan to add in the tuned version.
- Replace the detection logic with your actual analytics rule KQL.

**Performance notes:**
- Both rule versions scan the same data — run during off-peak hours on large datasets.
- The `print` statement at the end provides a single-row comparison summary. Extend with `union` for detailed per-user comparison.

## MITRE ATT&CK Context

| Technique | ID | How This Skill Helps |
|---|---|---|
| Valid Accounts | T1078 | Baseline deviation (Pattern 1) and dynamic thresholds (Pattern 3) reduce false positives on credential-based detections without losing sensitivity to real compromises. |
| Command and Scripting Interpreter | T1059 | Watchlist-driven exclusions (Pattern 2) let you whitelist known-good scripts while still detecting anomalous interpreter usage. |
| Brute Force | T1110 | Threshold analysis (Pattern 1) helps set evidence-based brute force thresholds. A/B testing (Pattern 5) validates tuned rules before deployment. |

## False Positive Guidance

| Pattern | Common False Positives | Tuning Advice |
|---|---|---|
| Baseline deviation | New employees with no baseline history | Require a minimum baseline period (e.g., 7 days of data) before including a user in deviation analysis. |
| Watchlist exclusions | Stale exclusion entries hiding real attacks | Add `ExpirationDate` to watchlists; run the audit query (Pattern 2b) weekly. |
| Dynamic thresholds | Holiday periods with unusually low baselines making return-to-work look anomalous | Incorporate calendar awareness; exclude known holiday weeks from baselines. |
| Alert volume trending | New rules temporarily inflating alert counts | Filter by rule creation date; allow new rules a 2-week burn-in before measuring FP rate. |

## Tuning Guide

### Tuning Workflow

1. **Measure** — Run Pattern 4 to identify the noisiest rules.
2. **Profile** — Run Pattern 1 against the metric the noisy rule detects to understand the distribution.
3. **Design exclusions** — Use Pattern 2 to build watchlist-based exclusions for known-good entities.
4. **Adjust thresholds** — Use Pattern 1 percentiles and Pattern 3 dynamic thresholds to set evidence-based limits.
5. **Test** — Run Pattern 5 to A/B test the tuned rule against historical data.
6. **Deploy** — Update the analytics rule. Monitor Pattern 4 for FP rate changes over the next 2 weeks.
7. **Audit** — Schedule the Pattern 2 audit query to ensure exclusions aren't hiding real attacks.

### Performance Optimization Checklist

- [ ] Baseline queries filter by `ResultType` before aggregation
- [ ] Watchlists kept under 10,000 rows for interactive query performance
- [ ] `percentile()` applied to pre-aggregated data (not raw rows)
- [ ] A/B test queries run on the same `TestWindow` for fair comparison
- [ ] Alert volume queries use `SecurityIncident` for disposition data (not `SecurityAlert`)
- [ ] Dynamic threshold baselines exclude the detection window to prevent data leakage

## Related Skills

- **[Threat Hunting Foundations](threat-hunting-foundations.md)** — Baseline deviation patterns used here originate from the hunting foundations.
- **[Sentinel Analytics Rules](sentinel-analytics-rules.md)** — Apply tuning results to scheduled analytics rules.
- **[Entra Sign-In Analysis](entra-signin-analysis.md)** — Sign-in-based detections are common tuning targets.
- **[UEBA Patterns](ueba-patterns.md)** — UEBA anomaly scores can replace static thresholds for adaptive detection.
