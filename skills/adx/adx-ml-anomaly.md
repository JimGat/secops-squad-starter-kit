---
title: ADX ML & Anomaly Detection
category: Azure Data Explorer
difficulty: advanced
mitre_attack:
  - T1078  # Valid Accounts — behavioral anomaly detection for identity
  - T1071  # Application Layer Protocol — network traffic anomaly detection
  - T1048  # Exfiltration Over Alternative Protocol — data volume anomaly detection
products:
  - Azure Data Explorer
  - Microsoft Sentinel
  - Microsoft Defender for Identity
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# ADX ML & Anomaly Detection

## Overview

ADX has built-in machine learning functions that run natively inside KQL — no external ML service needed. These functions are purpose-built for time series anomaly detection, pattern clustering, and diff analysis at security-relevant scale. For SOC teams, this means you can detect behavioral anomalies, cluster similar attack patterns, and identify statistically significant changes in your security telemetry — all within your KQL queries, at billions-of-rows speed.

Use this skill when:
- You need automated anomaly detection on time series data (sign-in volumes, network traffic, alert rates)
- You want to cluster similar security events to find attack pattern families
- You need to identify what changed between two time periods (before/after a compromise)
- You are building user behavior analytics (UBA) at scale using ADX
- You want to augment Sentinel detections with statistical anomaly detection

## Prerequisites

| Requirement | Detail |
|---|---|
| **Data** | Time series data with at least 2 weeks of baseline for anomaly detection; categorical data for clustering |
| **Cluster** | ADX cluster with sufficient compute for ML functions (ML is CPU-intensive) |
| **Knowledge** | Basic statistics concepts (standard deviation, percentiles, seasonality) |

## Core Patterns

### Pattern 1 — Time Series Anomaly Detection with series_decompose_anomalies

`series_decompose_anomalies` decomposes a time series into baseline, seasonal, trend, and residual components, then flags anomalies in the residual. This is the workhorse for security anomaly detection.

```kql
// Detect anomalous sign-in volumes per user over the past 30 days
// Anomalies could indicate brute force, credential stuffing, or account takeover
let LookbackDays = 30d;
let BinSize = 1h;
let AnomalyThreshold = 2.5;  // Standard deviations from baseline
SignInEvents
| where TimeGenerated > ago(LookbackDays)
| make-series SignInCount = count() default=0
    on TimeGenerated from ago(LookbackDays) to now() step BinSize
    by UserPrincipalName
| extend (Anomalies, AnomalyScore, ExpectedBaseline) =
    series_decompose_anomalies(SignInCount, AnomalyThreshold, -1, 'linefit')
| mv-expand TimeGenerated to typeof(datetime), SignInCount to typeof(long),
    Anomalies to typeof(int), AnomalyScore to typeof(double),
    ExpectedBaseline to typeof(double)
| where Anomalies != 0
| project TimeGenerated, UserPrincipalName, SignInCount,
    ExpectedBaseline = round(ExpectedBaseline, 1),
    AnomalyScore = round(AnomalyScore, 2),
    AnomalyDirection = iff(Anomalies > 0, "Spike", "Drop")
| order by abs(AnomalyScore) desc
```

**Parameters explained:**
- `AnomalyThreshold` (2.5): Number of standard deviations. Lower = more sensitive (more alerts). Start at 2.5 and tune.
- `-1` for seasonality: Auto-detect seasonality. Use `168` for weekly patterns (168 hours) or `24` for daily.
- `'linefit'`: Baseline algorithm. Use `'avg'` for flat baselines, `'linefit'` when expecting trends.

---

### Pattern 2 — Network Traffic Anomaly Detection

Detect unusual data transfer volumes that could indicate exfiltration or C2 beaconing.

```kql
// Detect anomalous outbound data volumes per device — potential exfiltration indicator
let LookbackDays = 14d;
let BinSize = 1h;
NetworkEvents
| where TimeGenerated > ago(LookbackDays)
| where Direction == "Outbound"
| make-series BytesOut = sum(BytesSent) default=0
    on TimeGenerated from ago(LookbackDays) to now() step BinSize
    by DeviceName
| extend (Anomalies, AnomalyScore) =
    series_decompose_anomalies(BytesOut, 3.0, -1, 'linefit')
| mv-expand TimeGenerated to typeof(datetime), BytesOut to typeof(long),
    Anomalies to typeof(int), AnomalyScore to typeof(double)
| where Anomalies > 0  // Only spikes (increased outbound data)
| where BytesOut > 104857600  // Only flag if > 100 MB in the hour
| project TimeGenerated, DeviceName,
    BytesOutMB = round(todouble(BytesOut) / 1048576.0, 1),
    AnomalyScore = round(AnomalyScore, 2)
| order by AnomalyScore desc
| take 50
```

---

### Pattern 3 — Clustering with autocluster and basket

`autocluster` identifies the most significant patterns (segments) in a dataset. `basket` finds frequent item sets. Both are invaluable for understanding what groups of attributes appear together in security events.

```kql
// Cluster failed sign-in attempts to identify attack patterns
// autocluster finds the attribute combinations that explain the most events
SignInEvents
| where TimeGenerated > ago(7d)
| where ResultType != 0  // Failed sign-ins only
| project UserPrincipalName, IPAddress, Location, AppDisplayName,
    ClientAppUsed, ConditionalAccessStatus, ResultType
| evaluate autocluster(0.05)
```

```kql
// Use basket to find frequent patterns in security alerts
// Reveals which alert combinations co-occur — useful for identifying attack campaigns
SecurityAlert
| where TimeGenerated > ago(30d)
| project AlertName, Severity, CompromisedEntity,
    TacticName = tostring(ExtendedProperties.Tactics)
| evaluate basket(0.01)
| order by Percent desc
| take 20
```

**autocluster vs. basket:**

| Function | Purpose | Best For |
|---|---|---|
| `autocluster` | Find segments that explain a property | "Why are these sign-ins failing?" — finds the IP/location/app pattern |
| `basket` | Find frequent item sets | "What alert combinations appear together?" — finds correlated alerts |

---

### Pattern 4 — Diff Analysis with diffpatterns

`diffpatterns` compares two populations and identifies the attribute combinations that distinguish them. Use it to understand what changed during a security incident.

```kql
// Compare user behavior before vs. during a suspected compromise
// What changed in the user's sign-in pattern?
let IncidentStart = datetime(2026-04-15);
let BaselineDays = 14d;
let CompromisedUser = "compromised.user@contoso.com";
SignInEvents
| where UserPrincipalName =~ CompromisedUser
| where TimeGenerated between (IncidentStart - BaselineDays .. IncidentStart + 7d)
| extend Period = iff(TimeGenerated < IncidentStart, "Before", "During")
| project Period, IPAddress, Location, AppDisplayName, ClientAppUsed,
    ResultType, RiskLevelDuringSignIn
| evaluate diffpatterns(Period, 'Before', 'During')
| order by PercentDiffAB desc
```

**Reading diffpatterns output:**
- `PercentA`: Percentage of "Before" rows matching this pattern
- `PercentB`: Percentage of "During" rows matching this pattern
- `PercentDiffAB`: Difference — high positive values indicate patterns unique to the incident period
- Look for new IP addresses, locations, or apps that appear only in the "During" period

---

### Pattern 5 — User Behavior Analytics at Scale

Combine time series anomaly detection with baseline modeling for scalable UBA. ADX handles millions of users with daily behavioral scoring.

```kql
// Daily behavioral scoring: detect users whose app usage pattern changed significantly
// Score each user's daily app diversity against their 30-day baseline
let BaselineDays = 30d;
let ScoringDay = 1d;
let Baselines = (
    SignInEvents
    | where TimeGenerated between (ago(BaselineDays) .. ago(ScoringDay))
    | summarize
        BaselineAppCount = dcount(AppDisplayName),
        BaselineIPCount = dcount(IPAddress),
        BaselineLocationCount = dcount(Location),
        BaselineDailySignIns = count() / datetime_diff('day', ago(ScoringDay), ago(BaselineDays))
        by UserPrincipalName
);
let TodayActivity = (
    SignInEvents
    | where TimeGenerated > ago(ScoringDay)
    | summarize
        TodayAppCount = dcount(AppDisplayName),
        TodayIPCount = dcount(IPAddress),
        TodayLocationCount = dcount(Location),
        TodaySignIns = count()
        by UserPrincipalName
);
Baselines
| join kind=inner TodayActivity on UserPrincipalName
| extend
    AppDiversityChange = todouble(TodayAppCount - BaselineAppCount) / max_of(BaselineAppCount, 1),
    IPDiversityChange = todouble(TodayIPCount - BaselineIPCount) / max_of(BaselineIPCount, 1),
    LocationChange = todouble(TodayLocationCount - BaselineLocationCount) / max_of(BaselineLocationCount, 1),
    VolumeChange = todouble(TodaySignIns - BaselineDailySignIns) / max_of(BaselineDailySignIns, 1)
| extend RiskScore = (abs(AppDiversityChange) + abs(IPDiversityChange) + abs(LocationChange) * 2 + abs(VolumeChange)) * 25
| where RiskScore > 50
| project UserPrincipalName, RiskScore = round(RiskScore, 1),
    AppDiversityChange = round(AppDiversityChange * 100, 1),
    IPDiversityChange = round(IPDiversityChange * 100, 1),
    LocationChange = round(LocationChange * 100, 1),
    VolumeChange = round(VolumeChange * 100, 1)
| order by RiskScore desc
| take 100
```

## MITRE ATT&CK Context

| Technique | ID | How This Skill Helps |
|---|---|---|
| Valid Accounts | T1078 | Time series anomaly detection catches credential abuse patterns invisible to static rules — unusual sign-in volume, new IP/location clusters. |
| Application Layer Protocol | T1071 | Network traffic anomalies (Pattern 2) detect C2 beaconing and unusual protocol usage. |
| Exfiltration Over Alternative Protocol | T1048 | Outbound volume anomaly detection flags unusual data transfer that could indicate exfiltration. |

## Tuning Guide

### Anomaly Detection Sensitivity

| Threshold | Sensitivity | False Positive Rate | Best For |
|---|---|---|---|
| 1.5 | Very high | High — expect 5-10% FP | Initial exploration, threat hunting |
| 2.0 | High | Moderate — expect 2-5% FP | Active SOC monitoring |
| 2.5 | Medium (recommended) | Low — expect 1-2% FP | Production alerting |
| 3.0 | Low | Very low — < 1% FP | Critical-only alerting |
| 4.0 | Very low | Minimal | Executive dashboards, high-confidence only |

### Performance Considerations

| Function | Compute Cost | Data Requirement | Scalability |
|---|---|---|---|
| `series_decompose_anomalies` | Medium | 2+ weeks baseline per entity | Scales well with `by` clause partitioning |
| `autocluster` | Low-Medium | Works on any dataset | Best with 10K–10M rows |
| `basket` | Medium-High | Works on any dataset | Slow above 1M rows; sample first |
| `diffpatterns` | Medium | Needs two populations | Best with balanced populations |
| UBA scoring (Pattern 5) | High | 30+ days baseline | Partition by user chunks if needed |

## Related Skills

- **[UEBA Patterns](../kql/ueba-patterns.md)** — KQL-based behavioral analytics patterns that complement ADX ML.
- **[Threat Hunting Foundations](../kql/threat-hunting-foundations.md)** — Hypothesis-driven hunting enhanced with anomaly detection.
- **[ADX Dashboards](adx-dashboards.md)** — Visualizing anomaly detection results in real-time dashboards.
- **[Security Data Modeling](security-data-modeling.md)** — Well-modeled data makes ML functions more effective.
- **[Detection Tuning](../kql/detection-tuning.md)** — Use anomaly detection thresholds as a tuning mechanism.
