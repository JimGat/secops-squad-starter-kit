---
title: ADX Integration
category: kql
difficulty: advanced
mitre_attack:
  - T1078  # Valid Accounts
  - T1059  # Command and Scripting Interpreter
  - T1027  # Obfuscated Files or Information
products:
  - Azure Data Explorer
  - Microsoft Sentinel
  - Azure Monitor Log Analytics
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# ADX Integration

## Overview

Azure Data Explorer (ADX) extends Sentinel and Log Analytics by providing long-term, cost-effective storage for security telemetry and high-performance queries over massive datasets. This skill covers querying ADX clusters from Log Analytics, federating across clusters, and designing data lake query patterns for historical investigation.

Use this skill when:
- You need to query data beyond Log Analytics retention limits (default 90 days)
- Your daily ingestion exceeds thresholds where Log Analytics becomes cost-prohibitive
- You need sub-second query performance over billions of rows
- You are building a security data lake for compliance or forensic readiness
- You need to join current Sentinel data with historical ADX data

## Prerequisites

| Requirement | Detail |
|---|---|
| **Tables** | ADX tables mirroring Sentinel schemas (e.g., `SecurityEvent`, `SignInLogs`, `CommonSecurityLog`) |
| **Infrastructure** | ADX cluster with data export configured from Log Analytics, or direct ingestion |
| **Permissions** | `Database Viewer` on the ADX database; `Log Analytics Reader` on the LA workspace |
| **Configuration** | ADX cluster URI, database name; LA workspace data export rules or Event Hub pipeline |

## Core Patterns

### Pattern 1 — Querying ADX from Log Analytics with adx()

The `adx()` proxy function lets you query ADX clusters directly from a Log Analytics query. This is ideal for joining current Sentinel data with historical ADX data in a single query.

```kql
// Query historical sign-in data from ADX while correlating with current Sentinel data.
// adx() syntax: adx('cluster-uri/database').TableName
let CurrentWindow = 7d;
let HistoricalLookback = 365d;
let SuspiciousUser = "compromised.user@contoso.com";
// Current sign-ins from Sentinel
let RecentActivity = (SignInLogs
    | where TimeGenerated > ago(CurrentWindow)
    | where UserPrincipalName =~ SuspiciousUser
    | project TimeGenerated, IPAddress, AppDisplayName, ResultType, Location = tostring(LocationDetails.countryOrRegion));
// Historical sign-ins from ADX (past year)
let HistoricalActivity = (adx('https://securitycluster.eastus.kusto.windows.net/SecurityLogs').SignInLogs
    | where TimeGenerated > ago(HistoricalLookback)
    | where UserPrincipalName =~ SuspiciousUser
    | project TimeGenerated, IPAddress, AppDisplayName, ResultType, Location = tostring(LocationDetails.countryOrRegion));
// Combine for full timeline
union RecentActivity, HistoricalActivity
| summarize
    TotalSignIns = count(),
    DistinctIPs = dcount(IPAddress),
    DistinctLocations = dcount(Location),
    Locations = make_set(Location, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by IPAddress
| order by TotalSignIns desc
```

**Parameters to customize:**
- `securitycluster.eastus.kusto.windows.net` — Replace with your ADX cluster URI.
- `SecurityLogs` — Replace with your ADX database name.
- `SuspiciousUser` — The entity under investigation.
- `HistoricalLookback` — ADX supports multi-year retention; adjust based on your data availability.

**Performance notes:**
- `adx()` queries execute on the ADX cluster and return results to Log Analytics for final processing. Push as many filters as possible into the ADX leg.
- ADX queries via `adx()` proxy are limited to 500,000 returned rows and 64 MB result size.
- ADX cluster must have `AllDatabasesViewer` or specific database permissions granted to the querying identity.

---

### Pattern 2 — When to Use ADX vs. Log Analytics

This decision tree helps you choose the right query target. It is not a KQL pattern but a critical architectural judgment call.

```kql
// Cost comparison: estimate your daily ingestion cost in LA vs ADX.
// Run this in your Log Analytics workspace to measure daily volume.
let AnalysisPeriod = 30d;
Usage
| where TimeGenerated > ago(AnalysisPeriod)
| where IsBillable == true
| summarize
    DailyIngestGB = sum(Quantity) / 1024.0 / AnalysisPeriod / 1d
    by DataType
| order by DailyIngestGB desc
| extend
    EstimatedLA_MonthlyCostUSD = round(DailyIngestGB * 30 * 2.76, 2),   // ~$2.76/GB/day for PAYG
    EstimatedADX_MonthlyCostUSD = round(DailyIngestGB * 30 * 0.12, 2)   // ~$0.12/GB/month storage + compute
| project DataType, DailyIngestGB = round(DailyIngestGB, 2), EstimatedLA_MonthlyCostUSD, EstimatedADX_MonthlyCostUSD
```

**Decision criteria:**

| Factor | Log Analytics | Azure Data Explorer |
|---|---|---|
| Retention needed | ≤2 years | 2+ years, unlimited |
| Query latency SLA | Seconds (small-medium data) | Sub-second (any data size) |
| Daily ingestion | < 500 GB/day | 500 GB+ /day |
| Cost model | Per-GB ingestion + retention | Cluster compute + storage |
| Sentinel integration | Native | Via `adx()` proxy or data export |
| Interactive hunting | ✓ (Sentinel workbooks) | ✓ (ADX dashboards, Grafana) |
| Long-term forensics | Limited by retention | Primary use case |

---

### Pattern 3 — Cross-Cluster Federation

When your organization has multiple ADX clusters (e.g., per-region for data residency), federate queries across them. ADX supports native cross-cluster queries.

```kql
// Federated query across US and EU ADX clusters for global threat hunt.
// Run this in ADX (Web UI or Kusto Explorer), not Log Analytics.
let LookbackPeriod = 90d;
let ThreatIP = "192.0.2.99";
union
    (cluster('https://security-us.eastus.kusto.windows.net').database('SecurityLogs').CommonSecurityLog
        | where TimeGenerated > ago(LookbackPeriod)
        | where SourceIP == ThreatIP or DestinationIP == ThreatIP
        | extend Region = "US"),
    (cluster('https://security-eu.westeurope.kusto.windows.net').database('SecurityLogs').CommonSecurityLog
        | where TimeGenerated > ago(LookbackPeriod)
        | where SourceIP == ThreatIP or DestinationIP == ThreatIP
        | extend Region = "EU")
| summarize
    HitCount = count(),
    DistinctDevices = dcount(DeviceName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Actions = make_set(DeviceAction, 10)
    by Region, SourceIP, DestinationIP, DestinationPort
| order by HitCount desc
```

**Parameters to customize:**
- Cluster URIs — Replace with your actual ADX cluster endpoints.
- `SecurityLogs` — Database name on each cluster.
- `ThreatIP` — IOC to sweep across regions.

**Performance notes:**
- Cross-cluster queries execute each leg on the remote cluster and merge results locally. Data transfer costs apply.
- Use `set notruncation;` at the top of ADX queries when you need more than the default 500,000 row limit.
- Cross-cluster queries require the querying identity to have permissions on both clusters.

---

### Pattern 4 — Data Lake Query Pattern for Historical Analysis

ADX excels at querying historical data exported from Log Analytics. This pattern queries a full year of data to build behavioral baselines for forensic investigations.

```kql
// Build a 12-month login baseline from ADX for forensic comparison.
// Run this in ADX directly for best performance.
let TargetUser = "exec.user@contoso.com";
let BaselineMonths = 12;
database('SecurityLogs').SignInLogs
| where TimeGenerated > ago(BaselineMonths * 30d)
| where UserPrincipalName =~ TargetUser
| where ResultType == 0  // Successful only
| summarize
    SignInCount = count(),
    DistinctIPs = dcount(IPAddress),
    DistinctApps = dcount(AppDisplayName),
    DistinctLocations = dcount(tostring(LocationDetails.countryOrRegion)),
    IPs = make_set(IPAddress, 50),
    Apps = make_set(AppDisplayName, 50),
    Locations = make_set(tostring(LocationDetails.countryOrRegion), 20)
    by bin(TimeGenerated, 7d)
| order by TimeGenerated asc
| extend
    // Detect sudden behavioral changes week-over-week
    PrevWeekIPs = prev(DistinctIPs),
    IPDelta = DistinctIPs - prev(DistinctIPs),
    PrevWeekSignIns = prev(SignInCount),
    SignInDelta = SignInCount - prev(SignInCount)
```

**Parameters to customize:**
- `TargetUser` — The identity under investigation.
- `BaselineMonths` — Increase for executive accounts or critical assets.
- `bin(TimeGenerated, 7d)` — Change to `1d` for granular baselines or `30d` for high-level trends.

**Performance notes:**
- ADX handles 12-month scans over billions of rows in seconds thanks to columnar storage and extent indexing.
- For multi-TB datasets, add `.datetime_partitioned_by(TimeGenerated, 1d)` during table creation to optimize time-range scans.
- Use `materialize()` in ADX when referencing the same intermediate result multiple times in a single query.

---

### Pattern 5 — Configuring Continuous Data Export from LA to ADX

This pattern is operational — it sets up the pipeline that feeds ADX with Sentinel data. Query the export status to ensure your data lake stays current.

```kql
// Monitor data export health from Log Analytics to ADX.
// Run this in Log Analytics to track export lag and failures.
let MonitorWindow = 7d;
LAQueryLogs
| where TimeGenerated > ago(MonitorWindow)
| where QueryText contains "adx(" or QueryText contains "cluster("
| summarize
    QueryCount = count(),
    AvgDurationMs = avg(ResponseDurationMs),
    P95DurationMs = percentile(ResponseDurationMs, 95),
    FailedQueries = countif(ResponseCode != 200)
    by bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

```kql
// Validate data completeness: compare row counts between LA and ADX for the overlap period.
// Run this in Log Analytics.
let OverlapWindow = 2d;  // Period where both LA and ADX should have the data
let LA_Count = (SecurityEvent
    | where TimeGenerated > ago(OverlapWindow)
    | summarize LACount = count());
let ADX_Count = (adx('https://securitycluster.eastus.kusto.windows.net/SecurityLogs').SecurityEvent
    | where TimeGenerated > ago(OverlapWindow)
    | summarize ADXCount = count());
LA_Count
| join kind=inner ADX_Count on 1==1
| extend
    Delta = LACount - ADXCount,
    CompletenessPercent = round(todouble(ADXCount) / todouble(LACount) * 100, 2)
```

**Parameters to customize:**
- `OverlapWindow` — Should match your data export latency (typically 5-20 minutes, but check for daily batches).
- Cluster URI and database — Replace with your actual ADX endpoint.

**Performance notes:**
- Run the completeness check daily via a Logic App or Azure Function to alert on data pipeline gaps.
- Data export from LA to ADX supports continuous export (near real-time) and event-hub-based pipelines.

## MITRE ATT&CK Context

| Technique | ID | How This Skill Helps |
|---|---|---|
| Valid Accounts | T1078 | Year-long baselines in ADX (Pattern 4) reveal compromised accounts that have been active for months — invisible in 90-day LA retention. |
| Command and Scripting Interpreter | T1059 | Cross-cluster federation (Pattern 3) enables process execution hunting across globally distributed ADX clusters. |
| Obfuscated Files or Information | T1027 | Historical analysis in ADX catches obfuscation patterns that evolve over time — comparing current vs. past encoding techniques. |

## False Positive Guidance

| Pattern | Common False Positives | Tuning Advice |
|---|---|---|
| Historical baseline deviation | Business changes (mergers, role changes) invalidating old baselines | Segment baselines by time period; weight recent months more heavily. |
| Cross-cluster IOC sweep | IP address reuse (dynamic IPs matching old threat intel) | Cross-reference with TI feed validity dates; expire IOCs automatically. |
| Data completeness alerts | Expected export lag during cluster scaling or maintenance | Set completeness threshold at 98% rather than 100%; alert on sustained gaps. |

## Tuning Guide

### ADX Cluster Sizing for Security Data

| Data Volume | Recommended SKU | Estimated Monthly Cost |
|---|---|---|
| < 100 GB/day | Dev/Test (D11_v2 × 2) | ~$500 |
| 100–500 GB/day | Standard (D14_v2 × 4-8) | ~$3,000–6,000 |
| 500 GB–2 TB/day | Standard (L8s_v3 × 8-16) | ~$8,000–16,000 |
| 2+ TB/day | Optimized (L16s_v3 × 16+) | Custom pricing |

### Performance Optimization Checklist

- [ ] Time filter is the first predicate in every ADX query (exploits datetime partitioning)
- [ ] `project` reduces columns before any cross-cluster or `adx()` proxy call
- [ ] `materialize()` used when the same subquery is referenced multiple times
- [ ] Table partitioning aligns with common query patterns (usually `TimeGenerated` by day)
- [ ] Hot cache period set to cover your most common lookback window (typically 7-30 days)
- [ ] Continuous export validated daily for completeness

## Related Skills

- **[Cross-Workspace Queries](cross-workspace-queries.md)** — When data is in multiple Log Analytics workspaces (not ADX).
- **[Threat Hunting Foundations](threat-hunting-foundations.md)** — ADX extends the hunting patterns from this skill to multi-year timelines.
- **[Detection Tuning](detection-tuning.md)** — Use ADX historical data to build more accurate baselines for threshold tuning.
