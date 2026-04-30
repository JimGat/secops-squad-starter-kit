---
title: Advanced Query Patterns
category: log-analytics
difficulty: advanced
mitre_attack:
  - T1078  # Valid Accounts — cross-workspace identity correlation
  - T1071  # Application Layer Protocol — network anomaly detection
  - T1059  # Command and Scripting Interpreter — process hunting patterns
products:
  - Azure Monitor Log Analytics
  - Microsoft Sentinel
  - Azure Data Explorer
  - Azure Resource Graph
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# Advanced Query Patterns

## Overview

This skill covers the advanced KQL query patterns that go beyond single-table, single-workspace queries. Cross-workspace federation, cross-resource queries, parameterized queries, time-series analysis, performance optimization, and ADX proxy queries are the tools that turn a Log Analytics workspace from a log store into a detection and analytics platform.

Use this skill when:
- Querying data across multiple Log Analytics workspaces (multi-region, multi-tenant)
- Correlating Log Analytics data with Application Insights or Azure Resource Graph
- Building parameterized queries for reusable hunting functions
- Performing time-series anomaly detection on security telemetry
- Optimizing slow queries that hit CPU or memory limits
- Querying long-term retention data in ADX from within Sentinel

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Log Analytics Reader` on all target workspaces; `Monitoring Reader` for Application Insights resources |
| **Knowledge** | Intermediate KQL (joins, summarize, let statements) |
| **Environment** | `.secops/data-sources/data-source-map.yaml` populated with table-to-workspace mappings |
| **For ADX proxy** | `Reader` on ADX cluster; ADX cluster URI and database name |

## Environment Context

Before writing cross-workspace or cross-resource queries, consult the `.secops/` framework:

1. **Data source map** — `.secops/data-sources/data-source-map.yaml` tells you which table lives in which workspace or ADX cluster. Never guess — check the map.
2. **Workspace IDs** — `.secops/workspaces/<name>.yaml` → `workspace_id` for `workspace()` function calls.
3. **Data tiers** — Basic-tier tables do not support `join` or `summarize`. Check `tier` before writing complex queries.
4. **Migrations** — `.secops/data-sources/migrations.yaml` tracks tables in transit. A table may exist in both old and new locations during migration.
5. **Retention** — `.secops/workspaces/<name>.yaml` → `retention` determines the queryable time range. Queries beyond `interactive_days` require search jobs or ADX.

---

## Pattern 1: Cross-Workspace Queries

### The `workspace()` Function

Query a table in another workspace by name or GUID:

```kql
// By workspace name (within same subscription/tenant)
workspace("soc-sentinel-prod").SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| summarize FailCount=count() by TargetAccount

// By workspace GUID (works across subscriptions and tenants)
workspace("aabbccdd-1234-5678-abcd-ef0123456789").SecurityEvent
| where TimeGenerated > ago(1h)
| summarize count()
```

### Union Across Workspaces

Combine the same table from multiple workspaces. Reference `.secops/data-sources/data-source-map.yaml` to know which workspaces to include:

```kql
// Correlate sign-in failures across all workspaces
let ws_prod = workspace("soc-sentinel-prod");
let ws_dev = workspace("soc-sentinel-dev");
union
    (ws_prod.SigninLogs | extend SourceWorkspace = "prod"),
    (ws_dev.SigninLogs | extend SourceWorkspace = "dev")
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| summarize
    FailCount = count(),
    Workspaces = make_set(SourceWorkspace)
    by UserPrincipalName, IPAddress
| where FailCount > 10
| order by FailCount desc
```

### Cross-Workspace Join

Join data from different workspaces — for example, correlate endpoint alerts with identity events:

```kql
let endpointAlerts = (
    workspace("soc-sentinel-prod").SecurityAlert
    | where TimeGenerated > ago(24h)
    | where ProductName == "Microsoft Defender for Endpoint"
    | project AlertTime = TimeGenerated, AlertName, CompromisedEntity, AlertSeverity
);
let identityEvents = (
    workspace("soc-identity-prod").SigninLogs
    | where TimeGenerated > ago(24h)
    | project SigninTime = TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType
);
endpointAlerts
| join kind=inner (identityEvents) on $left.CompromisedEntity == $right.UserPrincipalName
| where SigninTime between (AlertTime - 1h .. AlertTime + 1h)
| project AlertTime, AlertName, AlertSeverity, UserPrincipalName, IPAddress, Location, ResultType
```

### Cross-Workspace Limits

| Limit | Value |
|---|---|
| Maximum workspaces per query | 100 |
| Maximum tenants per query | 1 (use Azure Lighthouse for multi-tenant) |
| Performance impact | Each additional workspace adds latency; minimize with targeted time ranges |

---

## Pattern 2: Cross-Resource Queries

### `app()` — Application Insights

Query Application Insights resources from Log Analytics:

```kql
// Correlate web app exceptions with identity sign-in events
let appExceptions = (
    app("ai-contoso-webapp-prod").exceptions
    | where timestamp > ago(1h)
    | project ExceptionTime = timestamp, operation_Name, outerMessage, user_AuthenticatedId
);
SigninLogs
| where TimeGenerated > ago(1h)
| join kind=inner (appExceptions) on $left.UserPrincipalName == $right.user_AuthenticatedId
| project TimeGenerated, UserPrincipalName, AppDisplayName, ExceptionTime, operation_Name, outerMessage
```

### `resource()` — Resource-Centric Queries

Query by resource ID (requires resource-context RBAC):

```kql
// Query all logs for a specific VM — spans all tables
resource("/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/web-server-01")
| where TimeGenerated > ago(1h)
| summarize count() by Type
```

### `adx()` — Azure Data Explorer Proxy

Query ADX data directly from Log Analytics or Sentinel (see Pattern 6 for full coverage):

```kql
// Query long-term retention data in ADX
let adxHistory = (
    adx("https://adx-soc-prod.eastus2.kusto.windows.net/SecurityLogs").SecurityEvent
    | where TimeGenerated > ago(90d)
    | where EventID == 4625
    | summarize HistoricalFailCount = count() by TargetAccount
);
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| summarize RecentFailCount = count() by TargetAccount
| join kind=inner (adxHistory) on TargetAccount
| extend AnomalyRatio = RecentFailCount * 1.0 / HistoricalFailCount
| where AnomalyRatio > 5.0
| order by AnomalyRatio desc
```

---

## Pattern 3: Parameterized Queries & Dynamic Content

### Saved Functions with Parameters

Create reusable functions via saved searches (see [API Wrapper](api-wrapper.md) Section 2):

```kql
// Function: InvestigateUser(upn:string, lookback:timespan = 24h)
// Saved as functionAlias in saved searches API
let target_upn = upn;
let lookback_period = lookback;
union
    (SigninLogs | where TimeGenerated > ago(lookback_period) | where UserPrincipalName =~ target_upn | extend Activity = "SignIn", Detail = strcat(AppDisplayName, " - ", ResultDescription)),
    (AuditLogs | where TimeGenerated > ago(lookback_period) | where InitiatedBy.user.userPrincipalName =~ target_upn | extend Activity = "Audit", Detail = OperationName),
    (SecurityAlert | where TimeGenerated > ago(lookback_period) | where CompromisedEntity =~ target_upn | extend Activity = "Alert", Detail = AlertName)
| project TimeGenerated, Activity, Detail
| order by TimeGenerated desc
```

### Dynamic Table References

Use `datatable` and `mv-expand` for dynamic multi-table queries:

```kql
// Query multiple tables dynamically for IOC hunting
let iocs = datatable(indicator:string) [
    "198.51.100.42",
    "evil-domain.example.com",
    "abc123def456"
];
let checkNetworkLogs = (
    CommonSecurityLog
    | where TimeGenerated > ago(24h)
    | where DestinationIP in (iocs) or RequestURL has_any (iocs)
    | extend MatchedTable = "CommonSecurityLog"
);
let checkDnsLogs = (
    DnsEvents
    | where TimeGenerated > ago(24h)
    | where Name has_any (iocs)
    | extend MatchedTable = "DnsEvents"
);
let checkEndpointLogs = (
    DeviceNetworkEvents
    | where TimeGenerated > ago(24h)
    | where RemoteIP in (iocs) or RemoteUrl has_any (iocs)
    | extend MatchedTable = "DeviceNetworkEvents"
);
union checkNetworkLogs, checkDnsLogs, checkEndpointLogs
| summarize HitCount = count(), Tables = make_set(MatchedTable) by indicator = coalesce(DestinationIP, Name, RemoteIP)
```

### Query-Time Parameters with `declare`

Use `declare query_parameters` for Sentinel analytics rules and workbook parameters:

```kql
declare query_parameters(threshold:int = 10, lookbackHours:int = 24);
SecurityEvent
| where TimeGenerated > ago(1h * lookbackHours)
| where EventID == 4625
| summarize FailCount = count() by TargetAccount, IpAddress
| where FailCount > threshold
```

---

## Pattern 4: Time-Series Analysis

### Baseline Detection with `make-series`

```kql
// Build 7-day baseline of sign-in volume, detect anomalies in last 24h
SigninLogs
| where TimeGenerated > ago(7d)
| make-series SignInCount = count() on TimeGenerated from ago(7d) to now() step 1h
| extend (anomalies, score, baseline) = series_decompose_anomalies(SignInCount, 1.5)
| mv-expand
    TimeGenerated to typeof(datetime),
    SignInCount to typeof(long),
    anomalies to typeof(int),
    score to typeof(double),
    baseline to typeof(double)
| where anomalies != 0
| where TimeGenerated > ago(24h)
| project TimeGenerated, SignInCount, baseline, score, AnomalyDirection = iff(anomalies == 1, "Spike", "Dip")
```

### Seasonal Decomposition

```kql
// Decompose network traffic into trend, seasonal, and residual components
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where DeviceVendor == "Palo Alto Networks"
| make-series BytesTotal = sum(SentBytes + ReceivedBytes) on TimeGenerated from ago(30d) to now() step 1h
| extend (flag, score, baseline) = series_decompose_anomalies(BytesTotal, 2.0, 168)
// 168 = 24h * 7 = one-week seasonality in hourly buckets
| mv-expand
    TimeGenerated to typeof(datetime),
    BytesTotal to typeof(long),
    flag to typeof(int),
    score to typeof(double),
    baseline to typeof(double)
| where flag == 1 and TimeGenerated > ago(24h)
| project TimeGenerated, BytesTotal, baseline, score
| order by score desc
```

### Peer-Group Analysis

```kql
// Compare each user's sign-in pattern against their department baseline
let departmentBaseline = (
    SigninLogs
    | where TimeGenerated > ago(30d)
    | join kind=inner (
        IdentityInfo | where TimeGenerated > ago(1d) | distinct AccountUPN, Department
    ) on $left.UserPrincipalName == $right.AccountUPN
    | summarize AvgDaily = count() / 30.0 by Department
);
SigninLogs
| where TimeGenerated > ago(1d)
| join kind=inner (
    IdentityInfo | where TimeGenerated > ago(1d) | distinct AccountUPN, Department
) on $left.UserPrincipalName == $right.AccountUPN
| summarize TodayCount = count() by UserPrincipalName, Department
| join kind=inner (departmentBaseline) on Department
| extend DeviationRatio = TodayCount / AvgDaily
| where DeviationRatio > 3.0
| project UserPrincipalName, Department, TodayCount, AvgDaily, DeviationRatio
| order by DeviationRatio desc
```

---

## Pattern 5: Performance Optimization

### `materialize()` — Avoid Repeated Subquery Execution

When a subquery result is used multiple times, `materialize()` computes it once:

```kql
// Without materialize: subquery runs twice (once for join, once for summarize)
// With materialize: computed once, reused
let suspiciousIPs = materialize(
    SigninLogs
    | where TimeGenerated > ago(1h)
    | where ResultType != "0"
    | summarize FailCount = count() by IPAddress
    | where FailCount > 20
);
// Use 1: correlate with successful sign-ins
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"
| where IPAddress in ((suspiciousIPs | project IPAddress))
| join kind=inner (suspiciousIPs) on IPAddress
| project TimeGenerated, UserPrincipalName, IPAddress, FailCount
// Use 2: count total suspicious IPs (in a separate query or union)
```

### `partition` — Parallel Per-Group Processing

```kql
// Process each device independently for better parallelism
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| partition by DeviceId (
    top 5 by TimeGenerated desc
    | project TimeGenerated, DeviceId, FileName, ProcessCommandLine
)
```

### `shuffle` Strategy — Distribute Heavy Joins

```kql
// Use shuffle for large-to-large joins
SecurityEvent
| where TimeGenerated > ago(1h)
| join hint.strategy=shuffle (
    DeviceNetworkEvents
    | where TimeGenerated > ago(1h)
    | project RemoteIP, DeviceName, RemotePort
) on $left.IpAddress == $right.RemoteIP
```

### Query Optimization Checklist

| Technique | Impact | When to Use |
|---|---|---|
| **Time filter first** | High | Always — put `where TimeGenerated > ago(...)` as first filter |
| **Specific columns with `project`** | High | When you only need a subset of columns; reduces I/O |
| **`has` instead of `contains`** | Medium | `has` uses term index; `contains` does substring scan |
| **`in` instead of chained `or`** | Medium | `where X in ("a","b","c")` is optimized; chained `or` is not |
| **`materialize()`** | High | When the same subquery is referenced 2+ times |
| **`hint.strategy=shuffle`** | High | Large joins where both sides have millions of rows |
| **`partition by`** | Medium | Per-entity analytics (top-N per device, user, etc.) |
| **`summarize hint.shufflekey`** | Medium | High-cardinality summarize (>1M distinct keys) |
| **Avoid `*` in project** | Low | `project *` reads all columns; be explicit |
| **Pre-filter before join** | High | Filter both sides of join independently before joining |

### Diagnosing Slow Queries

```kql
// Use query_performance_stats (available in ADX, limited in Log Analytics)
// In Log Analytics, check the response headers:
// x-ms-query-exec-time-ms — total execution time
// x-ms-query-resource-usage — CPU and memory consumed

// Pattern: Break query into stages and time each one
let stage1 = (
    SecurityEvent
    | where TimeGenerated > ago(1h)
    | where EventID in (4624, 4625, 4648)
    | project TimeGenerated, Account, IpAddress, EventID
);
let stage2 = (
    stage1
    | summarize count() by Account, IpAddress, EventID
);
stage2
| order by count_ desc
| take 100
```

---

## Pattern 6: ADX Proxy Queries from Log Analytics

### When to Use ADX Proxy

Use the `adx()` proxy function when:
- You need historical data beyond Log Analytics interactive retention (typically 90 days)
- Data was exported to ADX via continuous export for long-term retention
- You need to join current Sentinel data with historical ADX data for baseline comparison

Check `.secops/data-sources/data-source-map.yaml` — tables with `location: "adx"` are in ADX and should be queried via proxy.

### Proxy Syntax

```kql
// Basic ADX proxy query
adx("https://adx-soc-prod.eastus2.kusto.windows.net/SecurityLogs").SecurityEvent
| where TimeGenerated > ago(365d)
| summarize count() by bin(TimeGenerated, 1d)
```

### Hybrid Query — Current + Historical

```kql
// Combine real-time Sentinel data with ADX long-term retention
let recentData = (
    SecurityEvent
    | where TimeGenerated > ago(90d)
    | where EventID == 4625
    | summarize RecentFails = count() by TargetAccount
);
let historicalData = (
    adx("https://adx-soc-prod.eastus2.kusto.windows.net/SecurityLogs").SecurityEvent_Archive
    | where TimeGenerated between (ago(365d) .. ago(90d))
    | where EventID == 4625
    | summarize HistoricalFails = count() by TargetAccount
);
recentData
| join kind=fullouter (historicalData) on TargetAccount
| extend
    TargetAccount = coalesce(TargetAccount, TargetAccount1),
    RecentFails = coalesce(RecentFails, 0),
    HistoricalFails = coalesce(HistoricalFails, 0)
| extend TrendDirection = iff(RecentFails > HistoricalFails * 1.5, "Increasing", "Stable")
| where TrendDirection == "Increasing"
| order by RecentFails desc
```

### ADX Proxy Limits

| Limit | Value |
|---|---|
| Max rows returned via proxy | 500,000 |
| Timeout | Inherits Log Analytics query timeout (10 min) |
| Authentication | AAD token must have Reader on both LA workspace and ADX cluster |
| Supported directions | Log Analytics → ADX only (not ADX → Log Analytics) |

---

## Pattern 7: Integration with `.secops/` Data Source Map

### Reading the Data Source Map Programmatically

Before writing any cross-resource query, load the data source map to determine where each table lives:

```python
import yaml

with open(".secops/data-sources/data-source-map.yaml") as f:
    dsm = yaml.safe_load(f)

# Build a lookup: table_name → (location, workspace, tier)
table_locations = {}
for table_name, config in dsm.get("sources", {}).items():
    table_locations[table_name] = {
        "location": config.get("location"),      # sentinel | adx | external
        "workspace": config.get("workspace"),     # workspace config file name
        "tier": config.get("tier"),               # Analytics | Basic | Auxiliary | Archive
    }

# Check before building a query
target_table = "SecurityEvent"
loc = table_locations.get(target_table, {})

if loc.get("tier") == "Basic":
    print(f"WARNING: {target_table} is Basic tier — join/summarize not available")
elif loc.get("location") == "adx":
    print(f"INFO: {target_table} is in ADX — use adx() proxy function")
elif loc.get("location") == "external":
    print(f"INFO: {target_table} is external — check connector status")
```

### PowerShell — Data Source Aware Query Builder

```powershell
# Load data source map and workspace configs
$dsm = Get-Content ".secops/data-sources/data-source-map.yaml" -Raw | ConvertFrom-Yaml
$tables = @("SecurityEvent", "SigninLogs", "AWSCloudTrail_CL")

foreach ($tableName in $tables) {
    $source = $dsm.sources[$tableName]
    if (-not $source) {
        Write-Warning "Table $tableName not found in data-source-map.yaml"
        continue
    }

    switch ($source.location) {
        "sentinel" {
            $wsConfig = Get-Content ".secops/workspaces/$($source.workspace).yaml" -Raw | ConvertFrom-Yaml
            Write-Host "  $tableName -> workspace($($wsConfig.workspace_id)) [Tier: $($source.tier)]"
        }
        "adx" {
            Write-Host "  $tableName -> adx() proxy query required"
        }
        "external" {
            Write-Host "  $tableName -> external source, check connector"
        }
    }
}
```

### Migration-Aware Queries

When `.secops/data-sources/migrations.yaml` shows a table in transit, query both source and destination:

```kql
// During migration: table exists in both old and new workspace
// Check migrations.yaml for active migrations before writing queries
union
    (workspace("old-workspace-guid").SecurityEvent
     | where TimeGenerated > ago(1h)),
    (workspace("new-workspace-guid").SecurityEvent
     | where TimeGenerated > ago(1h))
| summarize count() by Computer
```

---

## Best Practices

1. **Always consult `.secops/data-sources/data-source-map.yaml`** before writing cross-workspace queries. Never assume a table's location.
2. **Check tier before using operators** — Basic-tier tables reject `join`, `summarize`, and `union`. The query will fail at runtime.
3. **Use `workspace()` with GUIDs** for cross-subscription queries. Workspace names only resolve within the same subscription.
4. **Time-filter both sides of cross-workspace joins** — don't let one side scan unbounded time ranges.
5. **Use `materialize()` for any subquery referenced more than once** — reduces CPU and avoids duplicate I/O.
6. **Prefer `has` over `contains`** — `has` leverages the inverted term index; `contains` forces a full substring scan.
7. **Set explicit `server_timeout`** for complex cross-workspace queries that may exceed the default 10-minute limit.
8. **Tag queries with comments** — include the skill name, MITRE technique, and ticket number for audit trails.
9. **Test ADX proxy queries for latency** — network round-trip between Log Analytics and ADX adds overhead; keep proxy result sets small.
10. **Validate KQL before deployment** — use the `secops-squad kql validate` command to catch syntax issues before they hit production.

---

## Related Skills

| Skill | Relationship |
|---|---|
| [API Wrapper](api-wrapper.md) | REST API patterns for executing these queries programmatically |
| [Cross-Workspace Queries (KQL)](../kql/cross-workspace-queries.md) | KQL-focused cross-workspace patterns and federation |
| [ADX Integration (KQL)](../kql/adx-integration.md) | ADX proxy and cross-cluster query deep dive |
| [Threat Hunting (KQL)](../kql/threat-hunting.md) | Hunting query patterns used within these advanced constructs |
| [Workspace Architecture](workspace-architecture.md) | Topology that determines cross-workspace query requirements |
| [Cost Optimization](cost-optimization.md) | Cost impact of query patterns and data tier choices |
| [UEBA Patterns (KQL)](../kql/ueba-patterns.md) | Behavioral analytics that leverage time-series patterns |
