---
title: Performance Tuning & Optimization
category: platform
difficulty: advanced
mitre_attack:
  - General   # Operational — performance directly impacts IR response times
  - T1562     # Impair Defenses — degraded performance delays detection/response
products:
  - Azure Monitor Log Analytics
  - Microsoft Sentinel
  - Azure Data Explorer
  - Microsoft Defender XDR
author: Freamon
version: 1.0.0
last_updated: 2026-05-04
---

# Performance Tuning & Optimization

## Overview

In SecOps, performance is a security property. A query that takes 90 seconds instead of 5 means an analyst waits during triage. An API wrapper that exhausts its rate limit means enrichment calls fail mid-investigation. A workspace ingesting 500 GB/day without summary rules burns budget that could fund additional detection coverage.

This skill covers KQL query optimization, API wrapper performance, rate limiter tuning, MCP server efficiency, and cost optimization.

**Complements:** [rate-limiting.md](../powershell/rate-limiting.md), [cost-optimization.md](../log-analytics/cost-optimization.md), [api-patterns.md](../powershell/api-patterns.md), [sentinel-mcp-server.md](../msft-security/sentinel-mcp-server.md).

## Environment Context

| File | Check |
|---|---|
| `workspaces/*.yaml` | Workspace SKU, commitment tier, daily cap |
| `data-sources/data-source-map.yaml` | Table volumes, tiers (Analytics vs Basic) |
| `compliance/requirements.yaml` | Retention requirements that constrain tier changes |

## KQL Query Optimization

### Query Profiling

```kql
// Find slowest queries in the last 24 hours
LAQueryLogs
| where TimeGenerated > ago(24h) and ResponseCode == 200
| extend DurationSec = ResponseDurationMs / 1000.0
| where DurationSec > 10
| project TimeGenerated, QueryText = RequestBody, DurationSec, ResponseRowCount, RequestClientApp
| sort by DurationSec desc
| take 20
```

```kql
// Resource consumption by application
LAQueryLogs
| where TimeGenerated > ago(7d)
| summarize QueryCount = count(), AvgDurationSec = avg(ResponseDurationMs / 1000.0),
    P95DurationSec = percentile(ResponseDurationMs / 1000.0, 95),
    TotalScannedMB = sum(StatsDataProcessedKB) / 1024.0
    by RequestClientApp
| sort by TotalScannedMB desc
```

### Anti-Patterns and Fixes

| Anti-Pattern | Problem | Fix |
|---|---|---|
| No time filter | Scans entire retention | `where TimeGenerated > ago(Xd)` as first filter |
| `search *` | Scans all tables | Use specific table names |
| `join` before `where` | Joins full tables | Filter both sides first |
| `contains` on large tables | Full string scan | Use `has` / `has_cs` (indexed) |
| `project *` | Returns all columns | Project only needed columns |
| `sort` + `take` without filter | Sorts millions of rows | Filter/aggregate first |
| Repeated `let` subquery | Re-executes each use | Wrap with `materialize()` |

**Before (slow):**
```kql
SecurityEvent
| join kind=inner (SigninLogs) on $left.Account == $right.UserPrincipalName
| where EventID == 4625
| where TargetAccount contains "admin"
| project *
```

**After (fast):**
```kql
SecurityEvent
| where TimeGenerated > ago(1d) and EventID == 4625
| where TargetAccount has "admin"
| project TimeGenerated, Computer, TargetAccount, IpAddress, LogonType
| join kind=inner (
    SigninLogs | where TimeGenerated > ago(1d) | project UserPrincipalName, IPAddress
) on $left.TargetAccount == $right.UserPrincipalName
```

### Materialized Views

Pre-compute frequent aggregations for dashboards and scheduled rules:

```kql
.create materialized-view SigninFailureSummary on table SigninLogs {
    SigninLogs
    | where ResultType != 0
    | summarize FailureCount = count(), DistinctIPs = dcount(IPAddress)
        by UserPrincipalName, ResultType, bin(TimeGenerated, 1h)
}
```

### Summary Rules

For high-volume tables (>10 GB/day), summary rules aggregate into compact tables:

```kql
// Summary rule output table for firewall denies
CommonSecurityLog
| where DeviceAction == "Deny"
| summarize DenyCount = count(), DistinctSources = dcount(SourceIP)
    by bin(TimeGenerated, 1h), SourceIP, DestinationIP, DestinationPort
```

### Query Best Practices Checklist

- [ ] Time filter is the FIRST filter clause
- [ ] `has`/`has_cs` instead of `contains` for word matching
- [ ] Both `join` sides filtered before the join
- [ ] `project` explicitly lists only needed columns
- [ ] `materialize()` wraps any `let` used more than once
- [ ] No `search *` or `find` in production queries
- [ ] Tested with `set truncationmaxrecords=10` during development

## API Wrapper Optimization

### Connection Pooling

```powershell
function Get-SecOpsHttpClient {
    [CmdletBinding()]
    param([string]$BaseUri)
    $key = "SecOps_HttpClient_$BaseUri"
    if (-not $script:HttpClients) { $script:HttpClients = @{} }
    if (-not $script:HttpClients[$key]) {
        $handler = [System.Net.Http.HttpClientHandler]::new()
        $handler.MaxConnectionsPerServer = 10
        $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip
        $client = [System.Net.Http.HttpClient]::new($handler)
        $client.BaseAddress = [Uri]$BaseUri
        $client.Timeout = [TimeSpan]::FromSeconds(30)
        $script:HttpClients[$key] = $client
    }
    return $script:HttpClients[$key]
}
```

### Batch API Calls

```powershell
function Invoke-GraphBatchRequest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][array]$Requests)
    $allResponses = @()
    # Graph supports up to 20 requests per $batch call
    for ($i = 0; $i -lt $Requests.Count; $i += 20) {
        $batch = $Requests[$i..([Math]::Min($i + 19, $Requests.Count - 1))]
        $body = @{ requests = $batch } | ConvertTo-Json -Depth 5
        $response = Invoke-SecOpsRestMethod -Uri "https://graph.microsoft.com/v1.0/`$batch" `
            -Method POST -Body $body -ContentType "application/json"
        if ($response.ok) { $allResponses += ($response.data | ConvertFrom-Json).responses }
    }
    return New-SecOpsResult -Ok $true -Data $allResponses
}
```

### Response Caching (TTL-Based)

```powershell
function Get-CachedApiResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CacheKey,
        [Parameter(Mandatory)][scriptblock]$FetchBlock,
        [int]$TTLSeconds = 300
    )
    if (-not $script:ApiCache) { $script:ApiCache = @{} }
    $cached = $script:ApiCache[$CacheKey]
    if ($cached -and ((Get-Date) - $cached.Timestamp).TotalSeconds -lt $TTLSeconds) {
        Write-Verbose "Cache HIT: $CacheKey"
        return $cached.Data
    }
    $result = & $FetchBlock
    $script:ApiCache[$CacheKey] = @{ Data = $result; Timestamp = Get-Date }
    return $result
}

# Usage: cache incident list for 2 minutes
$incidents = Get-CachedApiResponse -CacheKey "Incidents_Active" -TTLSeconds 120 -FetchBlock {
    Get-SecOpsIncident -Status Active
}
```

## Rate Limiter Tuning

### Monitoring Throttle Events

```powershell
function Get-ThrottleMetrics {
    [CmdletBinding()]
    param([int]$HoursBack = 24)
    $throttles = Get-SecOpsAuditLog -Since (Get-Date).AddHours(-$HoursBack) |
        Where-Object { $_.StatusCode -eq 429 }
    $summary = $throttles | Group-Object ApiSurface | ForEach-Object {
        [PSCustomObject]@{
            API = $_.Name; ThrottleCount = $_.Count
            AvgRetryAfterSec = [math]::Round(($_.Group | Measure-Object RetryAfterSeconds -Average).Average, 1)
        }
    }
    $summary | Format-Table -AutoSize
    return New-SecOpsResult -Ok $true -Data $summary
}
```

### Tier Priority Configuration

```powershell
$tierConfig = @{
    Critical = @{ Weight = 10; BurstAllowed = $true; MaxQueueDepth = 0 }    # IR — never throttle
    High     = @{ Weight = 5;  BurstAllowed = $true; MaxQueueDepth = 10 }   # Active investigations
    Normal   = @{ Weight = 2;  BurstAllowed = $false; MaxQueueDepth = 50 }  # Scheduled automation
    Low      = @{ Weight = 1;  BurstAllowed = $false; MaxQueueDepth = 200 } # Background enrichment
}
```

### Queue Depth Monitoring

```powershell
function Watch-RateLimiterHealth {
    [CmdletBinding()]
    param([int]$IntervalSeconds = 30, [int]$QueueAlertThreshold = 100)
    while ($true) {
        $status = Get-SecOpsRateLimiterStatus
        foreach ($api in $status.Keys) {
            $q = $status[$api]
            $icon = if ($q.QueueDepth -gt $QueueAlertThreshold) {"🔴"} elseif ($q.QueueDepth -gt 50) {"🟡"} else {"🟢"}
            Write-Host "$icon $api — Queue: $($q.QueueDepth) | Rate: $($q.CurrentRPS)/$($q.MaxRPS) RPS"
        }
        Start-Sleep -Seconds $IntervalSeconds
    }
}
```

## MCP Server Optimization

### Tool Response Caching

Cache slowly-changing MCP tool responses (workspace lists, table schemas):

```powershell
$mcpToolCache = @{}
function Invoke-MCPToolWithCache {
    [CmdletBinding()]
    param([string]$ToolName, [hashtable]$Parameters, [int]$CacheTTLSeconds = 60)
    $cacheKey = "$ToolName|$(($Parameters.GetEnumerator() | Sort-Object Key | ForEach-Object {"$($_.Key)=$($_.Value)"}) -join '&')"
    $cached = $mcpToolCache[$cacheKey]
    if ($cached -and ((Get-Date) - $cached.Time).TotalSeconds -lt $CacheTTLSeconds) { return $cached.Result }
    $result = & "Invoke-$ToolName" @Parameters
    $mcpToolCache[$cacheKey] = @{ Result = $result; Time = Get-Date }
    return $result
}
```

### Connection Health & Memory

```powershell
function Test-MCPConnectionHealth {
    @(
        @{ Name = "Sentinel"; Test = { Get-SentinelContext } }
        @{ Name = "DefenderXDR"; Test = { Get-AzAccessToken -ResourceUrl "https://api.security.microsoft.com" } }
        @{ Name = "Graph"; Test = { Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" } }
    ) | ForEach-Object {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try { $null = & $_.Test; $sw.Stop()
            [PSCustomObject]@{ Connection = $_.Name; Status = "✅"; LatencyMs = $sw.ElapsedMilliseconds }
        } catch { [PSCustomObject]@{ Connection = $_.Name; Status = "❌"; Error = $_.Exception.Message } }
    } | Format-Table -AutoSize
}
```

## Cost Optimization

### Commitment Tier Analysis

```kql
Usage
| where TimeGenerated > ago(90d) and IsBillable == true
| summarize DailyGB = sum(Quantity) / 1024.0 by bin(TimeGenerated, 1d)
| summarize AvgDailyGB = avg(DailyGB), P50DailyGB = percentile(DailyGB, 50),
    P95DailyGB = percentile(DailyGB, 95)
| extend RecommendedTier = case(
    P50DailyGB >= 5000, "5000 GB/day", P50DailyGB >= 1000, "1000 GB/day",
    P50DailyGB >= 500, "500 GB/day", P50DailyGB >= 200, "200 GB/day",
    P50DailyGB >= 100, "100 GB/day", "Pay-as-you-go")
```

### Data Tier Migration Candidates

| Criteria | Analytics Tier | Basic Logs | Sentinel data lake |
|---|---|---|---|
| Query frequency | Detection rules, active hunting | Occasionally queried | Rarely queried (search-only) |
| Cost | ~$2.76/GB | ~$0.50/GB | ~$0.75/GB |
| Query cost | Included | $0.006/GB scanned | $0.006/GB scanned |
| KQL support | Full | Limited | Search-only |
| Examples | SecurityEvent, SigninLogs | ContainerLog, AppTraceEvents | VPC Flow Logs, verbose telemetry, long-term compliance |

```powershell
function Get-TierMigrationCandidates {
    [CmdletBinding()]
    param([int]$LookbackDays = 30, [double]$MinDailyGB = 1.0, [int]$MaxQueryCount = 5)
    $ingestion = Invoke-SecOpsQuery -Query "Usage | where TimeGenerated > ago(${LookbackDays}d) and IsBillable | summarize DailyGB = round(avg(Quantity / 1024.0), 2) by DataType | where DailyGB > $MinDailyGB"
    $queryFreq = Invoke-SecOpsQuery -Query "LAQueryLogs | where TimeGenerated > ago(${LookbackDays}d) | extend Tables = extract_all(@'(\w+)\s*\|', RequestBody) | mv-expand Table = Tables to typeof(string) | summarize QueryCount = count() by Table"
    $ingestion | ForEach-Object {
        $queries = ($queryFreq | Where-Object Table -eq $_.DataType).QueryCount
        if (-not $queries) { $queries = 0 }
        [PSCustomObject]@{
            Table = $_.DataType; DailyGB = $_.DailyGB; QueryCount = $queries
            MonthlySavings = [math]::Round($_.DailyGB * 30 * 2.26, 0)
            Recommendation = if ($queries -le $MaxQueryCount) { "Move to Basic" } else { "Keep Analytics" }
        }
    } | Where-Object Recommendation -eq "Move to Basic" | Sort-Object MonthlySavings -Descending | Format-Table -AutoSize
}
```

## PowerShell Performance Measurement

```powershell
function Measure-KQLPerformance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [int]$Iterations = 3,
        [string]$WorkspaceName = (Get-SecOpsConfig).PrimaryWorkspace
    )
    $results = for ($i = 1; $i -le $Iterations; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $response = Invoke-SecOpsQuery -Query $Query -WorkspaceName $WorkspaceName -IncludeStats
        $sw.Stop()
        [PSCustomObject]@{ Iteration = $i; DurationMs = $sw.ElapsedMilliseconds; RowCount = $response.Data.Count }
    }
    $results | Format-Table -AutoSize
    $avg = [math]::Round(($results.DurationMs | Measure-Object -Average).Average, 0)
    Write-Host "Summary: Avg=${avg}ms across $Iterations runs" -ForegroundColor Cyan
    return New-SecOpsResult -Ok $true -Data @{ Runs = $results; AvgMs = $avg }
}
```

## Quick Reference

| Function | Purpose |
|---|---|
| `Measure-KQLPerformance` | Benchmark KQL queries with stats |
| `Get-ThrottleMetrics` | Throttle event analysis |
| `Watch-RateLimiterHealth` | Live queue depth monitoring |
| `Get-SecOpsHttpClient` | Reusable HTTP client pool |
| `Invoke-GraphBatchRequest` | Graph API request batching |
| `Get-CachedApiResponse` | TTL-based response cache |
| `Get-TierMigrationCandidates` | Basic/Sentinel data lake vs Analytics tier analysis |
| `Test-MCPConnectionHealth` | MCP connection diagnostics |
| `Invoke-MCPToolWithCache` | MCP tool response caching |
