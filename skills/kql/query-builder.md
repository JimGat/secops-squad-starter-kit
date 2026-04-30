---
title: KQL Query Builder — Templates, Validation & Optimization
category: kql
difficulty: advanced
mitre_attack:
  - T1059      # Command and Scripting Interpreter
  - T1078      # Valid Accounts
  - T1110      # Brute Force
  - T1566      # Phishing
  - T1048      # Exfiltration Over Alternative Protocol
products:
  - Microsoft Sentinel
  - Microsoft Defender XDR
  - Azure Data Explorer
  - Azure Monitor Log Analytics
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# KQL Query Builder — Templates, Validation & Optimization

## Overview

Structured approach to constructing, parameterizing, validating, and optimizing KQL queries for SecOps automation. Use templates with `{{parameter}}` substitution, validate before execution, and apply optimization patterns to reduce cost and latency.

**Complements:** [threat-hunting-foundations.md](threat-hunting-foundations.md) (methodology), [defender-xdr-hunting.md](defender-xdr-hunting.md) (XDR patterns), [advanced-hunting-api.md](../detection/advanced-hunting-api.md) (API layer).

## Environment Context

Consult `.secops/` before building queries:
- `data-source-map.yaml` — Available tables, ingestion tiers (Analytics/Basic/Archive)
- `workspaces/*.yaml` — Workspace IDs for cross-workspace queries
- `environment.yaml` — Cloud environment (commercial/GCC/GCC-High) affects table availability

## Query Templates

### Template Syntax

```
// Parameters: timeRange (default: 1d), processName (required), deviceFilter (optional)
DeviceProcessEvents
| where Timestamp > ago({{timeRange:1d}})
| where FileName =~ "{{processName}}"
{{#if deviceFilter}}
| where DeviceName has "{{deviceFilter}}"
{{/if}}
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

- `{{param}}` — Required, error if missing
- `{{param:default}}` — Optional with default
- `{{#if param}}...{{/if}}` — Conditional block
- `{{#each items}}...{{/each}}` — Array iteration

### Template Resolution

```powershell
function Expand-SecOpsKqlTemplate {
    param([Parameter(Mandatory)] [string]$Template, [Parameter(Mandatory)] [hashtable]$Parameters)
    $result = $Template
    # Resolve conditional blocks
    $result = [regex]::Replace($result, '\{\{#if\s+(\w+)\}\}(.*?)\{\{/if\}\}', {
        param($m)
        if ($Parameters.ContainsKey($m.Groups[1].Value) -and $Parameters[$m.Groups[1].Value]) {
            $m.Groups[2].Value
        } else { '' }
    }, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    # Resolve iteration blocks
    $result = [regex]::Replace($result, '\{\{#each\s+(\w+)\}\}(.*?)\{\{/each\}\}', {
        param($m)
        $key = $m.Groups[1].Value; $body = $m.Groups[2].Value
        if ($Parameters[$key] -is [array]) {
            ($Parameters[$key] | ForEach-Object { $body -replace '\{\{this\}\}', $_ }) -join "`n"
        } else { '' }
    }, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    # Resolve parameterized values with defaults
    $result = [regex]::Replace($result, '\{\{(\w+)(?::([^}]*))?\}\}', {
        param($m)
        $key = $m.Groups[1].Value; $default = $m.Groups[2].Value
        if ($Parameters.ContainsKey($key)) { $Parameters[$key] }
        elseif ($default) { $default }
        else { throw "Missing required parameter: $key" }
    })
    return $result.Trim()
}
```

### Pre-Built Templates

#### Login Anomaly Detection

```
// Parameters: timeRange, failureThreshold (default: 10), successAfterFailure (default: true)
let threshold = {{failureThreshold:10}};
SigninLogs
| where TimeGenerated > ago({{timeRange:1d}})
| where ResultType != 0
| summarize FailureCount = count(), DistinctIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 10) by UserPrincipalName, bin(TimeGenerated, 1h)
| where FailureCount >= threshold
{{#if successAfterFailure}}
| join kind=inner (
    SigninLogs | where TimeGenerated > ago({{timeRange:1d}}) | where ResultType == 0
    | project SuccessTime = TimeGenerated, UserPrincipalName, SuccessIP = IPAddress
) on UserPrincipalName
| where SuccessTime between (TimeGenerated .. (TimeGenerated + 1h))
{{/if}}
```

#### Suspicious Process Creation

```
// Parameters: timeRange, targetProcesses (array), parentExclusions (array, optional)
DeviceProcessEvents
| where Timestamp > ago({{timeRange:1d}})
| where FileName in~ ({{#each targetProcesses}}"{{this}}"{{/each}})
{{#if parentExclusions}}
| where InitiatingProcessFileName !in~ ({{#each parentExclusions}}"{{this}}"{{/each}})
{{/if}}
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

#### Network Connection Monitoring

```
// Parameters: timeRange, minBytesSent (default: 10000000), excludedDomains (optional)
DeviceNetworkEvents
| where Timestamp > ago({{timeRange:1d}})
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
{{#if excludedDomains}}
| where not(RemoteUrl has_any ({{#each excludedDomains}}"{{this}}"{{/each}}))
{{/if}}
| summarize TotalBytesSent = sum(SentBytes), ConnectionCount = count(),
    Urls = make_set(RemoteUrl, 10) by DeviceName, RemoteIP, bin(Timestamp, 1h)
| where TotalBytesSent > {{minBytesSent:10000000}}
```

### Template Composition

```powershell
$baseTemplate = @"
// Hunt: {{huntName}} | MITRE: {{mitreTechnique}}
{{queryBody}}
| project-reorder Timestamp, DeviceName, AccountName
| sort by Timestamp desc | take {{maxResults:1000}}
"@

$composed = Expand-SecOpsKqlTemplate -Template $baseTemplate -Parameters @{
    huntName = "Encoded PowerShell"; mitreTechnique = "T1059.001"; maxResults = "500"
    queryBody = "DeviceProcessEvents`n| where Timestamp > ago({{timeRange}})`n| where FileName in~ ('powershell.exe','pwsh.exe')`n| where ProcessCommandLine has_any ('-enc','-EncodedCommand')"
}
```

## Parameterized Queries

### Time Range Parameters

```kql
// Dynamic relative — preferred for detection rules
| where TimeGenerated > ago(1h)
// Fixed datetime — forensic investigation with known bounds
| where TimeGenerated between (datetime(2026-04-29T08:00:00Z) .. datetime(2026-04-30T08:00:00Z))
```

### Entity & Threshold Parameters

```powershell
# Entity-scoped query
$query = Expand-SecOpsKqlTemplate -Template $template -Parameters @{
    device = "WKS-FINANCE-001"; user = "jsmith@contoso.com"; fileHash = "a1b2c3..."
}

# Environment-aware thresholds from .secops/
$alertConfig = Get-SecOpsConfig -File 'alerting/routing.yaml'
$params = @{
    failedLoginThreshold = $alertConfig.thresholds.failed_logins ?? 10
    dataExfilMB = $alertConfig.thresholds.data_exfil_mb ?? 100
}
```

## Query Validation

### Syntax Validation

Use `lib/kql-validator/` for offline syntax checks:

```powershell
function Test-SecOpsKqlSyntax {
    param([Parameter(Mandatory)] [string]$Query)
    $validatorPath = Join-Path $PSScriptRoot '../../lib/kql-validator'
    $result = node -e "const v=require('$($validatorPath -replace '\\','/')');console.log(JSON.stringify(v.validate(\`$($Query -replace '`','``')\`)));"
    return $result | ConvertFrom-Json
}
```

### Performance Validation

```powershell
function Test-SecOpsKqlPerformance {
    param([Parameter(Mandatory)] [string]$Query)
    $warnings = @()

    if ($Query -notmatch 'ago\(' -and $Query -notmatch 'between\s*\(') {
        $warnings += @{ Severity = 'Critical'; Rule = 'NO_TIME_FILTER'; Message = 'No time constraint — add ago() or between()' }
    }
    if ($Query -notmatch '\|\s*project\b') {
        $warnings += @{ Severity = 'Warning'; Rule = 'NO_PROJECTION'; Message = 'No projection — use project to limit columns' }
    }
    if ($Query -match '\bcontains\b') {
        $warnings += @{ Severity = 'Warning'; Rule = 'CONTAINS_OVER_HAS'; Message = 'contains is slower than has — use has for token matching' }
    }
    if ($Query -match '(?s)\|\s*join\b.*?\|\s*where\b' -and $Query -notmatch '(?s)\|\s*where\b.*?\|\s*join\b') {
        $warnings += @{ Severity = 'Warning'; Rule = 'JOIN_BEFORE_WHERE'; Message = 'Filter before join for better performance' }
    }
    if ($Query -match '\bmatches\s+regex\b') {
        $warnings += @{ Severity = 'Info'; Rule = 'REGEX_USAGE'; Message = 'matches regex is slowest — consider has or startswith' }
    }

    $score = if ($warnings.Count -eq 0) { 'Good' } elseif ($warnings | Where-Object { $_.Severity -eq 'Critical' }) { 'Critical' } else { 'NeedsReview' }
    return @{ Warnings = $warnings; Score = $score }
}
```

### Security Validation

```powershell
function Test-SecOpsKqlInjection {
    param([Parameter(Mandatory)] [string]$Value, [string]$ParamName = 'unknown')
    $dangerous = @(';\s*(drop|alter|create|delete)\b', '\|\s*invoke\b', 'evaluate\s+', 'externaldata\s*\(', 'cluster\s*\(')
    foreach ($p in $dangerous) {
        if ($Value -match $p) { throw "KQL injection risk in '$ParamName': matched '$p'" }
    }
    return $Value -replace "'", "''"  # Escape quotes
}
```

## Query Optimization

### Filter-First Patterns

```kql
// ❌ BAD: join then filter
DeviceProcessEvents
| join kind=inner DeviceNetworkEvents on DeviceId
| where Timestamp > ago(1h)

// ✅ GOOD: filter then join, project early
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceId, DeviceName, ProcessCommandLine
| join kind=inner (
    DeviceNetworkEvents | where Timestamp > ago(1h) | project DeviceId, RemoteIP, RemoteUrl
) on DeviceId
```

### Aggregation Before Join

```kql
// ✅ Summarize each side first, then join
let interactive = SigninLogs | where TimeGenerated > ago(1d) | summarize ICount = count() by UserPrincipalName;
let nonInteractive = AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(1d) | summarize NCount = count() by UserPrincipalName;
interactive | join kind=fullouter nonInteractive on UserPrincipalName
```

### Materialize for Multi-Use Subqueries

```kql
// ✅ Cache subquery result with materialize()
let suspiciousUsers = materialize(
    SigninLogs | where TimeGenerated > ago(1d) | where ResultType != 0
    | summarize Failures = count() by UserPrincipalName | where Failures > 10
);
suspiciousUsers | join kind=inner (SigninLogs | where ResultType == 0) on UserPrincipalName
| union (suspiciousUsers | join kind=inner AADNonInteractiveUserSignInLogs on UserPrincipalName)
```

### Partition and Shuffle

```kql
// partition — per-device analysis
DeviceProcessEvents
| where Timestamp > ago(7d)
| partition by DeviceName (summarize Count = count() by DeviceName | where Count > 1000)

// shuffle — distributed join (ADX/Fabric only)
DeviceProcessEvents | where Timestamp > ago(1d)
| join hint.strategy=shuffle (DeviceNetworkEvents | where Timestamp > ago(1d)) on DeviceId
```

### String Operator Performance

| Operator | Speed | Use Case |
|----------|-------|----------|
| `==` / `=~` | ★★★★★ | Exact match |
| `has` / `has_any` | ★★★★☆ | Whole-token match |
| `startswith` | ★★★★☆ | Prefix match |
| `endswith` | ★★★☆☆ | Suffix match |
| `contains` | ★★☆☆☆ | Substring (no boundary) |
| `matches regex` | ★☆☆☆☆ | Full regex — last resort |

## Cross-Platform Query Patterns

### Log Analytics vs ADX Differences

| Feature | Log Analytics | ADX/Fabric |
|---------|--------------|------------|
| `materialized_view()` | ❌ | ✅ |
| `shuffle` hint | ❌ Ignored | ✅ Distributed |
| `workspace()` | ✅ Cross-workspace | ❌ Use `cluster()` |
| `adx()` proxy | ✅ Proxy to ADX | ❌ Native |
| Max rows | 30K portal / 500K API | 500K |

### Advanced Hunting Schema Quirks

```kql
// Timestamp, not TimeGenerated
DeviceProcessEvents | where Timestamp > ago(1h)  // ✅
// AccountUpn, not UserPrincipalName
IdentityLogonEvents | where AccountUpn == "user@contoso.com"  // ✅
```

### Cross-Workspace + ADX Union

```kql
// Multi-workspace union
let prodEvents = workspace("prod-sentinel").SecurityEvent | where TimeGenerated > ago(1h) | where EventID == 4625;
let devEvents = workspace("dev-sentinel").SecurityEvent | where TimeGenerated > ago(1h) | where EventID == 4625;
union prodEvents, devEvents | summarize count() by Computer, Account

// Sentinel → ADX for long-term correlation
let recent = SecurityEvent | where TimeGenerated > ago(1d) | where EventID == 4625;
let historical = adx("https://secopsadx.eastus.kusto.windows.net/SecurityDB").SecurityEvents_Historical
    | where Timestamp > ago(90d) and Timestamp < ago(1d) | where EventId == 4625;
union recent, historical | summarize count() by Computer, bin(TimeGenerated, 1d)
```

### Multi-Source Normalization

```kql
let endpointLogons = DeviceLogonEvents | where Timestamp > ago(1d)
    | project Timestamp, Source = "MDE", User = AccountName, Device = DeviceName, IP = RemoteIP;
let entraLogons = SigninLogs | where TimeGenerated > ago(1d)
    | project Timestamp = TimeGenerated, Source = "Entra", User = UserPrincipalName, Device = tostring(DeviceDetail.displayName), IP = IPAddress;
let identityLogons = IdentityLogonEvents | where Timestamp > ago(1d)
    | project Timestamp, Source = "MDI", User = AccountUpn, Device = DeviceName, IP = IPAddress;
union endpointLogons, entraLogons, identityLogons
| summarize Sources = make_set(Source), Count = count() by User, IP, bin(Timestamp, 1h)
| where array_length(Sources) > 1
```

## PowerShell Integration

```powershell
function Invoke-SecOpsKqlQuery {
    param(
        [Parameter(Mandatory, ParameterSetName='Direct')] [string]$Query,
        [Parameter(Mandatory, ParameterSetName='Template')] [string]$TemplatePath,
        [Parameter(ParameterSetName='Template')] [hashtable]$Parameters = @{},
        [ValidateSet('Sentinel','MDE','XDR','ADX')] [string]$Target = 'Sentinel',
        [switch]$Validate
    )
    if ($TemplatePath) {
        $Query = Expand-SecOpsKqlTemplate -Template (Get-Content $TemplatePath -Raw) -Parameters $Parameters
    }
    if ($Validate) {
        $perf = Test-SecOpsKqlPerformance -Query $Query
        if ($perf.Score -eq 'Critical') { Write-Error "Critical: $($perf.Warnings[0].Message)"; return }
        $perf.Warnings | ForEach-Object { Write-Warning "[$($_.Severity)] $($_.Message)" }
    }
    switch ($Target) {
        'Sentinel' {
            $ws = Get-SecOpsConfig -File 'workspaces/primary.yaml'
            Invoke-SecOpsRestMethod -Method POST -Uri "https://api.loganalytics.io/v1/workspaces/$($ws.workspace_id)/query" -Body @{ query = $Query } -ApiType LogAnalytics
        }
        'XDR'  { Invoke-SecOpsRestMethod -Method POST -Uri "https://api.security.microsoft.com/api/advancedhunting/run" -Body @{ Query = $Query } -ApiType XDR }
        'MDE'  { Invoke-SecOpsRestMethod -Method POST -Uri "https://api.securitycenter.microsoft.com/api/advancedqueries/run" -Body @{ Query = $Query } -ApiType MDE }
        'ADX'  {
            $cfg = Get-SecOpsConfig -File 'environment.yaml'
            Invoke-SecOpsRestMethod -Method POST -Uri "$($cfg.adx_cluster_uri)/v1/rest/query" -Body @{ db = $cfg.adx_database; csl = $Query } -ApiType ADX
        }
    }
}

# Auto-route query to correct target based on table
function Get-SecOpsQueryTarget {
    param([Parameter(Mandatory)] [string]$TableName)
    $map = Get-SecOpsConfig -File 'data-sources/data-source-map.yaml'
    if (-not $map) { Write-Warning "No data-source-map.yaml. Default: Sentinel."; return 'Sentinel' }
    $source = $map.sources | Where-Object { $TableName -in $_.tables }
    switch ($source.platform) {
        'sentinel'     { 'Sentinel' }
        'defender_xdr' { 'XDR' }
        'adx'          { 'ADX' }
        default        { 'Sentinel' }
    }
}
```

## Related Skills

- [threat-hunting-foundations.md](threat-hunting-foundations.md) — Hunting methodology
- [defender-xdr-hunting.md](defender-xdr-hunting.md) — XDR table patterns
- [cross-workspace-queries.md](cross-workspace-queries.md) — Multi-workspace federation
- [advanced-hunting-api.md](../detection/advanced-hunting-api.md) — API endpoints for execution
- [sentinel-analytics-rules.md](sentinel-analytics-rules.md) — Converting queries into rules
