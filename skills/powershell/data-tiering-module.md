---
title: Data Tiering Submodule
category: powershell
difficulty: intermediate
mitre_attack:
  - T1485  # Data Destruction (retention policy impact)
  - T1565  # Data Manipulation (tier changes affect query availability)
products:
  - Azure Monitor Log Analytics
  - Microsoft Sentinel
  - Azure Data Explorer
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# Data Tiering Submodule

## Overview

The Data Tiering submodule manages Log Analytics table tiers, retention policies, and summary rules — the primary cost optimization levers for Sentinel deployments. It wraps the `Microsoft.OperationalInsights` resource provider to control where data lives, how long it's retained, and how to reduce costs while maintaining detection capability.

Use this skill when:
- Switching tables between Analytics, Basic, Auxiliary, and Archive tiers
- Configuring per-table retention and archive policies
- Creating summary rules for cost-effective long-term aggregation
- Auditing current table configurations and costs
- Implementing data tiering decisions from `.secops/data-sources/data-source-map.yaml`

## Prerequisites

| Requirement | Detail |
|---|---|
| **Az.OperationalInsights** | `Install-Module Az.OperationalInsights` |
| **Permissions** | `Log Analytics Contributor` for table management |
| **Permissions** | `Microsoft Sentinel Contributor` for Sentinel-managed tables |
| **Workspace** | Log Analytics workspace with Sentinel enabled |

## Data Tier Reference

| Tier | KQL Capability | Cost (Relative) | Retention | Use Case |
|---|---|---|---|---|
| **Analytics** | Full KQL (join, summarize, etc.) | Highest | 30-730 days interactive + 12yr archive | Active hunting, detection rules, dashboards |
| **Basic** | Search, `_BilledSize`, time filters only | ~65% cheaper | 8 days interactive + 30 days search | High-volume, low-query data (firewall, proxy) |
| **Auxiliary** | Search-only, very limited | ~85% cheaper | 30 days | Verbose telemetry, debug logs |
| **Archive** | Must restore before querying | Storage-only cost | Up to 12 years | Compliance, forensics, cold storage |

### Tier Decision Framework

```
Is the table used in analytics rules or frequent hunting?
├── YES → Analytics tier
└── NO → Is the data queried regularly (weekly+)?
    ├── YES → Is full KQL needed (joins, summarize)?
    │   ├── YES → Analytics tier
    │   └── NO → Basic tier
    └── NO → Is the data needed for compliance retention?
        ├── YES → Archive tier (with summary rule for metrics)
        └── NO → Auxiliary tier (or consider not ingesting)
```

## Key Functions

### Get-SecOpsTableInventory — Audit Table Configuration

```powershell
function Get-SecOpsTableInventory {
    <#
    .SYNOPSIS
        Lists all tables in a workspace with tier, retention, and estimated cost.
    .DESCRIPTION
        Queries the workspace tables API and enriches with data-source-map.yaml
        context. Use this to audit current configuration before making tier changes.
    .EXAMPLE
        Get-SecOpsTableInventory | Sort-Object DailyGB -Descending | Format-Table
    .EXAMPLE
        Get-SecOpsTableInventory -Tier 'Analytics' | Where-Object DailyGB -gt 5
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('Analytics', 'Basic', 'Auxiliary', 'Archive')]
        [string]$Tier,

        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName

    $uri = "https://management.azure.com/subscriptions/$($ctx.SubscriptionId)" +
           "/resourceGroups/$($ctx.ResourceGroup)" +
           "/providers/Microsoft.OperationalInsights/workspaces/$($ctx.WorkspaceName)" +
           "/tables?api-version=2023-09-01"

    $token = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ 'Authorization' = "Bearer $token" }

    $result = Invoke-SecOpsRestMethod -Uri $uri -Headers $headers `
        -OperationName 'Get-SecOpsTableInventory'

    if (-not $result.Ok) { return $result }

    # Load data source map for enrichment
    $dsMap = $script:SecOpsContext.DataSourceMap

    $tables = $result.Data.value | ForEach-Object {
        $tableName = $_.name
        $dsEntry = $dsMap.sources[$tableName]

        [PSCustomObject]@{
            TableName         = $tableName
            Plan              = $_.properties.plan                          # Analytics | Basic | Auxiliary
            RetentionDays     = $_.properties.retentionInDays
            ArchiveRetention  = $_.properties.totalRetentionInDays
            ProvisioningState = $_.properties.provisioningState
            DailyGB           = if ($dsEntry) { $dsEntry.daily_gb } else { $null }
            IngestionMethod   = if ($dsEntry) { $dsEntry.ingestion_method } else { 'unknown' }
            InDataSourceMap   = [bool]$dsEntry
        }
    }

    if ($Tier) {
        $tables = $tables | Where-Object { $_.Plan -eq $Tier }
    }

    return New-SecOpsResult -Success -Data ($tables | Sort-Object TableName)
}
```

### Set-SecOpsTableTier — Change Table Tier

```powershell
function Set-SecOpsTableTier {
    <#
    .SYNOPSIS
        Changes the data plan (tier) of a Log Analytics table.
    .DESCRIPTION
        Switches a table between Analytics, Basic, and Auxiliary tiers.
        IMPORTANT: Changing to Basic/Auxiliary removes join/summarize capability.
        Verify no analytics rules depend on the table before downgrading.
    .EXAMPLE
        Set-SecOpsTableTier -TableName 'Syslog' -Tier 'Basic' -WorkspaceName 'sentinel-prod'
    .EXAMPLE
        Set-SecOpsTableTier -TableName 'AWSCloudTrail' -Tier 'Basic'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$TableName,

        [Parameter(Mandatory)]
        [ValidateSet('Analytics', 'Basic', 'Auxiliary')]
        [string]$Tier,

        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName

    # Safety check: warn if downgrading a table used in analytics rules
    if ($Tier -in @('Basic', 'Auxiliary')) {
        Write-Warning @"
Changing '$TableName' to $Tier tier will disable join/summarize KQL operations.
Verify no Sentinel analytics rules reference this table before proceeding.
Use -WhatIf to preview the change without applying it.
"@
    }

    if (-not $PSCmdlet.ShouldProcess("$TableName -> $Tier", 'Change Table Tier')) { return }

    $body = @{
        properties = @{
            plan = $Tier
        }
    }

    $uri = "https://management.azure.com/subscriptions/$($ctx.SubscriptionId)" +
           "/resourceGroups/$($ctx.ResourceGroup)" +
           "/providers/Microsoft.OperationalInsights/workspaces/$($ctx.WorkspaceName)" +
           "/tables/$TableName" +
           "?api-version=2023-09-01"

    $token = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ 'Authorization' = "Bearer $token" }

    $result = Invoke-SecOpsRestMethod -Uri $uri -Method PATCH -Body $body `
        -Headers $headers -OperationName "Set-SecOpsTableTier ($TableName -> $Tier)"

    if ($result.Ok) {
        Write-Verbose "Table '$TableName' changed to $Tier tier"
    }

    return $result
}
```

### Set-SecOpsRetentionPolicy — Configure Retention

```powershell
function Set-SecOpsRetentionPolicy {
    <#
    .SYNOPSIS
        Sets retention and archive policies for a Log Analytics table.
    .DESCRIPTION
        Configures interactive retention (hot data, queryable with full KQL)
        and total retention (hot + archive). Archive data must be restored
        before querying.
    .EXAMPLE
        Set-SecOpsRetentionPolicy -TableName 'SecurityEvent' -InteractiveDays 90 -TotalDays 730
    .EXAMPLE
        Set-SecOpsRetentionPolicy -TableName 'Syslog' -InteractiveDays 30 -TotalDays 365
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$TableName,

        [Parameter(Mandatory)]
        [ValidateRange(4, 730)]
        [int]$InteractiveDays,

        [ValidateRange(4, 4383)]  # Up to ~12 years
        [int]$TotalDays,

        [string]$WorkspaceName
    )

    if ($TotalDays -and $TotalDays -lt $InteractiveDays) {
        return New-SecOpsResult -Error "TotalDays ($TotalDays) must be >= InteractiveDays ($InteractiveDays)" `
            -ErrorCode 'InvalidRetention'
    }

    # Check compliance minimums
    $compliancePath = Join-Path $script:SecOpsContext.SecOpsPath 'compliance' 'requirements.yaml'
    if (Test-Path $compliancePath) {
        $compliance = Get-Content $compliancePath -Raw | ConvertFrom-Yaml
        if ($compliance.retention -and $compliance.retention.minimum_days) {
            $minDays = $compliance.retention.minimum_days
            if ($InteractiveDays -lt $minDays) {
                Write-Warning "Compliance requires minimum $minDays days retention. Setting InteractiveDays to $minDays."
                $InteractiveDays = $minDays
            }
        }
    }

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName

    if (-not $PSCmdlet.ShouldProcess(
        "$TableName: interactive=$InteractiveDays, total=$TotalDays days",
        'Set Retention Policy')) { return }

    $body = @{
        properties = @{
            retentionInDays      = $InteractiveDays
            totalRetentionInDays = if ($TotalDays) { $TotalDays } else { $InteractiveDays }
        }
    }

    $uri = "https://management.azure.com/subscriptions/$($ctx.SubscriptionId)" +
           "/resourceGroups/$($ctx.ResourceGroup)" +
           "/providers/Microsoft.OperationalInsights/workspaces/$($ctx.WorkspaceName)" +
           "/tables/$TableName" +
           "?api-version=2023-09-01"

    $token = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ 'Authorization' = "Bearer $token" }

    return Invoke-SecOpsRestMethod -Uri $uri -Method PATCH -Body $body `
        -Headers $headers -OperationName "Set-SecOpsRetentionPolicy ($TableName)"
}
```

### New-SecOpsSummaryRule — Create a Summary Rule

```powershell
function New-SecOpsSummaryRule {
    <#
    .SYNOPSIS
        Creates a summary rule that aggregates data into a smaller table.
    .DESCRIPTION
        Summary rules run a KQL query on a schedule and write results to a
        destination table. Use them to keep aggregated metrics from high-volume
        tables after downgrading the source to Basic or Auxiliary tier.
    .EXAMPLE
        New-SecOpsSummaryRule -Name 'SyslogHourlySummary' `
            -Description 'Hourly summary of Syslog by facility and severity' `
            -Query 'Syslog | summarize Count=count(), AvgSize=avg(_BilledSize) by Facility, SeverityLevel, bin(TimeGenerated, 1h)' `
            -DestinationTable 'SyslogSummary_CL' `
            -BinSize 'PT1H'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Description = '',

        [Parameter(Mandatory)]
        [string]$Query,

        [Parameter(Mandatory)]
        [string]$DestinationTable,

        [ValidateSet('PT1H', 'PT6H', 'P1D')]
        [string]$BinSize = 'PT1H',

        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName

    if (-not $PSCmdlet.ShouldProcess("$Name -> $DestinationTable", 'Create Summary Rule')) {
        return
    }

    $body = @{
        properties = @{
            displayName      = $Name
            description      = $Description
            query            = $Query
            destinationTable = $DestinationTable
            binSize          = $BinSize
            isEnabled        = $true
        }
    }

    $uri = "https://management.azure.com/subscriptions/$($ctx.SubscriptionId)" +
           "/resourceGroups/$($ctx.ResourceGroup)" +
           "/providers/Microsoft.OperationalInsights/workspaces/$($ctx.WorkspaceName)" +
           "/providers/Microsoft.SecurityInsights/summaryRules/$([guid]::NewGuid())" +
           "?api-version=2024-03-01"

    $token = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ 'Authorization' = "Bearer $token" }

    return Invoke-SecOpsRestMethod -Uri $uri -Method PUT -Body $body `
        -Headers $headers -OperationName "New-SecOpsSummaryRule ($Name)"
}
```

## Data Tiering Workflow

### Step-by-Step: Downgrade a Table to Basic Tier

```powershell
# 1. Audit current state
$inventory = Get-SecOpsTableInventory -WorkspaceName 'sentinel-prod'
$target = $inventory.Data | Where-Object TableName -eq 'Syslog'
Write-Host "Current tier: $($target.Plan), Daily GB: $($target.DailyGB)"

# 2. Check for analytics rules that reference this table
$rules = Get-AzSentinelAlertRule -ResourceGroupName 'rg-soc' -WorkspaceName 'sentinel-prod'
$dependentRules = $rules | Where-Object { $_.Query -match 'Syslog' }
if ($dependentRules) {
    Write-Warning "Found $($dependentRules.Count) analytics rules using Syslog — review before downgrade"
    $dependentRules | Select-Object DisplayName, Severity
}

# 3. Create summary rule BEFORE downgrading
New-SecOpsSummaryRule -Name 'SyslogHourlySummary' `
    -Query 'Syslog | summarize Count=count(), AvgSize=avg(_BilledSize) by Facility, SeverityLevel, Computer, bin(TimeGenerated, 1h)' `
    -DestinationTable 'SyslogSummary_CL' -BinSize 'PT1H'

# 4. Downgrade to Basic tier
Set-SecOpsTableTier -TableName 'Syslog' -Tier 'Basic' -Confirm

# 5. Update .secops/data-sources/data-source-map.yaml
# (manual step — agent should suggest the YAML update)
```

## Cost Impact Estimates

| Table | Daily GB | Analytics/mo | Basic/mo | Savings/mo |
|---|---|---|---|---|
| Syslog | 10 GB | ~$150 | ~$53 | ~$97 (65%) |
| AWSCloudTrail | 15 GB | ~$225 | ~$79 | ~$146 (65%) |
| NetFlowLogs | 200 GB | ~$3,000 | Migrate to ADX | ~$2,700 (90%) |

*Estimates based on $4.99/GB Analytics, $1.75/GB Basic (East US 2, approximate)*

## Best Practices

1. **Summary rule first, then downgrade** — Create aggregation rules before changing tiers
2. **Audit analytics rules** — Never downgrade a table referenced in active Sentinel rules without review
3. **Compliance check** — Read `.secops/compliance/requirements.yaml` for minimum retention
4. **Update data-source-map** — After tier changes, update `.secops/data-sources/data-source-map.yaml`
5. **ADX for 100+ GB/day** — Tables above 100 GB/day should consider ADX migration, not just Basic tier
6. **WhatIf first** — Always run tier changes with `-WhatIf` before `-Confirm`
7. **Archive for compliance** — Use archive tier for data needed only for compliance/forensics

## Environment Context

Before modifying data tiers, agents MUST consult:

- **`.secops/data-sources/data-source-map.yaml`** — Current tier assignments and daily volumes
- **`.secops/data-sources/migrations.yaml`** — Active migrations that may conflict with tier changes
- **`.secops/compliance/requirements.yaml`** — Minimum retention requirements per framework
- **`.secops/workspaces/*.yaml`** — Workspace commitment tier (affects cost calculations)

## Related Skills

- `skills/log-analytics/retention-archive.md` — Detailed retention and archive patterns
- `skills/log-analytics/cost-optimization.md` — Comprehensive cost optimization strategies
- `skills/adx/migration-from-sentinel.md` — ADX migration for high-volume tables
- `skills/powershell/sentinel-module.md` — Sentinel API for analytics rule dependency checks
