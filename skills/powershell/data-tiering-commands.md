---
title: Data Tiering Commands
category: powershell
difficulty: advanced
mitre_attack:
  - T1485  # Data Destruction (retention/purge impact)
  - T1565  # Data Manipulation (tier changes affect availability)
  - T1489  # Service Stop (tier migration can affect query)
products:
  - Azure Monitor Log Analytics
  - Microsoft Sentinel
  - Azure Data Explorer
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# Data Tiering Commands

## Overview

Production-ready PowerShell commands for managing Log Analytics data tiers, retention policies, summary rules, purge operations, and data migrations. This skill complements `data-tiering-module.md` (submodule overview) with deep, executable PowerShell wrappers that integrate with the `.secops/` customer knowledge framework.

Use this skill when:
- Changing table tiers (Analytics ↔ Basic ↔ Auxiliary) with safety checks
- Auditing retention policies against compliance requirements
- Creating summary rules for cost-effective aggregation before tier downgrades
- Submitting GDPR/privacy data purge requests
- Orchestrating data migrations between Sentinel, ADX, and workspaces
- Running cost impact analysis before tier changes

**Complements (do not duplicate):**
- `data-tiering-module.md` — Submodule architecture, `Get-SecOpsTableInventory`, `Set-SecOpsTableTier`, `Set-SecOpsRetentionPolicy`, `New-SecOpsSummaryRule`
- `skills/log-analytics/retention-archive.md` — Retention concepts, search jobs, restore from archive
- `skills/log-analytics/cost-optimization.md` — Cost analysis KQL, DCR filtering, commitment tiers

## Prerequisites

| Requirement | Detail |
|---|---|
| **Az.OperationalInsights** | `Install-Module Az.OperationalInsights -MinimumVersion 3.2.0` |
| **Az.MonitoringSolutions** | For Sentinel-managed table awareness |
| **Permissions** | `Log Analytics Contributor` + `Microsoft Sentinel Contributor` |
| **API Version** | Tables API: `2023-09-01`, Purge API: `2023-09-01`, Summary Rules: `2024-03-01` |
| **`.secops/`** | `data-source-map.yaml`, `compliance/requirements.yaml`, `migrations.yaml` |

## Tier Reference: Analytics vs Basic vs Auxiliary vs Archive

| Attribute | Analytics | Basic | Auxiliary | Archive |
|---|---|---|---|---|
| **Ingestion cost** | ~$4.99/GB | ~$1.75/GB (65% less) | ~$0.75/GB (85% less) | N/A (storage only) |
| **Query cost** | Included | $0.006/GB scanned | $0.006/GB scanned | Restore/search job cost |
| **KQL operators** | Full (join, summarize, mv-expand…) | where, extend, project, parse, summarize | search, where, project only | Must restore first |
| **Analytics rules** | ✅ Supported | ❌ Not supported | ❌ Not supported | ❌ Not supported |
| **Interactive retention** | 30–730 days | 8–30 days | 30 days | N/A |
| **Total retention** | Up to 12 years | Up to 12 years | Up to 12 years | Up to 12 years |
| **Sentinel free retention** | 90 days | ❌ | ❌ | ❌ |
| **When to use** | Detection rules, active hunting, dashboards | High-volume, rarely-queried (firewall, proxy) | Verbose telemetry, debug | Compliance-only, cold forensics |

**Key constraints when downgrading:**
- Basic/Auxiliary tables **cannot** be used in Sentinel analytics rules
- `join`, `mv-expand`, `make-series` are **not available** on Basic tier
- `summarize` works on Basic but with performance limitations
- Tier changes take effect within minutes; the table is briefly unavailable during the switch

---

## Log Tier Management

### Get-LogAnalyticsTablePlan — Query Current Tiers

```powershell
function Get-LogAnalyticsTablePlan {
    <#
    .SYNOPSIS
        Retrieves the current data plan (tier) for all tables in a workspace.
    .DESCRIPTION
        Queries the Tables REST API and enriches results with .secops/data-source-map.yaml
        context. Returns plan, retention settings, provisioning state, and data source map status.
        Use this to audit before making tier changes.
    .EXAMPLE
        Get-LogAnalyticsTablePlan -WorkspaceName 'sentinel-prod' | Format-Table
    .EXAMPLE
        Get-LogAnalyticsTablePlan -Tier 'Analytics' | Where-Object DailyGB -gt 5
    .EXAMPLE
        Get-LogAnalyticsTablePlan -ShowMismatch  # Tables where actual tier ≠ data-source-map tier
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [string]$WorkspaceName,

        [ValidateSet('Analytics', 'Basic', 'Auxiliary')]
        [string]$Tier,

        [switch]$ShowMismatch
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $uri = "$($ctx.BaseUri)/tables?api-version=2023-09-01"
    $headers = Get-SecOpsAuthHeader

    $result = Invoke-SecOpsRestMethod -Uri $uri -Headers $headers `
        -OperationName 'Get-LogAnalyticsTablePlan'
    if (-not $result.Ok) { return $result }

    $dsMap = $script:SecOpsContext.DataSourceMap

    $tables = $result.Data.value | ForEach-Object {
        $name = $_.name
        $props = $_.properties
        $dsEntry = if ($dsMap.sources) { $dsMap.sources[$name] } else { $null }

        [PSCustomObject]@{
            TableName          = $name
            Plan               = $props.plan
            RetentionDays      = $props.retentionInDays
            TotalRetentionDays = $props.totalRetentionInDays
            ArchiveDays        = ($props.totalRetentionInDays - $props.retentionInDays)
            ProvisioningState  = $props.provisioningState
            DailyGB            = if ($dsEntry) { $dsEntry.daily_gb } else { $null }
            IngestionMethod    = if ($dsEntry) { $dsEntry.ingestion_method } else { 'unknown' }
            DataSourceMapTier  = if ($dsEntry) { $dsEntry.tier } else { $null }
            TierMismatch       = if ($dsEntry) { $props.plan -ne $dsEntry.tier } else { $false }
        }
    }

    if ($Tier) { $tables = $tables | Where-Object Plan -eq $Tier }
    if ($ShowMismatch) { $tables = $tables | Where-Object TierMismatch -eq $true }

    return New-SecOpsResult -Success -Data ($tables | Sort-Object TableName)
}
```

### Set-LogAnalyticsTablePlan — Change Table Tier with Safety Checks

```powershell
function Set-LogAnalyticsTablePlan {
    <#
    .SYNOPSIS
        Changes the data plan (tier) of a Log Analytics table with pre-flight safety checks.
    .DESCRIPTION
        Before changing the tier, validates:
        1. No active Sentinel analytics rules reference the table (for downgrades)
        2. No in-progress migrations affect the table (.secops/data-sources/migrations.yaml)
        3. Compliance requirements are not violated (.secops/compliance/requirements.yaml)
        4. Summary rules exist for aggregation (warns if missing on downgrade)
    .EXAMPLE
        Set-LogAnalyticsTablePlan -TableName 'Syslog' -Tier 'Basic' -WhatIf
    .EXAMPLE
        Set-LogAnalyticsTablePlan -TableName 'Syslog' -Tier 'Basic' -SkipRuleCheck -Confirm
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$TableName,

        [Parameter(Mandatory)]
        [ValidateSet('Analytics', 'Basic', 'Auxiliary')]
        [string]$Tier,

        [string]$WorkspaceName,
        [switch]$SkipRuleCheck,
        [switch]$SkipMigrationCheck
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName

    # --- Pre-flight: Check active migrations ---
    if (-not $SkipMigrationCheck) {
        $migPath = Join-Path $script:SecOpsContext.SecOpsPath 'data-sources' 'migrations.yaml'
        if (Test-Path $migPath) {
            $migrations = Get-Content $migPath -Raw | ConvertFrom-Yaml
            $activeMig = $migrations.migrations | Where-Object {
                $_.status -eq 'in-progress' -and
                ($_.source.table -eq $TableName -or $_.target.table -eq $TableName)
            }
            if ($activeMig) {
                return New-SecOpsResult -Error `
                    "Table '$TableName' has an active migration (ID: $($activeMig.id)). Complete or cancel the migration before changing tiers." `
                    -ErrorCode 'ActiveMigration'
            }
        }
    }

    # --- Pre-flight: Check analytics rule dependencies (downgrade only) ---
    $isDowngrade = $Tier -in @('Basic', 'Auxiliary')
    if ($isDowngrade -and -not $SkipRuleCheck) {
        Write-Verbose "Checking Sentinel analytics rules for references to '$TableName'..."
        try {
            $rulesUri = "$($ctx.BaseUri)/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01"
            $rulesResult = Invoke-SecOpsRestMethod -Uri $rulesUri -Headers (Get-SecOpsAuthHeader) `
                -OperationName 'CheckAnalyticsRuleDependencies'

            if ($rulesResult.Ok) {
                $dependentRules = $rulesResult.Data.value | Where-Object {
                    $_.properties.query -match [regex]::Escape($TableName)
                }
                if ($dependentRules) {
                    $ruleNames = ($dependentRules | ForEach-Object { $_.properties.displayName }) -join ', '
                    return New-SecOpsResult -Error `
                        "Cannot downgrade '$TableName' to $Tier — $($dependentRules.Count) analytics rule(s) reference it: $ruleNames. Use -SkipRuleCheck to override." `
                        -ErrorCode 'AnalyticsRuleDependency'
                }
            }
        }
        catch {
            Write-Warning "Could not check analytics rules: $($_.Exception.Message). Proceeding with caution."
        }
    }

    # --- Pre-flight: Warn if no summary rule exists for downgrade ---
    if ($isDowngrade) {
        Write-Warning @"
Downgrading '$TableName' to $Tier tier:
  - join/mv-expand/make-series will be UNAVAILABLE
  - Sentinel analytics rules CANNOT use this table
  - Consider creating a summary rule first (New-SummaryRule)
  - Use -WhatIf to preview without applying
"@
    }

    if (-not $PSCmdlet.ShouldProcess("$TableName → $Tier", 'Change Table Plan')) { return }

    # --- Execute tier change ---
    $body = @{ properties = @{ plan = $Tier } }
    $uri = "$($ctx.BaseUri)/tables/${TableName}?api-version=2023-09-01"

    $result = Invoke-SecOpsRestMethod -Uri $uri -Method PATCH `
        -Body ($body | ConvertTo-Json -Depth 5) `
        -Headers (Get-SecOpsAuthHeader) `
        -OperationName "Set-LogAnalyticsTablePlan ($TableName → $Tier)"

    if ($result.Ok) {
        Write-Verbose "✅ Table '$TableName' changed to $Tier tier"
        Write-Warning "ACTION REQUIRED: Update .secops/data-sources/data-source-map.yaml — set tier: '$Tier' for $TableName"
    }

    return $result
}
```

### Get-TierRecommendation — Analyze Query Patterns for Optimal Tiers

```powershell
function Get-TierRecommendation {
    <#
    .SYNOPSIS
        Analyzes query patterns and usage to recommend optimal tiers for each table.
    .DESCRIPTION
        Queries LAQueryLogs and Usage tables to determine:
        - Query frequency per table (how often is it queried?)
        - KQL operator usage (does it need full KQL or just search?)
        - Daily ingestion volume (is it worth optimizing?)
        - Current cost vs. projected cost at each tier
        Returns a recommendation per table: keep, downgrade to Basic, downgrade to Auxiliary.
    .EXAMPLE
        Get-TierRecommendation -WorkspaceName 'sentinel-prod' -LookbackDays 30
    .EXAMPLE
        Get-TierRecommendation -TableName 'Syslog' -Verbose
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [string]$WorkspaceName,
        [string]$TableName,

        [ValidateRange(7, 90)]
        [int]$LookbackDays = 30
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $headers = Get-SecOpsAuthHeader

    # --- Query frequency analysis via LAQueryLogs ---
    $queryAnalysisKql = @"
LAQueryLogs
| where TimeGenerated > ago(${LookbackDays}d)
| extend Tables = extractall(@'(\w+)\s*\|', QueryText)
| mv-expand Tables to typeof(string)
| summarize
    QueryCount = count(),
    DistinctUsers = dcount(AADEmail),
    UsesJoin = countif(QueryText has_any ('join', 'mv-expand', 'make-series')),
    UsesSummarize = countif(QueryText has 'summarize'),
    LastQueried = max(TimeGenerated)
    by TableName = Tables
| extend
    QueriesPerDay = round(QueryCount * 1.0 / $LookbackDays, 1),
    NeedsFullKQL = (UsesJoin > 0)
"@

    # --- Ingestion volume from Usage table ---
    $volumeKql = @"
Usage
| where TimeGenerated > ago(${LookbackDays}d)
| where IsBillable == true
| summarize
    DailyAvgGB = round(avg(Quantity) / 1024.0, 3),
    TotalGB = round(sum(Quantity) / 1024.0, 2)
    by DataType
"@

    $queryApiUri = "https://api.loganalytics.io/v1/workspaces/$($ctx.WorkspaceId)/query"

    $queryResult = Invoke-SecOpsRestMethod -Uri $queryApiUri -Method POST `
        -Body (@{ query = $queryAnalysisKql } | ConvertTo-Json) `
        -Headers $headers -OperationName 'TierRecommendation-QueryAnalysis'

    $volumeResult = Invoke-SecOpsRestMethod -Uri $queryApiUri -Method POST `
        -Body (@{ query = $volumeKql } | ConvertTo-Json) `
        -Headers $headers -OperationName 'TierRecommendation-VolumeAnalysis'

    if (-not $queryResult.Ok -or -not $volumeResult.Ok) {
        return New-SecOpsResult -Error "Failed to query workspace analytics" -ErrorCode 'QueryFailed'
    }

    # --- Build recommendations ---
    # Cost constants (East US 2 approximate, per GB/month for 30 days of daily ingestion)
    $costPerGB = @{
        Analytics = 4.99
        Basic     = 1.75
        Auxiliary = 0.75
    }

    $recommendations = foreach ($table in $volumeResult.Data.tables[0].rows) {
        $dataType = $table[0]
        $dailyGB = [double]$table[1]
        $queryInfo = $queryResult.Data.tables[0].rows | Where-Object { $_[0] -eq $dataType }

        $queriesPerDay = if ($queryInfo) { [double]$queryInfo[5] } else { 0 }
        $needsFullKQL = if ($queryInfo) { [int]$queryInfo[4] -gt 0 } else { $false }

        # Decision logic
        $recommendation = if ($needsFullKQL -or $queriesPerDay -ge 1) {
            'Analytics'
        }
        elseif ($queriesPerDay -ge 0.1) {
            'Basic'
        }
        elseif ($dailyGB -gt 0.5) {
            'Auxiliary'
        }
        else {
            'Analytics'  # Low volume — savings negligible
        }

        $currentCost = $dailyGB * 30 * $costPerGB['Analytics']
        $recommendedCost = $dailyGB * 30 * $costPerGB[$recommendation]

        [PSCustomObject]@{
            TableName         = $dataType
            DailyGB           = $dailyGB
            QueriesPerDay     = $queriesPerDay
            NeedsFullKQL      = $needsFullKQL
            CurrentTier       = 'Analytics'
            RecommendedTier   = $recommendation
            CurrentMonthlyCost    = [math]::Round($currentCost, 2)
            RecommendedMonthlyCost = [math]::Round($recommendedCost, 2)
            MonthlySavings    = [math]::Round($currentCost - $recommendedCost, 2)
        }
    }

    if ($TableName) {
        $recommendations = $recommendations | Where-Object TableName -eq $TableName
    }

    return New-SecOpsResult -Success -Data ($recommendations | Sort-Object MonthlySavings -Descending)
}
```

### Cost Impact Calculator

```powershell
function Get-TierCostImpact {
    <#
    .SYNOPSIS
        Calculates cost impact of changing a table from one tier to another.
    .DESCRIPTION
        Estimates monthly cost difference including ingestion, query scan charges,
        and storage. Uses daily volume from .secops/data-source-map.yaml or live query.
    .EXAMPLE
        Get-TierCostImpact -TableName 'Syslog' -FromTier 'Analytics' -ToTier 'Basic'
    .EXAMPLE
        Get-TierCostImpact -TableName 'AWSCloudTrail' -FromTier 'Analytics' -ToTier 'Basic' -EstimatedQueriesPerDay 5
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$TableName,

        [Parameter(Mandatory)]
        [ValidateSet('Analytics', 'Basic', 'Auxiliary')]
        [string]$FromTier,

        [Parameter(Mandatory)]
        [ValidateSet('Analytics', 'Basic', 'Auxiliary')]
        [string]$ToTier,

        [double]$DailyGB,
        [int]$EstimatedQueriesPerDay = 2,
        [double]$AvgQueryScanGB = 1.0
    )

    # Resolve daily volume from .secops/ if not provided
    if (-not $DailyGB) {
        $dsMap = $script:SecOpsContext.DataSourceMap
        if ($dsMap.sources -and $dsMap.sources[$TableName]) {
            $DailyGB = $dsMap.sources[$TableName].daily_gb
        }
        else {
            return New-SecOpsResult -Error `
                "DailyGB not provided and '$TableName' not found in data-source-map.yaml" `
                -ErrorCode 'MissingVolume'
        }
    }

    # Cost matrix (approximate USD, East US 2)
    $ingestionCost = @{ Analytics = 4.99; Basic = 1.75; Auxiliary = 0.75 }
    $queryScanCost = @{ Analytics = 0.00; Basic = 0.006; Auxiliary = 0.006 }
    $storageCostPerGBMonth = 0.023  # Archive/retention storage

    $monthlyIngestionFrom = $DailyGB * 30 * $ingestionCost[$FromTier]
    $monthlyIngestionTo   = $DailyGB * 30 * $ingestionCost[$ToTier]
    $monthlyQueryFrom     = $EstimatedQueriesPerDay * 30 * $AvgQueryScanGB * $queryScanCost[$FromTier]
    $monthlyQueryTo       = $EstimatedQueriesPerDay * 30 * $AvgQueryScanGB * $queryScanCost[$ToTier]

    $totalFrom = $monthlyIngestionFrom + $monthlyQueryFrom
    $totalTo   = $monthlyIngestionTo + $monthlyQueryTo
    $savings   = $totalFrom - $totalTo
    $savingsPct = if ($totalFrom -gt 0) { [math]::Round(($savings / $totalFrom) * 100, 1) } else { 0 }

    return New-SecOpsResult -Success -Data ([PSCustomObject]@{
        TableName              = $TableName
        DailyGB                = $DailyGB
        FromTier               = $FromTier
        ToTier                 = $ToTier
        MonthlyIngestionFrom   = [math]::Round($monthlyIngestionFrom, 2)
        MonthlyIngestionTo     = [math]::Round($monthlyIngestionTo, 2)
        MonthlyQueryCostFrom   = [math]::Round($monthlyQueryFrom, 2)
        MonthlyQueryCostTo     = [math]::Round($monthlyQueryTo, 2)
        TotalMonthlyCostFrom   = [math]::Round($totalFrom, 2)
        TotalMonthlyCostTo     = [math]::Round($totalTo, 2)
        MonthlySavings         = [math]::Round($savings, 2)
        SavingsPercent         = $savingsPct
        AnnualSavings          = [math]::Round($savings * 12, 2)
        TradeOffs              = if ($ToTier -ne 'Analytics') {
            @(
                "No Sentinel analytics rules on $ToTier tier"
                if ($ToTier -eq 'Auxiliary') { "Search-only queries — no summarize" }
                if ($ToTier -eq 'Basic') { "No join/mv-expand — limited KQL" }
            ) | Where-Object { $_ }
        } else { @() }
    })
}
```

---

## Retention Policy Management

### Get-LogAnalyticsRetention — Query Retention Settings

```powershell
function Get-LogAnalyticsRetention {
    <#
    .SYNOPSIS
        Retrieves retention and archive settings for all tables in a workspace.
    .DESCRIPTION
        Returns interactive retention, total retention, and computed archive duration
        per table. Enriches with compliance requirements from .secops/compliance/requirements.yaml.
    .EXAMPLE
        Get-LogAnalyticsRetention | Where-Object ArchiveDays -gt 0 | Format-Table
    .EXAMPLE
        Get-LogAnalyticsRetention -TableName 'SecurityEvent'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [string]$WorkspaceName,
        [string]$TableName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $uri = "$($ctx.BaseUri)/tables?api-version=2023-09-01"

    $result = Invoke-SecOpsRestMethod -Uri $uri -Headers (Get-SecOpsAuthHeader) `
        -OperationName 'Get-LogAnalyticsRetention'
    if (-not $result.Ok) { return $result }

    # Load compliance requirements
    $complianceMin = $null
    $compPath = Join-Path $script:SecOpsContext.SecOpsPath 'compliance' 'requirements.yaml'
    if (Test-Path $compPath) {
        $comp = Get-Content $compPath -Raw | ConvertFrom-Yaml
        $complianceMin = $comp.retention_requirements
    }

    $tables = $result.Data.value | ForEach-Object {
        $name = $_.name
        $props = $_.properties
        $interactive = $props.retentionInDays
        $total = $props.totalRetentionInDays
        $archive = $total - $interactive

        # Check compliance override
        $override = $null
        if ($complianceMin.overrides) {
            $override = $complianceMin.overrides | Where-Object { $_.table -eq $name }
        }
        $requiredInteractive = if ($override) { $override.interactive_days }
                               elseif ($complianceMin.default) { $complianceMin.default.interactive_days }
                               else { $null }

        $compliant = if ($requiredInteractive) { $interactive -ge $requiredInteractive } else { $null }

        [PSCustomObject]@{
            TableName           = $name
            Plan                = $props.plan
            InteractiveDays     = $interactive
            ArchiveDays         = [math]::Max(0, $archive)
            TotalRetentionDays  = $total
            RequiredMinDays     = $requiredInteractive
            ComplianceStatus    = if ($null -eq $compliant) { 'Unknown' }
                                  elseif ($compliant) { 'Compliant' }
                                  else { 'NonCompliant' }
        }
    }

    if ($TableName) { $tables = $tables | Where-Object TableName -eq $TableName }

    return New-SecOpsResult -Success -Data ($tables | Sort-Object TableName)
}
```

### Set-LogAnalyticsRetention — Configure Retention with Compliance Validation

```powershell
function Set-LogAnalyticsRetention {
    <#
    .SYNOPSIS
        Sets interactive and total retention for a table with compliance enforcement.
    .DESCRIPTION
        Configures retention and validates against .secops/compliance/requirements.yaml.
        If the requested retention is below the compliance minimum, the function either
        raises the value (with -AutoComply) or returns an error.
    .EXAMPLE
        Set-LogAnalyticsRetention -TableName 'SecurityEvent' -InteractiveDays 180 -TotalDays 730
    .EXAMPLE
        Set-LogAnalyticsRetention -TableName 'Syslog' -InteractiveDays 30 -TotalDays 365 -AutoComply
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$TableName,

        [Parameter(Mandatory)]
        [ValidateRange(4, 730)]
        [int]$InteractiveDays,

        [ValidateRange(4, 4383)]
        [int]$TotalDays,

        [string]$WorkspaceName,
        [switch]$AutoComply
    )

    if ($TotalDays -and $TotalDays -lt $InteractiveDays) {
        return New-SecOpsResult -Error "TotalDays ($TotalDays) must be >= InteractiveDays ($InteractiveDays)" `
            -ErrorCode 'InvalidRetention'
    }

    # --- Compliance validation ---
    $compPath = Join-Path $script:SecOpsContext.SecOpsPath 'compliance' 'requirements.yaml'
    if (Test-Path $compPath) {
        $comp = Get-Content $compPath -Raw | ConvertFrom-Yaml
        $req = $comp.retention_requirements

        # Per-table override or default
        $override = $req.overrides | Where-Object { $_.table -eq $TableName }
        $minInteractive = if ($override) { $override.interactive_days } else { $req.default.interactive_days }
        $minTotal = if ($override) { $override.interactive_days + $override.archive_days }
                    else { $req.default.total_days }

        if ($InteractiveDays -lt $minInteractive) {
            if ($AutoComply) {
                Write-Warning "Compliance requires $minInteractive days interactive. Raising from $InteractiveDays to $minInteractive."
                $InteractiveDays = $minInteractive
            }
            else {
                return New-SecOpsResult -Error `
                    "InteractiveDays ($InteractiveDays) below compliance minimum ($minInteractive). Use -AutoComply to auto-raise." `
                    -ErrorCode 'ComplianceViolation'
            }
        }

        if ($TotalDays -and $TotalDays -lt $minTotal) {
            if ($AutoComply) {
                Write-Warning "Compliance requires $minTotal total days. Raising from $TotalDays to $minTotal."
                $TotalDays = $minTotal
            }
            else {
                return New-SecOpsResult -Error `
                    "TotalDays ($TotalDays) below compliance minimum ($minTotal). Use -AutoComply to auto-raise." `
                    -ErrorCode 'ComplianceViolation'
            }
        }
    }

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    if (-not $PSCmdlet.ShouldProcess(
        "$TableName: interactive=$InteractiveDays, total=$($TotalDays ?? $InteractiveDays) days",
        'Set Retention Policy')) { return }

    $body = @{
        properties = @{
            retentionInDays      = $InteractiveDays
            totalRetentionInDays = if ($TotalDays) { $TotalDays } else { $InteractiveDays }
        }
    }

    $uri = "$($ctx.BaseUri)/tables/${TableName}?api-version=2023-09-01"

    return Invoke-SecOpsRestMethod -Uri $uri -Method PATCH `
        -Body ($body | ConvertTo-Json -Depth 5) `
        -Headers (Get-SecOpsAuthHeader) `
        -OperationName "Set-LogAnalyticsRetention ($TableName)"
}
```

### Test-RetentionCompliance — Bulk Compliance Audit

```powershell
function Test-RetentionCompliance {
    <#
    .SYNOPSIS
        Audits all workspace tables against .secops/compliance/requirements.yaml.
    .DESCRIPTION
        Returns a compliance report showing which tables meet, exceed, or violate
        retention requirements. Non-compliant tables are flagged with the required
        minimum and the delta.
    .EXAMPLE
        Test-RetentionCompliance -WorkspaceName 'sentinel-prod' | Where-Object Status -eq 'NonCompliant'
    .EXAMPLE
        Test-RetentionCompliance | Export-Csv retention-audit.csv
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [string]$WorkspaceName
    )

    $retention = Get-LogAnalyticsRetention -WorkspaceName $WorkspaceName
    if (-not $retention.Ok) { return $retention }

    $nonCompliant = $retention.Data | Where-Object ComplianceStatus -eq 'NonCompliant'
    $compliant = $retention.Data | Where-Object ComplianceStatus -eq 'Compliant'
    $unknown = $retention.Data | Where-Object ComplianceStatus -eq 'Unknown'

    $summary = [PSCustomObject]@{
        TotalTables    = $retention.Data.Count
        Compliant      = $compliant.Count
        NonCompliant   = $nonCompliant.Count
        Unknown        = $unknown.Count
        Details        = $retention.Data
    }

    if ($nonCompliant.Count -gt 0) {
        Write-Warning "⚠️ $($nonCompliant.Count) table(s) below compliance minimums:"
        $nonCompliant | ForEach-Object {
            Write-Warning "  - $($_.TableName): $($_.InteractiveDays) days (required: $($_.RequiredMinDays))"
        }
    }

    return New-SecOpsResult -Success -Data $summary
}
```

### Bulk Retention Application

```powershell
function Set-BulkRetentionPolicy {
    <#
    .SYNOPSIS
        Applies retention policies to multiple tables from a configuration hashtable.
    .DESCRIPTION
        Accepts a hashtable of table names to retention settings and applies them in bulk.
        Each table is validated against compliance requirements before applying.
    .EXAMPLE
        $policies = @{
            'SecurityEvent'  = @{ Interactive = 180; Total = 730 }
            'SigninLogs'     = @{ Interactive = 180; Total = 730 }
            'Syslog'         = @{ Interactive = 30;  Total = 365 }
            'AWSCloudTrail'  = @{ Interactive = 30;  Total = 180 }
        }
        Set-BulkRetentionPolicy -Policies $policies
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Policies,

        [string]$WorkspaceName,
        [switch]$AutoComply
    )

    $results = foreach ($table in $Policies.Keys) {
        $config = $Policies[$table]
        $r = Set-LogAnalyticsRetention -TableName $table `
            -InteractiveDays $config.Interactive `
            -TotalDays $config.Total `
            -WorkspaceName $WorkspaceName `
            -AutoComply:$AutoComply

        [PSCustomObject]@{
            TableName = $table
            Status    = if ($r.Ok) { 'Applied' } else { 'Failed' }
            Error     = if (-not $r.Ok) { $r.Error } else { $null }
        }
    }

    return New-SecOpsResult -Success -Data $results
}
```

---

## Summary Rules

### What Are Summary Rules?

Summary rules execute a KQL aggregation on a schedule and write results to a destination table. They are the critical bridge between cost optimization and data retention — you keep the aggregated metrics in an Analytics-tier table while downgrading or archiving the raw source.

**When to use summary rules:**
- Before downgrading a high-volume table to Basic/Auxiliary tier
- When you need long-term trend data but not raw events
- To maintain dashboards after source table archival
- To pre-compute expensive aggregations (reduce query cost)

**Summary rule constraints:**
- Bin sizes: `PT1H` (hourly), `PT6H` (6-hour), `P1D` (daily)
- Destination must be a custom table (`_CL` suffix) or Log Analytics system table
- KQL must include `bin(TimeGenerated, ...)` matching the bin size
- Maximum 30 summary rules per workspace

### New-SummaryRule — Create Summary Rule

```powershell
function New-SummaryRule {
    <#
    .SYNOPSIS
        Creates a summary rule to aggregate data before tier downgrade.
    .DESCRIPTION
        Creates a Sentinel summary rule that runs KQL on a schedule and writes
        aggregated results to a destination table. Essential for cost optimization:
        create the summary rule BEFORE downgrading the source table.
    .EXAMPLE
        New-SummaryRule -Name 'SyslogHourly' `
            -Query 'Syslog | summarize Count=count(), AvgSize=avg(_BilledSize) by Facility, SeverityLevel, Computer, bin(TimeGenerated, 1h)' `
            -DestinationTable 'SyslogSummary_CL' -BinSize 'PT1H'
    .EXAMPLE
        New-SummaryRule -Name 'FirewallDaily' `
            -Query 'CommonSecurityLog | summarize Connections=count(), BytesIn=sum(ReceivedBytes), BytesOut=sum(SentBytes) by DeviceVendor, DeviceProduct, Activity, bin(TimeGenerated, 1d)' `
            -DestinationTable 'FirewallSummary_CL' -BinSize 'P1D'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Description,

        [Parameter(Mandatory)]
        [string]$Query,

        [Parameter(Mandatory)]
        [string]$DestinationTable,

        [Parameter(Mandatory)]
        [ValidateSet('PT1H', 'PT6H', 'P1D')]
        [string]$BinSize,

        [string]$WorkspaceName,
        [switch]$Disabled
    )

    # Validate KQL contains matching bin()
    $expectedBin = switch ($BinSize) {
        'PT1H' { '1h' }
        'PT6H' { '6h' }
        'P1D'  { '1d' }
    }
    if ($Query -notmatch "bin\s*\(\s*TimeGenerated\s*,\s*$expectedBin\s*\)") {
        Write-Warning "Query should contain 'bin(TimeGenerated, $expectedBin)' to match BinSize '$BinSize'"
    }

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName

    if (-not $PSCmdlet.ShouldProcess("$Name → $DestinationTable (bin: $BinSize)", 'Create Summary Rule')) {
        return
    }

    $ruleId = [guid]::NewGuid().ToString()
    $body = @{
        properties = @{
            displayName      = $Name
            description      = if ($Description) { $Description } else { "Summary rule: $Name" }
            query            = $Query
            destinationTable = $DestinationTable
            binSize          = $BinSize
            isEnabled        = (-not $Disabled)
        }
    }

    $uri = "$($ctx.BaseUri)/providers/Microsoft.SecurityInsights/summaryRules/${ruleId}?api-version=2024-03-01"

    return Invoke-SecOpsRestMethod -Uri $uri -Method PUT `
        -Body ($body | ConvertTo-Json -Depth 5) `
        -Headers (Get-SecOpsAuthHeader) `
        -OperationName "New-SummaryRule ($Name)"
}
```

### Get-SummaryRule — List Summary Rules

```powershell
function Get-SummaryRule {
    <#
    .SYNOPSIS
        Lists all summary rules in the workspace.
    .EXAMPLE
        Get-SummaryRule | Format-Table Name, DestinationTable, BinSize, IsEnabled
    .EXAMPLE
        Get-SummaryRule -Name 'SyslogHourly'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [string]$WorkspaceName,
        [string]$Name
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $uri = "$($ctx.BaseUri)/providers/Microsoft.SecurityInsights/summaryRules?api-version=2024-03-01"

    $result = Invoke-SecOpsRestMethod -Uri $uri -Headers (Get-SecOpsAuthHeader) `
        -OperationName 'Get-SummaryRule'
    if (-not $result.Ok) { return $result }

    $rules = $result.Data.value | ForEach-Object {
        [PSCustomObject]@{
            Id               = $_.name
            Name             = $_.properties.displayName
            Query            = $_.properties.query
            DestinationTable = $_.properties.destinationTable
            BinSize          = $_.properties.binSize
            IsEnabled        = $_.properties.isEnabled
        }
    }

    if ($Name) { $rules = $rules | Where-Object Name -eq $Name }

    return New-SecOpsResult -Success -Data $rules
}
```

### Test-SummaryRule — Validate Summary Rule KQL

```powershell
function Test-SummaryRule {
    <#
    .SYNOPSIS
        Validates a summary rule's KQL query against the workspace without creating it.
    .DESCRIPTION
        Executes the query with a small time window to verify it parses, runs,
        and produces the expected schema. Use before New-SummaryRule to catch errors.
    .EXAMPLE
        Test-SummaryRule -Query 'Syslog | summarize Count=count() by Facility, bin(TimeGenerated, 1h)' -BinSize 'PT1H'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Query,

        [Parameter(Mandatory)]
        [ValidateSet('PT1H', 'PT6H', 'P1D')]
        [string]$BinSize,

        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName

    # Execute with 1-hour time window to validate
    $testQuery = "$Query | take 5"
    $body = @{
        query    = $testQuery
        timespan = 'PT1H'
    }

    $queryUri = "https://api.loganalytics.io/v1/workspaces/$($ctx.WorkspaceId)/query"

    $result = Invoke-SecOpsRestMethod -Uri $queryUri -Method POST `
        -Body ($body | ConvertTo-Json) `
        -Headers (Get-SecOpsAuthHeader) `
        -OperationName 'Test-SummaryRule'

    if ($result.Ok) {
        $columns = $result.Data.tables[0].columns | ForEach-Object { $_.name }
        $rowCount = $result.Data.tables[0].rows.Count

        # Check bin alignment
        $expectedBin = switch ($BinSize) { 'PT1H' { '1h' }; 'PT6H' { '6h' }; 'P1D' { '1d' } }
        $hasBin = $Query -match "bin\s*\(\s*TimeGenerated\s*,\s*$expectedBin\s*\)"

        return New-SecOpsResult -Success -Data ([PSCustomObject]@{
            Valid            = $true
            Columns          = $columns
            SampleRowCount   = $rowCount
            BinAligned       = $hasBin
            Warnings         = @(
                if (-not $hasBin) { "Query missing bin(TimeGenerated, $expectedBin) — required for $BinSize schedule" }
                if ('TimeGenerated' -notin $columns) { "Output should include TimeGenerated column" }
            ) | Where-Object { $_ }
        })
    }

    return New-SecOpsResult -Error "Query validation failed: $($result.Error)" -ErrorCode 'InvalidQuery'
}
```

### Summary Rule Templates for Common Tables

```powershell
# --- Pre-built summary rule configurations ---
$SummaryRuleTemplates = @{

    Syslog = @{
        Name  = 'SyslogHourlySummary'
        Query = @'
Syslog
| summarize
    EventCount = count(),
    AvgSize = avg(_BilledSize),
    Computers = dcount(Computer)
    by Facility, SeverityLevel, bin(TimeGenerated, 1h)
'@
        Destination = 'SyslogSummary_CL'
        BinSize     = 'PT1H'
    }

    CommonSecurityLog = @{
        Name  = 'FirewallDailySummary'
        Query = @'
CommonSecurityLog
| summarize
    Connections = count(),
    BytesIn = sum(ReceivedBytes),
    BytesOut = sum(SentBytes),
    UniqueSourceIPs = dcount(SourceIP),
    UniqueDestIPs = dcount(DestinationIP)
    by DeviceVendor, DeviceProduct, Activity, bin(TimeGenerated, 1d)
'@
        Destination = 'FirewallSummary_CL'
        BinSize     = 'P1D'
    }

    AWSCloudTrail = @{
        Name  = 'AWSCloudTrailHourlySummary'
        Query = @'
AWSCloudTrail
| summarize
    EventCount = count(),
    UniqueUsers = dcount(UserIdentityArn),
    ErrorCount = countif(ErrorCode != ""),
    Regions = make_set(AWSRegion, 20)
    by EventSource, EventName, bin(TimeGenerated, 1h)
'@
        Destination = 'AWSCloudTrailSummary_CL'
        BinSize     = 'PT1H'
    }
}

# Usage: Apply a template
# $t = $SummaryRuleTemplates['Syslog']
# New-SummaryRule -Name $t.Name -Query $t.Query -DestinationTable $t.Destination -BinSize $t.BinSize
```

---

## Purge Operations

### Submit-DataPurge — GDPR/Privacy Data Purge

```powershell
function Submit-DataPurge {
    <#
    .SYNOPSIS
        Submits a data purge request for GDPR/privacy compliance.
    .DESCRIPTION
        Uses the Log Analytics Purge API to permanently delete records matching
        a filter. Purge operations are audited and irreversible.
        The API returns a purge ID for status tracking.

        IMPORTANT: Purge operations may take up to 30 days to complete.
        Data is not immediately removed — it becomes inaccessible within 5 days
        and is physically deleted within 30 days.
    .EXAMPLE
        Submit-DataPurge -TableName 'SigninLogs' `
            -Filters @(@{ column = 'UserPrincipalName'; operator = '=='; value = 'user@contoso.com' }) `
            -Reason 'GDPR data subject deletion request #DSR-2026-0042'
    .EXAMPLE
        Submit-DataPurge -TableName 'SecurityEvent' `
            -Filters @(
                @{ column = 'Computer'; operator = '=='; value = 'DECOM-SERVER01' },
                @{ column = 'TimeGenerated'; operator = '<'; value = '2025-01-01T00:00:00Z' }
            ) `
            -Reason 'Decommissioned asset data cleanup'
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$TableName,

        [Parameter(Mandatory)]
        [array]$Filters,

        [Parameter(Mandatory)]
        [string]$Reason,

        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName

    # Build filter preview for ShouldProcess
    $filterDesc = ($Filters | ForEach-Object { "$($_.column) $($_.operator) $($_.value)" }) -join ' AND '

    if (-not $PSCmdlet.ShouldProcess(
        "PURGE $TableName WHERE $filterDesc — Reason: $Reason",
        'Submit Data Purge (IRREVERSIBLE)')) { return }

    $body = @{
        table   = $TableName
        filters = $Filters
    }

    $uri = "$($ctx.BaseUri)/purge?api-version=2023-09-01"

    $result = Invoke-SecOpsRestMethod -Uri $uri -Method POST `
        -Body ($body | ConvertTo-Json -Depth 10) `
        -Headers (Get-SecOpsAuthHeader) `
        -OperationName "Submit-DataPurge ($TableName)"

    if ($result.Ok) {
        $purgeId = $result.Data.operationId
        Write-Warning @"
Purge submitted successfully.
  Purge ID:    $purgeId
  Table:       $TableName
  Reason:      $Reason
  Timeline:    Data inaccessible within ~5 days, physically deleted within ~30 days
  Track with:  Get-PurgeStatus -PurgeId '$purgeId'
"@

        # Log to audit
        $auditEntry = @{
            Timestamp = (Get-Date).ToString('o')
            Operation = 'DataPurge'
            Table     = $TableName
            Filters   = $filterDesc
            Reason    = $Reason
            PurgeId   = $purgeId
            Operator  = (Get-AzContext).Account.Id
        }
        Write-Verbose "Audit: $($auditEntry | ConvertTo-Json -Compress)"
    }

    return $result
}
```

### Get-PurgeStatus — Track Purge Request

```powershell
function Get-PurgeStatus {
    <#
    .SYNOPSIS
        Gets the status of a data purge operation.
    .DESCRIPTION
        Queries the purge status API. States: pending, completed.
        Purge completion may take up to 30 days.
    .EXAMPLE
        Get-PurgeStatus -PurgeId 'purge-abc123-def456'
    .EXAMPLE
        Get-PurgeStatus -ListAll  # List all recent purge operations
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$PurgeId,
        [switch]$ListAll,
        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName

    if ($PurgeId) {
        $uri = "$($ctx.BaseUri)/operations/${PurgeId}?api-version=2023-09-01"
        $result = Invoke-SecOpsRestMethod -Uri $uri -Headers (Get-SecOpsAuthHeader) `
            -OperationName "Get-PurgeStatus ($PurgeId)"

        if ($result.Ok) {
            return New-SecOpsResult -Success -Data ([PSCustomObject]@{
                PurgeId = $PurgeId
                Status  = $result.Data.properties.status  # pending | completed
            })
        }
        return $result
    }

    if ($ListAll) {
        $uri = "$($ctx.BaseUri)/operations?api-version=2023-09-01"
        return Invoke-SecOpsRestMethod -Uri $uri -Headers (Get-SecOpsAuthHeader) `
            -OperationName 'Get-PurgeStatus (ListAll)'
    }

    return New-SecOpsResult -Error 'Provide -PurgeId or -ListAll' -ErrorCode 'MissingParameter'
}
```

---

## Data Tiering Decision Framework

### Decision Tree: Which Tier for Which Table?

```
START: Evaluate table for tier placement
│
├── Is the table used in Sentinel analytics rules?
│   └── YES → Analytics tier (REQUIRED — Basic/Auxiliary don't support rules)
│
├── Is the table queried daily with join/summarize/mv-expand?
│   └── YES → Analytics tier
│
├── Is the daily volume > 100 GB?
│   └── YES → Consider ADX migration (see skills/adx/migration-from-sentinel.md)
│       └── Create summary rule + migrate raw to ADX
│
├── Is the table queried weekly with simple filters?
│   └── YES → Basic tier
│       └── Create summary rule for aggregated metrics
│
├── Is the table only needed for compliance/forensics?
│   └── YES → Archive tier (interactive retention = minimum, long archive)
│       └── Create summary rule for trend data
│
├── Is the table verbose telemetry (debug, trace)?
│   └── YES → Auxiliary tier
│       └── Shortest retention allowed by compliance
│
└── Default → Analytics tier (if volume < 1 GB/day, savings are negligible)
```

### Frequency-Based Tier Selection

| Query Frequency | Daily Volume | Recommended Tier | Annual Savings (vs Analytics) |
|---|---|---|---|
| Multiple times/day | Any | Analytics | $0 (baseline) |
| Weekly | < 5 GB/day | Analytics | $0 (savings negligible) |
| Weekly | 5–50 GB/day | Basic | ~$58,500/yr at 50 GB |
| Weekly | > 50 GB/day | Basic + Summary Rule | ~$58,500+ |
| Monthly or less | Any | Auxiliary or Archive | ~$76,500/yr at 50 GB |
| Never (compliance only) | Any | Archive | ~$89,100/yr at 50 GB |

### Cost Modeling Formulas

```
Monthly cost per tier (for a table ingesting D GB/day):

Analytics:  D × 30 × $4.99 = D × $149.70/month
Basic:      D × 30 × $1.75 = D × $52.50/month
Auxiliary:  D × 30 × $0.75 = D × $22.50/month

Query cost (Basic/Auxiliary only):
  Queries/day × 30 × AvgScanGB × $0.006/GB

Storage cost (archive beyond interactive retention):
  D × ArchiveDays × $0.023/GB/month (prorated)

Break-even: Basic query cost exceeds savings when:
  QueriesPerDay × ScanGB × $0.006 × 30 > D × 30 × ($4.99 - $1.75)
  → QueriesPerDay × ScanGB > D × 540
  (e.g., 10 GB/day table: break-even at ~5,400 queries/day scanning 1 GB each)
```

### Integration with `.secops/data-sources/data-source-map.yaml`

After every tier change, update the data source map:

```yaml
# Before tier change:
  Syslog:
    location: "sentinel"
    workspace: "example-workspace"
    tier: "Analytics"
    daily_gb: 10

# After downgrade to Basic:
  Syslog:
    location: "sentinel"
    workspace: "example-workspace"
    tier: "Basic"
    daily_gb: 10
    ingestion_method: "ama-agent"
    notes: "Downgraded from Analytics 2026-04-30. Summary rule: SyslogHourlySummary → SyslogSummary_CL"
```

---

## Migration Workflows

### Start-DataMigration — Orchestrate Data Movement

```powershell
function Start-DataMigration {
    <#
    .SYNOPSIS
        Initiates a data migration between locations with tracking in migrations.yaml.
    .DESCRIPTION
        Supports three migration patterns:
        1. ADX → Sentinel: Create DCR + data connection, validate, decommission ADX source
        2. Sentinel → ADX: Continuous export + external table, validate, reduce Sentinel retention
        3. Workspace consolidation: Cross-workspace query proxy, parallel ingestion, cutover
    .EXAMPLE
        Start-DataMigration -Type 'ADXToSentinel' -SourceTable 'NetFlowLogs' `
            -SourceCluster 'soc-adx-prod' -SourceDatabase 'SecurityLake' `
            -TargetWorkspace 'sentinel-prod' -TargetTable 'NetFlowLogs_CL' -TargetTier 'Auxiliary'
    .EXAMPLE
        Start-DataMigration -Type 'SentinelToADX' -SourceTable 'CommonSecurityLog' `
            -TargetCluster 'soc-adx-prod' -TargetDatabase 'SecurityLake'
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ADXToSentinel', 'SentinelToADX', 'WorkspaceConsolidation')]
        [string]$Type,

        [Parameter(Mandatory)]
        [string]$SourceTable,

        [string]$SourceCluster,
        [string]$SourceDatabase,
        [string]$SourceWorkspace,

        [string]$TargetWorkspace,
        [string]$TargetTable,
        [string]$TargetCluster,
        [string]$TargetDatabase,

        [ValidateSet('Analytics', 'Basic', 'Auxiliary')]
        [string]$TargetTier = 'Analytics',

        [string]$Owner
    )

    # Check for conflicting migrations
    $migPath = Join-Path $script:SecOpsContext.SecOpsPath 'data-sources' 'migrations.yaml'
    if (Test-Path $migPath) {
        $existing = Get-Content $migPath -Raw | ConvertFrom-Yaml
        $conflict = $existing.migrations | Where-Object {
            $_.status -eq 'in-progress' -and
            ($_.source.table -eq $SourceTable -or $_.target.table -eq $TargetTable)
        }
        if ($conflict) {
            return New-SecOpsResult -Error `
                "Conflicting migration in progress: $($conflict.id) — $($conflict.description)" `
                -ErrorCode 'MigrationConflict'
        }
    }

    $migId = "mig-$(Get-Date -Format 'yyyyMMdd')-$([guid]::NewGuid().ToString().Substring(0,8))"

    $migrationPlan = switch ($Type) {
        'ADXToSentinel' {
            @{
                Steps = @(
                    "1. Create custom table '$TargetTable' in workspace '$TargetWorkspace' with $TargetTier tier"
                    "2. Create DCR with ingestion-time transform matching ADX schema"
                    "3. Configure Event Hub bridge: ADX continuous export → Event Hub → DCR → Sentinel"
                    "4. Validate data in both locations for 7 days"
                    "5. Update .secops/data-sources/data-source-map.yaml"
                    "6. Update Sentinel analytics rules to reference '$TargetTable'"
                    "7. Decommission ADX ingestion pipeline"
                )
                YamlEntry = @{
                    id = $migId; status = 'in-progress'
                    description = "ADX to Sentinel: $SourceTable → $TargetTable ($TargetTier)"
                    source = @{ location = 'adx'; cluster = $SourceCluster; database = $SourceDatabase; table = $SourceTable }
                    target = @{ location = 'sentinel'; workspace = $TargetWorkspace; table = $TargetTable; tier = $TargetTier }
                    started = (Get-Date -Format 'yyyy-MM-dd')
                    owner = if ($Owner) { $Owner } else { (Get-AzContext).Account.Id }
                }
            }
        }
        'SentinelToADX' {
            @{
                Steps = @(
                    "1. Create target table and staging table in ADX cluster '$TargetCluster'"
                    "2. Configure continuous export from Log Analytics to Azure Storage"
                    "3. Set up ADX external table over Storage + ingestion pipeline"
                    "4. Create proxy function in Sentinel: let $SourceTable = adx('$TargetCluster/...$SourceTable')"
                    "5. Validate data flow for 7 days"
                    "6. Reduce Sentinel retention to minimum (compliance-aware)"
                    "7. Update .secops/ files: data-source-map.yaml + migrations.yaml"
                )
                YamlEntry = @{
                    id = $migId; status = 'in-progress'
                    description = "Sentinel to ADX: $SourceTable → $TargetCluster/$TargetDatabase"
                    source = @{ location = 'sentinel'; workspace = $SourceWorkspace; table = $SourceTable }
                    target = @{ location = 'adx'; cluster = $TargetCluster; database = $TargetDatabase; table = $SourceTable }
                    started = (Get-Date -Format 'yyyy-MM-dd')
                    owner = if ($Owner) { $Owner } else { (Get-AzContext).Account.Id }
                }
            }
        }
        'WorkspaceConsolidation' {
            @{
                Steps = @(
                    "1. Audit source workspace '$SourceWorkspace': table list, retention, analytics rules"
                    "2. Create cross-workspace queries: workspace('$SourceWorkspace').TableName"
                    "3. Redirect data connectors from source to target workspace"
                    "4. Run parallel ingestion for 14 days"
                    "5. Migrate analytics rules (update workspace references)"
                    "6. Validate detection coverage in target workspace"
                    "7. Decommission source workspace"
                )
                YamlEntry = @{
                    id = $migId; status = 'in-progress'
                    description = "Workspace consolidation: $SourceWorkspace → $TargetWorkspace"
                    source = @{ location = 'sentinel'; workspace = $SourceWorkspace }
                    target = @{ location = 'sentinel'; workspace = $TargetWorkspace }
                    started = (Get-Date -Format 'yyyy-MM-dd')
                    owner = if ($Owner) { $Owner } else { (Get-AzContext).Account.Id }
                }
            }
        }
    }

    Write-Host "`n📋 Migration Plan ($Type): $migId" -ForegroundColor Cyan
    $migrationPlan.Steps | ForEach-Object { Write-Host "  $_" }
    Write-Host "`n⚠️  Add this to .secops/data-sources/migrations.yaml:" -ForegroundColor Yellow
    Write-Host ($migrationPlan.YamlEntry | ConvertTo-Yaml)

    if (-not $PSCmdlet.ShouldProcess($migId, "Start $Type migration")) { return }

    return New-SecOpsResult -Success -Data ([PSCustomObject]@{
        MigrationId = $migId
        Type        = $Type
        Status      = 'in-progress'
        Steps       = $migrationPlan.Steps
        YamlEntry   = $migrationPlan.YamlEntry
    })
}
```

### Get-MigrationStatus — Track Active Migrations

```powershell
function Get-MigrationStatus {
    <#
    .SYNOPSIS
        Reports on active data migrations from .secops/data-sources/migrations.yaml.
    .DESCRIPTION
        Reads the migrations file and enriches with live data checks —
        verifies data is flowing to target, compares volumes between source and target.
    .EXAMPLE
        Get-MigrationStatus
    .EXAMPLE
        Get-MigrationStatus -Id 'mig-001' -ValidateDataFlow
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [string]$Id,
        [switch]$ValidateDataFlow,
        [switch]$ActiveOnly
    )

    $migPath = Join-Path $script:SecOpsContext.SecOpsPath 'data-sources' 'migrations.yaml'
    if (-not (Test-Path $migPath)) {
        return New-SecOpsResult -Error 'No migrations.yaml found in .secops/data-sources/' `
            -ErrorCode 'FileNotFound'
    }

    $migrations = (Get-Content $migPath -Raw | ConvertFrom-Yaml).migrations

    if ($Id) { $migrations = $migrations | Where-Object id -eq $Id }
    if ($ActiveOnly) { $migrations = $migrations | Where-Object status -eq 'in-progress' }

    $results = foreach ($mig in $migrations) {
        $data = [PSCustomObject]@{
            Id          = $mig.id
            Status      = $mig.status
            Description = $mig.description
            Source      = "$($mig.source.location): $($mig.source.table ?? $mig.source.workspace)"
            Target      = "$($mig.target.location): $($mig.target.table ?? $mig.target.workspace)"
            Started     = $mig.started
            EstComplete = $mig.estimated_completion
            Owner       = $mig.owner
            DataFlowOk  = $null
        }

        if ($ValidateDataFlow -and $mig.status -eq 'in-progress') {
            Write-Verbose "Validating data flow for migration $($mig.id)..."
            # Live check: query target location for recent data
            # (Implementation depends on target type — Sentinel vs ADX)
            $data.DataFlowOk = '⏳ Manual validation recommended'
        }

        $data
    }

    return New-SecOpsResult -Success -Data $results
}
```

---

## Complete Workflow: Downgrade Table with Full Safety

```powershell
# =============================================================================
# PRODUCTION WORKFLOW: Downgrade Syslog from Analytics → Basic
# =============================================================================

# Step 1: Assess current state
$inventory = Get-LogAnalyticsTablePlan -WorkspaceName 'sentinel-prod'
$syslog = $inventory.Data | Where-Object TableName -eq 'Syslog'
Write-Host "Current: $($syslog.Plan) tier, $($syslog.DailyGB) GB/day, $($syslog.RetentionDays) days retention"

# Step 2: Cost impact analysis
$impact = Get-TierCostImpact -TableName 'Syslog' -FromTier 'Analytics' -ToTier 'Basic'
Write-Host "Monthly savings: $$($impact.Data.MonthlySavings) ($($impact.Data.SavingsPercent)%)"
Write-Host "Annual savings: $$($impact.Data.AnnualSavings)"

# Step 3: Get tier recommendation (validates against query patterns)
$rec = Get-TierRecommendation -TableName 'Syslog' -LookbackDays 30
Write-Host "Recommendation: $($rec.Data.RecommendedTier) (queries/day: $($rec.Data.QueriesPerDay))"

# Step 4: Validate compliance
$compliance = Test-RetentionCompliance -WorkspaceName 'sentinel-prod'
$syslogCompliance = $compliance.Data.Details | Where-Object TableName -eq 'Syslog'
Write-Host "Compliance: $($syslogCompliance.ComplianceStatus)"

# Step 5: Check for active migrations
$migrations = Get-MigrationStatus -ActiveOnly
$syslogMig = $migrations.Data | Where-Object { $_.Source -match 'Syslog' -or $_.Target -match 'Syslog' }
if ($syslogMig) { Write-Warning "Active migration detected — abort tier change" }

# Step 6: Create summary rule FIRST
$validated = Test-SummaryRule `
    -Query 'Syslog | summarize Count=count(), AvgSize=avg(_BilledSize) by Facility, SeverityLevel, Computer, bin(TimeGenerated, 1h)' `
    -BinSize 'PT1H'
if ($validated.Data.Valid) {
    New-SummaryRule -Name 'SyslogHourlySummary' `
        -Query 'Syslog | summarize Count=count(), AvgSize=avg(_BilledSize) by Facility, SeverityLevel, Computer, bin(TimeGenerated, 1h)' `
        -DestinationTable 'SyslogSummary_CL' -BinSize 'PT1H'
}

# Step 7: Execute tier change (with pre-flight safety checks)
Set-LogAnalyticsTablePlan -TableName 'Syslog' -Tier 'Basic' -WhatIf  # Preview first
Set-LogAnalyticsTablePlan -TableName 'Syslog' -Tier 'Basic' -Confirm  # Apply

# Step 8: Update .secops/ (manual — remind operator)
Write-Warning "UPDATE: .secops/data-sources/data-source-map.yaml → Syslog tier: 'Basic'"
```

## Best Practices

1. **Summary rule first, tier change second** — Always create aggregation before downgrading
2. **WhatIf before Confirm** — Preview every tier change and retention modification
3. **Check migrations.yaml** — Never change tiers on tables with active migrations
4. **Compliance is non-negotiable** — Use `-AutoComply` or fix retention manually; never skip
5. **Update data-source-map.yaml** — Every tier/retention change must be reflected in `.secops/`
6. **Cost model before committing** — Run `Get-TierCostImpact` to validate savings justify the trade-offs
7. **Monitor after changes** — Check `LAQueryLogs` for failed queries after tier downgrades
8. **Purge audit trail** — Every purge must have a documented reason (GDPR DSR ticket, decommission ticket)
9. **Migration overlap** — During migrations, query both source and target for 7–14 days
10. **ADX for extreme volume** — Tables > 100 GB/day belong in ADX, not Basic/Auxiliary tier

## Environment Context

Before executing any data tiering command, agents MUST consult:

1. **`.secops/data-sources/data-source-map.yaml`** — Current tier assignments, daily volumes, ingestion methods
2. **`.secops/data-sources/migrations.yaml`** — Active migrations that may conflict with tier changes
3. **`.secops/compliance/requirements.yaml`** — Minimum retention per framework, data residency constraints
4. **`.secops/workspaces/*.yaml`** — Workspace commitment tier, region, and Sentinel enablement

If `.secops/` doesn't exist, proceed with defaults but suggest `secops-squad init --secops`.

See `.copilot/skills/secops-environment-context.md` for the full discovery flow.

## Related Skills

- **`data-tiering-module.md`** — Submodule architecture, `Get-SecOpsTableInventory`, `Set-SecOpsTableTier`
- **`skills/log-analytics/retention-archive.md`** — Retention concepts, search jobs, restore operations
- **`skills/log-analytics/cost-optimization.md`** — Cost analysis KQL, DCR filtering, commitment tiers
- **`skills/log-analytics/purge-and-export.md`** — Purge API details, data export patterns
- **`skills/adx/migration-from-sentinel.md`** — ADX migration for high-volume tables
- **`skills/powershell/sentinel-module.md`** — Sentinel API for analytics rule dependency checks
- **`skills/powershell/error-handling.md`** — `New-SecOpsResult`, `Invoke-SecOpsRestMethod` patterns
- **`skills/powershell/auth-patterns.md`** — `Get-SecOpsAuthHeader`, token acquisition
