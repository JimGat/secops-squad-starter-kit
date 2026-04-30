---
title: Sentinel Submodule
category: powershell
difficulty: intermediate
mitre_attack:
  - T1078  # Valid Accounts (auth context)
  - T1059.001  # PowerShell
  - T1562.001  # Impair Defenses: Disable or Modify Tools
products:
  - Microsoft Sentinel
  - Azure Log Analytics
  - SecurityInsights Resource Provider
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# Sentinel Submodule

## Overview

The Sentinel submodule wraps the `Microsoft.SecurityInsights` Azure resource provider — incident management, analytics rules, workbooks, threat intelligence, and hunting queries. It provides PowerShell functions that combine `Az.SecurityInsights` cmdlets with direct REST API calls for capabilities the SDK doesn't yet cover.

Use this skill when:
- Building incident management automation (list, triage, update, close)
- Managing analytics rules as code (create, update, export, import)
- Working with threat intelligence indicators programmatically
- Exporting or deploying workbooks
- Running hunting queries from PowerShell

## Prerequisites

| Requirement | Detail |
|---|---|
| **Az.SecurityInsights** | `Install-Module Az.SecurityInsights` |
| **Az.OperationalInsights** | For query execution via Log Analytics |
| **Permissions** | `Microsoft Sentinel Contributor` for write ops; `Microsoft Sentinel Reader` for read |
| **Workspace** | Sentinel-enabled Log Analytics workspace |

## REST API Endpoints

The Sentinel submodule wraps these `SecurityInsights` provider endpoints:

| Endpoint Path | Purpose | HTTP Methods |
|---|---|---|
| `.../Microsoft.SecurityInsights/incidents` | Incident CRUD | GET, PUT, DELETE |
| `.../Microsoft.SecurityInsights/incidents/{id}/comments` | Incident comments | GET, PUT |
| `.../Microsoft.SecurityInsights/incidents/{id}/relations` | Incident entities/bookmarks | GET |
| `.../Microsoft.SecurityInsights/alertRules` | Analytics rules | GET, PUT, DELETE |
| `.../Microsoft.SecurityInsights/alertRuleTemplates` | Rule templates | GET |
| `.../Microsoft.SecurityInsights/threatIntelligence/main/indicators` | TI indicators | GET, POST |
| `.../Microsoft.SecurityInsights/bookmarks` | Hunting bookmarks | GET, PUT, DELETE |
| `.../Microsoft.SecurityInsights/dataConnectors` | Data connectors | GET, PUT, DELETE |

**Base URI pattern:**
```
https://management.azure.com/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/
```

## Workspace Context Injection

Every Sentinel function reads workspace context from `.secops/` automatically:

```powershell
function Get-SentinelContext {
    <#
    .SYNOPSIS
        Resolves Sentinel workspace context from .secops/ configuration.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$WorkspaceName
    )

    $env = $script:SecOpsContext.Environment
    if (-not $env) {
        throw "No .secops/environment.yaml found. Run: secops-squad init --secops"
    }

    # Use specified workspace or default
    $wsName = if ($WorkspaceName) { $WorkspaceName } else { $env.default_workspace }

    # Load workspace definition
    $wsFile = Join-Path $script:SecOpsContext.SecOpsPath 'workspaces' "$wsName.yaml"
    if (-not (Test-Path $wsFile)) {
        throw "Workspace config not found: $wsFile"
    }

    $wsConfig = Get-Content $wsFile -Raw | ConvertFrom-Yaml

    return @{
        SubscriptionId = $wsConfig.subscription_id
        ResourceGroup  = $wsConfig.resource_group
        WorkspaceName  = $wsConfig.name
        WorkspaceId    = $wsConfig.workspace_id
        Region         = $wsConfig.region
    }
}
```

## Key Functions

### Get-SecOpsIncident — List and Filter Incidents

```powershell
function Get-SecOpsIncident {
    <#
    .SYNOPSIS
        Lists Sentinel incidents with optional filtering.
    .EXAMPLE
        Get-SecOpsIncident -Severity High -Status Active
    .EXAMPLE
        Get-SecOpsIncident -DaysBack 7 -AssignedTo 'analyst@contoso.com'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$Severity,

        [ValidateSet('New', 'Active', 'Closed')]
        [string]$Status,

        [string]$AssignedTo,

        [int]$DaysBack = 30,

        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName

    # Build OData filter
    $filters = @()
    if ($Severity) { $filters += "properties/severity eq '$Severity'" }
    if ($Status)   { $filters += "properties/status eq '$Status'" }
    $filters += "properties/createdTimeUtc ge $((Get-Date).AddDays(-$DaysBack).ToString('o'))"

    $filterString = $filters -join ' and '

    $uri = "https://management.azure.com/subscriptions/$($ctx.SubscriptionId)" +
           "/resourceGroups/$($ctx.ResourceGroup)" +
           "/providers/Microsoft.OperationalInsights/workspaces/$($ctx.WorkspaceName)" +
           "/providers/Microsoft.SecurityInsights/incidents" +
           "?api-version=2024-03-01&`$filter=$filterString&`$orderby=properties/createdTimeUtc desc"

    $token = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ 'Authorization' = "Bearer $token" }

    $result = Invoke-SecOpsRestMethod -Uri $uri -Headers $headers -OperationName 'Get-SecOpsIncident'

    if ($result.Ok) {
        $incidents = $result.Data.value | ForEach-Object {
            [PSCustomObject]@{
                Id          = $_.properties.incidentNumber
                Title       = $_.properties.title
                Severity    = $_.properties.severity
                Status      = $_.properties.status
                AssignedTo  = $_.properties.owner.assignedTo
                CreatedTime = $_.properties.createdTimeUtc
                AlertCount  = $_.properties.additionalData.alertsCount
                ResourceId  = $_.name
            }
        }

        if ($AssignedTo) {
            $incidents = $incidents | Where-Object { $_.AssignedTo -eq $AssignedTo }
        }

        return New-SecOpsResult -Success -Data $incidents
    }

    return $result
}
```

### New-SecOpsAnalyticsRule — Create a Scheduled Analytics Rule

```powershell
function New-SecOpsAnalyticsRule {
    <#
    .SYNOPSIS
        Creates a scheduled analytics rule in Sentinel.
    .EXAMPLE
        New-SecOpsAnalyticsRule -DisplayName "Brute Force Detection" `
            -Query "SigninLogs | where ResultType == '50126' | summarize count() by UserPrincipalName, bin(TimeGenerated, 1h) | where count_ > 10" `
            -Severity High -QueryFrequency "PT1H" -QueryPeriod "PT1H"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$DisplayName,

        [Parameter(Mandatory)]
        [string]$Query,

        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$Severity = 'Medium',

        [string]$QueryFrequency = 'PT5H',

        [string]$QueryPeriod = 'PT5H',

        [string]$Description = '',

        [string[]]$Tactics = @(),

        [string[]]$Techniques = @(),

        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $ruleId = [guid]::NewGuid().ToString()

    $body = @{
        kind       = 'Scheduled'
        properties = @{
            displayName        = $DisplayName
            description        = $Description
            severity           = $Severity
            query              = $Query
            queryFrequency     = $QueryFrequency
            queryPeriod        = $QueryPeriod
            triggerOperator    = 'GreaterThan'
            triggerThreshold   = 0
            tactics            = $Tactics
            techniques         = $Techniques
            enabled            = $true
            suppressionEnabled = $false
            incidentConfiguration = @{
                createIncident        = $true
                groupingConfiguration = @{
                    enabled              = $true
                    reopenClosedIncident = $false
                    lookbackDuration     = 'PT5H'
                    matchingMethod       = 'AllEntities'
                }
            }
        }
    }

    if (-not $PSCmdlet.ShouldProcess($DisplayName, 'Create Analytics Rule')) {
        return
    }

    $uri = "https://management.azure.com/subscriptions/$($ctx.SubscriptionId)" +
           "/resourceGroups/$($ctx.ResourceGroup)" +
           "/providers/Microsoft.OperationalInsights/workspaces/$($ctx.WorkspaceName)" +
           "/providers/Microsoft.SecurityInsights/alertRules/$ruleId" +
           "?api-version=2024-03-01"

    $token = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ 'Authorization' = "Bearer $token" }

    return Invoke-SecOpsRestMethod -Uri $uri -Method PUT -Body $body `
        -Headers $headers -OperationName 'New-SecOpsAnalyticsRule'
}
```

### Invoke-SecOpsHuntingQuery — Run KQL Hunting Queries

```powershell
function Invoke-SecOpsHuntingQuery {
    <#
    .SYNOPSIS
        Executes a KQL hunting query against a Sentinel workspace.
    .EXAMPLE
        Invoke-SecOpsHuntingQuery -Query "SecurityAlert | summarize count() by AlertName | top 10 by count_"
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Query,

        [string]$Timespan = 'P7D',

        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName

    $result = Invoke-AzOperationalInsightsQuery `
        -WorkspaceId $ctx.WorkspaceId `
        -Query $Query `
        -Timespan $Timespan `
        -ErrorAction SilentlyContinue `
        -ErrorVariable queryError

    if ($queryError) {
        return New-SecOpsResult -Error $queryError[0].Exception.Message -ErrorCode 'QueryFailed'
    }

    return New-SecOpsResult -Success -Data $result.Results
}
```

### Export-SecOpsWorkbook — Export a Sentinel Workbook

```powershell
function Export-SecOpsWorkbook {
    <#
    .SYNOPSIS
        Exports a Sentinel workbook to JSON for version control.
    .EXAMPLE
        Export-SecOpsWorkbook -WorkbookName "SOC Dashboard" -OutputPath "./workbooks/"
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$WorkbookName,

        [string]$OutputPath = '.',

        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName

    # List workbooks
    $uri = "https://management.azure.com/subscriptions/$($ctx.SubscriptionId)" +
           "/resourceGroups/$($ctx.ResourceGroup)" +
           "/providers/Microsoft.Insights/workbooks" +
           "?api-version=2022-04-01&category=sentinel&canFetchContent=true"

    $token = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ 'Authorization' = "Bearer $token" }

    $result = Invoke-SecOpsRestMethod -Uri $uri -Headers $headers -OperationName 'Export-SecOpsWorkbook'

    if (-not $result.Ok) { return $result }

    $workbook = $result.Data.value |
        Where-Object { $_.properties.displayName -eq $WorkbookName } |
        Select-Object -First 1

    if (-not $workbook) {
        return New-SecOpsResult -Error "Workbook '$WorkbookName' not found" -ErrorCode 'NotFound'
    }

    # Write workbook JSON to file
    $fileName = ($WorkbookName -replace '[^\w\-]', '_') + '.json'
    $filePath = Join-Path $OutputPath $fileName
    $workbook | ConvertTo-Json -Depth 20 | Set-Content -Path $filePath -Encoding utf8

    return New-SecOpsResult -Success -Data @{
        Path     = $filePath
        Name     = $WorkbookName
        Exported = [DateTimeOffset]::UtcNow.ToString('o')
    }
}
```

## Best Practices

1. **Always resolve workspace from `.secops/`** — Never hardcode workspace IDs
2. **Use `ShouldProcess`** — All write operations support `-WhatIf` and `-Confirm`
3. **Validate KQL before deploying** — Run queries through `secops-squad kql validate` before creating analytics rules
4. **Version-control workbooks** — Export workbooks to JSON and track in Git
5. **MITRE ATT&CK tagging** — Include tactics and techniques on analytics rules for coverage mapping
6. **Pagination** — Handle `nextLink` for large incident lists (the REST wrapper handles this automatically)

## Environment Context

Before using Sentinel functions, agents MUST consult:

- **`.secops/environment.yaml`** — Default workspace, subscription, cloud type
- **`.secops/workspaces/*.yaml`** — Workspace-specific configuration
- **`.secops/data-sources/data-source-map.yaml`** — Which tables are in Sentinel vs ADX
- **`.secops/data-sources/migrations.yaml`** — Active migrations that may affect table locations

## Related Skills

- `skills/kql/threat-hunting.md` — KQL queries to use with `Invoke-SecOpsHuntingQuery`
- `skills/kql/analytics-rules.md` — Rule query patterns for `New-SecOpsAnalyticsRule`
- `skills/log-analytics/workspace-architecture.md` — Workspace topology context
- `skills/powershell/auth-patterns.md` — Authentication for Sentinel API access
- `skills/powershell/error-handling.md` — Error handling for Sentinel REST calls
