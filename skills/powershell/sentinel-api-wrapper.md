---
title: Sentinel REST API Wrapper — Production PowerShell Functions
category: powershell
difficulty: advanced
mitre_attack:
  - T1059.001  # PowerShell
  - T1078      # Valid Accounts
  - T1562.001  # Impair Defenses: Disable or Modify Tools
  - T1190      # Exploit Public-Facing Application
  - T1530      # Data from Cloud Storage
products:
  - Microsoft Sentinel
  - Azure Log Analytics
  - SecurityInsights Resource Provider
  - Azure Resource Manager
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# Sentinel REST API Wrapper — Production PowerShell Functions

## Overview

Production-ready PowerShell wrappers for the full Microsoft Sentinel REST API surface. Every function uses `.secops/workspaces/` for workspace discovery, returns `SecOps.Result` structured objects (see `error-handling.md`), handles pagination automatically, and respects ARM rate limits.

**Complements:**
- `sentinel-module.md` — submodule architecture overview with foundational functions (`Get-SentinelContext`, `Get-SecOpsIncident`, `New-SecOpsAnalyticsRule`, `Export-SecOpsWorkbook`)
- `sentinel-api-reference.md` — raw REST endpoint reference
- `sentinel-mcp-server.md` — MCP-based agent access (this skill covers the PowerShell angle)

**This skill adds:** bulk operations, incident relations, rule templates, TI lifecycle, watchlists, data connector management, workbook import, and advanced pagination — none of which are in sentinel-module.md.

## Prerequisites

| Requirement | Detail |
|---|---|
| **Az.Accounts** | Token acquisition via `Get-AzAccessToken` |
| **Az.SecurityInsights** | Optional — used where cmdlet approach is shown |
| **Permissions** | `Microsoft Sentinel Contributor` for writes; `Reader` for reads |
| **API Version** | `2024-03-01` (stable) throughout |
| **.secops/** | Workspace configs in `.secops/workspaces/*.yaml` |

## Shared Helpers

Every function below depends on `Get-SentinelContext` (defined in `sentinel-module.md`) and these two helpers:

```powershell
function Get-SentinelBaseUri {
    <#
    .SYNOPSIS
        Builds the SecurityInsights base URI from workspace context.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Context
    )

    $cloud = Get-SecOpsCloudEnvironment  # from auth-patterns.md
    $baseUrl = switch ($cloud) {
        'AzureUSGovernment' { 'https://management.usgovcloudapi.net' }
        'AzureChinaCloud'   { 'https://management.chinacloudapi.cn' }
        default             { 'https://management.azure.com' }
    }

    return "$baseUrl/subscriptions/$($Context.SubscriptionId)" +
           "/resourceGroups/$($Context.ResourceGroup)" +
           "/providers/Microsoft.OperationalInsights/workspaces/$($Context.WorkspaceName)" +
           "/providers/Microsoft.SecurityInsights"
}

function Invoke-SentinelApi {
    <#
    .SYNOPSIS
        Thin wrapper: resolves token, builds headers, delegates to Invoke-SecOpsRestMethod.
        Handles nextLink pagination automatically for GET requests.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'GET',
        [object]$Body,
        [string]$OperationName = 'Sentinel API',
        [switch]$NoPagination
    )

    $cloud = Get-SecOpsCloudEnvironment
    $resource = switch ($cloud) {
        'AzureUSGovernment' { 'https://management.usgovcloudapi.net' }
        'AzureChinaCloud'   { 'https://management.chinacloudapi.cn' }
        default             { 'https://management.azure.com' }
    }
    $token = (Get-AzAccessToken -ResourceUrl $resource).Token
    $headers = @{ 'Authorization' = "Bearer $token" }

    if ($Method -ne 'GET' -or $NoPagination) {
        return Invoke-SecOpsRestMethod -Uri $Uri -Method $Method -Body $Body `
            -Headers $headers -OperationName $OperationName
    }

    # Auto-paginate GET requests
    $allItems = @()
    $currentUri = $Uri
    $page = 0

    while ($currentUri) {
        $page++
        Write-Verbose "$OperationName — fetching page $page"
        $result = Invoke-SecOpsRestMethod -Uri $currentUri -Headers $headers `
            -OperationName "$OperationName (page $page)"

        if (-not $result.Ok) { return $result }

        if ($result.Data.value) {
            $allItems += $result.Data.value
        }
        $currentUri = $result.Data.nextLink
    }

    return New-SecOpsResult -Success -Data $allItems
}
```

---

## 1 — Incident Management

### Update-SentinelIncident

Updates incident properties — severity, status, owner, classification. Supports `ShouldProcess` for safety.

```powershell
function Update-SentinelIncident {
    <#
    .SYNOPSIS
        Updates a Sentinel incident (severity, status, owner, classification).
    .EXAMPLE
        Update-SentinelIncident -IncidentId 'abc-123' -Status Active -Severity High
    .EXAMPLE
        Update-SentinelIncident -IncidentId 'abc-123' -AssignTo 'analyst@contoso.com'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$IncidentId,

        [ValidateSet('New', 'Active', 'Closed')]
        [string]$Status,

        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$Severity,

        [string]$AssignTo,

        [ValidateSet('BenignPositive', 'FalsePositive', 'TruePositive', 'Undetermined')]
        [string]$Classification,

        [string]$ClassificationComment,

        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $base = Get-SentinelBaseUri -Context $ctx

    # GET current incident (required — PUT needs full properties + etag)
    $getUri = "$base/incidents/$IncidentId`?api-version=2024-03-01"
    $current = Invoke-SentinelApi -Uri $getUri -OperationName 'Get incident for update' -NoPagination

    if (-not $current.Ok) { return $current }

    $incident = $current.Data

    # Apply changes
    if ($Status)      { $incident.properties.status = $Status }
    if ($Severity)    { $incident.properties.severity = $Severity }
    if ($Classification) {
        $incident.properties.classification = $Classification
        if ($ClassificationComment) {
            $incident.properties.classificationComment = $ClassificationComment
        }
    }
    if ($AssignTo) {
        $incident.properties.owner = @{
            assignedTo    = $AssignTo
            objectId      = $null  # Entra ID resolves by email
            userPrincipalName = $AssignTo
        }
    }

    if (-not $PSCmdlet.ShouldProcess("Incident $IncidentId", 'Update')) { return }

    return Invoke-SentinelApi -Uri $getUri -Method PUT -Body $incident `
        -OperationName 'Update-SentinelIncident'
}
```

### Close-SentinelIncident

Closes an incident with classification and reason — enforces required fields.

```powershell
function Close-SentinelIncident {
    <#
    .SYNOPSIS
        Closes a Sentinel incident with classification.
    .EXAMPLE
        Close-SentinelIncident -IncidentId 'abc-123' -Classification FalsePositive `
            -ClassificationComment 'Known test activity from pen test team'
    .EXAMPLE
        Close-SentinelIncident -IncidentId 'abc-123' -Classification TruePositive `
            -ClassificationReason SuspiciousActivity
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$IncidentId,

        [Parameter(Mandatory)]
        [ValidateSet('BenignPositive', 'FalsePositive', 'TruePositive', 'Undetermined')]
        [string]$Classification,

        [string]$ClassificationComment = '',

        [ValidateSet('SuspiciousActivity', 'SuspiciousButExpected', 'IncorrectAlertLogic',
                      'InaccurateData')]
        [string]$ClassificationReason,

        [string]$WorkspaceName
    )

    return Update-SentinelIncident -IncidentId $IncidentId -Status Closed `
        -Classification $Classification -ClassificationComment $ClassificationComment `
        -WorkspaceName $WorkspaceName
}
```

### Invoke-SentinelBulkIncidentClose

Mass-close incidents matching a filter — essential for tuning noisy rules.

```powershell
function Invoke-SentinelBulkIncidentClose {
    <#
    .SYNOPSIS
        Bulk-closes Sentinel incidents matching a filter.
    .EXAMPLE
        # Close all low-severity informational incidents older than 30 days
        Invoke-SentinelBulkIncidentClose -Severity Informational `
            -OlderThanDays 30 -Classification FalsePositive `
            -ClassificationComment 'Bulk close — aged out informational alerts'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$Severity,

        [string]$TitleContains,
        [int]$OlderThanDays = 30,

        [Parameter(Mandatory)]
        [ValidateSet('BenignPositive', 'FalsePositive', 'TruePositive', 'Undetermined')]
        [string]$Classification,

        [string]$ClassificationComment = 'Bulk close operation',
        [string]$WorkspaceName
    )

    # Fetch matching open incidents
    $incidents = Get-SecOpsIncident -Severity $Severity -Status New `
        -DaysBack $OlderThanDays -WorkspaceName $WorkspaceName

    if (-not $incidents.Ok) { return $incidents }

    $targets = $incidents.Data
    if ($TitleContains) {
        $targets = $targets | Where-Object { $_.Title -like "*$TitleContains*" }
    }

    if ($targets.Count -eq 0) {
        return New-SecOpsResult -Success -Data @{ Closed = 0; Message = 'No matching incidents' }
    }

    if (-not $PSCmdlet.ShouldProcess("$($targets.Count) incidents", 'Bulk close')) { return }

    $results = Invoke-SecOpsBatchOperation -Items $targets -BatchSize 10 `
        -DelayBetweenBatchesMs 3000 -Operation {
            param($incident)
            Close-SentinelIncident -IncidentId $incident.ResourceId `
                -Classification $Classification `
                -ClassificationComment $ClassificationComment `
                -WorkspaceName $WorkspaceName
        }

    $succeeded = ($results | Where-Object { $_.Ok }).Count
    $failed = ($results | Where-Object { -not $_.Ok }).Count

    return New-SecOpsResult -Success -Data @{
        Closed   = $succeeded
        Failed   = $failed
        Total    = $targets.Count
    }
}
```

### Add-SentinelIncidentComment

```powershell
function Add-SentinelIncidentComment {
    <#
    .SYNOPSIS
        Adds a comment to a Sentinel incident.
    .EXAMPLE
        Add-SentinelIncidentComment -IncidentId 'abc-123' `
            -Message 'Escalated to Tier 2 — possible lateral movement detected'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$IncidentId,
        [Parameter(Mandatory)][string]$Message,
        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $base = Get-SentinelBaseUri -Context $ctx
    $commentId = [guid]::NewGuid().ToString()

    $uri = "$base/incidents/$IncidentId/comments/$commentId`?api-version=2024-03-01"
    $body = @{ properties = @{ message = $Message } }

    if (-not $PSCmdlet.ShouldProcess("Incident $IncidentId", 'Add comment')) { return }

    return Invoke-SentinelApi -Uri $uri -Method PUT -Body $body `
        -OperationName 'Add-SentinelIncidentComment'
}
```

### Get-SentinelIncidentRelations

Retrieves alerts, bookmarks, and entities linked to an incident.

```powershell
function Get-SentinelIncidentRelations {
    <#
    .SYNOPSIS
        Gets entities, alerts, and bookmarks related to a Sentinel incident.
    .EXAMPLE
        Get-SentinelIncidentRelations -IncidentId 'abc-123' | Select-Object -Expand Data
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$IncidentId,
        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $base = Get-SentinelBaseUri -Context $ctx

    # Parallel: relations + entities + alerts
    $relationsUri = "$base/incidents/$IncidentId/relations?api-version=2024-03-01"
    $entitiesUri  = "$base/incidents/$IncidentId/entities?api-version=2024-03-01"
    $alertsUri    = "$base/incidents/$IncidentId/alerts?api-version=2024-03-01"

    $relations = Invoke-SentinelApi -Uri $relationsUri -OperationName 'Get relations'
    $entities  = Invoke-SentinelApi -Uri $entitiesUri -Method POST -Body @{} `
        -OperationName 'Get entities'
    $alerts    = Invoke-SentinelApi -Uri $alertsUri -Method POST -Body @{} `
        -OperationName 'Get alerts'

    return New-SecOpsResult -Success -Data @{
        Relations = if ($relations.Ok) { $relations.Data } else { @() }
        Entities  = if ($entities.Ok)  { $entities.Data.entities } else { @() }
        Alerts    = if ($alerts.Ok)    { $alerts.Data.value } else { @() }
    }
}
```

### Az.SecurityInsights Cmdlet Approach

```powershell
# List incidents — cmdlet approach (simpler but less control)
Get-AzSentinelIncident -ResourceGroupName 'rg-soc-prod' -WorkspaceName 'soc-sentinel-prod' |
    Where-Object { $_.Status -eq 'New' -and $_.Severity -eq 'High' }

# Update incident — cmdlet approach
Update-AzSentinelIncident -ResourceGroupName 'rg-soc-prod' -WorkspaceName 'soc-sentinel-prod' `
    -IncidentId 'abc-123' -Status 'Active' -Severity 'High' `
    -OwnerAssignedTo 'analyst@contoso.com'
```

---

## 2 — Analytics Rules

### Get-SentinelAnalyticsRule

Retrieves all rules or a single rule, with optional filtering by kind or enabled status.

```powershell
function Get-SentinelAnalyticsRule {
    <#
    .SYNOPSIS
        Lists or gets Sentinel analytics rules with filtering.
    .EXAMPLE
        Get-SentinelAnalyticsRule -Kind Scheduled -EnabledOnly
    .EXAMPLE
        Get-SentinelAnalyticsRule -RuleId 'abc-123-def'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$RuleId,

        [ValidateSet('Scheduled', 'NRT', 'Fusion', 'MLBehaviorAnalytics', 'MicrosoftSecurityIncidentCreation')]
        [string]$Kind,

        [switch]$EnabledOnly,
        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $base = Get-SentinelBaseUri -Context $ctx

    if ($RuleId) {
        $uri = "$base/alertRules/$RuleId`?api-version=2024-03-01"
        return Invoke-SentinelApi -Uri $uri -OperationName 'Get rule' -NoPagination
    }

    $uri = "$base/alertRules?api-version=2024-03-01"
    $result = Invoke-SentinelApi -Uri $uri -OperationName 'List analytics rules'

    if (-not $result.Ok) { return $result }

    $rules = $result.Data
    if ($Kind)        { $rules = $rules | Where-Object { $_.kind -eq $Kind } }
    if ($EnabledOnly) { $rules = $rules | Where-Object { $_.properties.enabled -eq $true } }

    return New-SecOpsResult -Success -Data $rules
}
```

### New-SentinelNrtRule

Creates a Near-Real-Time (NRT) analytics rule — similar to scheduled but runs every minute.

```powershell
function New-SentinelNrtRule {
    <#
    .SYNOPSIS
        Creates a Near-Real-Time (NRT) analytics rule.
    .DESCRIPTION
        NRT rules run approximately every minute. No QueryFrequency/QueryPeriod needed.
    .EXAMPLE
        New-SentinelNrtRule -DisplayName 'NRT: Critical DLP Policy Match' `
            -Query 'InformationProtectionLogs_CL | where PolicyAction == "Block"' `
            -Severity High -Tactics @('Exfiltration') -Techniques @('T1041')
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$Query,
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$Severity = 'Medium',
        [string]$Description = '',
        [string[]]$Tactics = @(),
        [string[]]$Techniques = @(),
        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $base = Get-SentinelBaseUri -Context $ctx
    $ruleId = [guid]::NewGuid().ToString()

    $body = @{
        kind       = 'NRT'
        properties = @{
            displayName      = $DisplayName
            description      = $Description
            severity         = $Severity
            query            = $Query
            tactics          = $Tactics
            techniques       = $Techniques
            enabled          = $true
            suppressionEnabled   = $false
            suppressionDuration  = 'PT5H'
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

    if (-not $PSCmdlet.ShouldProcess($DisplayName, 'Create NRT rule')) { return }

    $uri = "$base/alertRules/$ruleId`?api-version=2024-03-01"
    return Invoke-SentinelApi -Uri $uri -Method PUT -Body $body `
        -OperationName 'New-SentinelNrtRule'
}
```

### New-SentinelRuleFromTemplate

Instantiates an analytics rule from a built-in template — the gallery-to-production workflow.

```powershell
function New-SentinelRuleFromTemplate {
    <#
    .SYNOPSIS
        Creates an analytics rule from a Sentinel rule template.
    .DESCRIPTION
        Lists templates, finds the matching one, and creates a live rule from it.
    .EXAMPLE
        New-SentinelRuleFromTemplate -TemplateName 'Brute force attack against Azure Portal'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$TemplateName,
        [switch]$Disabled,
        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $base = Get-SentinelBaseUri -Context $ctx

    # List all templates
    $templatesUri = "$base/alertRuleTemplates?api-version=2024-03-01"
    $templates = Invoke-SentinelApi -Uri $templatesUri -OperationName 'List rule templates'

    if (-not $templates.Ok) { return $templates }

    $template = $templates.Data |
        Where-Object { $_.properties.displayName -like "*$TemplateName*" } |
        Select-Object -First 1

    if (-not $template) {
        return New-SecOpsResult -Error "Template not found: $TemplateName" -ErrorCode 'NotFound'
    }

    $ruleId = [guid]::NewGuid().ToString()
    $body = @{
        kind       = $template.kind
        properties = @{
            displayName          = $template.properties.displayName
            description          = $template.properties.description
            severity             = $template.properties.severity
            query                = $template.properties.query
            queryFrequency       = $template.properties.queryFrequency
            queryPeriod          = $template.properties.queryPeriod
            triggerOperator      = $template.properties.triggerOperator
            triggerThreshold     = $template.properties.triggerThreshold
            tactics              = $template.properties.tactics
            techniques           = $template.properties.techniques
            enabled              = (-not $Disabled)
            alertRuleTemplateName = $template.name
            templateVersion      = $template.properties.version
        }
    }

    if (-not $PSCmdlet.ShouldProcess($template.properties.displayName, 'Create rule from template')) {
        return
    }

    $uri = "$base/alertRules/$ruleId`?api-version=2024-03-01"
    return Invoke-SentinelApi -Uri $uri -Method PUT -Body $body `
        -OperationName 'New-SentinelRuleFromTemplate'
}
```

### Test-SentinelRuleQuery

Validates a KQL query against the workspace before enabling a rule — prevents broken rules.

```powershell
function Test-SentinelRuleQuery {
    <#
    .SYNOPSIS
        Tests a KQL query against the workspace to validate it before rule creation.
    .DESCRIPTION
        Runs the query with a 1-row limit. If it returns without error, the query is valid.
    .EXAMPLE
        Test-SentinelRuleQuery -Query 'SigninLogs | where ResultType == "50126"'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$Query,
        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName

    # Wrap query with limit to avoid scanning large datasets
    $testQuery = "$Query | take 1"

    $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $ctx.WorkspaceId `
        -Query $testQuery -Timespan 'P1D' `
        -ErrorAction SilentlyContinue -ErrorVariable queryError

    if ($queryError) {
        return New-SecOpsResult -Error $queryError[0].Exception.Message `
            -ErrorCode 'InvalidQuery'
    }

    return New-SecOpsResult -Success -Data @{
        Valid      = $true
        RowCount   = $result.Results.Count
        Message    = 'Query is valid and executable against this workspace'
    }
}
```

### Set-SentinelRulesByMitreTechnique

Bulk enable or disable rules matching a MITRE ATT&CK technique.

```powershell
function Set-SentinelRulesByMitreTechnique {
    <#
    .SYNOPSIS
        Bulk enable/disable analytics rules by MITRE technique.
    .EXAMPLE
        Set-SentinelRulesByMitreTechnique -Technique 'T1078' -Enabled $true
    .EXAMPLE
        Set-SentinelRulesByMitreTechnique -Technique 'T1059' -Enabled $false -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$Technique,
        [Parameter(Mandatory)][bool]$Enabled,
        [string]$WorkspaceName
    )

    $rules = Get-SentinelAnalyticsRule -WorkspaceName $WorkspaceName
    if (-not $rules.Ok) { return $rules }

    $matching = $rules.Data | Where-Object {
        $_.properties.techniques -contains $Technique
    }

    if ($matching.Count -eq 0) {
        return New-SecOpsResult -Success -Data @{
            Updated = 0; Message = "No rules matched technique $Technique"
        }
    }

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $base = Get-SentinelBaseUri -Context $ctx
    $action = if ($Enabled) { 'Enable' } else { 'Disable' }

    if (-not $PSCmdlet.ShouldProcess("$($matching.Count) rules", "$action by $Technique")) {
        return
    }

    $results = Invoke-SecOpsBatchOperation -Items $matching -BatchSize 10 `
        -DelayBetweenBatchesMs 2000 -Operation {
            param($rule)
            $rule.properties.enabled = $Enabled
            $ruleUri = "$base/alertRules/$($rule.name)?api-version=2024-03-01"
            Invoke-SentinelApi -Uri $ruleUri -Method PUT -Body $rule `
                -OperationName "Set rule $($rule.properties.displayName)"
        }

    $succeeded = ($results | Where-Object { $_.Ok }).Count
    return New-SecOpsResult -Success -Data @{
        Updated = $succeeded; Failed = $results.Count - $succeeded; Technique = $Technique
    }
}
```

---

## 3 — Threat Intelligence

### Import-SentinelThreatIntel

Creates a single TI indicator — STIX-compatible properties.

```powershell
function Import-SentinelThreatIntel {
    <#
    .SYNOPSIS
        Creates a threat intelligence indicator in Sentinel.
    .EXAMPLE
        Import-SentinelThreatIntel -PatternType 'ipv4-addr' `
            -Pattern '203.0.113.50' -ThreatType 'malicious-activity' `
            -Description 'C2 server observed in phishing campaign' `
            -Confidence 85 -ValidDays 90
    .EXAMPLE
        Import-SentinelThreatIntel -PatternType 'domain-name' `
            -Pattern 'evil-domain.example' -ThreatType 'malware' `
            -Source 'Internal IR Team' -Tags @('campaign-2026q1', 'apt-group-x')
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ipv4-addr', 'ipv6-addr', 'domain-name', 'url',
                     'file', 'email-addr', 'windows-registry-key')]
        [string]$PatternType,

        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$ThreatType,
        [string]$Description = '',
        [string]$Source = 'SecOps PowerShell',
        [int]$Confidence = 80,
        [int]$ValidDays = 90,
        [string[]]$Tags = @(),
        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $base = Get-SentinelBaseUri -Context $ctx

    $stixPattern = "[$PatternType`:value = '$Pattern']"
    $validUntil = (Get-Date).AddDays($ValidDays).ToUniversalTime().ToString('o')

    $body = @{
        kind       = 'indicator'
        properties = @{
            patternType       = $PatternType
            pattern           = $stixPattern
            threatTypes       = @($ThreatType)
            description       = $Description
            source            = $Source
            confidence        = $Confidence
            validFrom         = (Get-Date).ToUniversalTime().ToString('o')
            validUntil        = $validUntil
            displayName       = "$PatternType`: $Pattern"
            labels            = $Tags
        }
    }

    if (-not $PSCmdlet.ShouldProcess("$PatternType=$Pattern", 'Import TI indicator')) {
        return
    }

    $uri = "$base/threatIntelligence/main/createIndicator?api-version=2024-03-01"
    return Invoke-SentinelApi -Uri $uri -Method POST -Body $body `
        -OperationName 'Import-SentinelThreatIntel'
}
```

### Get-SentinelTIIndicator

Queries existing TI indicators with OData filtering.

```powershell
function Get-SentinelTIIndicator {
    <#
    .SYNOPSIS
        Queries Sentinel TI indicators with optional filtering.
    .EXAMPLE
        Get-SentinelTIIndicator -PatternType 'ipv4-addr' -MinConfidence 70
    .EXAMPLE
        Get-SentinelTIIndicator -Source 'TAXII Feed' -DaysBack 30
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$PatternType,
        [string]$Source,
        [int]$MinConfidence,
        [int]$DaysBack = 90,
        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $base = Get-SentinelBaseUri -Context $ctx

    $uri = "$base/threatIntelligence/main/indicators?api-version=2024-03-01"
    $result = Invoke-SentinelApi -Uri $uri -OperationName 'Get-SentinelTIIndicator'

    if (-not $result.Ok) { return $result }

    $indicators = $result.Data
    $cutoff = (Get-Date).AddDays(-$DaysBack)

    if ($PatternType) {
        $indicators = $indicators | Where-Object {
            $_.properties.patternType -eq $PatternType
        }
    }
    if ($Source) {
        $indicators = $indicators | Where-Object {
            $_.properties.source -like "*$Source*"
        }
    }
    if ($MinConfidence) {
        $indicators = $indicators | Where-Object {
            $_.properties.confidence -ge $MinConfidence
        }
    }

    return New-SecOpsResult -Success -Data ($indicators | ForEach-Object {
        [PSCustomObject]@{
            DisplayName = $_.properties.displayName
            PatternType = $_.properties.patternType
            Pattern     = $_.properties.pattern
            Confidence  = $_.properties.confidence
            Source      = $_.properties.source
            ThreatTypes = $_.properties.threatTypes -join ', '
            ValidUntil  = $_.properties.validUntil
            ResourceId  = $_.name
        }
    })
}
```

### Import-SentinelTIBulk

Bulk-imports TI indicators from a CSV file.

```powershell
function Import-SentinelTIBulk {
    <#
    .SYNOPSIS
        Bulk-imports TI indicators from CSV.
    .DESCRIPTION
        CSV must have columns: PatternType, Pattern, ThreatType, Confidence, Description.
        Optional: Source, ValidDays, Tags (semicolon-separated).
    .EXAMPLE
        Import-SentinelTIBulk -CsvPath './ti-feeds/blocklist.csv' -Source 'OSINT Feed'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$CsvPath,
        [string]$Source = 'Bulk CSV Import',
        [int]$DefaultValidDays = 90,
        [string]$WorkspaceName
    )

    if (-not (Test-Path $CsvPath)) {
        return New-SecOpsResult -Error "CSV not found: $CsvPath" -ErrorCode 'FileNotFound'
    }

    $rows = Import-Csv -Path $CsvPath
    Write-Host "Loaded $($rows.Count) indicators from $CsvPath"

    if (-not $PSCmdlet.ShouldProcess("$($rows.Count) indicators from $CsvPath", 'Bulk import')) {
        return
    }

    $results = Invoke-SecOpsBatchOperation -Items $rows -BatchSize 20 `
        -DelayBetweenBatchesMs 3000 -Operation {
            param($row)
            Import-SentinelThreatIntel `
                -PatternType $row.PatternType `
                -Pattern $row.Pattern `
                -ThreatType $row.ThreatType `
                -Description ($row.Description ?? '') `
                -Source ($row.Source ?? $Source) `
                -Confidence ([int]($row.Confidence ?? 80)) `
                -ValidDays ([int]($row.ValidDays ?? $DefaultValidDays)) `
                -Tags (if ($row.Tags) { $row.Tags -split ';' } else { @() }) `
                -WorkspaceName $WorkspaceName
        }

    $succeeded = ($results | Where-Object { $_.Ok }).Count
    return New-SecOpsResult -Success -Data @{
        Imported = $succeeded
        Failed   = $results.Count - $succeeded
        Total    = $rows.Count
        Source   = $CsvPath
    }
}
```

---

## 4 — Workbooks

### Import-SentinelWorkbook

Imports a workbook JSON into a workspace — the complement to `Export-SecOpsWorkbook` in sentinel-module.md.

```powershell
function Import-SentinelWorkbook {
    <#
    .SYNOPSIS
        Imports a workbook from JSON into a Sentinel workspace.
    .DESCRIPTION
        Reads a workbook JSON (exported via Export-SecOpsWorkbook) and creates it in
        the target workspace. Supports cross-workspace migration.
    .EXAMPLE
        Import-SentinelWorkbook -JsonPath './workbooks/SOC_Dashboard.json'
    .EXAMPLE
        Import-SentinelWorkbook -JsonPath './workbooks/SOC_Dashboard.json' `
            -WorkspaceName 'soc-sentinel-staging' -NewDisplayName 'SOC Dashboard (Staging)'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$JsonPath,
        [string]$NewDisplayName,
        [string]$WorkspaceName
    )

    if (-not (Test-Path $JsonPath)) {
        return New-SecOpsResult -Error "File not found: $JsonPath" -ErrorCode 'FileNotFound'
    }

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $workbook = Get-Content $JsonPath -Raw | ConvertFrom-Json

    $displayName = if ($NewDisplayName) { $NewDisplayName }
                   else { $workbook.properties.displayName }

    $workbookId = [guid]::NewGuid().ToString()

    $body = @{
        location   = $ctx.Region
        kind       = 'shared'
        properties = @{
            displayName    = $displayName
            serializedData = $workbook.properties.serializedData
            category       = 'sentinel'
            sourceId       = "microsoft.operationalinsights/workspaces/$($ctx.WorkspaceName)"
        }
    }

    if (-not $PSCmdlet.ShouldProcess($displayName, 'Import workbook')) { return }

    # Workbooks use Microsoft.Insights provider (not SecurityInsights)
    $cloud = Get-SecOpsCloudEnvironment
    $baseUrl = switch ($cloud) {
        'AzureUSGovernment' { 'https://management.usgovcloudapi.net' }
        'AzureChinaCloud'   { 'https://management.chinacloudapi.cn' }
        default             { 'https://management.azure.com' }
    }
    $uri = "$baseUrl/subscriptions/$($ctx.SubscriptionId)" +
           "/resourceGroups/$($ctx.ResourceGroup)" +
           "/providers/Microsoft.Insights/workbooks/$workbookId" +
           "?api-version=2022-04-01"

    return Invoke-SentinelApi -Uri $uri -Method PUT -Body $body `
        -OperationName 'Import-SentinelWorkbook'
}
```

### Get-SentinelWorkbook

Lists workbooks with optional category and name filtering.

```powershell
function Get-SentinelWorkbook {
    <#
    .SYNOPSIS
        Lists Sentinel workbooks in a workspace.
    .EXAMPLE
        Get-SentinelWorkbook -NameFilter 'SOC'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$NameFilter,
        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $cloud = Get-SecOpsCloudEnvironment
    $baseUrl = switch ($cloud) {
        'AzureUSGovernment' { 'https://management.usgovcloudapi.net' }
        'AzureChinaCloud'   { 'https://management.chinacloudapi.cn' }
        default             { 'https://management.azure.com' }
    }

    $uri = "$baseUrl/subscriptions/$($ctx.SubscriptionId)" +
           "/resourceGroups/$($ctx.ResourceGroup)" +
           "/providers/Microsoft.Insights/workbooks" +
           "?api-version=2022-04-01&category=sentinel"

    $result = Invoke-SentinelApi -Uri $uri -OperationName 'Get-SentinelWorkbook'
    if (-not $result.Ok) { return $result }

    $workbooks = $result.Data
    if ($NameFilter) {
        $workbooks = $workbooks | Where-Object {
            $_.properties.displayName -like "*$NameFilter*"
        }
    }

    return New-SecOpsResult -Success -Data ($workbooks | ForEach-Object {
        [PSCustomObject]@{
            Name        = $_.properties.displayName
            Category    = $_.properties.category
            Modified    = $_.properties.timeModified
            ResourceId  = $_.id
        }
    })
}
```

---

## 5 — Data Connectors

### Get-SentinelConnectorStatus

Reports connector health — which are connected, disconnected, or degraded.

```powershell
function Get-SentinelConnectorStatus {
    <#
    .SYNOPSIS
        Lists data connectors and their health status.
    .DESCRIPTION
        Combines REST API connector list with .secops/ expected state to flag gaps.
    .EXAMPLE
        Get-SentinelConnectorStatus | Select-Object -Expand Data | Format-Table
    .EXAMPLE
        Get-SentinelConnectorStatus -StatusFilter 'disconnected'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('connected', 'disconnected', 'all')]
        [string]$StatusFilter = 'all',
        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $base = Get-SentinelBaseUri -Context $ctx

    $uri = "$base/dataConnectors?api-version=2024-03-01"
    $result = Invoke-SentinelApi -Uri $uri -OperationName 'Get-SentinelConnectorStatus'

    if (-not $result.Ok) { return $result }

    $connectors = $result.Data | ForEach-Object {
        [PSCustomObject]@{
            Name         = $_.properties.connectorUiConfig.title ?? $_.kind
            Kind         = $_.kind
            Status       = if ($_.properties.dataTypes) { 'connected' } else { 'unknown' }
            ResourceId   = $_.name
            LastModified = $_.systemData.lastModifiedAt
        }
    }

    if ($StatusFilter -ne 'all') {
        $connectors = $connectors | Where-Object { $_.Status -eq $StatusFilter }
    }

    # Cross-reference with .secops/ expected connectors
    $wsFile = Join-Path $script:SecOpsContext.SecOpsPath 'workspaces' `
        "$($ctx.WorkspaceName).yaml"
    if (Test-Path $wsFile) {
        $wsConfig = Get-Content $wsFile -Raw | ConvertFrom-Yaml
        $expected = $wsConfig.data_connectors | ForEach-Object { $_.name }
        $found = $connectors | ForEach-Object { $_.Name }
        $missing = $expected | Where-Object { $_ -notin $found }

        if ($missing) {
            Write-Warning "Connectors in .secops/ but not found in workspace: $($missing -join ', ')"
        }
    }

    return New-SecOpsResult -Success -Data $connectors
}
```

### Enable-SentinelConnector

Enables a connector by kind — demonstrates the AAD (Entra ID) diagnostic settings connector.

```powershell
function Enable-SentinelConnector {
    <#
    .SYNOPSIS
        Enables a Sentinel data connector.
    .DESCRIPTION
        Different connector kinds require different payloads. This function handles
        the most common kinds. For connectors requiring additional configuration
        (e.g., AWS S3), use Invoke-SentinelApi directly.
    .EXAMPLE
        Enable-SentinelConnector -Kind 'AzureActiveDirectory' -TenantId 'aaa-bbb-ccc'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('AzureActiveDirectory', 'AzureSecurityCenter',
                     'MicrosoftDefenderAdvancedThreatProtection', 'Office365',
                     'MicrosoftCloudAppSecurity', 'ThreatIntelligence')]
        [string]$Kind,

        [string]$TenantId,
        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $base = Get-SentinelBaseUri -Context $ctx
    $connectorId = [guid]::NewGuid().ToString()

    if (-not $TenantId) {
        $primary = Get-SecOpsTenants -Type 'primary' | Select-Object -First 1
        $TenantId = $primary.id
    }

    $body = @{
        kind       = $Kind
        properties = @{ tenantId = $TenantId; dataTypes = @{} }
    }

    # Set data types based on connector kind
    switch ($Kind) {
        'AzureActiveDirectory' {
            $body.properties.dataTypes = @{
                alerts = @{ state = 'Enabled' }
                logs   = @{ state = 'Enabled' }
            }
        }
        'Office365' {
            $body.properties.dataTypes = @{
                exchange   = @{ state = 'Enabled' }
                sharePoint = @{ state = 'Enabled' }
                teams      = @{ state = 'Enabled' }
            }
        }
        default {
            $body.properties.dataTypes = @{
                alerts = @{ state = 'Enabled' }
            }
        }
    }

    if (-not $PSCmdlet.ShouldProcess($Kind, 'Enable data connector')) { return }

    $uri = "$base/dataConnectors/$connectorId`?api-version=2024-03-01"
    return Invoke-SentinelApi -Uri $uri -Method PUT -Body $body `
        -OperationName 'Enable-SentinelConnector'
}
```

---

## 6 — Watchlists

### New-SentinelWatchlist

Creates a new watchlist with inline items or from CSV.

```powershell
function New-SentinelWatchlist {
    <#
    .SYNOPSIS
        Creates a Sentinel watchlist.
    .EXAMPLE
        New-SentinelWatchlist -Alias 'wl-vip-users' -DisplayName 'VIP Users' `
            -SearchKey 'UPN' -Description 'Executive and VIP user accounts for enhanced monitoring'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$Alias,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$SearchKey,
        [string]$Description = '',
        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $base = Get-SentinelBaseUri -Context $ctx

    $body = @{
        properties = @{
            displayName      = $DisplayName
            provider         = 'SecOps PowerShell'
            source           = 'Local file'
            description      = $Description
            itemsSearchKey   = $SearchKey
            contentType      = 'Text/Csv'
            numberOfLinesToSkip = 0
        }
    }

    if (-not $PSCmdlet.ShouldProcess($DisplayName, 'Create watchlist')) { return }

    $uri = "$base/watchlists/$Alias`?api-version=2024-03-01"
    return Invoke-SentinelApi -Uri $uri -Method PUT -Body $body `
        -OperationName 'New-SentinelWatchlist'
}
```

### Import-SentinelWatchlistItems

Bulk-imports items into an existing watchlist from CSV.

```powershell
function Import-SentinelWatchlistItems {
    <#
    .SYNOPSIS
        Imports items into an existing Sentinel watchlist from CSV.
    .DESCRIPTION
        Reads a CSV and creates watchlist items in batches. The CSV columns
        must match the watchlist schema. SearchKey column is required.
    .EXAMPLE
        Import-SentinelWatchlistItems -WatchlistAlias 'wl-vip-users' `
            -CsvPath './data/vip-users.csv'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$WatchlistAlias,
        [Parameter(Mandatory)][string]$CsvPath,
        [string]$WorkspaceName
    )

    if (-not (Test-Path $CsvPath)) {
        return New-SecOpsResult -Error "CSV not found: $CsvPath" -ErrorCode 'FileNotFound'
    }

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $base = Get-SentinelBaseUri -Context $ctx

    $rows = Import-Csv -Path $CsvPath
    Write-Host "Loaded $($rows.Count) items from $CsvPath"

    if (-not $PSCmdlet.ShouldProcess("$($rows.Count) items into $WatchlistAlias", 'Import')) {
        return
    }

    $results = Invoke-SecOpsBatchOperation -Items $rows -BatchSize 20 `
        -DelayBetweenBatchesMs 2000 -Operation {
            param($row)
            $itemId = [guid]::NewGuid().ToString()
            $itemProps = @{}
            $row.PSObject.Properties | ForEach-Object { $itemProps[$_.Name] = $_.Value }

            $itemBody = @{ properties = @{ itemsKeyValue = $itemProps } }
            $itemUri = "$base/watchlists/$WatchlistAlias/watchlistItems/$itemId" +
                       "?api-version=2024-03-01"

            Invoke-SentinelApi -Uri $itemUri -Method PUT -Body $itemBody `
                -OperationName "Add watchlist item $itemId"
        }

    $succeeded = ($results | Where-Object { $_.Ok }).Count
    return New-SecOpsResult -Success -Data @{
        Imported  = $succeeded
        Failed    = $results.Count - $succeeded
        Total     = $rows.Count
        Watchlist = $WatchlistAlias
    }
}
```

### Export-SentinelWatchlistItems

Exports watchlist items to CSV for backup or cross-workspace migration.

```powershell
function Export-SentinelWatchlistItems {
    <#
    .SYNOPSIS
        Exports all items from a Sentinel watchlist to CSV.
    .EXAMPLE
        Export-SentinelWatchlistItems -WatchlistAlias 'wl-vip-users' -OutputPath './exports/'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$WatchlistAlias,
        [string]$OutputPath = '.',
        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $base = Get-SentinelBaseUri -Context $ctx

    $uri = "$base/watchlists/$WatchlistAlias/watchlistItems?api-version=2024-03-01"
    $result = Invoke-SentinelApi -Uri $uri -OperationName 'Export-SentinelWatchlistItems'

    if (-not $result.Ok) { return $result }

    $items = $result.Data | ForEach-Object {
        $_.properties.itemsKeyValue
    }

    if ($items.Count -eq 0) {
        return New-SecOpsResult -Success -Data @{ Path = $null; Count = 0 }
    }

    $filePath = Join-Path $OutputPath "$WatchlistAlias.csv"
    $items | Export-Csv -Path $filePath -NoTypeInformation -Encoding utf8

    return New-SecOpsResult -Success -Data @{
        Path     = $filePath
        Count    = $items.Count
        Exported = [DateTimeOffset]::UtcNow.ToString('o')
    }
}
```

### Using Watchlists in KQL

Watchlists are referenced in analytics rules and hunting queries via the `_GetWatchlist()` function:

```kql
// Match sign-ins against a VIP watchlist
let VIPUsers = _GetWatchlist('wl-vip-users') | project UPN;
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName in (VIPUsers)
| where ResultType != "0"
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where FailedAttempts > 5
```

```kql
// Cross-reference TI watchlist with network data
let BlockedIPs = _GetWatchlist('wl-blocklist-ips') | project IPAddress;
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DestinationIP in (BlockedIPs)
| summarize HitCount = count() by SourceIP, DestinationIP, DeviceAction
```

---

## Rate Limits and Pagination

### ARM Rate Limits for Sentinel APIs

| Operation | Limit | Scope |
|---|---|---|
| **Reads (GET)** | 1,200 / 5 minutes | Per subscription |
| **Writes (PUT/POST/DELETE)** | 400 / 5 minutes | Per subscription |
| **TI indicator creation** | 100 / minute | Per workspace |
| **Watchlist item creation** | 100 / minute | Per watchlist |

All functions in this skill use `Invoke-SecOpsBatchOperation` (from `error-handling.md`) for bulk operations, which enforces configurable batch sizes and delays.

### Pagination Pattern

The `Invoke-SentinelApi` helper (defined above) handles `nextLink` pagination automatically for all GET requests. For manual control:

```powershell
# Manual pagination example — useful for progress reporting on very large sets
function Get-AllSentinelIncidentsPaged {
    [CmdletBinding()]
    param([string]$WorkspaceName, [int]$MaxPages = 100)

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $base = Get-SentinelBaseUri -Context $ctx
    $uri = "$base/incidents?api-version=2024-03-01&`$top=50"

    $allIncidents = @()
    $page = 0

    while ($uri -and $page -lt $MaxPages) {
        $page++
        Write-Progress -Activity 'Fetching incidents' -Status "Page $page"

        $result = Invoke-SentinelApi -Uri $uri -OperationName "List incidents p$page" -NoPagination
        if (-not $result.Ok) { return $result }

        $allIncidents += $result.Data.value
        $uri = $result.Data.nextLink
    }

    Write-Progress -Activity 'Fetching incidents' -Completed
    return New-SecOpsResult -Success -Data $allIncidents
}
```

---

## Best Practices

1. **Workspace from `.secops/`** — Never hardcode subscription IDs, resource groups, or workspace names. Use `Get-SentinelContext` which reads `.secops/workspaces/*.yaml`.
2. **Test queries before deploying rules** — Always run `Test-SentinelRuleQuery` before `New-SecOpsAnalyticsRule` or `New-SentinelNrtRule`.
3. **Use `-WhatIf`** — All write functions support `ShouldProcess`. Use `-WhatIf` for dry runs, especially on bulk operations.
4. **Batch operations** — Use `Invoke-SecOpsBatchOperation` for any operation touching >10 resources. Default batch size of 10-20 with 2-3s delays avoids 429s.
5. **Follow naming conventions** — Read `.secops/workspaces/*.yaml` `naming_conventions` before creating rules, watchlists, or workbooks.
6. **Version-control exports** — Pipe `Export-SecOpsWorkbook` and `Export-SentinelWatchlistItems` output to Git-tracked directories.
7. **Audit trail** — All functions flow through `Invoke-SecOpsRestMethod` which calls `Write-SecOpsAuditLog`. Check `./logs/secops-audit-*.jsonl` for forensic review.

## Environment Context

Before using any function in this skill, agents MUST consult:

- **`.secops/environment.yaml`** — Cloud type, default workspace, subscriptions
- **`.secops/workspaces/*.yaml`** — Workspace-specific config including naming conventions and retention
- **`.secops/data-sources/data-source-map.yaml`** — Which tables are in Sentinel vs ADX (affects TI matching queries)
- **`.secops/identity/tenants.yaml`** — Multi-tenant context for connector configuration
- **`.secops/compliance/requirements.yaml`** — Data residency rules that constrain where workbooks and rules are deployed

## Related Skills

- `skills/powershell/sentinel-module.md` — Submodule architecture, `Get-SentinelContext`, foundational functions
- `skills/powershell/auth-patterns.md` — Token acquisition, government cloud endpoints
- `skills/powershell/error-handling.md` — `Invoke-SecOpsRestMethod`, `New-SecOpsResult`, retry patterns
- `skills/msft-security/sentinel-api-reference.md` — Raw REST endpoint reference
- `skills/msft-security/sentinel-mcp-server.md` — MCP-based Sentinel access for agents
- `skills/kql/analytics-rules.md` — KQL patterns for `New-SecOpsAnalyticsRule` / `New-SentinelNrtRule`
- `skills/kql/threat-hunting.md` — Hunting queries to use with `Invoke-SecOpsHuntingQuery`
- `skills/log-analytics/api-wrapper.md` — Log Analytics query API wrappers
