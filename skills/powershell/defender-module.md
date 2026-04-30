---
title: Defender Submodule
category: powershell
difficulty: intermediate
mitre_attack:
  - T1059.001  # PowerShell
  - T1518.001  # Software Discovery: Security Software
  - T1562.001  # Impair Defenses: Disable or Modify Tools
products:
  - Microsoft Defender for Endpoint
  - Microsoft Defender for Cloud
  - Microsoft Defender for Identity
  - Microsoft 365 Defender
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# Defender Submodule

## Overview

The Defender submodule wraps Microsoft's Defender family APIs — Defender for Endpoint (MDE), Defender for Cloud, and Defender for Identity. It provides PowerShell functions for alert management, advanced hunting, device actions (isolate, scan, restrict), and security recommendations.

Use this skill when:
- Querying and managing MDE alerts programmatically
- Running advanced hunting queries via MDE API
- Executing device response actions (isolate, scan, collect investigation package)
- Retrieving security recommendations from Defender for Cloud
- Correlating alerts across Defender products

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions (MDE)** | App registration with `Machine.ReadWrite.All`, `Alert.ReadWrite.All`, `AdvancedQuery.Read.All` |
| **Permissions (MDC)** | `Security Reader` or `Security Admin` RBAC role |
| **Licensing** | Microsoft Defender for Endpoint P2 or M365 E5 |
| **Network** | Access to `api.securitycenter.microsoft.com` (commercial) or `api-gcc.securitycenter.microsoft.us` (GCC-H) |

## REST API Endpoints

### Defender for Endpoint (MDE)

| Endpoint | Purpose | Permission |
|---|---|---|
| `/api/alerts` | Alert management | `Alert.ReadWrite.All` |
| `/api/advancedqueries/run` | Advanced hunting | `AdvancedQuery.Read.All` |
| `/api/machines` | Device inventory | `Machine.Read.All` |
| `/api/machines/{id}/isolate` | Isolate device | `Machine.Isolate` |
| `/api/machines/{id}/unisolate` | Release from isolation | `Machine.Isolate` |
| `/api/machines/{id}/runAntiVirusScan` | Trigger AV scan | `Machine.Scan` |
| `/api/machines/{id}/restrictCodeExecution` | Restrict app execution | `Machine.RestrictExecution` |
| `/api/machines/{id}/collectInvestigationPackage` | Collect forensic package | `Machine.CollectForensics` |
| `/api/recommendations` | Security recommendations | `SecurityRecommendation.Read.All` |

**Base URI:**
- Commercial: `https://api.securitycenter.microsoft.com`
- GCC-High: `https://api-gcc.securitycenter.microsoft.us`
- DoD: `https://api-gov.securitycenter.microsoft.us`

### Defender for Cloud (MDC)

| Endpoint | Purpose |
|---|---|
| `/providers/Microsoft.Security/alerts` | Security alerts |
| `/providers/Microsoft.Security/assessments` | Security assessments |
| `/providers/Microsoft.Security/secureScores` | Secure score |
| `/providers/Microsoft.Security/recommendations` | Recommendations |

## Cloud-Aware Endpoint Resolution

```powershell
function Get-DefenderBaseUri {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $cloud = Get-SecOpsCloudEnvironment
    switch ($cloud) {
        'AzureCloud'         { return 'https://api.securitycenter.microsoft.com' }
        'AzureUSGovernment'  { return 'https://api-gcc.securitycenter.microsoft.us' }
        default              { return 'https://api.securitycenter.microsoft.com' }
    }
}

function Get-DefenderToken {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $cloud = Get-SecOpsCloudEnvironment
    $resource = switch ($cloud) {
        'AzureCloud'         { 'https://api.securitycenter.microsoft.com' }
        'AzureUSGovernment'  { 'https://api-gcc.securitycenter.microsoft.us' }
        default              { 'https://api.securitycenter.microsoft.com' }
    }

    return (Get-AzAccessToken -ResourceUrl $resource).Token
}
```

## Key Functions

### Get-SecOpsAlert — Retrieve Defender Alerts

```powershell
function Get-SecOpsAlert {
    <#
    .SYNOPSIS
        Retrieves alerts from Microsoft Defender for Endpoint.
    .EXAMPLE
        Get-SecOpsAlert -Severity High -Status New -DaysBack 7
    .EXAMPLE
        Get-SecOpsAlert -Category 'Ransomware'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$Severity,

        [ValidateSet('New', 'InProgress', 'Resolved')]
        [string]$Status,

        [string]$Category,

        [int]$DaysBack = 30,

        [int]$Top = 100
    )

    $baseUri = Get-DefenderBaseUri
    $token = Get-DefenderToken
    $headers = @{ 'Authorization' = "Bearer $token" }

    # Build OData filter
    $filters = @()
    $filters += "alertCreationTime ge $((Get-Date).AddDays(-$DaysBack).ToString('o'))"
    if ($Severity) { $filters += "severity eq '$Severity'" }
    if ($Status)   { $filters += "status eq '$Status'" }
    if ($Category) { $filters += "category eq '$Category'" }

    $filterString = $filters -join ' and '
    $uri = "$baseUri/api/alerts?`$filter=$filterString&`$top=$Top&`$orderby=alertCreationTime desc"

    $result = Invoke-SecOpsRestMethod -Uri $uri -Headers $headers -OperationName 'Get-SecOpsAlert'

    if ($result.Ok) {
        $alerts = $result.Data.value | ForEach-Object {
            [PSCustomObject]@{
                Id              = $_.id
                Title           = $_.title
                Severity        = $_.severity
                Status          = $_.status
                Category        = $_.category
                MachineId       = $_.machineId
                CreationTime    = $_.alertCreationTime
                MitreTechniques = $_.mitreTechniques -join ', '
            }
        }
        return New-SecOpsResult -Success -Data $alerts
    }

    return $result
}
```

### Invoke-SecOpsAdvancedHunting — Run Advanced Hunting Queries

```powershell
function Invoke-SecOpsAdvancedHunting {
    <#
    .SYNOPSIS
        Executes a KQL query via MDE Advanced Hunting API.
    .DESCRIPTION
        Runs KQL queries against Defender XDR tables (DeviceProcessEvents,
        DeviceNetworkEvents, EmailEvents, etc.). Results are limited to
        10,000 rows per query.
    .EXAMPLE
        Invoke-SecOpsAdvancedHunting -Query @"
            DeviceProcessEvents
            | where Timestamp > ago(1h)
            | where FileName in~ ("powershell.exe", "cmd.exe")
            | where ProcessCommandLine has_any ("Invoke-Expression", "IEX", "-enc")
            | project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
            | take 100
        "@
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Query,

        [int]$TimeoutSec = 60
    )

    $baseUri = Get-DefenderBaseUri
    $token = Get-DefenderToken
    $headers = @{ 'Authorization' = "Bearer $token" }

    $body = @{ Query = $Query }
    $uri = "$baseUri/api/advancedqueries/run"

    $result = Invoke-SecOpsRestMethod -Uri $uri -Method POST -Body $body `
        -Headers $headers -TimeoutSec $TimeoutSec `
        -OperationName 'Invoke-SecOpsAdvancedHunting'

    if ($result.Ok) {
        $schema = $result.Data.Schema
        $rows = $result.Data.Results
        Write-Verbose "Advanced hunting returned $($rows.Count) rows"
        return New-SecOpsResult -Success -Data $rows
    }

    return $result
}
```

### Set-SecOpsDeviceIsolation — Isolate or Release a Device

```powershell
function Set-SecOpsDeviceIsolation {
    <#
    .SYNOPSIS
        Isolates or releases a device in Microsoft Defender for Endpoint.
    .DESCRIPTION
        Network isolation prevents the device from communicating with anything
        except the MDE cloud service. Use for active threat containment.
    .EXAMPLE
        Set-SecOpsDeviceIsolation -MachineId '<device-guid>' -Isolate -Comment "IR-2026-042: Active ransomware"
    .EXAMPLE
        Set-SecOpsDeviceIsolation -MachineId '<device-guid>' -Release -Comment "IR-2026-042: Remediated"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$MachineId,

        [Parameter(Mandatory, ParameterSetName = 'Isolate')]
        [switch]$Isolate,

        [Parameter(Mandatory, ParameterSetName = 'Release')]
        [switch]$Release,

        [ValidateSet('Full', 'Selective')]
        [string]$IsolationType = 'Full',

        [Parameter(Mandatory)]
        [string]$Comment
    )

    $action = if ($Isolate) { 'isolate' } else { 'unisolate' }
    $actionDisplay = if ($Isolate) { 'Isolate' } else { 'Release from isolation' }

    if (-not $PSCmdlet.ShouldProcess("Device $MachineId", $actionDisplay)) {
        return
    }

    $baseUri = Get-DefenderBaseUri
    $token = Get-DefenderToken
    $headers = @{ 'Authorization' = "Bearer $token" }

    $body = @{
        Comment       = $Comment
        IsolationType = $IsolationType
    }

    $uri = "$baseUri/api/machines/$MachineId/$action"

    $result = Invoke-SecOpsRestMethod -Uri $uri -Method POST -Body $body `
        -Headers $headers -OperationName "Set-SecOpsDeviceIsolation ($action)"

    if ($result.Ok) {
        Write-Verbose "Device $MachineId: $actionDisplay action submitted"
    }

    return $result
}
```

### Get-SecOpsSecurityRecommendation — Defender for Cloud Recommendations

```powershell
function Get-SecOpsSecurityRecommendation {
    <#
    .SYNOPSIS
        Retrieves security recommendations from Defender for Cloud.
    .EXAMPLE
        Get-SecOpsSecurityRecommendation -Severity High
    .EXAMPLE
        Get-SecOpsSecurityRecommendation -Category 'Compute'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('Low', 'Medium', 'High')]
        [string]$Severity,

        [string]$Category
    )

    $subId = (Get-AzContext).Subscription.Id
    $uri = "https://management.azure.com/subscriptions/$subId" +
           "/providers/Microsoft.Security/assessments" +
           "?api-version=2021-06-01"

    $token = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ 'Authorization' = "Bearer $token" }

    $result = Invoke-SecOpsRestMethod -Uri $uri -Headers $headers `
        -OperationName 'Get-SecOpsSecurityRecommendation'

    if ($result.Ok) {
        $recs = $result.Data.value | ForEach-Object {
            [PSCustomObject]@{
                Name        = $_.properties.displayName
                Status      = $_.properties.status.code
                Severity    = $_.properties.metadata.severity
                Category    = $_.properties.metadata.categories -join ', '
                Description = $_.properties.metadata.description
                ResourceId  = $_.properties.resourceDetails.Id
            }
        }

        if ($Severity) { $recs = $recs | Where-Object { $_.Severity -eq $Severity } }
        if ($Category) { $recs = $recs | Where-Object { $_.Category -match $Category } }

        return New-SecOpsResult -Success -Data $recs
    }

    return $result
}
```

## Best Practices

1. **Always log device actions** — Isolations, scans, and restrictions are high-impact; audit trail is mandatory
2. **ShouldProcess on destructive actions** — `Set-SecOpsDeviceIsolation` supports `-WhatIf`
3. **Comment every action** — MDE requires a comment string for device actions; make it meaningful (include incident ID)
4. **Advanced hunting limits** — Queries return max 10,000 rows; add `| take N` and time filters
5. **Cloud-aware endpoints** — Use `Get-DefenderBaseUri` instead of hardcoding commercial URLs
6. **Rate limits** — MDE enforces 100 calls/minute for some endpoints; use batch processing

## Environment Context

Before using Defender functions, agents MUST consult:

- **`.secops/environment.yaml`** — Cloud type determines MDE API base URI
- **`.secops/identity/tenants.yaml`** — Multi-tenant scenarios require per-tenant MDE connections
- **`.secops/data-sources/data-source-map.yaml`** — Check if Defender tables are in Sentinel or raw MDE

## Related Skills

- `skills/kql/defender-xdr-hunting.md` — KQL queries for `Invoke-SecOpsAdvancedHunting`
- `skills/msft-security/microsoft-graph-security.md` — Graph Security unified alerts
- `skills/powershell/auth-patterns.md` — MDE requires app registration with specific permissions
- `skills/powershell/error-handling.md` — MDE-specific error codes and throttling
