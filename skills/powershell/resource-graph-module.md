---
title: Resource Graph Submodule
category: powershell
difficulty: intermediate
mitre_attack:
  - T1580  # Cloud Infrastructure Discovery
  - T1526  # Cloud Service Discovery
  - T1190  # Exploit Public-Facing Application
products:
  - Azure Resource Graph
  - Azure Policy
  - Microsoft Defender for Cloud
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# Resource Graph Submodule

## Overview

The Resource Graph submodule provides security-focused Azure Resource Graph (ARG) queries — finding exposed ports, unencrypted storage, missing NSGs, VMs without endpoint protection, and overall compliance posture. It enables cross-subscription resource inventory and security assessment at scale.

Use this skill when:
- Running security posture assessments across subscriptions
- Finding misconfigured or exposed resources
- Building compliance reports against `.secops/compliance/requirements.yaml`
- Inventorying resources for incident response scope assessment
- Querying across subscriptions without iterating subscription-by-subscription

## Prerequisites

| Requirement | Detail |
|---|---|
| **Az.ResourceGraph** | `Install-Module Az.ResourceGraph` |
| **Permissions** | `Reader` on target subscriptions |
| **Network** | Access to `management.azure.com` |

## REST API

| Endpoint | Purpose |
|---|---|
| `POST /providers/Microsoft.ResourceGraph/resources` | Execute ARG query |

**Key constraint:** ARG queries return max 1,000 rows per page. The submodule handles pagination automatically via `$skipToken`.

## Core Query Function

### Invoke-SecOpsResourceQuery — Execute ARG Queries

```powershell
function Invoke-SecOpsResourceQuery {
    <#
    .SYNOPSIS
        Executes an Azure Resource Graph query with automatic pagination.
    .DESCRIPTION
        Wraps Search-AzGraph with pagination, cross-subscription support,
        and structured result objects. Automatically queries all accessible
        subscriptions unless scoped.
    .EXAMPLE
        Invoke-SecOpsResourceQuery -Query "Resources | where type =~ 'microsoft.compute/virtualmachines' | summarize count() by location"
    .EXAMPLE
        Invoke-SecOpsResourceQuery -Query "Resources | where type =~ 'microsoft.storage/storageaccounts'" -SubscriptionId @('sub-1', 'sub-2')
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Query,

        [string[]]$SubscriptionId,

        [int]$MaxResults = 5000
    )

    try {
        $params = @{
            Query = $Query
            First = [Math]::Min($MaxResults, 1000)
        }
        if ($SubscriptionId) {
            $params.Subscription = $SubscriptionId
        }

        $allResults = @()
        $result = Search-AzGraph @params

        $allResults += $result.Data
        $remaining = $MaxResults - $result.Data.Count

        while ($result.SkipToken -and $remaining -gt 0) {
            $params.SkipToken = $result.SkipToken
            $params.First = [Math]::Min($remaining, 1000)
            $result = Search-AzGraph @params
            $allResults += $result.Data
            $remaining -= $result.Data.Count
        }

        return New-SecOpsResult -Success -Data $allResults

    }
    catch {
        return New-SecOpsResult -Error $_.Exception.Message -ErrorCode 'ResourceGraphQueryFailed'
    }
}
```

## Security-Focused ARG Queries

### Get-SecOpsExposedResources — Find Security Exposures

```powershell
function Get-SecOpsExposedResources {
    <#
    .SYNOPSIS
        Finds common security exposures across Azure subscriptions.
    .EXAMPLE
        Get-SecOpsExposedResources -Category 'NetworkExposure'
    .EXAMPLE
        Get-SecOpsExposedResources -Category 'All'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('NetworkExposure', 'StorageSecurity', 'EndpointProtection', 'EncryptionGaps', 'All')]
        [string]$Category = 'All',

        [string[]]$SubscriptionId
    )

    $queries = @{}

    # --- Network Exposure ---
    $queries['NetworkExposure'] = @"
Resources
| where type =~ 'microsoft.network/networksecuritygroups'
| mv-expand rules = properties.securityRules
| where rules.properties.direction =~ 'Inbound'
    and rules.properties.access =~ 'Allow'
    and rules.properties.sourceAddressPrefix in ('*', '0.0.0.0/0', 'Internet')
| project
    nsgName = name,
    resourceGroup,
    subscriptionId,
    ruleName = rules.name,
    destinationPort = rules.properties.destinationPortRange,
    protocol = rules.properties.protocol,
    priority = rules.properties.priority
| order by nsgName asc, toint(priority) asc
"@

    # --- Storage Security ---
    $queries['StorageSecurity'] = @"
Resources
| where type =~ 'microsoft.storage/storageaccounts'
| where properties.supportsHttpsTrafficOnly == false
    or properties.networkAcls.defaultAction =~ 'Allow'
    or properties.minimumTlsVersion != 'TLS1_2'
| project
    name,
    resourceGroup,
    subscriptionId,
    httpsOnly = properties.supportsHttpsTrafficOnly,
    networkDefaultAction = properties.networkAcls.defaultAction,
    tlsVersion = properties.minimumTlsVersion,
    location
"@

    # --- Endpoint Protection ---
    $queries['EndpointProtection'] = @"
Resources
| where type =~ 'microsoft.compute/virtualmachines'
| extend
    vmId = tolower(id)
| join kind=leftouter (
    Resources
    | where type =~ 'microsoft.compute/virtualmachines/extensions'
    | where properties.type in~ (
        'MDE.Windows', 'MDE.Linux',
        'MicrosoftMonitoringAgent', 'OmsAgentForLinux',
        'AzureMonitorWindowsAgent', 'AzureMonitorLinuxAgent'
    )
    | extend vmId = tolower(substring(id, 0, indexof(id, '/extensions/')))
    | project vmId, extensionType = properties.type
) on vmId
| where isempty(extensionType)
| project
    vmName = name,
    resourceGroup,
    subscriptionId,
    osType = properties.storageProfile.osDisk.osType,
    location,
    missingAgent = 'No MDE or monitoring agent'
"@

    # --- Encryption Gaps ---
    $queries['EncryptionGaps'] = @"
Resources
| where type =~ 'microsoft.compute/disks'
| where properties.encryption.type !~ 'EncryptionAtRestWithPlatformKey'
    and properties.encryption.type !~ 'EncryptionAtRestWithCustomerKey'
    and properties.encryption.type !~ 'EncryptionAtRestWithPlatformAndCustomerKeys'
| project
    diskName = name,
    resourceGroup,
    subscriptionId,
    encryptionType = coalesce(tostring(properties.encryption.type), 'None'),
    diskState = properties.diskState,
    location
"@

    $categoriesToRun = if ($Category -eq 'All') { $queries.Keys } else { @($Category) }
    $allFindings = @{}

    foreach ($cat in $categoriesToRun) {
        $result = Invoke-SecOpsResourceQuery -Query $queries[$cat] -SubscriptionId $SubscriptionId
        if ($result.Ok) {
            $allFindings[$cat] = $result.Data
        }
        else {
            Write-Warning "Query failed for category '$cat': $($result.Error)"
            $allFindings[$cat] = @()
        }
    }

    return New-SecOpsResult -Success -Data $allFindings
}
```

### Get-SecOpsCompliancePosture — Compliance Assessment

```powershell
function Get-SecOpsCompliancePosture {
    <#
    .SYNOPSIS
        Generates a compliance posture report using Resource Graph data
        and .secops/compliance/requirements.yaml constraints.
    .EXAMPLE
        Get-SecOpsCompliancePosture | Format-Table Category, TotalResources, Compliant, NonCompliant, CompliancePercent
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string[]]$SubscriptionId
    )

    # Load compliance requirements from .secops/
    $compliancePath = Join-Path $script:SecOpsContext.SecOpsPath 'compliance' 'requirements.yaml'
    $compliance = $null
    if (Test-Path $compliancePath) {
        $compliance = Get-Content $compliancePath -Raw | ConvertFrom-Yaml
    }

    # Run posture queries
    $checks = @(
        @{
            Category = 'HTTPS Enforcement'
            Query    = @"
Resources
| where type =~ 'microsoft.storage/storageaccounts'
| extend httpsOnly = tobool(properties.supportsHttpsTrafficOnly)
| summarize
    Total = count(),
    Compliant = countif(httpsOnly == true),
    NonCompliant = countif(httpsOnly != true)
"@
        },
        @{
            Category = 'TLS 1.2 Minimum'
            Query    = @"
Resources
| where type =~ 'microsoft.storage/storageaccounts'
| extend tls = tostring(properties.minimumTlsVersion)
| summarize
    Total = count(),
    Compliant = countif(tls == 'TLS1_2'),
    NonCompliant = countif(tls != 'TLS1_2')
"@
        },
        @{
            Category = 'Network Restriction'
            Query    = @"
Resources
| where type =~ 'microsoft.storage/storageaccounts'
| extend netDefault = tostring(properties.networkAcls.defaultAction)
| summarize
    Total = count(),
    Compliant = countif(netDefault =~ 'Deny'),
    NonCompliant = countif(netDefault =~ 'Allow')
"@
        },
        @{
            Category = 'VM Disk Encryption'
            Query    = @"
Resources
| where type =~ 'microsoft.compute/disks'
| where properties.diskState =~ 'Attached'
| extend encrypted = isnotempty(properties.encryption.type)
| summarize
    Total = count(),
    Compliant = countif(encrypted == true),
    NonCompliant = countif(encrypted == false)
"@
        }
    )

    $posture = @()
    foreach ($check in $checks) {
        $result = Invoke-SecOpsResourceQuery -Query $check.Query -SubscriptionId $SubscriptionId
        if ($result.Ok -and $result.Data.Count -gt 0) {
            $row = $result.Data[0]
            $total = [int]$row.Total
            $compliant = [int]$row.Compliant
            $posture += [PSCustomObject]@{
                Category         = $check.Category
                TotalResources   = $total
                Compliant        = $compliant
                NonCompliant     = [int]$row.NonCompliant
                CompliancePercent = if ($total -gt 0) { [math]::Round(($compliant / $total) * 100, 1) } else { 100 }
            }
        }
    }

    # Add compliance framework context if available
    $frameworks = @()
    if ($compliance -and $compliance.frameworks) {
        $frameworks = $compliance.frameworks | ForEach-Object { $_.name }
    }

    return New-SecOpsResult -Success -Data @{
        Posture    = $posture
        Frameworks = $frameworks
        Timestamp  = [DateTimeOffset]::UtcNow.ToString('o')
    }
}
```

## Additional Security Queries

### VMs Without Endpoint Protection

```powershell
# Quick check: VMs missing MDE or monitoring agents
$query = @"
Resources
| where type =~ 'microsoft.compute/virtualmachines'
| extend vmId = tolower(id)
| join kind=leftouter (
    Resources
    | where type =~ 'microsoft.compute/virtualmachines/extensions'
    | where properties.type in~ ('MDE.Windows', 'MDE.Linux')
    | extend vmId = tolower(substring(id, 0, indexof(id, '/extensions/')))
    | distinct vmId
) on vmId
| where isempty(vmId1)
| project name, resourceGroup, subscriptionId, location,
    osType = properties.storageProfile.osDisk.osType
"@
Invoke-SecOpsResourceQuery -Query $query
```

### Public IP Address Inventory

```powershell
# Find all public IPs and their associations
$query = @"
Resources
| where type =~ 'microsoft.network/publicipaddresses'
| project
    name,
    resourceGroup,
    subscriptionId,
    ipAddress = properties.ipAddress,
    allocationMethod = properties.publicIPAllocationMethod,
    associatedTo = coalesce(
        tostring(properties.ipConfiguration.id),
        'Unassociated'
    ),
    location
| order by name asc
"@
Invoke-SecOpsResourceQuery -Query $query
```

## Best Practices

1. **Cross-subscription by default** — ARG queries all accessible subscriptions; scope only when needed
2. **Pagination is automatic** — `Invoke-SecOpsResourceQuery` handles `$skipToken` pagination
3. **Time-independent** — ARG queries current state, not historical; use Log Analytics for time-series
4. **Query limits** — Max 1,000 rows per page; 5,000 rows total default; raise `MaxResults` if needed
5. **Throttle awareness** — ARG allows 15 requests per 5 seconds per tenant; batch queries wisely
6. **Compliance integration** — Read `.secops/compliance/requirements.yaml` for framework-specific checks

## Environment Context

Before using Resource Graph functions, agents MUST consult:

- **`.secops/environment.yaml`** — Subscription list and org type
- **`.secops/compliance/requirements.yaml`** — Compliance frameworks and prohibited regions
- **`.secops/data-sources/data-source-map.yaml`** — Correlate ARG findings with monitoring coverage

## Related Skills

- `skills/kql/cloud-security-posture.md` — KQL queries for Defender for Cloud data in Sentinel
- `skills/powershell/auth-patterns.md` — Authentication for cross-subscription queries
- `skills/powershell/error-handling.md` — ARG-specific throttling (15 req/5 sec)
- `skills/log-analytics/workspace-architecture.md` — Understanding where ARG findings correlate with log data
