---
title: Defender REST API Wrapper Skill
category: powershell
difficulty: advanced
mitre_attack:
  - T1059.001  # PowerShell
  - T1078      # Valid Accounts
  - T1110      # Brute Force
  - T1566      # Phishing
  - T1486      # Data Encrypted for Impact
  - T1003      # OS Credential Dumping
  - T1190      # Exploit Public-Facing Application
  - T1087      # Account Discovery
  - T1558      # Steal or Forge Kerberos Tickets
  - T1562.001  # Impair Defenses: Disable or Modify Tools
products:
  - Microsoft Defender for Endpoint
  - Microsoft Defender for Cloud
  - Microsoft Defender XDR
  - Microsoft Defender for Identity
  - Microsoft Graph Security API
author: Kima
version: 1.0.0
last_updated: 2026-04-30
---

# Defender REST API Wrapper Skill

## Overview

Production-ready PowerShell wrappers for the full Microsoft Defender REST API surface. Each function uses `Invoke-SecOpsRestMethod` from [error-handling.md](error-handling.md), authenticates via patterns in [auth-patterns.md](auth-patterns.md), and reads `.secops/environment.yaml` for tenant context.

This skill **complements** — does not duplicate:
- **[defender-module.md](defender-module.md)** — base functions (`Get-SecOpsAlert`, `Invoke-SecOpsAdvancedHunting`, `Set-SecOpsDeviceIsolation`, `Get-SecOpsSecurityRecommendation`)
- **[defender-mcp-server.md](../msft-security/defender-mcp-server.md)** — MCP agent integration patterns
- **[defender-api-permissions.md](../msft-security/defender-api-permissions.md)** — full permissions matrices

Use this skill when:
- Running advanced hunting queries against MDE or XDR tables from PowerShell
- Executing machine response actions (isolate, restrict, scan, live response)
- Managing XDR incidents, investigations, and attack disruption status
- Querying Defender for Cloud secure scores, compliance, and JIT VM access
- Monitoring MDI health issues and suspicious activities
- Building cross-product SOC automation scripts

## Shared Utilities

All wrappers below depend on these helpers from sibling skills. Import order matters.

```powershell
# Prerequisites — source these first:
#   . ./secops-core.ps1          # New-SecOpsResult, Invoke-SecOpsRestMethod, Write-SecOpsAuditLog
#   . ./secops-auth.ps1          # Get-DefenderBaseUri, Get-DefenderToken, Get-SecOpsCloudEnvironment
```

### Pagination Helper

Most Defender APIs return paged results via `@odata.nextLink`. This helper drains all pages.

```powershell
function Invoke-SecOpsPaginatedRequest {
    <#
    .SYNOPSIS
        Follows @odata.nextLink to retrieve all pages from a Defender API endpoint.
    .PARAMETER Uri
        Initial request URI.
    .PARAMETER Headers
        Auth headers (Bearer token).
    .PARAMETER MaxPages
        Safety limit to prevent runaway pagination. Default 50.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [int]$MaxPages = 50,
        [string]$OperationName = 'PaginatedRequest'
    )

    $allResults = [System.Collections.Generic.List[object]]::new()
    $currentUri = $Uri
    $page = 0

    while ($currentUri -and $page -lt $MaxPages) {
        $page++
        $result = Invoke-SecOpsRestMethod -Uri $currentUri -Headers $Headers `
            -OperationName "$OperationName (page $page)"

        if (-not $result.Ok) { return $result }

        if ($result.Data.value) {
            $allResults.AddRange($result.Data.value)
        }
        $currentUri = $result.Data.'@odata.nextLink'
    }

    return New-SecOpsResult -Success -Data $allResults
}
```

---

## Section 1: Defender for Endpoint (MDE)

### Run-MdeAdvancedHunting — KQL Against MDE Tables

Extends `Invoke-SecOpsAdvancedHunting` (defender-module.md) with result shaping and quota tracking.

```powershell
function Run-MdeAdvancedHunting {
    <#
    .SYNOPSIS
        Runs a KQL query against MDE Advanced Hunting tables.
    .DESCRIPTION
        Queries DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, etc.
        Tracks query quota (max 10,000 rows, 10 min CPU per query).
        MITRE: T1059.001 (detect), T1003 (hunt)
    .EXAMPLE
        # Hunt for LSASS credential dumping
        Run-MdeAdvancedHunting -Query @"
            DeviceProcessEvents
            | where Timestamp > ago(24h)
            | where FileName =~ "rundll32.exe"
            | where ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump"
            | project Timestamp, DeviceName, AccountName, ProcessCommandLine
        "@
    .EXAMPLE
        # Export results as CSV
        $r = Run-MdeAdvancedHunting -Query "DeviceInfo | take 10"
        if ($r.Ok) { $r.Data | Export-Csv -Path ./devices.csv -NoTypeInformation }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$Query,
        [int]$TimeoutSec = 120
    )

    $baseUri = Get-DefenderBaseUri
    $token   = Get-DefenderToken
    $headers = @{ Authorization = "Bearer $token" }
    $body    = @{ Query = $Query }

    $result = Invoke-SecOpsRestMethod -Uri "$baseUri/api/advancedqueries/run" `
        -Method POST -Body $body -Headers $headers -TimeoutSec $TimeoutSec `
        -OperationName 'Run-MdeAdvancedHunting'

    if ($result.Ok) {
        $stats = $result.Data.Stats
        Write-Verbose ("Hunting: {0} rows, CPU={1}ms, dataset={2} bytes" -f
            $result.Data.Results.Count,
            $stats.ExecutionTime,
            $stats.dataset_statistics.table_row_count)
        return New-SecOpsResult -Success -Data $result.Data.Results
    }
    return $result
}
```

### Invoke-MdeMachineAction — Device Response Actions

```powershell
function Invoke-MdeMachineAction {
    <#
    .SYNOPSIS
        Executes a response action on an MDE-managed device.
    .DESCRIPTION
        Supports: isolate, unisolate, restrictCodeExecution, unrestrict,
        runAntiVirusScan (Quick/Full), collectInvestigationPackage, offboard.
        All actions are audited and require a comment (incident ID recommended).
        MITRE: T1562.001 (respond to defense evasion)
    .EXAMPLE
        Invoke-MdeMachineAction -MachineId '<guid>' -Action isolate -Comment 'INC-2026-099: ransomware'
    .EXAMPLE
        Invoke-MdeMachineAction -MachineId '<guid>' -Action runAntiVirusScan -ScanType Full -Comment 'Scheduled deep scan'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$MachineId,
        [Parameter(Mandatory)]
        [ValidateSet('isolate','unisolate','restrictCodeExecution',
                     'unrestrictCodeExecution','runAntiVirusScan',
                     'collectInvestigationPackage','offboard')]
        [string]$Action,
        [Parameter(Mandatory)][string]$Comment,
        [ValidateSet('Full','Selective')][string]$IsolationType = 'Full',
        [ValidateSet('Quick','Full')][string]$ScanType = 'Quick'
    )

    if (-not $PSCmdlet.ShouldProcess("Device $MachineId", $Action)) { return }

    $baseUri = Get-DefenderBaseUri
    $token   = Get-DefenderToken
    $headers = @{ Authorization = "Bearer $token" }

    $body = @{ Comment = $Comment }
    if ($Action -eq 'isolate')           { $body.IsolationType = $IsolationType }
    if ($Action -eq 'runAntiVirusScan')  { $body.ScanType = $ScanType }

    $uri = "$baseUri/api/machines/$MachineId/$Action"

    return Invoke-SecOpsRestMethod -Uri $uri -Method POST -Body $body `
        -Headers $headers -OperationName "MdeMachineAction:$Action"
}
```

### Start-MdeLiveResponse — Initiate Live Response Session

```powershell
function Start-MdeLiveResponse {
    <#
    .SYNOPSIS
        Starts a Live Response session on an MDE device and runs a command or script.
    .DESCRIPTION
        Submits a Live Response action via the MDE API. The session runs asynchronously;
        poll the returned action ID for completion.
        Permissions: Machine.LiveResponse
        MITRE: T1059 (investigate scripting abuse)
    .EXAMPLE
        # Run a built-in command
        Start-MdeLiveResponse -MachineId '<guid>' -CommandType 'RunCommand' `
            -Command 'processes' -Comment 'IR-042: process listing'
    .EXAMPLE
        # Run a custom script (must be uploaded to Live Response library first)
        Start-MdeLiveResponse -MachineId '<guid>' -CommandType 'RunScript' `
            -ScriptName 'CollectArtifacts.ps1' -Comment 'IR-042: artifact collection'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$MachineId,
        [Parameter(Mandatory)]
        [ValidateSet('RunCommand','RunScript','GetFile','PutFile')]
        [string]$CommandType,
        [string]$Command,
        [string]$ScriptName,
        [string]$FilePath,
        [Parameter(Mandatory)][string]$Comment
    )

    if (-not $PSCmdlet.ShouldProcess("Device $MachineId", "LiveResponse:$CommandType")) { return }

    $baseUri = Get-DefenderBaseUri
    $token   = Get-DefenderToken
    $headers = @{ Authorization = "Bearer $token" }

    $body = @{
        Commands = @(@{
            type    = $CommandType
            params  = @()
        })
        Comment  = $Comment
    }

    switch ($CommandType) {
        'RunCommand' { $body.Commands[0].params += @{ key = 'Command'; value = $Command } }
        'RunScript'  { $body.Commands[0].params += @{ key = 'ScriptName'; value = $ScriptName } }
        'GetFile'    { $body.Commands[0].params += @{ key = 'Path'; value = $FilePath } }
        'PutFile'    { $body.Commands[0].params += @{ key = 'FileName'; value = $FilePath } }
    }

    return Invoke-SecOpsRestMethod -Uri "$baseUri/api/machines/$MachineId/runliveresponse" `
        -Method POST -Body $body -Headers $headers -OperationName "LiveResponse:$CommandType"
}
```

### Get-MdeAlert / Update-MdeAlert

```powershell
function Get-MdeAlert {
    <#
    .SYNOPSIS
        Retrieves MDE alerts with OData filtering. Extends Get-SecOpsAlert (defender-module.md)
        with full pagination and classification filtering.
    .EXAMPLE
        Get-MdeAlert -Classification TruePositive -DaysBack 7
    .EXAMPLE
        Get-MdeAlert -AssignedTo 'analyst@contoso.com' -Status InProgress
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('Informational','Low','Medium','High')][string]$Severity,
        [ValidateSet('New','InProgress','Resolved')][string]$Status,
        [ValidateSet('TruePositive','FalsePositive','InformationalExpectedActivity','Unknown')]
        [string]$Classification,
        [string]$AssignedTo,
        [int]$DaysBack = 30
    )

    $baseUri = Get-DefenderBaseUri
    $token   = Get-DefenderToken
    $headers = @{ Authorization = "Bearer $token" }

    $filters = @("alertCreationTime ge $((Get-Date).AddDays(-$DaysBack).ToString('o'))")
    if ($Severity)       { $filters += "severity eq '$Severity'" }
    if ($Status)         { $filters += "status eq '$Status'" }
    if ($Classification) { $filters += "classification eq '$Classification'" }
    if ($AssignedTo)     { $filters += "assignedTo eq '$AssignedTo'" }

    $filter = $filters -join ' and '
    $uri = "$baseUri/api/alerts?`$filter=$filter&`$orderby=alertCreationTime desc"

    return Invoke-SecOpsPaginatedRequest -Uri $uri -Headers $headers `
        -OperationName 'Get-MdeAlert'
}

function Update-MdeAlert {
    <#
    .SYNOPSIS
        Updates an MDE alert (status, classification, assignment, comment).
    .EXAMPLE
        Update-MdeAlert -AlertId '<guid>' -Status Resolved -Classification TruePositive `
            -Comment 'Confirmed malware — host reimaged'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$AlertId,
        [ValidateSet('New','InProgress','Resolved')][string]$Status,
        [ValidateSet('TruePositive','FalsePositive','InformationalExpectedActivity')]
        [string]$Classification,
        [string]$AssignedTo,
        [string]$Comment
    )

    if (-not $PSCmdlet.ShouldProcess("Alert $AlertId", "Update")) { return }

    $baseUri = Get-DefenderBaseUri
    $token   = Get-DefenderToken
    $headers = @{ Authorization = "Bearer $token" }

    $body = @{}
    if ($Status)         { $body.status = $Status }
    if ($Classification) { $body.classification = $Classification }
    if ($AssignedTo)     { $body.assignedTo = $AssignedTo }
    if ($Comment)        { $body.comment = $Comment }

    return Invoke-SecOpsRestMethod -Uri "$baseUri/api/alerts/$AlertId" `
        -Method PATCH -Body $body -Headers $headers -OperationName 'Update-MdeAlert'
}
```

### Software & Vulnerability Inventory

```powershell
function Get-MdeSoftwareInventory {
    <#
    .SYNOPSIS
        Lists software installed across MDE-managed devices with known vulnerabilities.
    .DESCRIPTION
        Queries Threat & Vulnerability Management (TVM). Useful for identifying
        unpatched software exposure. Permission: Software.Read.All
        MITRE: T1518.001 (security software discovery defense)
    .EXAMPLE
        $sw = Get-MdeSoftwareInventory
        $sw.Data | Where-Object { $_.ExposedMachines -gt 0 } | Sort-Object ExposedMachines -Descending | Select-Object -First 20
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $baseUri = Get-DefenderBaseUri
    $token   = Get-DefenderToken
    $headers = @{ Authorization = "Bearer $token" }

    return Invoke-SecOpsPaginatedRequest `
        -Uri "$baseUri/api/Software" -Headers $headers `
        -OperationName 'Get-MdeSoftwareInventory'
}

function Get-MdeVulnerability {
    <#
    .SYNOPSIS
        Lists CVEs found by TVM across the estate. Filter by severity or CVE ID.
    .EXAMPLE
        Get-MdeVulnerability -Severity Critical | Select-Object -First 10
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('Low','Medium','High','Critical')][string]$Severity,
        [string]$CveId
    )

    $baseUri = Get-DefenderBaseUri
    $token   = Get-DefenderToken
    $headers = @{ Authorization = "Bearer $token" }

    $uri = "$baseUri/api/vulnerabilities"
    $filters = @()
    if ($Severity) { $filters += "severity eq '$Severity'" }
    if ($CveId)    { $filters += "id eq '$CveId'" }
    if ($filters)  { $uri += "?`$filter=$($filters -join ' and ')" }

    return Invoke-SecOpsPaginatedRequest -Uri $uri -Headers $headers `
        -OperationName 'Get-MdeVulnerability'
}
```

### Custom Detection Rules CRUD

```powershell
function Get-MdeCustomDetection {
    <#
    .SYNOPSIS
        Lists custom detection rules configured in MDE.
    .EXAMPLE
        Get-MdeCustomDetection | Where-Object { $_.Data.isEnabled }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $token   = (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com').Token
    $headers = @{ Authorization = "Bearer $token" }
    $uri     = "https://$(Get-SecOpsGraphEndpoint)/v1.0/security/rules/detectionRules"

    return Invoke-SecOpsPaginatedRequest -Uri $uri -Headers $headers `
        -OperationName 'Get-MdeCustomDetection'
}

function New-MdeCustomDetection {
    <#
    .SYNOPSIS
        Creates a new custom detection rule from a KQL query.
    .DESCRIPTION
        Schedule: every 1h, 3h, 12h, or 24h. Query must return AlertEvidence columns
        (Timestamp, DeviceId, ReportId). Permission: CustomDetections.ReadWrite.All
    .EXAMPLE
        New-MdeCustomDetection -DisplayName 'Suspicious encoded PowerShell' `
            -Query 'DeviceProcessEvents | where Timestamp > ago(1h) | where ProcessCommandLine has "-enc"' `
            -Frequency '1h' -Severity Medium -MitreTechnique 'T1059.001'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$Query,
        [ValidateSet('1h','3h','12h','24h')][string]$Frequency = '24h',
        [ValidateSet('Informational','Low','Medium','High')][string]$Severity = 'Medium',
        [string]$MitreTechnique,
        [string]$Description
    )

    if (-not $PSCmdlet.ShouldProcess($DisplayName, "Create custom detection")) { return }

    $graphEndpoint = Get-SecOpsGraphEndpoint
    $token   = (Get-AzAccessToken -ResourceUrl "https://$graphEndpoint").Token
    $headers = @{ Authorization = "Bearer $token" }

    $periodMap = @{ '1h' = 'PT1H'; '3h' = 'PT3H'; '12h' = 'PT12H'; '24h' = 'P1D' }

    $body = @{
        displayName      = $DisplayName
        isEnabled        = $true
        queryCondition   = @{ queryText = $Query; lastQueryTimestamp = $null }
        schedule         = @{ period = $periodMap[$Frequency] }
        detectionAction  = @{
            alertTemplate = @{
                title                = $DisplayName
                severity             = $Severity
                description          = $Description ?? $DisplayName
                recommendedActions   = 'Investigate the process execution chain.'
                mitreTechniques      = if ($MitreTechnique) { @($MitreTechnique) } else { @() }
            }
        }
    }

    return Invoke-SecOpsRestMethod -Uri "https://$graphEndpoint/v1.0/security/rules/detectionRules" `
        -Method POST -Body $body -Headers $headers -OperationName 'New-MdeCustomDetection'
}
```

---

## Section 2: Defender for Cloud

All Defender for Cloud APIs go through Azure Resource Manager (`management.azure.com`).

### Get-DefenderSecureScore

```powershell
function Get-DefenderSecureScore {
    <#
    .SYNOPSIS
        Retrieves the Microsoft Defender for Cloud secure score for a subscription.
    .EXAMPLE
        Get-DefenderSecureScore
        # Returns: current/max score, percentage, weight per control
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$SubscriptionId
    )

    if (-not $SubscriptionId) { $SubscriptionId = (Get-AzContext).Subscription.Id }
    $token   = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ Authorization = "Bearer $token" }

    $uri = "https://management.azure.com/subscriptions/$SubscriptionId" +
           "/providers/Microsoft.Security/secureScores?api-version=2020-01-01"

    $result = Invoke-SecOpsRestMethod -Uri $uri -Headers $headers `
        -OperationName 'Get-DefenderSecureScore'

    if ($result.Ok) {
        $scores = $result.Data.value | ForEach-Object {
            [PSCustomObject]@{
                Name       = $_.properties.displayName
                Current    = $_.properties.score.current
                Max        = $_.properties.score.max
                Percentage = [math]::Round(($_.properties.score.current / $_.properties.score.max) * 100, 1)
                Weight     = $_.properties.weight
            }
        }
        return New-SecOpsResult -Success -Data $scores
    }
    return $result
}
```

### Get-DefenderCloudAlert

```powershell
function Get-DefenderCloudAlert {
    <#
    .SYNOPSIS
        Retrieves Defender for Cloud security alerts. Supports cross-subscription queries.
    .EXAMPLE
        Get-DefenderCloudAlert -Severity High -DaysBack 7
    .EXAMPLE
        # All active alerts across all subscriptions
        Get-AzSubscription | ForEach-Object {
            Get-DefenderCloudAlert -SubscriptionId $_.Id -Status Active
        }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$SubscriptionId,
        [ValidateSet('Low','Medium','High')][string]$Severity,
        [ValidateSet('Active','Resolved','Dismissed')][string]$Status,
        [int]$DaysBack = 30
    )

    if (-not $SubscriptionId) { $SubscriptionId = (Get-AzContext).Subscription.Id }
    $token   = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ Authorization = "Bearer $token" }

    $uri = "https://management.azure.com/subscriptions/$SubscriptionId" +
           "/providers/Microsoft.Security/alerts?api-version=2022-01-01"

    $result = Invoke-SecOpsPaginatedRequest -Uri $uri -Headers $headers `
        -OperationName 'Get-DefenderCloudAlert'

    if ($result.Ok) {
        $alerts = $result.Data | ForEach-Object {
            [PSCustomObject]@{
                Name        = $_.properties.alertDisplayName
                Severity    = $_.properties.severity
                Status      = $_.properties.status
                Intent      = $_.properties.intent
                StartTime   = $_.properties.startTimeUtc
                Resource    = $_.properties.compromisedEntity
                Description = $_.properties.description
            }
        }

        $cutoff = (Get-Date).AddDays(-$DaysBack)
        $alerts = $alerts | Where-Object { [datetime]$_.StartTime -ge $cutoff }
        if ($Severity) { $alerts = $alerts | Where-Object Severity -eq $Severity }
        if ($Status)   { $alerts = $alerts | Where-Object Status -eq $Status }

        return New-SecOpsResult -Success -Data $alerts
    }
    return $result
}
```

### Get-ComplianceAssessment — Regulatory Compliance

```powershell
function Get-ComplianceAssessment {
    <#
    .SYNOPSIS
        Retrieves regulatory compliance assessment results from Defender for Cloud.
    .DESCRIPTION
        Returns assessment status per control across standards (NIST 800-53, CIS, PCI-DSS, ISO 27001).
        Check .secops/compliance/requirements.yaml for applicable frameworks.
    .EXAMPLE
        Get-ComplianceAssessment -Standard 'Azure CIS 1.4.0'
    .EXAMPLE
        Get-ComplianceAssessment | Where-Object { $_.State -eq 'Failed' } | Group-Object Standard
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$SubscriptionId,
        [string]$Standard
    )

    if (-not $SubscriptionId) { $SubscriptionId = (Get-AzContext).Subscription.Id }
    $token   = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ Authorization = "Bearer $token" }

    $uri = "https://management.azure.com/subscriptions/$SubscriptionId" +
           "/providers/Microsoft.Security/regulatoryComplianceStandards?api-version=2019-01-01-preview"

    $result = Invoke-SecOpsPaginatedRequest -Uri $uri -Headers $headers `
        -OperationName 'Get-ComplianceAssessment'

    if (-not $result.Ok) { return $result }

    $standards = $result.Data
    if ($Standard) { $standards = $standards | Where-Object { $_.name -match $Standard } }

    $assessments = foreach ($std in $standards) {
        $controlUri = "https://management.azure.com$($std.id)/regulatoryComplianceControls?api-version=2019-01-01-preview"
        $controls = Invoke-SecOpsPaginatedRequest -Uri $controlUri -Headers $headers `
            -OperationName "ComplianceControls:$($std.name)"

        if ($controls.Ok) {
            $controls.Data | ForEach-Object {
                [PSCustomObject]@{
                    Standard    = $std.name
                    ControlId   = $_.name
                    Description = $_.properties.description
                    State       = $_.properties.state
                    Passed      = $_.properties.passedAssessments
                    Failed      = $_.properties.failedAssessments
                    Skipped     = $_.properties.skippedAssessments
                }
            }
        }
    }

    return New-SecOpsResult -Success -Data $assessments
}
```

### Request-JitVmAccess — Just-In-Time VM Access

```powershell
function Request-JitVmAccess {
    <#
    .SYNOPSIS
        Requests JIT VM access through Defender for Cloud.
    .DESCRIPTION
        Opens specified ports for a limited time. Requires a JIT policy to exist on the VM.
        Permission: Microsoft.Security/locations/jitNetworkAccessPolicies/initiate/action
        MITRE: T1190 (compensating control for exposed management ports)
    .EXAMPLE
        Request-JitVmAccess -VmResourceId '/subscriptions/.../vm-jumpbox' `
            -Ports @(3389, 22) -DurationHours 3 -Justification 'IR-2026-012 forensic access'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$VmResourceId,
        [Parameter(Mandatory)][int[]]$Ports,
        [int]$DurationHours = 3,
        [Parameter(Mandatory)][string]$Justification,
        [string]$AllowedSourceIp = '*'
    )

    if (-not $PSCmdlet.ShouldProcess($VmResourceId, "JIT access: ports $($Ports -join ',')")) { return }

    $token   = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ Authorization = "Bearer $token" }

    $endTime = (Get-Date).AddHours($DurationHours).ToUniversalTime().ToString('o')

    $portRequests = $Ports | ForEach-Object {
        @{
            number                     = $_
            allowedSourceAddressPrefix = $AllowedSourceIp
            endDateTime                = $endTime
        }
    }

    $body = @{
        virtualMachines = @(@{
            id    = $VmResourceId
            ports = $portRequests
        })
        justification = $Justification
    }

    # Resolve JIT policy location from VM resource ID
    $vmParts = $VmResourceId -split '/'
    $subId   = $vmParts[2]
    $rg      = $vmParts[4]
    $location = (Get-AzResource -ResourceId $VmResourceId).Location

    $uri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg" +
           "/providers/Microsoft.Security/locations/$location" +
           "/jitNetworkAccessPolicies/default/initiate?api-version=2020-01-01"

    return Invoke-SecOpsRestMethod -Uri $uri -Method POST -Body $body `
        -Headers $headers -OperationName 'Request-JitVmAccess'
}
```

---

## Section 3: Defender XDR (Unified)

XDR APIs run through Microsoft Graph Security (`graph.microsoft.com/v1.0/security`).

### Get-XdrIncident / Update-XdrIncident

```powershell
function Get-XdrIncident {
    <#
    .SYNOPSIS
        Retrieves XDR incidents from Microsoft 365 Defender.
    .DESCRIPTION
        Unified incidents correlate alerts across MDE, MDO, MDI, and MDCA.
        Permission: SecurityIncident.Read.All
    .EXAMPLE
        Get-XdrIncident -Status Active -Severity High -DaysBack 7
    .EXAMPLE
        Get-XdrIncident -AssignedTo 'analyst@contoso.com'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('Active','Resolved','Redirected')][string]$Status,
        [ValidateSet('Informational','Low','Medium','High')][string]$Severity,
        [string]$AssignedTo,
        [int]$DaysBack = 30
    )

    $graphEndpoint = Get-SecOpsGraphEndpoint
    $token   = (Get-AzAccessToken -ResourceUrl "https://$graphEndpoint").Token
    $headers = @{ Authorization = "Bearer $token" }

    $filters = @("createdDateTime ge $((Get-Date).AddDays(-$DaysBack).ToString('o'))")
    if ($Status)     { $filters += "status eq '$($Status.ToLower())'" }
    if ($Severity)   { $filters += "severity eq '$($Severity.ToLower())'" }
    if ($AssignedTo) { $filters += "assignedTo eq '$AssignedTo'" }

    $filter = $filters -join ' and '
    $uri = "https://$graphEndpoint/v1.0/security/incidents?`$filter=$filter&`$orderby=createdDateTime desc&`$top=100"

    return Invoke-SecOpsPaginatedRequest -Uri $uri -Headers $headers `
        -OperationName 'Get-XdrIncident'
}

function Update-XdrIncident {
    <#
    .SYNOPSIS
        Updates an XDR incident (status, assignment, classification, tags).
    .EXAMPLE
        Update-XdrIncident -IncidentId '12345' -Status Resolved `
            -Classification TruePositive -Comment 'Phishing confirmed and remediated'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$IncidentId,
        [ValidateSet('Active','Resolved','Redirected')][string]$Status,
        [ValidateSet('TruePositive','FalsePositive','InformationalExpectedActivity','Unknown')]
        [string]$Classification,
        [string]$AssignedTo,
        [string]$Comment,
        [string[]]$Tags
    )

    if (-not $PSCmdlet.ShouldProcess("Incident $IncidentId", "Update")) { return }

    $graphEndpoint = Get-SecOpsGraphEndpoint
    $token   = (Get-AzAccessToken -ResourceUrl "https://$graphEndpoint").Token
    $headers = @{ Authorization = "Bearer $token" }

    $body = @{}
    if ($Status)         { $body.status = $Status.ToLower() }
    if ($Classification) { $body.classification = $Classification }
    if ($AssignedTo)     { $body.assignedTo = $AssignedTo }
    if ($Tags)           { $body.customTags = $Tags }

    $result = Invoke-SecOpsRestMethod `
        -Uri "https://$graphEndpoint/v1.0/security/incidents/$IncidentId" `
        -Method PATCH -Body $body -Headers $headers -OperationName 'Update-XdrIncident'

    # Post comment as separate call if provided
    if ($result.Ok -and $Comment) {
        $commentBody = @{ comment = $Comment; createdDateTime = (Get-Date).ToString('o') }
        Invoke-SecOpsRestMethod `
            -Uri "https://$graphEndpoint/v1.0/security/incidents/$IncidentId/comments" `
            -Method POST -Body $commentBody -Headers $headers `
            -OperationName 'Update-XdrIncident:Comment' | Out-Null
    }

    return $result
}
```

### Invoke-XdrAdvancedHunting — Cross-Product Hunting

```powershell
function Invoke-XdrAdvancedHunting {
    <#
    .SYNOPSIS
        Runs a KQL query across ALL Defender XDR tables (MDE + MDO + MDI + MDCA + Entra).
    .DESCRIPTION
        Uses the Graph Security Advanced Hunting endpoint. Unlike Run-MdeAdvancedHunting,
        this queries unified tables: EmailEvents, IdentityLogonEvents, CloudAppEvents, etc.
        Permission: ThreatHunting.Read.All
        MITRE: T1078 (hunt), T1110 (hunt), T1566 (hunt)
    .EXAMPLE
        # Hunt for password spray across identity and email telemetry
        Invoke-XdrAdvancedHunting -Query @"
            IdentityLogonEvents
            | where Timestamp > ago(24h)
            | where ActionType == "LogonFailed"
            | summarize FailCount=count(), DistinctAccounts=dcount(AccountUpn) by IPAddress
            | where DistinctAccounts > 10
            | sort by DistinctAccounts desc
        "@
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][string]$Query,
        [int]$TimeoutSec = 120
    )

    $graphEndpoint = Get-SecOpsGraphEndpoint
    $token   = (Get-AzAccessToken -ResourceUrl "https://$graphEndpoint").Token
    $headers = @{ Authorization = "Bearer $token" }

    $body = @{ query = $Query }

    $result = Invoke-SecOpsRestMethod `
        -Uri "https://$graphEndpoint/v1.0/security/runHuntingQuery" `
        -Method POST -Body $body -Headers $headers -TimeoutSec $TimeoutSec `
        -OperationName 'Invoke-XdrAdvancedHunting'

    if ($result.Ok) {
        Write-Verbose "XDR hunting: $($result.Data.results.Count) rows returned"
        return New-SecOpsResult -Success -Data $result.Data.results
    }
    return $result
}
```

### Get-XdrInvestigation / Attack Disruption

```powershell
function Get-XdrInvestigation {
    <#
    .SYNOPSIS
        Retrieves automated investigation details from Defender XDR.
    .EXAMPLE
        Get-XdrInvestigation -Status Running
    .EXAMPLE
        Get-XdrInvestigation -IncidentId '12345'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('Running','Pending','PartiallyRemediated','FullyRemediated',
                     'Failed','PendingApproval','Terminated')][string]$Status,
        [string]$IncidentId
    )

    $baseUri = Get-DefenderBaseUri
    $token   = Get-DefenderToken
    $headers = @{ Authorization = "Bearer $token" }

    $uri = "$baseUri/api/investigations"
    $filters = @()
    if ($Status)     { $filters += "status eq '$Status'" }
    if ($IncidentId) { $filters += "incidentId eq $IncidentId" }
    if ($filters)    { $uri += "?`$filter=$($filters -join ' and ')" }

    return Invoke-SecOpsPaginatedRequest -Uri $uri -Headers $headers `
        -OperationName 'Get-XdrInvestigation'
}

function Get-XdrAttackDisruption {
    <#
    .SYNOPSIS
        Checks attack disruption actions taken by Defender XDR automated response.
    .DESCRIPTION
        Attack disruption automatically contains compromised entities during active attacks.
        This function retrieves the actions taken (e.g., user disabled, device isolated).
    .EXAMPLE
        Get-XdrAttackDisruption -DaysBack 7
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param([int]$DaysBack = 7)

    $graphEndpoint = Get-SecOpsGraphEndpoint
    $token   = (Get-AzAccessToken -ResourceUrl "https://$graphEndpoint").Token
    $headers = @{ Authorization = "Bearer $token" }

    $since = (Get-Date).AddDays(-$DaysBack).ToString('o')
    $uri = "https://$graphEndpoint/v1.0/security/incidents?" +
           "`$filter=classification eq 'truePositive' and " +
           "createdDateTime ge $since&`$orderby=createdDateTime desc"

    $result = Invoke-SecOpsPaginatedRequest -Uri $uri -Headers $headers `
        -OperationName 'Get-XdrAttackDisruption'

    if ($result.Ok) {
        # Filter to incidents with attack disruption actions
        $disrupted = $result.Data | Where-Object {
            $_.systemTags -contains 'AttackDisruption' -or
            $_.comments.comment -match 'attack disruption'
        }
        return New-SecOpsResult -Success -Data $disrupted
    }
    return $result
}
```

---

## Section 4: Defender for Identity (MDI)

MDI APIs are accessible via Graph Security and direct MDI endpoints.

### Get-MdiHealthIssue

```powershell
function Get-MdiHealthIssue {
    <#
    .SYNOPSIS
        Retrieves MDI sensor health issues (offline sensors, config problems, high CPU).
    .DESCRIPTION
        MDI health issues indicate sensor or service problems that can create blind spots.
        Permission: SecurityIdentitiesHealth.Read.All
        MITRE: T1562.001 (monitoring for defense impairment)
    .EXAMPLE
        Get-MdiHealthIssue -Status Open
    .EXAMPLE
        Get-MdiHealthIssue | Where-Object { $_.Severity -eq 'High' }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('Open','Closed','Suppressed')][string]$Status
    )

    $graphEndpoint = Get-SecOpsGraphEndpoint
    $token   = (Get-AzAccessToken -ResourceUrl "https://$graphEndpoint").Token
    $headers = @{ Authorization = "Bearer $token" }

    $uri = "https://$graphEndpoint/v1.0/security/identities/healthIssues"
    if ($Status) { $uri += "?`$filter=status eq '$($Status.ToLower())'" }

    $result = Invoke-SecOpsPaginatedRequest -Uri $uri -Headers $headers `
        -OperationName 'Get-MdiHealthIssue'

    if ($result.Ok) {
        $issues = $result.Data | ForEach-Object {
            [PSCustomObject]@{
                Id            = $_.id
                DisplayName   = $_.displayName
                HealthType    = $_.healthIssueType
                Severity      = $_.severity
                Status        = $_.status
                DomainName    = $_.domainName
                SensorDnsName = $_.sensorDNSNames -join ', '
                Description   = $_.description
                Recommendations = $_.recommendations -join '; '
                CreatedAt     = $_.createdDateTime
                UpdatedAt     = $_.lastModifiedDateTime
            }
        }
        return New-SecOpsResult -Success -Data $issues
    }
    return $result
}
```

### MDI Security Assessments & Suspicious Activities

```powershell
function Get-MdiSecurityAssessment {
    <#
    .SYNOPSIS
        Retrieves MDI identity security posture assessments.
    .DESCRIPTION
        Assessments cover: unsecured Kerberos delegation, weak cipher usage,
        dormant sensitive accounts, LDAP signing, etc.
        MITRE: T1558 (Kerberos), T1087 (account discovery)
    .EXAMPLE
        Get-MdiSecurityAssessment | Where-Object { $_.Status -eq 'unhealthy' }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    # MDI assessments are exposed as Defender for Cloud assessments scoped to identity
    $subId   = (Get-AzContext).Subscription.Id
    $token   = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ Authorization = "Bearer $token" }

    $uri = "https://management.azure.com/subscriptions/$subId" +
           "/providers/Microsoft.Security/assessments?api-version=2021-06-01"

    $result = Invoke-SecOpsPaginatedRequest -Uri $uri -Headers $headers `
        -OperationName 'Get-MdiSecurityAssessment'

    if ($result.Ok) {
        # Filter to identity-related assessments
        $identityAssessments = $result.Data | Where-Object {
            $_.properties.metadata.categories -contains 'IdentityAndAccess' -or
            $_.properties.displayName -match 'identity|kerberos|LDAP|delegation|credential'
        } | ForEach-Object {
            [PSCustomObject]@{
                Name        = $_.properties.displayName
                Status      = $_.properties.status.code
                Severity    = $_.properties.metadata.severity
                Description = $_.properties.metadata.description
                ResourceId  = $_.properties.resourceDetails.Id
            }
        }
        return New-SecOpsResult -Success -Data $identityAssessments
    }
    return $result
}

function Get-MdiSuspiciousActivity {
    <#
    .SYNOPSIS
        Queries MDI alerts for suspicious identity activities via XDR Advanced Hunting.
    .DESCRIPTION
        Searches IdentityLogonEvents and IdentityDirectoryEvents for anomalous
        patterns detected by MDI sensors.
        MITRE: T1078 (valid accounts), T1110 (brute force)
    .EXAMPLE
        Get-MdiSuspiciousActivity -DaysBack 7
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param([int]$DaysBack = 7)

    $query = @"
AlertInfo
| where Timestamp > ago($($DaysBack)d)
| where ServiceSource == "Microsoft Defender for Identity"
| join kind=inner AlertEvidence on AlertId
| project Timestamp, AlertId, Title, Severity, Category,
          EntityType, AccountName, DeviceName, RemoteIP
| sort by Timestamp desc
"@

    return Invoke-XdrAdvancedHunting -Query $query
}
```

### Get-MdiEntityProfile — User/Device Identity Context

```powershell
function Get-MdiEntityProfile {
    <#
    .SYNOPSIS
        Retrieves MDI entity profile (user or device) with risk score and activities.
    .DESCRIPTION
        Returns lateral movement paths, group memberships, and recent activities.
        Useful during incident investigation to understand blast radius.
        MITRE: T1087 (account discovery context)
    .EXAMPLE
        Get-MdiEntityProfile -Upn 'admin@contoso.com'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Upn')][string]$Upn,
        [Parameter(Mandatory, ParameterSetName = 'DeviceName')][string]$DeviceName
    )

    # Entity profiles via XDR Advanced Hunting
    if ($Upn) {
        $query = @"
IdentityInfo
| where AccountUpn =~ "$Upn"
| project AccountUpn, AccountDisplayName, Department, JobTitle,
          IsAccountEnabled, RiskScore = ""
| take 1
"@
    } else {
        $query = @"
DeviceInfo
| where DeviceName =~ "$DeviceName"
| summarize arg_max(Timestamp, *) by DeviceId
| project DeviceName, OSPlatform, OSVersion, MachineGroup,
          PublicIP, LoggedOnUsers, ExposureLevel, DeviceId
| take 1
"@
    }

    return Invoke-XdrAdvancedHunting -Query $query
}
```

---

## Section 5: Graph SDK Alternative Approach

For teams preferring the Microsoft Graph PowerShell SDK over raw REST:

```powershell
# Install SDK modules (one-time)
# Install-Module Microsoft.Graph.Security -Scope CurrentUser

function Get-XdrIncidentSdk {
    <#
    .SYNOPSIS
        Get-XdrIncident equivalent using Microsoft.Graph.Security SDK.
    .DESCRIPTION
        Uses the Graph SDK cmdlets instead of raw Invoke-RestMethod.
        Handles pagination and auth automatically via Connect-MgGraph.
    .EXAMPLE
        Connect-MgGraph -Scopes 'SecurityIncident.Read.All'
        Get-XdrIncidentSdk -Severity High -DaysBack 7
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('Active','Resolved','Redirected')][string]$Status,
        [ValidateSet('Informational','Low','Medium','High')][string]$Severity,
        [int]$DaysBack = 30
    )

    try {
        $filter = "createdDateTime ge $((Get-Date).AddDays(-$DaysBack).ToString('o'))"
        if ($Status)   { $filter += " and status eq '$($Status.ToLower())'" }
        if ($Severity) { $filter += " and severity eq '$($Severity.ToLower())'" }

        $incidents = Get-MgSecurityIncident -Filter $filter `
            -Sort 'createdDateTime desc' -All -ErrorAction Stop

        return New-SecOpsResult -Success -Data $incidents
    }
    catch {
        return New-SecOpsResult -Error $_.Exception.Message -StatusCode 0 `
            -ErrorCode 'GraphSdkError'
    }
}

# Pattern: SDK vs REST decision matrix
# | Factor               | Use SDK (Connect-MgGraph) | Use REST (Invoke-SecOpsRestMethod) |
# |---|---|---|
# | Pagination           | Handled automatically     | Manual @odata.nextLink             |
# | Auth                 | Connect-MgGraph once      | Token per call                     |
# | Custom headers       | Limited                   | Full control                       |
# | Gov cloud            | -Environment USGov        | Manual endpoint switch             |
# | Audit logging        | Add custom layer          | Built into wrapper                 |
# | Automation/Functions | REST preferred             | REST preferred                     |
# | Interactive SOC      | SDK preferred              | Either works                       |
```

---

## Environment Context

Before using any wrapper, agents MUST consult:

- **`.secops/environment.yaml`** — Cloud type determines all API base URIs
- **`.secops/identity/tenants.yaml`** — Multi-tenant requires per-tenant tokens
- **`.secops/data-sources/data-source-map.yaml`** — Verify which Defender products are deployed
- **`.secops/compliance/requirements.yaml`** — Data residency may restrict API regions

```powershell
# Quick environment pre-flight check
function Test-DefenderPreFlight {
    [CmdletBinding()]
    param()

    $checks = @{}
    $checks['AzContext']   = [bool](Get-AzContext -ErrorAction SilentlyContinue)
    $checks['CloudType']   = try { Get-SecOpsCloudEnvironment } catch { 'Unknown' }
    $checks['MdeAccess']   = (Invoke-SecOpsRestMethod -Uri "$(Get-DefenderBaseUri)/api/alerts?`$top=1" `
        -Headers @{ Authorization = "Bearer $(Get-DefenderToken)" } `
        -OperationName 'PreFlight:MDE').Ok
    $checks['GraphAccess'] = (Invoke-SecOpsRestMethod `
        -Uri "https://$(Get-SecOpsGraphEndpoint)/v1.0/security/incidents?`$top=1" `
        -Headers @{ Authorization = "Bearer $((Get-AzAccessToken -ResourceUrl "https://$(Get-SecOpsGraphEndpoint)").Token)" } `
        -OperationName 'PreFlight:Graph').Ok

    [PSCustomObject]$checks
}
```

## Best Practices

1. **Always use `ShouldProcess`** on destructive actions — every `Invoke-MdeMachineAction`, `Update-*`, `Request-JitVmAccess` supports `-WhatIf`
2. **Include incident IDs in comments** — MDE requires a comment string; format as `INC-YYYY-NNN: description`
3. **Prefer XDR over MDE-only** — Use `Invoke-XdrAdvancedHunting` (Graph) for cross-product queries; `Run-MdeAdvancedHunting` for MDE-only tables
4. **Drain pagination** — Use `Invoke-SecOpsPaginatedRequest` for any list endpoint; never assume a single page
5. **Cloud-aware endpoints** — Always resolve via `Get-DefenderBaseUri` / `Get-SecOpsGraphEndpoint`; never hardcode
6. **Rate limits** — MDE: 100 calls/min on action endpoints; Graph: 10,000/10 min per app per tenant
7. **Monitor MDI health** — Offline sensors create detection blind spots; run `Get-MdiHealthIssue` daily
8. **Pre-flight check** — Run `Test-DefenderPreFlight` before bulk operations to validate connectivity

## Related Skills

- [defender-module.md](defender-module.md) — Base MDE wrappers this skill extends
- [auth-patterns.md](auth-patterns.md) — All authentication flows (interactive, SP, MI, multi-tenant)
- [error-handling.md](error-handling.md) — `Invoke-SecOpsRestMethod`, `New-SecOpsResult`, retry patterns
- [../msft-security/defender-mcp-server.md](../msft-security/defender-mcp-server.md) — MCP agent integration
- [../msft-security/defender-api-permissions.md](../msft-security/defender-api-permissions.md) — Permission matrices
- [../msft-security/defender-for-endpoint.md](../msft-security/defender-for-endpoint.md) — MDE onboarding, ASR, device groups
- [../kql/defender-xdr-hunting.md](../kql/defender-xdr-hunting.md) — KQL queries for hunting functions
