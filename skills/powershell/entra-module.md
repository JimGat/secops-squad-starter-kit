---
title: Entra ID Submodule
category: powershell
difficulty: intermediate
mitre_attack:
  - T1078  # Valid Accounts
  - T1556  # Modify Authentication Process
  - T1098  # Account Manipulation
  - T1110  # Brute Force
products:
  - Microsoft Entra ID
  - Microsoft Graph
  - Privileged Identity Management
  - Conditional Access
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# Entra ID Submodule

## Overview

The Entra submodule wraps Microsoft Graph identity endpoints — Conditional Access policy management, Privileged Identity Management (PIM) role activation, Identity Protection risk events, and sign-in log analysis. It enables SOC teams to manage identity security as code.

Use this skill when:
- Exporting and importing Conditional Access policies for version control
- Activating or managing PIM eligible role assignments
- Querying Identity Protection for risky sign-ins and risky users
- Analyzing sign-in logs for suspicious patterns
- Automating identity security posture management

## Prerequisites

| Requirement | Detail |
|---|---|
| **Microsoft.Graph modules** | `Microsoft.Graph.Authentication`, `Microsoft.Graph.Identity.SignIns`, `Microsoft.Graph.Identity.Governance` |
| **Permissions** | `Policy.ReadWrite.ConditionalAccess`, `IdentityRiskEvent.Read.All`, `RoleManagement.ReadWrite.Directory`, `AuditLog.Read.All` |
| **Licensing** | Entra ID P2 for PIM and Identity Protection |
| **Admin Consent** | Required for application-level Graph permissions |

## REST API Endpoints

| Endpoint | Purpose | Permission |
|---|---|---|
| `/identity/conditionalAccess/policies` | CA policy CRUD | `Policy.ReadWrite.ConditionalAccess` |
| `/identityProtection/riskDetections` | Risk detection events | `IdentityRiskEvent.Read.All` |
| `/identityProtection/riskyUsers` | Users flagged as risky | `IdentityRiskyUser.ReadWrite.All` |
| `/auditLogs/signIns` | Sign-in logs | `AuditLog.Read.All` |
| `/roleManagement/directory/roleEligibilityScheduleRequests` | PIM eligible roles | `RoleManagement.ReadWrite.Directory` |
| `/roleManagement/directory/roleAssignmentScheduleRequests` | PIM active assignments | `RoleManagement.ReadWrite.Directory` |

**Base URI:** Use `Get-SecOpsGraphEndpoint` from auth-patterns to resolve cloud-specific Graph endpoint.

## Key Functions

### Get-SecOpsConditionalAccessPolicy — List CA Policies

```powershell
function Get-SecOpsConditionalAccessPolicy {
    <#
    .SYNOPSIS
        Lists all Conditional Access policies with state and conditions.
    .EXAMPLE
        Get-SecOpsConditionalAccessPolicy | Where-Object State -eq 'enabled'
    .EXAMPLE
        Get-SecOpsConditionalAccessPolicy -PolicyId '<guid>'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$PolicyId
    )

    $graphEndpoint = Get-SecOpsGraphEndpoint
    $token = Get-SecOpsToken -Resource $graphEndpoint
    $headers = @{ 'Authorization' = "Bearer $token" }

    $uri = if ($PolicyId) {
        "$graphEndpoint/v1.0/identity/conditionalAccess/policies/$PolicyId"
    }
    else {
        "$graphEndpoint/v1.0/identity/conditionalAccess/policies"
    }

    $result = Invoke-SecOpsRestMethod -Uri $uri -Headers $headers `
        -OperationName 'Get-SecOpsConditionalAccessPolicy'

    if ($result.Ok) {
        $policies = if ($PolicyId) { @($result.Data) } else { $result.Data.value }

        $formatted = $policies | ForEach-Object {
            [PSCustomObject]@{
                Id                 = $_.id
                DisplayName        = $_.displayName
                State              = $_.state
                CreatedDateTime    = $_.createdDateTime
                ModifiedDateTime   = $_.modifiedDateTime
                GrantControls      = ($_.grantControls.builtInControls -join ', ')
                SessionControls    = ($_.sessionControls | ConvertTo-Json -Compress -Depth 3)
                IncludeUsers       = ($_.conditions.users.includeUsers -join ', ')
                ExcludeUsers       = ($_.conditions.users.excludeUsers -join ', ')
                IncludeApplications = ($_.conditions.applications.includeApplications -join ', ')
                IncludePlatforms   = ($_.conditions.platforms.includePlatforms -join ', ')
                IncludeLocations   = ($_.conditions.locations.includeLocations -join ', ')
            }
        }

        return New-SecOpsResult -Success -Data $formatted
    }

    return $result
}
```

### Export-SecOpsConditionalAccessPolicy — Export CA Policies as Code

```powershell
function Export-SecOpsConditionalAccessPolicy {
    <#
    .SYNOPSIS
        Exports Conditional Access policies to JSON for version control.
    .DESCRIPTION
        Exports all or specific CA policies to JSON files suitable for
        Git tracking. Strips read-only properties to make files idempotent
        for re-import.
    .EXAMPLE
        Export-SecOpsConditionalAccessPolicy -OutputPath "./ca-policies/"
    .EXAMPLE
        Export-SecOpsConditionalAccessPolicy -State 'enabled' -OutputPath "./ca-policies/"
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$OutputPath = './ca-policies',

        [ValidateSet('enabled', 'disabled', 'enabledForReportingButNotEnforced')]
        [string]$State
    )

    $graphEndpoint = Get-SecOpsGraphEndpoint
    $token = Get-SecOpsToken -Resource $graphEndpoint
    $headers = @{ 'Authorization' = "Bearer $token" }

    $uri = "$graphEndpoint/v1.0/identity/conditionalAccess/policies"
    $result = Invoke-SecOpsRestMethod -Uri $uri -Headers $headers `
        -OperationName 'Export-SecOpsConditionalAccessPolicy'

    if (-not $result.Ok) { return $result }

    $policies = $result.Data.value
    if ($State) {
        $policies = $policies | Where-Object { $_.state -eq $State }
    }

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $exported = @()
    foreach ($policy in $policies) {
        # Strip read-only fields for clean export
        $clean = $policy | Select-Object -Property * -ExcludeProperty id, createdDateTime, modifiedDateTime

        $fileName = ($policy.displayName -replace '[^\w\-\s]', '' -replace '\s+', '-').ToLower() + '.json'
        $filePath = Join-Path $OutputPath $fileName

        $clean | ConvertTo-Json -Depth 10 | Set-Content -Path $filePath -Encoding utf8
        $exported += @{ Name = $policy.displayName; Path = $filePath }
    }

    return New-SecOpsResult -Success -Data @{
        ExportedCount = $exported.Count
        OutputPath    = $OutputPath
        Policies      = $exported
    }
}
```

### Enable-SecOpsPimRole — Activate PIM Eligible Role

```powershell
function Enable-SecOpsPimRole {
    <#
    .SYNOPSIS
        Activates a PIM eligible role assignment.
    .DESCRIPTION
        Requests activation of a time-limited privileged role via PIM.
        Requires justification and respects maximum activation duration
        configured in the PIM policy.
    .EXAMPLE
        Enable-SecOpsPimRole -RoleName 'Security Reader' -Justification 'IR-2026-042 investigation' -DurationHours 4
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$RoleName,

        [Parameter(Mandatory)]
        [string]$Justification,

        [ValidateRange(1, 24)]
        [int]$DurationHours = 8
    )

    $graphEndpoint = Get-SecOpsGraphEndpoint
    $token = Get-SecOpsToken -Resource $graphEndpoint
    $headers = @{ 'Authorization' = "Bearer $token" }

    # Resolve role definition ID
    $rolesUri = "$graphEndpoint/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq '$RoleName'"
    $roleResult = Invoke-SecOpsRestMethod -Uri $rolesUri -Headers $headers `
        -OperationName 'Enable-SecOpsPimRole (resolve role)'

    if (-not $roleResult.Ok -or $roleResult.Data.value.Count -eq 0) {
        return New-SecOpsResult -Error "Role '$RoleName' not found" -ErrorCode 'RoleNotFound'
    }
    $roleDefinitionId = $roleResult.Data.value[0].id

    # Get current user's principal ID
    $meUri = "$graphEndpoint/v1.0/me"
    $meResult = Invoke-SecOpsRestMethod -Uri $meUri -Headers $headers `
        -OperationName 'Enable-SecOpsPimRole (resolve principal)'
    if (-not $meResult.Ok) { return $meResult }
    $principalId = $meResult.Data.id

    if (-not $PSCmdlet.ShouldProcess("$RoleName for $DurationHours hours", 'Activate PIM Role')) {
        return
    }

    # Create activation request
    $body = @{
        action           = 'selfActivate'
        principalId      = $principalId
        roleDefinitionId = $roleDefinitionId
        directoryScopeId = '/'
        justification    = $Justification
        scheduleInfo     = @{
            startDateTime = (Get-Date).ToUniversalTime().ToString('o')
            expiration    = @{
                type     = 'afterDuration'
                duration = "PT${DurationHours}H"
            }
        }
    }

    $activateUri = "$graphEndpoint/v1.0/roleManagement/directory/roleAssignmentScheduleRequests"
    $result = Invoke-SecOpsRestMethod -Uri $activateUri -Method POST -Body $body `
        -Headers $headers -OperationName 'Enable-SecOpsPimRole (activate)'

    if ($result.Ok) {
        Write-Verbose "PIM role '$RoleName' activated for $DurationHours hours"
    }

    return $result
}
```

### Get-SecOpsRiskySignIn — Query Identity Protection

```powershell
function Get-SecOpsRiskySignIn {
    <#
    .SYNOPSIS
        Queries risky sign-in events from Identity Protection.
    .EXAMPLE
        Get-SecOpsRiskySignIn -RiskLevel 'high' -DaysBack 7
    .EXAMPLE
        Get-SecOpsRiskySignIn -UserPrincipalName 'admin@contoso.com'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('low', 'medium', 'high', 'hidden', 'none')]
        [string]$RiskLevel,

        [string]$UserPrincipalName,

        [int]$DaysBack = 30,

        [int]$Top = 100
    )

    $graphEndpoint = Get-SecOpsGraphEndpoint
    $token = Get-SecOpsToken -Resource $graphEndpoint
    $headers = @{ 'Authorization' = "Bearer $token" }

    # Build filter
    $filters = @()
    $filters += "activityDateTime ge $((Get-Date).AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    if ($RiskLevel)          { $filters += "riskLevel eq '$RiskLevel'" }
    if ($UserPrincipalName)  { $filters += "userPrincipalName eq '$UserPrincipalName'" }

    $filterString = $filters -join ' and '
    $uri = "$graphEndpoint/v1.0/identityProtection/riskDetections" +
           "?`$filter=$filterString&`$top=$Top&`$orderby=activityDateTime desc"

    $result = Invoke-SecOpsRestMethod -Uri $uri -Headers $headers `
        -OperationName 'Get-SecOpsRiskySignIn'

    if ($result.Ok) {
        $events = $result.Data.value | ForEach-Object {
            [PSCustomObject]@{
                Id                  = $_.id
                UserDisplayName     = $_.userDisplayName
                UserPrincipalName   = $_.userPrincipalName
                RiskLevel           = $_.riskLevel
                RiskState           = $_.riskState
                RiskDetail          = $_.riskDetail
                DetectionType       = $_.riskEventType
                IpAddress           = $_.ipAddress
                Location            = "$($_.location.city), $($_.location.countryOrRegion)"
                ActivityDateTime    = $_.activityDateTime
                Source              = $_.source
                TokenIssuerType     = $_.tokenIssuerType
            }
        }

        return New-SecOpsResult -Success -Data $events
    }

    return $result
}
```

## Sign-In Log Analysis Patterns

### Suspicious Sign-In Detection

```powershell
# Find sign-ins from unfamiliar locations with failed MFA
$graphEndpoint = Get-SecOpsGraphEndpoint
$token = Get-SecOpsToken -Resource $graphEndpoint
$headers = @{ 'Authorization' = "Bearer $token" }

$filter = "createdDateTime ge $((Get-Date).AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ'))" +
          " and status/errorCode ne 0" +
          " and conditionalAccessStatus eq 'failure'"

$uri = "$graphEndpoint/v1.0/auditLogs/signIns?`$filter=$filter&`$top=100"
$result = Invoke-SecOpsRestMethod -Uri $uri -Headers $headers -OperationName 'SignIn Analysis'

if ($result.Ok) {
    $result.Data.value | Group-Object -Property userPrincipalName |
        Sort-Object Count -Descending |
        Select-Object Name, Count -First 20
}
```

### Bulk Risky User Remediation

```powershell
# Dismiss risk for users who have completed MFA re-registration
function Reset-SecOpsUserRisk {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string[]]$UserIds
    )

    $graphEndpoint = Get-SecOpsGraphEndpoint
    $token = Get-SecOpsToken -Resource $graphEndpoint
    $headers = @{ 'Authorization' = "Bearer $token" }

    $body = @{ userIds = $UserIds }
    $uri = "$graphEndpoint/v1.0/identityProtection/riskyUsers/dismiss"

    if ($PSCmdlet.ShouldProcess("$($UserIds.Count) users", 'Dismiss risk')) {
        return Invoke-SecOpsRestMethod -Uri $uri -Method POST -Body $body `
            -Headers $headers -OperationName 'Reset-SecOpsUserRisk'
    }
}
```

## Best Practices

1. **Export CA policies before changes** — Always snapshot current state before modifying Conditional Access
2. **PIM justification is mandatory** — Include incident or ticket numbers in justification strings
3. **Minimum activation duration** — Request only the PIM duration needed for the task
4. **Risk dismissal requires verification** — Only dismiss user risk after confirming MFA re-enrollment
5. **Sign-in logs are delayed** — Graph sign-in logs have up to 15-minute delay; for real-time, use Sentinel
6. **Government cloud differences** — Some Identity Protection features are limited in GCC-High

## Environment Context

Before using Entra functions, agents MUST consult:

- **`.secops/environment.yaml`** — Cloud type affects Graph endpoint and feature availability
- **`.secops/identity/tenants.yaml`** — Multi-tenant scenarios require per-tenant Graph connections
- **`.secops/compliance/requirements.yaml`** — Data residency may restrict where identity data is queried

## Related Skills

- `skills/kql/entra-signin-analysis.md` — KQL queries for sign-in log analysis in Sentinel
- `skills/msft-security/microsoft-graph-security.md` — Graph Security API for identity risk
- `skills/powershell/auth-patterns.md` — Graph authentication flows
- `skills/powershell/error-handling.md` — Graph-specific error codes
