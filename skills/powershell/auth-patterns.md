---
title: PowerShell Authentication Patterns
category: powershell
difficulty: intermediate
mitre_attack:
  - T1078  # Valid Accounts
  - T1556  # Modify Authentication Process
products:
  - Microsoft Entra ID
  - MSAL.PS
  - Azure PowerShell
  - Azure Lighthouse
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# PowerShell Authentication Patterns

## Overview

Authentication is the foundation of every security operation. This skill covers all authentication flows used by SecOps PowerShell modules — interactive login, service principal, managed identity, and certificate-based auth. It also covers multi-tenant scenarios (Lighthouse, B2B, MSSP), government cloud endpoints, and how to read `.secops/` configuration for auth context.

Use this skill when:
- Setting up authentication for any SecOps PowerShell module
- Implementing service principal auth for unattended automation
- Working with multi-tenant or MSSP scenarios
- Connecting to government cloud environments (GCC, GCC-High, DoD)
- Managing token caching and refresh for long-running operations

## Prerequisites

| Requirement | Detail |
|---|---|
| **PowerShell** | 7.4+ recommended |
| **MSAL.PS** | `Install-Module MSAL.PS -Scope CurrentUser` |
| **Az.Accounts** | `Install-Module Az.Accounts -Scope CurrentUser` |
| **App Registration** | Entra ID app for service principal and daemon flows |
| **Permissions** | Varies by target API — see individual module skills |

## Interactive Authentication

### Connect-AzAccount (Recommended Starting Point)

```powershell
# Interactive login — opens browser, supports MFA
Connect-AzAccount

# Specify tenant explicitly (required for multi-tenant)
Connect-AzAccount -TenantId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

# Set subscription context after login
Set-AzContext -SubscriptionId '11111111-2222-3333-4444-555555555555'
```

### MSAL Interactive Token Acquisition

```powershell
# Direct MSAL token for APIs not covered by Az modules
$msalParams = @{
    ClientId    = '<app-registration-client-id>'
    TenantId    = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    Scopes      = @('https://graph.microsoft.com/.default')
    Interactive = $true
}
$tokenResult = Get-MsalToken @msalParams

# Use token in REST calls
$headers = @{
    'Authorization' = "Bearer $($tokenResult.AccessToken)"
    'Content-Type'  = 'application/json'
}
```

## Service Principal Authentication

### Client Secret (Dev/Test Only)

```powershell
# Client secret auth — NOT recommended for production
$credential = New-Object System.Management.Automation.PSCredential(
    '<client-id>',
    (ConvertTo-SecureString '<client-secret>' -AsPlainText -Force)
)

Connect-AzAccount -ServicePrincipal -Credential $credential `
    -TenantId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
```

### Certificate-Based (Production Recommended)

```powershell
# Certificate-based service principal — production pattern
# Certificate must be installed in CurrentUser\My or LocalMachine\My

# Option 1: Certificate thumbprint
Connect-AzAccount -ServicePrincipal `
    -ApplicationId '<client-id>' `
    -TenantId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' `
    -CertificateThumbprint '<thumbprint>'

# Option 2: Certificate from file (for CI/CD pipelines)
$cert = Get-PfxCertificate -FilePath './certs/secops-sp.pfx'
Connect-AzAccount -ServicePrincipal `
    -ApplicationId '<client-id>' `
    -TenantId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' `
    -Certificate $cert
```

### MSAL Certificate Token

```powershell
# MSAL with certificate for Graph API calls
$cert = Get-Item 'Cert:\CurrentUser\My\<thumbprint>'

$msalParams = @{
    ClientId            = '<client-id>'
    TenantId            = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    ClientCertificate   = $cert
    Scopes              = @('https://graph.microsoft.com/.default')
}
$tokenResult = Get-MsalToken @msalParams
```

## Managed Identity Authentication

### System-Assigned Managed Identity

```powershell
# On Azure VMs, App Service, Azure Functions, or ARC-enabled servers
Connect-AzAccount -Identity

# The identity's permissions are defined by Azure RBAC assignments
# No credentials to manage — Azure handles token acquisition
```

### User-Assigned Managed Identity

```powershell
# Specify which managed identity to use (when VM has multiple)
Connect-AzAccount -Identity -AccountId '<managed-identity-client-id>'
```

### MSAL for Managed Identity

```powershell
# Direct token acquisition via managed identity (for REST calls)
$msalParams = @{
    ClientId = '<managed-identity-client-id>'
    Scopes   = @('https://management.azure.com/.default')
}
# MSAL.PS detects managed identity environment automatically
$tokenResult = Get-MsalToken @msalParams
```

## Token Caching and Refresh

### Token Cache Strategy

```powershell
# MSAL token cache — persists tokens to disk for session continuity
$cacheFile = Join-Path $env:HOME '.secops' 'token-cache.bin'

# Initialize cache helper
$tokenCache = [Microsoft.Identity.Client.TokenCacheHelper]::new($cacheFile)

# Get-MsalToken checks cache first, refreshes if expired
$tokenResult = Get-MsalToken @msalParams

# Access token metadata
$tokenResult.ExpiresOn     # When the token expires
$tokenResult.Scopes        # Granted scopes
$tokenResult.Account       # Authenticated account info
```

### Proactive Token Refresh

```powershell
function Get-SecOpsToken {
    <#
    .SYNOPSIS
        Acquires or refreshes an access token with caching.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Resource,

        [switch]$ForceRefresh
    )

    $cacheKey = "SecOps_$Resource"
    $cached = $script:TokenCache[$cacheKey]

    # Return cached token if valid (with 5-minute buffer)
    if ($cached -and -not $ForceRefresh) {
        $bufferTime = [DateTimeOffset]::UtcNow.AddMinutes(5)
        if ($cached.ExpiresOn -gt $bufferTime) {
            return $cached.AccessToken
        }
    }

    # Acquire new token
    $scopes = @("$Resource/.default")
    $tokenResult = Get-MsalToken -ClientId $script:ClientId `
        -TenantId $script:TenantId -Scopes $scopes -Silent -ErrorAction SilentlyContinue

    if (-not $tokenResult) {
        $tokenResult = Get-MsalToken -ClientId $script:ClientId `
            -TenantId $script:TenantId -Scopes $scopes -Interactive
    }

    $script:TokenCache[$cacheKey] = $tokenResult
    return $tokenResult.AccessToken
}
```

## Multi-Tenant Authentication

### Azure Lighthouse (MSSP Pattern)

```powershell
# Lighthouse: authenticate to YOUR tenant, then access delegated resources
# in CUSTOMER tenants without switching context

# Step 1: Connect to management (MSSP) tenant
Connect-AzAccount -TenantId '<mssp-tenant-id>'

# Step 2: Access delegated customer resources directly
# Lighthouse makes customer resources visible in your tenant context
$customerWorkspaces = Get-AzOperationalInsightsWorkspace `
    -ResourceGroupName 'rg-customer-soc' |
    Where-Object { $_.CustomerId -eq '<customer-workspace-id>' }

# Step 3: Query across all delegated workspaces
$query = "SecurityAlert | where TimeGenerated > ago(24h) | summarize count() by AlertName"
$results = @()
foreach ($ws in $customerWorkspaces) {
    $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $ws.CustomerId -Query $query
    $results += $result.Results
}
```

### B2B Guest Access

```powershell
# B2B: authenticate to the CUSTOMER tenant as a guest user
Connect-AzAccount -TenantId '<customer-tenant-id>'
# You'll be prompted with your home tenant credentials
# Azure routes you as a guest in the target tenant

# Check your access
$context = Get-AzContext
Write-Host "Tenant: $($context.Tenant.Id)"
Write-Host "Account: $($context.Account.Id)"
Write-Host "Home Tenant: $($context.Account.ExtendedProperties.HomeAccountId)"
```

### Cross-Tenant Token Acquisition

```powershell
# Acquire tokens for multiple tenants in sequence
function Connect-SecOpsMultiTenant {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$Tenants  # @{ Id = '...'; Name = '...'; Type = '...' }
    )

    $connections = @{}
    foreach ($tenant in $Tenants) {
        try {
            $ctx = Connect-AzAccount -TenantId $tenant.Id -ErrorAction Stop
            $connections[$tenant.Id] = @{
                Name    = $tenant.Name
                Type    = $tenant.Type
                Context = $ctx.Context
                Status  = 'Connected'
            }
            Write-Verbose "Connected to $($tenant.Name) ($($tenant.Id))"
        }
        catch {
            $connections[$tenant.Id] = @{
                Name    = $tenant.Name
                Type    = $tenant.Type
                Status  = 'Failed'
                Error   = $_.Exception.Message
            }
            Write-Warning "Failed to connect to $($tenant.Name): $($_.Exception.Message)"
        }
    }
    return $connections
}
```

## Government Cloud Endpoints

### Cloud-Specific Login

```powershell
# Azure Government (GCC-High, DoD)
Connect-AzAccount -Environment AzureUSGovernment

# Azure China (21Vianet)
Connect-AzAccount -Environment AzureChinaCloud

# List all available environments
Get-AzEnvironment | Select-Object Name, ActiveDirectoryAuthority, ResourceManagerUrl
```

### Cloud Endpoint Map

| Cloud | Environment Name | Login Authority | Resource Manager | Graph Endpoint |
|---|---|---|---|---|
| **Commercial** | `AzureCloud` | `login.microsoftonline.com` | `management.azure.com` | `graph.microsoft.com` |
| **GCC** | `AzureCloud` | `login.microsoftonline.com` | `management.azure.com` | `graph.microsoft.com` |
| **GCC-High** | `AzureUSGovernment` | `login.microsoftonline.us` | `management.usgovcloudapi.net` | `graph.microsoft.us` |
| **DoD** | `AzureUSGovernment` | `login.microsoftonline.us` | `management.usgovcloudapi.net` | `dod-graph.microsoft.us` |
| **China** | `AzureChinaCloud` | `login.chinacloudapi.cn` | `management.chinacloudapi.cn` | `microsoftgraph.chinacloudapi.cn` |

### Resolving Cloud from .secops/

```powershell
function Get-SecOpsCloudEnvironment {
    <#
    .SYNOPSIS
        Resolves the Azure cloud environment from .secops/environment.yaml.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $secopsEnv = $script:SecOpsContext.Environment
    if (-not $secopsEnv) {
        Write-Verbose "No .secops/ context — defaulting to AzureCloud"
        return 'AzureCloud'
    }

    $cloud = $secopsEnv.organization.cloud
    switch ($cloud) {
        'azure-commercial'   { return 'AzureCloud' }
        'azure-government'   { return 'AzureUSGovernment' }
        'azure-china'        { return 'AzureChinaCloud' }
        default {
            Write-Warning "Unknown cloud type '$cloud' in .secops/ — defaulting to AzureCloud"
            return 'AzureCloud'
        }
    }
}

function Get-SecOpsGraphEndpoint {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $env = Get-SecOpsCloudEnvironment
    switch ($env) {
        'AzureCloud'         { return 'https://graph.microsoft.com' }
        'AzureUSGovernment'  { return 'https://graph.microsoft.us' }
        'AzureChinaCloud'    { return 'https://microsoftgraph.chinacloudapi.cn' }
    }
}
```

## Reading .secops/ for Auth Context

### Loading Tenant Topology

```powershell
function Get-SecOpsTenants {
    <#
    .SYNOPSIS
        Returns tenant list from .secops/identity/tenants.yaml.
    #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [ValidateSet('primary', 'secondary', 'managed', 'lighthouse-delegated', 'csp')]
        [string]$Type
    )

    $tenantConfig = $script:SecOpsContext.Tenants
    if (-not $tenantConfig) {
        Write-Warning "No tenant configuration found in .secops/identity/tenants.yaml"
        return @()
    }

    $tenants = $tenantConfig.tenants
    if ($Type) {
        $tenants = $tenants | Where-Object { $_.type -eq $Type }
    }

    return $tenants
}

# Usage: Connect to the primary tenant
$primary = Get-SecOpsTenants -Type 'primary' | Select-Object -First 1
Connect-AzAccount -TenantId $primary.id
```

### Environment-Aware Connection

```powershell
function Connect-SecOps {
    <#
    .SYNOPSIS
        Connects to Azure using .secops/ environment context.
    .DESCRIPTION
        Reads .secops/environment.yaml and identity/tenants.yaml to determine
        cloud environment and primary tenant, then authenticates.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Interactive', 'ServicePrincipal', 'ManagedIdentity')]
        [string]$AuthMethod = 'Interactive',

        [string]$TenantId,

        [PSCredential]$Credential,

        [string]$CertificateThumbprint
    )

    # Resolve cloud environment
    $cloudEnv = Get-SecOpsCloudEnvironment

    # Resolve tenant
    if (-not $TenantId) {
        $primary = Get-SecOpsTenants -Type 'primary' | Select-Object -First 1
        if ($primary) {
            $TenantId = $primary.id
            Write-Verbose "Using primary tenant from .secops/: $($primary.name) ($TenantId)"
        }
    }

    $connectParams = @{
        Environment = $cloudEnv
    }
    if ($TenantId) { $connectParams.TenantId = $TenantId }

    switch ($AuthMethod) {
        'Interactive' {
            Connect-AzAccount @connectParams
        }
        'ServicePrincipal' {
            if ($CertificateThumbprint) {
                Connect-AzAccount @connectParams -ServicePrincipal `
                    -ApplicationId $Credential.UserName `
                    -CertificateThumbprint $CertificateThumbprint
            }
            else {
                Connect-AzAccount @connectParams -ServicePrincipal `
                    -Credential $Credential
            }
        }
        'ManagedIdentity' {
            Connect-AzAccount @connectParams -Identity
        }
    }

    # Set subscription context if available
    $env = $script:SecOpsContext.Environment
    if ($env -and $env.subscriptions) {
        $socSub = $env.subscriptions | Where-Object { $_.purpose -match 'sentinel' } |
                  Select-Object -First 1
        if ($socSub) {
            Set-AzContext -SubscriptionId $socSub.id | Out-Null
            Write-Verbose "Set subscription context: $($socSub.name)"
        }
    }
}
```

## Best Practices

1. **Never store secrets in code** — Use Key Vault, managed identity, or certificate-based auth
2. **Certificate over secret** — Client secrets expire and can leak; certificates are stronger
3. **Managed identity first** — When running in Azure, always prefer managed identity
4. **Minimum permissions** — Request only the scopes/roles needed for the operation
5. **Token cache outside repo** — Store token cache in `$env:HOME/.secops/`, never in the project directory
6. **Multi-tenant isolation** — Never mix tenant contexts in a single operation
7. **Government cloud awareness** — Always resolve endpoints from `.secops/` — never hardcode commercial URLs

## Environment Context

Before configuring authentication, agents MUST consult:

- **`.secops/environment.yaml`** — Determines cloud environment (commercial vs. government)
- **`.secops/identity/tenants.yaml`** — Lists all tenants, types, and cross-tenant access settings
- **`.secops/compliance/requirements.yaml`** — Data residency may restrict which tenants can be accessed

## Related Skills

- `skills/powershell/module-foundation.md` — Module structure that uses these auth patterns
- `skills/powershell/error-handling.md` — Error handling for auth failures
- `skills/msft-security/microsoft-graph-security.md` — Graph API authentication reference
- `skills/log-analytics/workspace-rbac.md` — RBAC patterns for workspace access
