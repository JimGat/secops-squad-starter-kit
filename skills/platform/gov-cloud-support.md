---
title: Sovereign Cloud Support (GCC, GCC High, DoD)
category: platform
difficulty: advanced
products:
  - Microsoft Sentinel
  - Microsoft Defender XDR
  - Microsoft Defender for Endpoint
  - Microsoft Defender for Cloud
  - Microsoft Copilot for Security
  - Microsoft Entra ID
  - Microsoft Purview
  - Azure Government
cloud_environments:
  - commercial
  - gcc
  - gcc_high
  - dod
  - china
compliance_frameworks:
  - FedRAMP High
  - IL4
  - IL5
  - ITAR
  - DISA SRG
  - CJIS
  - IRS 1075
author: Kima
version: 1.0.0
last_updated: 2026-05-04
---

# Sovereign Cloud Support (GCC, GCC High, DoD)

## Overview

Sovereign clouds are isolated Azure environments that meet stringent government compliance requirements. SecOps teams operating in these environments face different API endpoints, feature availability gaps, authentication flows, and data residency constraints compared to commercial Azure.

This skill ensures agents correctly resolve endpoints, authenticate, and handle feature parity gaps across all Microsoft sovereign cloud environments. Every SecOps operation — from KQL queries to Defender API calls to Copilot for Security prompts — must target the correct cloud-specific endpoints.

### Why Sovereign Clouds Matter for SecOps

| Concern | Impact on SecOps |
|---|---|
| **FedRAMP** | Required for any SaaS/PaaS handling federal data; defines control baselines |
| **IL4 / IL5** | Impact levels for CUI (IL4) and national security systems (IL5); determine which cloud tier is required |
| **ITAR** | International Traffic in Arms Regulations; data cannot leave US sovereign boundary |
| **CJIS** | Criminal Justice Information Services; law enforcement data handling |
| **IRS 1075** | Federal Tax Information safeguards |
| **Data Residency** | Certain data types must remain in-country; affects workspace and storage placement |

**Use this skill when:**
- Deploying SecOps tooling to government customers
- Building multi-cloud detection rules that span commercial and government tenants
- Configuring `.secops/environment.yaml` for government environments
- Troubleshooting authentication or API failures in sovereign clouds
- Planning feature rollouts where parity gaps exist

**Skills referenced (not duplicated):**

| Domain | Key Skills |
|---|---|
| **PowerShell** | `sentinel-api-wrapper.md`, `defender-api-wrapper.md`, `error-handling.md` |
| **MSFT Security** | `sentinel-mcp-server.md`, `defender-mcp-server.md`, `copilot-for-security.md` |
| **Platform** | `copilot-security-workflows.md` |

## Environment Context

Before performing any sovereign cloud operation, check `.secops/`:

1. **`.secops/environment.yaml`** — `organization.cloud` determines all endpoint resolution
2. **`.secops/identity/tenants.yaml`** — Sovereign tenants use different authority URLs
3. **`.secops/compliance/requirements.yaml`** — Check `prohibited_regions` and `encryption_requirements`
4. **`.secops/workspaces/*.yaml`** — Workspace resource IDs contain sovereign subscription GUIDs

## Section 1: Cloud Environments

### Environment Reference Table

| Cloud | Azure Environment | Target Workloads | Impact Level | Authority |
|---|---|---|---|---|
| **Commercial** | `AzureCloud` | General public, enterprise | N/A | NIST 800-53 (customer choice) |
| **GCC** | `AzureCloud` (GCC partition) | US government moderate | IL2 | FedRAMP High |
| **GCC High** | `AzureUSGovernment` | US government high impact | IL4 | FedRAMP High + DoD CC SRG IL4 |
| **DoD** | `AzureUSGovernment` (DoD regions) | US DoD IL5 workloads | IL5 | DISA SRG IL5 |
| **Azure Government** | `AzureUSGovernment` | US government (general) | IL2-IL5 | FedRAMP High |
| **Azure China** | `AzureChinaCloud` | China data residency | N/A | China cybersecurity law |

### GCC vs. GCC High vs. DoD

```
Commercial Azure
  └── GCC (Government Community Cloud)
        ├── Shared Azure infrastructure, logical isolation
        ├── FedRAMP High authorized
        ├── US-based datacenters only
        └── Moderate-impact federal data (CUI on IL2)

Azure Government
  ├── GCC High
  │     ├── Physically separated infrastructure
  │     ├── IL4+ data (controlled unclassified - high impact)
  │     ├── ITAR-compliant
  │     └── US-person screened operators
  └── DoD
        ├── Dedicated DoD regions (US DoD Central, US DoD East)
        ├── IL5 data (national security systems)
        ├── DISA SRG compliant
        └── Most restrictive access controls
```

### Azure China (21Vianet)

Azure China is operated by 21Vianet under Chinese law. Key differences:

- **Separate identity plane**: `login.chinacloudapi.cn`
- **Separate management plane**: `management.chinacloudapi.cn`
- **No cross-cloud connectivity**: China cloud is fully isolated
- **Limited M365 Security features**: Many Defender/Sentinel features unavailable
- **Data residency**: All data remains within China

## Section 2: Endpoint Differences

### Identity & Authentication Endpoints

| Cloud | Login Endpoint | Graph Endpoint |
|---|---|---|
| **Commercial** | `login.microsoftonline.com` | `graph.microsoft.com` |
| **GCC** | `login.microsoftonline.com` | `graph.microsoft.com` |
| **GCC High** | `login.microsoftonline.us` | `graph.microsoft.us` |
| **DoD** | `login.microsoftonline.us` | `dod-graph.microsoft.us` |
| **China** | `login.chinacloudapi.cn` | `microsoftgraph.chinacloudapi.cn` |

### Management Plane Endpoints

| Cloud | ARM Endpoint | Sentinel API Base |
|---|---|---|
| **Commercial** | `management.azure.com` | `management.azure.com` |
| **GCC** | `management.azure.com` | `management.azure.com` |
| **GCC High** | `management.usgovcloudapi.net` | `management.usgovcloudapi.net` |
| **DoD** | `management.usgovcloudapi.net` | `management.usgovcloudapi.net` |
| **China** | `management.chinacloudapi.cn` | `management.chinacloudapi.cn` |

### Defender API Endpoints

| Cloud | Defender for Endpoint API | Defender XDR |
|---|---|---|
| **Commercial** | `api.securitycenter.microsoft.com` | `api.security.microsoft.com` |
| **GCC** | `api-gcc.securitycenter.microsoft.us` | `api-gcc.security.microsoft.us` |
| **GCC High** | `api-gov.securitycenter.microsoft.us` | `api-gov.security.microsoft.us` |
| **DoD** | `api-gov.securitycenter.microsoft.us` | `api-gov.security.microsoft.us` |
| **China** | Not available | Not available |

### Log Analytics Endpoints

| Cloud | Log Analytics API | Data Collection Endpoint |
|---|---|---|
| **Commercial** | `api.loganalytics.io` | `*.ingest.monitor.azure.com` |
| **GCC** | `api.loganalytics.io` | `*.ingest.monitor.azure.com` |
| **GCC High** | `api.loganalytics.us` | `*.ingest.monitor.azure.us` |
| **DoD** | `api.loganalytics.us` | `*.ingest.monitor.azure.us` |
| **China** | `api.loganalytics.azure.cn` | `*.ingest.monitor.azure.cn` |

### Sentinel REST API Paths

All Sentinel REST API calls follow the ARM pattern. The base URL changes per cloud, but the path is consistent:

```
{arm_endpoint}/subscriptions/{subId}/resourceGroups/{rg}/
  providers/Microsoft.OperationalInsights/workspaces/{ws}/
  providers/Microsoft.SecurityInsights/{resource}?api-version=2024-03-01
```

## Section 3: Authentication Flow Differences

### App Registration in Sovereign Clouds

App registrations in sovereign clouds are **completely separate** from commercial Azure:

| Task | Commercial | GCC High / DoD | China |
|---|---|---|---|
| **Entra Portal** | `entra.microsoft.com` | `entra.microsoft.us` | `entra.chinacloudapi.cn` |
| **Azure Portal** | `portal.azure.com` | `portal.azure.us` | `portal.azure.cn` |
| **App Registration** | Commercial Entra tenant | Gov Entra tenant | China Entra tenant |
| **Certificates** | Recommended | **Required** (GCC High/DoD) | Recommended |

### Token Acquisition with Sovereign Authority

```powershell
# Commercial
$authority = "https://login.microsoftonline.com/$tenantId"
$scope = "https://management.azure.com/.default"

# GCC High
$authority = "https://login.microsoftonline.us/$tenantId"
$scope = "https://management.usgovcloudapi.net/.default"

# DoD
$authority = "https://login.microsoftonline.us/$tenantId"
$scope = "https://management.usgovcloudapi.net/.default"

# China
$authority = "https://login.chinacloudapi.cn/$tenantId"
$scope = "https://management.chinacloudapi.cn/.default"
```

### Certificate-Based Auth (Required for GCC High/DoD)

GCC High and DoD environments **require** certificate-based authentication for service principals in production. Client secrets are permitted for development only with short lifetimes.

```powershell
function Connect-SecOpsSovereignTenant {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('commercial','gcc','gcc_high','dod','china')]
        [string]$CloudType,

        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $endpoints = Get-SecOpsCloudEndpoints -CloudType $CloudType

    $certBase64 = [Convert]::ToBase64String($Certificate.GetRawCertData())
    $thumbprint = $Certificate.Thumbprint
    $jwtHeader = @{ alg = "RS256"; typ = "JWT"; x5t = $thumbprint } | ConvertTo-Json -Compress
    $now = [int]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    $jwtPayload = @{
        aud = "$($endpoints.Login)/$TenantId/oauth2/v2.0/token"
        iss = $ClientId; sub = $ClientId
        nbf = $now; exp = ($now + 600)
        jti = [Guid]::NewGuid().ToString()
    } | ConvertTo-Json -Compress

    # Sign JWT with certificate private key (abbreviated — use MSAL in production)
    $body = @{
        client_id             = $ClientId
        scope                 = "$($endpoints.Resource)/.default"
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        client_assertion      = $signedJwt
        grant_type            = "client_credentials"
    }

    $token = Invoke-RestMethod -Uri "$($endpoints.Login)/$TenantId/oauth2/v2.0/token" `
        -Method POST -Body $body

    return @{
        ok       = $true
        token    = $token.access_token
        expires  = (Get-Date).AddSeconds($token.expires_in)
        cloud    = $CloudType
        endpoint = $endpoints
    }
}
```

### Conditional Access Differences

| Aspect | Commercial | GCC High / DoD |
|---|---|---|
| **Named Locations** | All location types | Limited to IP-based |
| **Device Compliance** | Full Intune integration | Intune available with GCC High licensing |
| **Risk-Based Policies** | Entra ID P2 | Available in GCC High |
| **Cross-Tenant Access** | B2B collaboration | Restricted; requires explicit allowlist |
| **FIDO2 Keys** | Generally available | Available (check DoD key requirements) |

## Section 4: `.secops/` Integration

### `environment.yaml` Cloud Type Configuration

The `organization.cloud` field drives all endpoint resolution. Extended values for sovereign clouds:

```yaml
# .secops/environment.yaml
schema_version: "1.0"
organization:
  name: "Defense Agency XYZ"
  cloud: "gcc_high"           # commercial | gcc | gcc_high | dod | china
  primary_region: "usgovvirginia"
  data_residency: "us"
  org_type: "enterprise"

  # Sovereign-specific settings
  sovereign_cloud:
    impact_level: "IL4"       # IL2 | IL4 | IL5
    fedramp_authorization: "High"
    encryption_standard: "FIPS 140-2"   # FIPS 140-2 | CNSA
    us_person_requirement: true
    itar_controlled: false
```

### Automatic Endpoint Resolution

Agents use `organization.cloud` to resolve all endpoints automatically. No hardcoded URLs in skills.

```yaml
# .secops/environment.yaml — workspace with sovereign context
workspaces:
  - name: "GovSOC-Primary"
    resource_id: "/subscriptions/{subId}/resourceGroups/soc-rg/providers/Microsoft.OperationalInsights/workspaces/govsoc-prod"
    cloud: "gcc_high"       # Inherits from organization.cloud if omitted
    region: "usgovvirginia"
    log_analytics_workspace_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### Cloud-Specific Workspace Configurations

```yaml
# .secops/workspaces/govsoc-production.yaml
schema_version: "1.0"
workspace:
  name: "GovSOC-Production"
  cloud: "gcc_high"
  resource_id: "/subscriptions/.../workspaces/govsoc-prod"
  workspace_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  region: "usgovvirginia"

  # Sovereign-specific metadata
  authorization_boundary: "FedRAMP High"
  data_classification: "CUI"
  max_retention_days: 730      # IL4 requires 2-year minimum for certain log types
  encryption:
    at_rest: "Microsoft-managed (FIPS 140-2)"
    in_transit: "TLS 1.2+"

  # Endpoint overrides (auto-resolved from cloud, but can be explicit)
  endpoints:
    arm: "https://management.usgovcloudapi.net"
    log_analytics: "https://api.loganalytics.us"
    sentinel_api: "https://management.usgovcloudapi.net"
```

## Section 5: Feature Availability Matrix

### Sentinel Feature Availability

| Feature | Commercial | GCC | GCC High | DoD | China |
|---|---|---|---|---|---|
| **Incidents** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Analytics Rules** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **NRT Rules** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **UEBA** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **SOC Optimizations** | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Fusion Rules** | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Notebooks** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Content Hub** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Data Connectors** | Full | Most | Most | Limited | Limited |
| **Automation Rules** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Playbooks (Logic Apps)** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Watchlists** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Hunting Queries** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Workbooks** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Multi-Workspace** | ✅ | ✅ | ✅ | ✅ | ✅ |

### Defender Feature Availability

| Feature | Commercial | GCC | GCC High | DoD | China |
|---|---|---|---|---|---|
| **Defender for Endpoint** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Defender for Identity** | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Defender for Cloud Apps** | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Defender for Cloud** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Defender for Office 365** | ✅ | ✅ | ✅ | ❌ | ❌ |
| **XDR Unified Incidents** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Advanced Hunting** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Automated Investigation** | ✅ | ✅ | ✅ | Limited | ❌ |
| **Live Response** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Threat Analytics** | ✅ | ✅ | ✅ | ❌ | ❌ |

### Copilot for Security & Compliance

| Feature | Commercial | GCC | GCC High | DoD | China |
|---|---|---|---|---|---|
| **Copilot for Security** | ✅ | ✅ | ❌ (planned) | ❌ | ❌ |
| **Copilot Embedded (XDR)** | ✅ | ✅ | ❌ (planned) | ❌ | ❌ |
| **eDiscovery (Premium)** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Purview DLP** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Purview IRM** | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Sensitivity Labels** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Communication Compliance** | ✅ | ✅ | ✅ | ❌ | ❌ |

> **Agent Rule:** Before calling any Copilot for Security API, check `organization.cloud`. If `gcc_high`, `dod`, or `china`, Copilot for Security is **not available**. Fall back to manual investigation workflows. See `copilot-security-workflows.md` for fallback patterns.

## Section 6: PowerShell Patterns

### `Get-SecOpsCloudEndpoints` — Endpoint Resolution

```powershell
function Get-SecOpsCloudEndpoints {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('commercial','gcc','gcc_high','dod','china')]
        [string]$CloudType
    )

    $endpoints = @{
        commercial = @{
            Login          = "https://login.microsoftonline.com"
            Graph          = "https://graph.microsoft.com"
            ARM            = "https://management.azure.com"
            Resource       = "https://management.azure.com"
            LogAnalytics   = "https://api.loganalytics.io"
            MDE            = "https://api.securitycenter.microsoft.com"
            DefenderXDR    = "https://api.security.microsoft.com"
            CopilotAPI     = "https://api.securitycopilot.microsoft.com"
            DataCollection = "*.ingest.monitor.azure.com"
            Portal         = "https://portal.azure.com"
            EntraPortal    = "https://entra.microsoft.com"
            Environment    = "AzureCloud"
        }
        gcc = @{
            Login          = "https://login.microsoftonline.com"
            Graph          = "https://graph.microsoft.com"
            ARM            = "https://management.azure.com"
            Resource       = "https://management.azure.com"
            LogAnalytics   = "https://api.loganalytics.io"
            MDE            = "https://api-gcc.securitycenter.microsoft.us"
            DefenderXDR    = "https://api-gcc.security.microsoft.us"
            CopilotAPI     = "https://api.securitycopilot.microsoft.com"
            DataCollection = "*.ingest.monitor.azure.com"
            Portal         = "https://portal.azure.com"
            EntraPortal    = "https://entra.microsoft.com"
            Environment    = "AzureCloud"
        }
        gcc_high = @{
            Login          = "https://login.microsoftonline.us"
            Graph          = "https://graph.microsoft.us"
            ARM            = "https://management.usgovcloudapi.net"
            Resource       = "https://management.usgovcloudapi.net"
            LogAnalytics   = "https://api.loganalytics.us"
            MDE            = "https://api-gov.securitycenter.microsoft.us"
            DefenderXDR    = "https://api-gov.security.microsoft.us"
            CopilotAPI     = $null  # Not available in GCC High
            DataCollection = "*.ingest.monitor.azure.us"
            Portal         = "https://portal.azure.us"
            EntraPortal    = "https://entra.microsoft.us"
            Environment    = "AzureUSGovernment"
        }
        dod = @{
            Login          = "https://login.microsoftonline.us"
            Graph          = "https://dod-graph.microsoft.us"
            ARM            = "https://management.usgovcloudapi.net"
            Resource       = "https://management.usgovcloudapi.net"
            LogAnalytics   = "https://api.loganalytics.us"
            MDE            = "https://api-gov.securitycenter.microsoft.us"
            DefenderXDR    = "https://api-gov.security.microsoft.us"
            CopilotAPI     = $null  # Not available in DoD
            DataCollection = "*.ingest.monitor.azure.us"
            Portal         = "https://portal.azure.us"
            EntraPortal    = "https://entra.microsoft.us"
            Environment    = "AzureUSGovernment"
        }
        china = @{
            Login          = "https://login.chinacloudapi.cn"
            Graph          = "https://microsoftgraph.chinacloudapi.cn"
            ARM            = "https://management.chinacloudapi.cn"
            Resource       = "https://management.chinacloudapi.cn"
            LogAnalytics   = "https://api.loganalytics.azure.cn"
            MDE            = $null  # Not available in China
            DefenderXDR    = $null  # Not available in China
            CopilotAPI     = $null  # Not available in China
            DataCollection = "*.ingest.monitor.azure.cn"
            Portal         = "https://portal.azure.cn"
            EntraPortal    = "https://entra.chinacloudapi.cn"
            Environment    = "AzureChinaCloud"
        }
    }

    $result = $endpoints[$CloudType]
    if (-not $result) {
        return @{ ok = $false; error = "Unknown cloud type: $CloudType" }
    }

    return @{
        ok        = $true
        cloud     = $CloudType
        endpoints = $result
    }
}
```

### `Connect-SecOpsEnvironment` — Cloud-Aware Connection

```powershell
function Connect-SecOpsEnvironment {
    <#
    .SYNOPSIS
        Connects to the correct Azure environment based on .secops/ config.
    .DESCRIPTION
        Reads .secops/environment.yaml, resolves endpoints, and authenticates
        using the appropriate authority and resource URLs.
    #>
    [CmdletBinding()]
    param(
        [string]$SecOpsPath = ".secops",
        [PSCredential]$Credential,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    # Load environment config
    $envFile = Join-Path $SecOpsPath "environment.yaml"
    if (-not (Test-Path $envFile)) {
        return @{ ok = $false; error = ".secops/environment.yaml not found. Run secops-squad init --secops" }
    }

    $config = ConvertFrom-Yaml (Get-Content $envFile -Raw)
    $cloudType = $config.organization.cloud -replace '-', '_' -replace 'azure_', ''

    # Map azure-commercial → commercial, azure-government → gcc_high, etc.
    $cloudMap = @{
        'commercial'  = 'commercial'
        'government'  = 'gcc_high'
        'gcc'         = 'gcc'
        'gcc_high'    = 'gcc_high'
        'dod'         = 'dod'
        'china'       = 'china'
    }
    $resolved = $cloudMap[$cloudType]
    if (-not $resolved) {
        return @{ ok = $false; error = "Unsupported cloud type in environment.yaml: $($config.organization.cloud)" }
    }

    $ep = (Get-SecOpsCloudEndpoints -CloudType $resolved).endpoints

    # GCC High/DoD require certificate auth
    if ($resolved -in @('gcc_high', 'dod') -and -not $Certificate) {
        Write-Warning "GCC High/DoD environments require certificate-based authentication for production."
    }

    # Connect Az module
    $connectParams = @{
        Environment = $ep.Environment
        TenantId    = $config.tenants[0].id
    }
    if ($Certificate) {
        $connectParams.CertificateThumbprint = $Certificate.Thumbprint
        $connectParams.ApplicationId = $config.tenants[0].app_registration_id
    }

    Connect-AzAccount @connectParams -ErrorAction Stop

    return @{
        ok       = $true
        cloud    = $resolved
        tenant   = $config.tenants[0].name
        endpoint = $ep
    }
}
```

### Cross-Cloud Migration Helpers

```powershell
function Test-SecOpsCloudFeature {
    <#
    .SYNOPSIS
        Checks if a feature is available in the target cloud before attempting operations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Feature,
        [Parameter(Mandatory)]
        [ValidateSet('commercial','gcc','gcc_high','dod','china')]
        [string]$CloudType
    )

    $matrix = @{
        'CopilotForSecurity'  = @('commercial', 'gcc')
        'DefenderForIdentity' = @('commercial', 'gcc', 'gcc_high')
        'DefenderCloudApps'   = @('commercial', 'gcc', 'gcc_high')
        'AdvancedHunting'     = @('commercial', 'gcc', 'gcc_high', 'dod')
        'NRTRules'            = @('commercial', 'gcc', 'gcc_high', 'dod')
        'FusionRules'         = @('commercial', 'gcc', 'gcc_high')
        'UEBA'                = @('commercial', 'gcc', 'gcc_high', 'dod')
        'Playbooks'           = @('commercial', 'gcc', 'gcc_high', 'dod')
        'PurviewIRM'          = @('commercial', 'gcc', 'gcc_high')
        'eDiscoveryPremium'   = @('commercial', 'gcc', 'gcc_high', 'dod')
        'ContentHub'          = @('commercial', 'gcc', 'gcc_high', 'dod')
    }

    $supported = $matrix[$Feature]
    if (-not $supported) {
        return @{ ok = $false; error = "Unknown feature: $Feature. Known: $($matrix.Keys -join ', ')" }
    }

    $available = $CloudType -in $supported
    return @{
        ok        = $true
        feature   = $Feature
        cloud     = $CloudType
        available = $available
        message   = if ($available) { "$Feature is available in $CloudType" }
                    else { "$Feature is NOT available in $CloudType. Consider alternative approaches." }
    }
}
```

```powershell
function Export-SecOpsCloudConfig {
    <#
    .SYNOPSIS
        Exports cloud-aware configuration for migration between environments.
    .DESCRIPTION
        Generates a configuration diff showing endpoint changes, feature gaps,
        and required auth modifications when migrating between cloud types.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('commercial','gcc','gcc_high','dod','china')]
        [string]$SourceCloud,

        [Parameter(Mandatory)]
        [ValidateSet('commercial','gcc','gcc_high','dod','china')]
        [string]$TargetCloud
    )

    $source = (Get-SecOpsCloudEndpoints -CloudType $SourceCloud).endpoints
    $target = (Get-SecOpsCloudEndpoints -CloudType $TargetCloud).endpoints

    $changes = @()
    foreach ($key in $source.Keys) {
        if ($source[$key] -ne $target[$key]) {
            $changes += @{
                Setting   = $key
                From      = $source[$key] ?? "(not available)"
                To        = $target[$key] ?? "(not available)"
                Breaking  = ($null -eq $target[$key])
            }
        }
    }

    # Check feature gaps
    $features = @('CopilotForSecurity','DefenderForIdentity','DefenderCloudApps',
                   'AdvancedHunting','FusionRules','UEBA','PurviewIRM')
    $featureGaps = foreach ($f in $features) {
        $srcResult = Test-SecOpsCloudFeature -Feature $f -CloudType $SourceCloud
        $tgtResult = Test-SecOpsCloudFeature -Feature $f -CloudType $TargetCloud
        if ($srcResult.available -and -not $tgtResult.available) {
            @{ Feature = $f; Status = "LOST in $TargetCloud" }
        }
    }

    return @{
        ok          = $true
        source      = $SourceCloud
        target      = $TargetCloud
        changes     = $changes
        featureGaps = $featureGaps
        authChange  = ($source.Login -ne $target.Login)
        certRequired = $TargetCloud -in @('gcc_high', 'dod')
    }
}
```

## Section 7: Compliance Constraints

### Data Residency Requirements

| Cloud | Allowed Regions | Data Boundary |
|---|---|---|
| **Commercial** | All Azure regions | Customer choice |
| **GCC** | US regions only | US sovereign boundary |
| **GCC High** | `usgovvirginia`, `usgovarizona`, `usgovtexas` | US sovereign boundary |
| **DoD** | `usdodcentral`, `usdodeast` | DoD-controlled boundary |
| **China** | `chinaeast`, `chinaeast2`, `chinanorth`, `chinanorth2` | China data boundary |

### Audit & Encryption Requirements

| Requirement | IL2 (GCC) | IL4 (GCC High) | IL5 (DoD) |
|---|---|---|---|
| **Encryption at Rest** | AES-256 | AES-256, FIPS 140-2 validated | AES-256, FIPS 140-2 validated |
| **Encryption in Transit** | TLS 1.2 | TLS 1.2 | TLS 1.2+ (CNSA suite preferred) |
| **Key Management** | Microsoft-managed OK | Customer-managed keys recommended | CMK required for some services |
| **Audit Log Retention** | 90 days minimum | 1 year minimum | 2 years minimum |
| **Background Checks** | Standard | US persons, clearance for some | Clearance required |
| **Physical Security** | Standard datacenter | Enhanced, US-only | DoD-controlled facilities |

### `.secops/compliance/` Sovereign Configuration

```yaml
# .secops/compliance/requirements.yaml — GCC High example
schema_version: "1.0"
compliance:
  frameworks:
    - name: "FedRAMP High"
      status: "authorized"
      audit_frequency: "annual"
    - name: "DoD CC SRG IL4"
      status: "authorized"
      audit_frequency: "continuous"

  data_residency:
    allowed_regions:
      - "usgovvirginia"
      - "usgovarizona"
    prohibited_regions:
      - "*"    # Everything not in allowed_regions
    data_classification: "CUI"
    cross_border_transfer: "prohibited"

  encryption:
    standard: "FIPS 140-2"
    at_rest: "AES-256"
    in_transit: "TLS 1.2"
    key_management: "customer-managed"
    key_vault_sku: "premium"   # HSM-backed for FIPS compliance

  audit:
    log_retention_days: 365
    unified_audit_log: true
    activity_log_export: true
    export_destination: "sentinel"
    immutable_storage: true    # IL4 requires tamper-proof audit trails
```

## Section 8: Agent Decision Flow

When an agent starts any SecOps operation, follow this decision tree:

```
START
  │
  ├─ Read .secops/environment.yaml → get organization.cloud
  │
  ├─ Call Get-SecOpsCloudEndpoints with cloud type
  │     ├─ Use returned endpoints for ALL API calls
  │     └─ Never hardcode commercial endpoints
  │
  ├─ Check feature availability
  │     ├─ Feature available → proceed
  │     └─ Feature NOT available → log gap, use fallback
  │           ├─ Copilot unavailable → manual investigation
  │           ├─ Defender API unavailable → Sentinel-only path
  │           └─ Playbooks unavailable → manual response actions
  │
  ├─ Check auth requirements
  │     ├─ GCC High/DoD → require certificate auth
  │     └─ Commercial/GCC → certificate or secret OK
  │
  └─ Check compliance constraints
        ├─ Verify region is in allowed_regions
        ├─ Verify encryption meets standard
        └─ Verify retention meets minimum
```

## References

- [Microsoft 365 US Government - Service Descriptions](https://learn.microsoft.com/en-us/office365/servicedescriptions/office-365-platform-service-description/office-365-us-government/office-365-us-government)
- [Azure Government Documentation](https://learn.microsoft.com/en-us/azure/azure-government/)
- [Microsoft Sentinel in Azure Government](https://learn.microsoft.com/en-us/azure/sentinel/azure-sentinel-government)
- [Defender for Endpoint for US Government](https://learn.microsoft.com/en-us/defender-endpoint/gov)
- [FedRAMP Authorization](https://marketplace.fedramp.gov/)
- [DISA SRG Overview](https://public.cyber.mil/stigs/srg-stig-tools/)
