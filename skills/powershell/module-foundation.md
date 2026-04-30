---
title: PowerShell Module Foundation
category: powershell
difficulty: intermediate
mitre_attack:
  - T1059.001  # Command and Scripting Interpreter: PowerShell
products:
  - Azure PowerShell
  - Microsoft Graph PowerShell SDK
  - PSDepend
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# PowerShell Module Foundation

## Overview

This skill covers the foundational structure of a PowerShell module for Microsoft Security operations — **SecOps.Tools**. It defines the project layout, dependency management with PSDepend, module manifest (.psd1) best practices, initialization patterns, and the six-submodule architecture that maps to Microsoft's security API surfaces.

Use this skill when:
- Scaffolding a new SecOps PowerShell module or extending an existing one
- Setting up PSDepend for reproducible dependency management
- Designing module manifests with security-appropriate metadata
- Understanding how submodules map to Microsoft APIs
- Initializing a module with dependency checks and environment validation

## Prerequisites

| Requirement | Detail |
|---|---|
| **PowerShell** | 7.4+ (cross-platform) or Windows PowerShell 5.1 |
| **PSDepend** | `Install-Module PSDepend -Scope CurrentUser` |
| **Az Modules** | Az.Accounts, Az.SecurityInsights, Az.OperationalInsights, Az.Monitor, Az.ResourceGraph |
| **Microsoft.Graph** | Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns |
| **MSAL.PS** | For token acquisition patterns |
| **Permissions** | Varies by submodule — see individual skill files |

## Project Layout

```
SecOps.Tools/
├── SecOps.Tools.psd1                  # Module manifest
├── SecOps.Tools.psm1                  # Root module — orchestrates submodule loading
├── requirements.psd1                  # PSDepend dependency file
├── config/
│   └── defaults.psd1                  # Default configuration values
├── Sentinel/
│   ├── Sentinel.psm1                  # Submodule entry point
│   ├── Public/                        # Exported functions
│   │   ├── Get-SecOpsIncident.ps1
│   │   ├── New-SecOpsAnalyticsRule.ps1
│   │   └── Export-SecOpsWorkbook.ps1
│   └── Private/                       # Internal helper functions
│       ├── Invoke-SentinelApi.ps1
│       └── ConvertTo-SentinelObject.ps1
├── Defender/
│   ├── Defender.psm1
│   ├── Public/
│   └── Private/
├── Entra/
│   ├── Entra.psm1
│   ├── Public/
│   └── Private/
├── AzureMonitor/
│   ├── AzureMonitor.psm1
│   ├── Public/
│   └── Private/
├── ResourceGraph/
│   ├── ResourceGraph.psm1
│   ├── Public/
│   └── Private/
├── DataTiering/
│   ├── DataTiering.psm1
│   ├── Public/
│   └── Private/
└── Tests/
    ├── SecOps.Tools.Tests.ps1
    ├── Sentinel.Tests.ps1
    └── ...
```

## PSDepend Configuration

### requirements.psd1

PSDepend manages all external dependencies declaratively. Pin versions for reproducibility.

```powershell
# requirements.psd1 — PSDepend dependency manifest
@{
    PSDependOptions = @{
        Target    = 'CurrentUser'
        AddToPath = $true
    }

    # --- Core Azure modules ---
    'Az.Accounts'             = @{ Version = '3.0.0'; Tags = 'core' }
    'Az.SecurityInsights'     = @{ Version = '3.1.0'; Tags = 'sentinel' }
    'Az.OperationalInsights'  = @{ Version = '3.2.0'; Tags = 'sentinel', 'data-tiering' }
    'Az.Monitor'              = @{ Version = '5.2.0'; Tags = 'azure-monitor' }
    'Az.ResourceGraph'        = @{ Version = '1.0.0'; Tags = 'resource-graph' }

    # --- Microsoft Graph SDK ---
    'Microsoft.Graph.Authentication'       = @{ Version = '2.20.0'; Tags = 'entra' }
    'Microsoft.Graph.Identity.SignIns'      = @{ Version = '2.20.0'; Tags = 'entra' }
    'Microsoft.Graph.Identity.Governance'   = @{ Version = '2.20.0'; Tags = 'entra' }

    # --- Auth ---
    'MSAL.PS'                 = @{ Version = '4.37.0'; Tags = 'auth' }

    # --- Testing ---
    'Pester'                  = @{ Version = '5.6.0'; Tags = 'test'; DependencyType = 'PSGalleryModule' }
    'PSScriptAnalyzer'        = @{ Version = '1.22.0'; Tags = 'test'; DependencyType = 'PSGalleryModule' }
}
```

### Installing Dependencies

```powershell
# Install PSDepend (one-time)
Install-Module PSDepend -Scope CurrentUser -Force

# Install all dependencies from requirements.psd1
Invoke-PSDepend -Path .\requirements.psd1 -Install -Force

# Install only sentinel-tagged dependencies
Invoke-PSDepend -Path .\requirements.psd1 -Install -Tags 'sentinel'
```

## Module Manifest (.psd1)

### SecOps.Tools.psd1

```powershell
@{
    # Module identity
    RootModule        = 'SecOps.Tools.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'  # Generate with [guid]::NewGuid()
    Author            = 'SecOps Squad'
    CompanyName       = 'SecOps Squad'
    Description       = 'PowerShell module for Microsoft Security operations — Sentinel, Defender, Entra, Azure Monitor, Resource Graph, and Data Tiering.'

    # Compatibility
    PowerShellVersion      = '7.4'
    CompatiblePSEditions   = @('Core')   # Target pwsh 7+; add 'Desktop' if 5.1 support needed
    DotNetFrameworkVersion = '4.7.2'

    # Dependencies — must be installed before import
    RequiredModules = @(
        @{ ModuleName = 'Az.Accounts'; ModuleVersion = '3.0.0' }
    )

    # Submodule loading — nested modules loaded by root .psm1
    NestedModules = @(
        'Sentinel/Sentinel.psm1',
        'Defender/Defender.psm1',
        'Entra/Entra.psm1',
        'AzureMonitor/AzureMonitor.psm1',
        'ResourceGraph/ResourceGraph.psm1',
        'DataTiering/DataTiering.psm1'
    )

    # Exported functions — explicitly list for discoverability
    FunctionsToExport = @(
        # Sentinel
        'Get-SecOpsIncident', 'New-SecOpsAnalyticsRule', 'Export-SecOpsWorkbook',
        'Get-SecOpsThreatIndicator', 'Invoke-SecOpsHuntingQuery',
        # Defender
        'Get-SecOpsAlert', 'Invoke-SecOpsAdvancedHunting', 'Set-SecOpsDeviceIsolation',
        'Get-SecOpsSecurityRecommendation',
        # Entra
        'Get-SecOpsConditionalAccessPolicy', 'Export-SecOpsConditionalAccessPolicy',
        'Enable-SecOpsPimRole', 'Get-SecOpsRiskySignIn',
        # AzureMonitor
        'New-SecOpsActionGroup', 'New-SecOpsAlertRule', 'Set-SecOpsDiagnosticSetting',
        # ResourceGraph
        'Invoke-SecOpsResourceQuery', 'Get-SecOpsExposedResources',
        'Get-SecOpsCompliancePosture',
        # DataTiering
        'Set-SecOpsTableTier', 'Set-SecOpsRetentionPolicy',
        'New-SecOpsSummaryRule', 'Get-SecOpsTableInventory'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    # Metadata
    PrivateData = @{
        PSData = @{
            Tags         = @('Security', 'Sentinel', 'Defender', 'Entra', 'SOC', 'SecOps')
            ProjectUri   = 'https://github.com/your-org/secops-squad'
            LicenseUri   = 'https://github.com/your-org/secops-squad/blob/main/LICENSE'
            ReleaseNotes = 'Initial release — 6 submodules covering Microsoft Security API surfaces.'
        }
    }
}
```

## Root Module (.psm1) — Initialization

### SecOps.Tools.psm1

```powershell
#Requires -Version 7.4
#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    SecOps.Tools — Root module initializer.
.DESCRIPTION
    Loads all submodules, validates dependencies, and reads .secops/ context.
#>

# --- Module-scoped state ---
$script:SecOpsContext = @{
    Environment     = $null
    Tenants         = $null
    DataSourceMap   = $null
    Initialized     = $false
    SecOpsPath      = $null
}

# --- Dependency Validation ---
function Test-SecOpsDependencies {
    [CmdletBinding()]
    param()

    $required = @(
        @{ Name = 'Az.Accounts'; MinVersion = '3.0.0' }
    )

    $missing = @()
    foreach ($dep in $required) {
        $mod = Get-Module -ListAvailable -Name $dep.Name |
               Where-Object { $_.Version -ge [version]$dep.MinVersion } |
               Select-Object -First 1
        if (-not $mod) {
            $missing += "$($dep.Name) >= $($dep.MinVersion)"
        }
    }

    if ($missing.Count -gt 0) {
        Write-Warning "Missing dependencies: $($missing -join ', '). Run: Invoke-PSDepend -Path requirements.psd1 -Install"
        return $false
    }
    return $true
}

# --- .secops/ Context Loading ---
function Initialize-SecOpsContext {
    [CmdletBinding()]
    param(
        [string]$SecOpsPath
    )

    # Walk up from current directory to find .secops/
    if (-not $SecOpsPath) {
        $searchPath = $PWD.Path
        while ($searchPath -and -not (Test-Path (Join-Path $searchPath '.secops' 'environment.yaml'))) {
            $searchPath = Split-Path $searchPath -Parent
        }
        if ($searchPath) {
            $SecOpsPath = Join-Path $searchPath '.secops'
        }
    }

    if (-not $SecOpsPath -or -not (Test-Path $SecOpsPath)) {
        Write-Verbose ".secops/ not found — operating with defaults. Run: secops-squad init --secops"
        return
    }

    $script:SecOpsContext.SecOpsPath = $SecOpsPath

    # Load environment.yaml
    $envFile = Join-Path $SecOpsPath 'environment.yaml'
    if (Test-Path $envFile) {
        $script:SecOpsContext.Environment = Get-Content $envFile -Raw |
            ConvertFrom-Yaml -ErrorAction SilentlyContinue
    }

    # Load tenants.yaml
    $tenantsFile = Join-Path $SecOpsPath 'identity' 'tenants.yaml'
    if (Test-Path $tenantsFile) {
        $script:SecOpsContext.Tenants = Get-Content $tenantsFile -Raw |
            ConvertFrom-Yaml -ErrorAction SilentlyContinue
    }

    # Load data-source-map.yaml
    $dsFile = Join-Path $SecOpsPath 'data-sources' 'data-source-map.yaml'
    if (Test-Path $dsFile) {
        $script:SecOpsContext.DataSourceMap = Get-Content $dsFile -Raw |
            ConvertFrom-Yaml -ErrorAction SilentlyContinue
    }

    $script:SecOpsContext.Initialized = $true
    Write-Verbose "Loaded .secops/ context from: $SecOpsPath"
}

# --- Submodule Loading ---
function Import-SecOpsSubmodules {
    [CmdletBinding()]
    param()

    $submodules = @('Sentinel', 'Defender', 'Entra', 'AzureMonitor', 'ResourceGraph', 'DataTiering')
    $moduleRoot = $PSScriptRoot

    foreach ($sub in $submodules) {
        $subPath = Join-Path $moduleRoot $sub "$sub.psm1"
        if (Test-Path $subPath) {
            try {
                Import-Module $subPath -Force -DisableNameChecking -ErrorAction Stop
                Write-Verbose "Loaded submodule: $sub"
            }
            catch {
                Write-Warning "Failed to load submodule $sub — $($_.Exception.Message)"
            }
        }
        else {
            Write-Verbose "Submodule not found: $subPath (skipping)"
        }
    }
}

# --- Initialization Sequence ---
if (Test-SecOpsDependencies) {
    Initialize-SecOpsContext
    Import-SecOpsSubmodules
}
```

## Submodule Pattern

Each submodule follows an identical structure. The submodule `.psm1` dot-sources all Public and Private functions:

```powershell
# Sentinel/Sentinel.psm1 — Submodule entry point

# Dot-source all private functions
$privatePath = Join-Path $PSScriptRoot 'Private'
if (Test-Path $privatePath) {
    Get-ChildItem -Path $privatePath -Filter '*.ps1' -Recurse | ForEach-Object {
        . $_.FullName
    }
}

# Dot-source all public functions
$publicPath = Join-Path $PSScriptRoot 'Public'
if (Test-Path $publicPath) {
    Get-ChildItem -Path $publicPath -Filter '*.ps1' -Recurse | ForEach-Object {
        . $_.FullName
    }
}

# Export only public functions
$publicFunctions = Get-ChildItem -Path $publicPath -Filter '*.ps1' -Recurse |
    Select-Object -ExpandProperty BaseName
Export-ModuleMember -Function $publicFunctions
```

## Submodule-to-API Mapping

| Submodule | Microsoft API Surface | Primary Az Module | REST Base URI |
|---|---|---|---|
| **Sentinel** | SecurityInsights resource provider | `Az.SecurityInsights` | `management.azure.com/.../Microsoft.SecurityInsights/` |
| **Defender** | Microsoft 365 Defender, MDE API | `Microsoft.Graph.Security` | `api.securitycenter.microsoft.com/api/` |
| **Entra** | Microsoft Graph Identity | `Microsoft.Graph.Identity.*` | `graph.microsoft.com/v1.0/identity/` |
| **AzureMonitor** | Azure Monitor resource provider | `Az.Monitor` | `management.azure.com/.../Microsoft.Insights/` |
| **ResourceGraph** | Azure Resource Graph | `Az.ResourceGraph` | `management.azure.com/providers/Microsoft.ResourceGraph/` |
| **DataTiering** | Log Analytics workspace management | `Az.OperationalInsights` | `management.azure.com/.../Microsoft.OperationalInsights/` |

## Configuration Defaults

### config/defaults.psd1

```powershell
@{
    # API behavior
    MaxRetries           = 3
    RetryBaseDelayMs     = 1000
    RequestTimeoutSec    = 30
    ThrottleWaitMaxSec   = 120
    PageSize             = 100

    # Logging
    LogLevel             = 'Information'   # Verbose | Information | Warning | Error
    AuditLogEnabled      = $true
    AuditLogPath         = './logs/secops-audit.log'

    # Environment defaults (overridden by .secops/)
    DefaultCloud         = 'AzureCloud'    # AzureCloud | AzureUSGovernment | AzureChinaCloud
    DefaultApiVersion    = '2024-03-01'
}
```

## Best Practices

1. **Verb-Noun naming** — Follow PowerShell conventions: `Get-SecOps*`, `Set-SecOps*`, `New-SecOps*`, `Remove-SecOps*`
2. **SecOps prefix** — All exported functions use the `SecOps` noun prefix to avoid collisions
3. **CmdletBinding** — Every function uses `[CmdletBinding()]` for `-Verbose`, `-Debug`, `-ErrorAction` support
4. **Comment-Based Help** — Every public function has `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`
5. **OutputType** — Declare `[OutputType()]` on all public functions
6. **ShouldProcess** — Functions that modify state support `-WhatIf` and `-Confirm`
7. **No hardcoded endpoints** — All URIs resolve from cloud environment context
8. **Idempotent where possible** — `New-*` functions check for existing resources before creating

## Environment Context

Before generating module code, agents MUST consult:

- **`.secops/environment.yaml`** — Cloud type determines API base URIs and available features
- **`.secops/identity/tenants.yaml`** — Tenant topology affects auth flow selection
- **`.secops/data-sources/data-source-map.yaml`** — Table locations determine which submodule to use

If `.secops/` does not exist, the module initializes with defaults and logs a warning.

## Related Skills

- `skills/powershell/auth-patterns.md` — Authentication flows used by all submodules
- `skills/powershell/error-handling.md` — Error wrapping and retry patterns
- `skills/powershell/sentinel-module.md` — Sentinel submodule details
- `skills/powershell/defender-module.md` — Defender submodule details
- `skills/msft-security/microsoft-graph-security.md` — Graph Security API reference
