---
title: Sentinel Workspace Setup
category: msft-security
difficulty: intermediate
mitre_attack:
  - T1530  # Data from Cloud Storage
  - T1078  # Valid Accounts
products:
  - Microsoft Sentinel
  - Azure Monitor
  - Azure Lighthouse
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# Sentinel Workspace Setup

## Overview

Provisioning a Microsoft Sentinel workspace is the foundation of every security operations deployment. This skill covers end-to-end workspace creation, from the Log Analytics resource through Sentinel onboarding, Content Hub solution installation, data connector priority, and multi-tenant configuration for MSSPs.

Use this skill when:
- Standing up a new Sentinel environment from scratch
- Migrating from a legacy SIEM to Sentinel
- Configuring a multi-tenant MSSP architecture via Azure Lighthouse
- Estimating initial Sentinel deployment costs
- Enabling UEBA, Entity Analytics, and Anomalies features

## Prerequisites

| Requirement | Detail |
|---|---|
| **Subscription** | Azure subscription with `Owner` or `Contributor` + `Microsoft Sentinel Contributor` |
| **Resource Group** | Dedicated RG for security operations (e.g., `rg-sentinel-prod`) |
| **Permissions** | `Microsoft.OperationalInsights/workspaces/write` and `Microsoft.SecurityInsights/onboardingStates/write` |
| **Region** | Select the region closest to your data sources; Sentinel pricing varies by region |
| **Retention** | Plan for 90-day interactive + 2-year archive (default: 90 days free with Sentinel) |

## Configuration Patterns

### Workspace Creation via Bicep

```bicep
@description('Sentinel workspace deployment')
param location string = resourceGroup().location
param workspaceName string = 'law-sentinel-prod'
param retentionInDays int = 90
param dailyQuotaGb int = -1 // -1 = no cap

// Log Analytics Workspace
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    workspaceCapping: {
      dailyQuotaGb: dailyQuotaGb
    }
    features: {
      enableDataExport: true
    }
  }
}

// Sentinel Onboarding
resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  name: 'default'
  scope: workspace
  properties: {}
}

// UEBA Settings
resource ueba 'Microsoft.SecurityInsights/settings@2024-03-01' = {
  name: 'Ueba'
  scope: workspace
  kind: 'Ueba'
  properties: {
    dataSources: [
      'AuditLogs'
      'AzureActivity'
      'SecurityEvent'
      'SigninLogs'
    ]
  }
}

// Entity Analytics
resource entityAnalytics 'Microsoft.SecurityInsights/settings@2024-03-01' = {
  name: 'EntityAnalytics'
  scope: workspace
  kind: 'EntityAnalytics'
  properties: {
    entityProviders: [
      'AzureActiveDirectory'
      'ActiveDirectory'
    ]
  }
}

// Anomalies
resource anomalies 'Microsoft.SecurityInsights/settings@2024-03-01' = {
  name: 'Anomalies'
  scope: workspace
  kind: 'Anomalies'
  properties: {
    isEnabled: true
  }
}

output workspaceId string = workspace.id
output workspaceResourceId string = workspace.properties.customerId
```

### Content Hub Solutions Installation

Install solutions via PowerShell after workspace provisioning. Priority order:

```powershell
# Connect to Azure
Connect-AzAccount
Set-AzContext -SubscriptionId '<subscription-id>'

$rgName = 'rg-sentinel-prod'
$workspaceName = 'law-sentinel-prod'

# Priority 1: Identity & Access
$solutions = @(
    'Azure Active Directory'         # Entra ID sign-in/audit logs
    'Microsoft Entra ID'             # Modern Entra solution
    'Azure Activity'                 # Azure control plane
    'Microsoft 365'                  # M365 audit logs
    'Microsoft Defender XDR'         # Unified incidents
)

# Priority 2: Endpoint & Cloud Workloads
$solutions += @(
    'Microsoft Defender for Cloud'   # Cloud security alerts
    'Microsoft Defender for Endpoint' # Device telemetry
    'Windows Security Events'        # Windows event logs
    'DNS Essentials'                 # DNS analytics
)

# Priority 3: Network & Threat Intelligence
$solutions += @(
    'Microsoft Defender Threat Intelligence' # TI indicators
    'Network Session Essentials'     # Network flow data
    'Azure Firewall'                 # Firewall logs
    'Azure Web Application Firewall' # WAF logs
)

# Priority 4: Compliance & Data Protection
$solutions += @(
    'Microsoft Purview'              # DLP, sensitivity labels
    'Azure Key Vault'                # Key Vault diagnostics
)

# Install each solution from Content Hub
foreach ($solution in $solutions) {
    Write-Host "Installing: $solution" -ForegroundColor Cyan
    # Content Hub solutions are installed via the catalog
    # Use the Sentinel API or Portal: Sentinel > Content Hub > Search > Install
    $catalogItem = Get-AzSentinelContentPackage -ResourceGroupName $rgName `
        -WorkspaceName $workspaceName | Where-Object { $_.DisplayName -eq $solution }
    if ($catalogItem) {
        Install-AzSentinelContentPackage -ResourceGroupName $rgName `
            -WorkspaceName $workspaceName -ContentId $catalogItem.ContentId
    }
}
```

### Data Connector Onboarding Priority

| Priority | Connector | Table(s) | Why First |
|---|---|---|---|
| **P0** | Microsoft Entra ID | `SigninLogs`, `AuditLogs` | Identity is the perimeter — every attack starts here |
| **P0** | Microsoft Defender XDR | `AlertEvidence`, `DeviceEvents` | Unified XDR incidents flow into Sentinel |
| **P0** | Azure Activity | `AzureActivity` | Cloud control plane audit trail |
| **P1** | Microsoft 365 | `OfficeActivity` | Email/SharePoint/Teams telemetry |
| **P1** | Defender for Cloud | `SecurityAlert` | Cloud workload protection alerts |
| **P1** | Windows Security Events | `SecurityEvent` | Endpoint event logs |
| **P2** | DNS | `DnsEvents` | C2 detection, exfiltration |
| **P2** | Azure Firewall | `AzureDiagnostics` | Network boundary telemetry |
| **P2** | Syslog / CEF | `Syslog`, `CommonSecurityLog` | Third-party device integration |
| **P3** | Custom logs | `CustomLog_CL` | Application-specific telemetry |

### Workspace Settings Checklist

```powershell
# Verify workspace configuration
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $rgName -Name $workspaceName

# Check retention
Write-Host "Retention: $($workspace.RetentionInDays) days"

# Check Sentinel features
$settings = Get-AzSentinelSetting -ResourceGroupName $rgName -WorkspaceName $workspaceName

# Verify UEBA is enabled
$ueba = $settings | Where-Object { $_.Kind -eq 'Ueba' }
Write-Host "UEBA Enabled: $($ueba.IsEnabled)"

# Verify Anomalies
$anomalies = $settings | Where-Object { $_.Kind -eq 'Anomalies' }
Write-Host "Anomalies Enabled: $($anomalies.IsEnabled)"

# Verify Entity Analytics
$entityAnalytics = $settings | Where-Object { $_.Kind -eq 'EntityAnalytics' }
Write-Host "Entity Analytics Providers: $($entityAnalytics.EntityProviders -join ', ')"
```

### Multi-Tenant Lighthouse Configuration (MSSP)

```bicep
@description('Azure Lighthouse delegation for MSSP Sentinel management')
param mspTenantId string
param mspPrincipalId string
param mspPrincipalDisplayName string = 'MSSP SOC Team'

resource delegation 'Microsoft.ManagedServices/registrationDefinitions@2022-10-01' = {
  name: guid('SentinelMSSP', mspTenantId)
  properties: {
    registrationDefinitionName: 'Sentinel MSSP Access'
    description: 'Grants MSSP SOC team access to manage Sentinel workspace'
    managedByTenantId: mspTenantId
    authorizations: [
      {
        principalId: mspPrincipalId
        principalIdDisplayName: mspPrincipalDisplayName
        roleDefinitionId: 'ab8e14d6-4a74-4a29-9ba8-549422addade' // Microsoft Sentinel Contributor
      }
      {
        principalId: mspPrincipalId
        principalIdDisplayName: mspPrincipalDisplayName
        roleDefinitionId: '3e150937-b8fe-4cfb-8069-0eaf05ecd056' // Microsoft Sentinel Responder
      }
      {
        principalId: mspPrincipalId
        principalIdDisplayName: mspPrincipalDisplayName
        roleDefinitionId: '8d289c81-5878-46d4-8554-54e1e3d8b5cb' // Microsoft Sentinel Reader
      }
    ]
  }
}

resource assignment 'Microsoft.ManagedServices/registrationAssignments@2022-10-01' = {
  name: guid('SentinelMSSPAssign', mspTenantId)
  properties: {
    registrationDefinitionId: delegation.id
  }
}
```

### Cost Estimation for Initial Deployment

| Data Source | Estimated Daily Volume | Monthly Cost (Pay-As-You-Go) |
|---|---|---|
| Entra ID Sign-in/Audit | 1–5 GB/day | $50–$250 |
| Microsoft 365 | 2–10 GB/day | $100–$500 |
| Defender XDR | 1–5 GB/day | $50–$250 |
| Windows Security Events | 5–50 GB/day | $250–$2,500 |
| Azure Activity | 0.5–2 GB/day | $25–$100 |
| Syslog/CEF | 5–20 GB/day | $250–$1,000 |
| **Total (mid-size org)** | **~15–50 GB/day** | **$750–$2,500** |

**Cost optimization tactics:**
- Use Commitment Tiers (100/200/300/400/500 GB/day) for 30–50% savings
- Configure Basic Logs for high-volume, low-query tables (`ContainerLog`, `AppTraces`)
- Set up Archive tier for data beyond 90 days (query via search jobs)
- Use data collection rules (DCR) to filter noisy events before ingestion
- Free data sources: Azure Activity, Office 365 audit logs (with E5), Sentinel health

## Integration Points

- **Defender XDR** — Bi-directional incident sync via the unified portal (security.microsoft.com)
- **Azure Lighthouse** — Multi-tenant workspace management for MSSPs
- **Logic Apps** — Automated response playbooks triggered by analytics rules
- **Azure Data Explorer** — Long-term retention and cross-cluster queries for historical hunting
- **Microsoft Purview** — DLP alerts ingested via Sentinel connector

## Operational Procedures

### Post-Deployment Validation KQL

```kql
// Verify data connector health — check which tables are receiving data
Usage
| where TimeGenerated > ago(24h)
| summarize RecordCount = count(), DataSizeMB = sum(Quantity) by DataType
| sort by DataSizeMB desc
| take 20
```

```kql
// Check for data ingestion gaps in the last 7 days
let tables = dynamic(["SigninLogs", "AuditLogs", "SecurityEvent", "AzureActivity"]);
union withsource=TableName *
| where TimeGenerated > ago(7d)
| where TableName in (tables)
| summarize LastEvent = max(TimeGenerated), EventCount = count() by TableName
| extend HoursSinceLastEvent = datetime_diff('hour', now(), LastEvent)
| where HoursSinceLastEvent > 1
| sort by HoursSinceLastEvent desc
```

```kql
// UEBA validation — confirm behavioral analytics are populating
BehaviorAnalytics
| where TimeGenerated > ago(24h)
| summarize count() by ActivityType
| sort by count_ desc
```

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| Connector shows "Connected" but no data | Diagnostic settings not configured on source | Verify diagnostic settings point to the workspace |
| UEBA not populating | Data sources not selected | Re-enable UEBA with all 4 data source types |
| Content Hub solution won't install | Missing provider registration | Register `Microsoft.SecurityInsights` provider on subscription |
| High ingestion cost | Noisy table (e.g., `AADNonInteractiveUserSignInLogs`) | Apply workspace transformation DCR to filter |
| Lighthouse delegation fails | Incorrect role definition IDs | Verify GUIDs match Azure built-in role IDs |
| Anomalies blade empty | Feature takes 14 days to baseline | Wait for learning period; verify data sources are active |

## Related Skills

- **[Defender XDR Configuration](defender-xdr-configuration.md)** — Configure the unified portal that syncs with Sentinel
- **[Defender for Cloud Policies](defender-for-cloud-policies.md)** — Enable cloud workload protection that feeds into Sentinel
- **[Scheduled Rule Pattern](../detection/scheduled-rule-pattern.md)** — Build detection rules after workspace is provisioned
- **[MITRE ATT&CK Mapping](../detection/mitre-attack-mapping.md)** — Map your detection coverage once rules are deployed
- **[Log Analytics Workspace Design](../log-analytics/)** — Advanced workspace architecture patterns
- **[Purview DLP Patterns](purview-dlp-patterns.md)** — DLP alerts flow into Sentinel via connector

## Environment Context

Before executing this skill, check the customer's `.secops/` knowledge framework:

1. **Data location:** Read `.secops/data-sources/data-source-map.yaml` — tables may be in Sentinel, ADX, or external sources
2. **Active migrations:** Read `.secops/data-sources/migrations.yaml` — data may be moving between locations
3. **Workspace config:** Read `.secops/workspaces/` — know the workspace ID, tier, retention, and naming conventions
4. **Compliance:** Read `.secops/compliance/requirements.yaml` — respect data residency and regulatory constraints

If `.secops/` doesn't exist, proceed with defaults but suggest `secops-squad init --secops`.

See `.copilot/skills/secops-environment-context.md` for the full discovery flow.
