---
title: Defender API Permissions Reference
category: msft-security
difficulty: intermediate
mitre_attack:
  - T1078  # Valid Accounts — auth context
  - T1098  # Account Manipulation — permission management
products:
  - Microsoft Entra ID
  - Microsoft Graph Security API
  - Microsoft Defender for Endpoint
  - Microsoft Defender for Cloud
  - Microsoft Defender for Cloud Apps
  - Microsoft Defender for Identity
author: Kima
version: 1.0.0
last_updated: 2026-04-30
---

# Defender API Permissions Reference

## Overview

Complete permissions reference for all Microsoft Defender product APIs. Covers the full permissions matrix, least-privilege patterns for common SOC workflows, app registration setup, authentication methods, and production deployment patterns.

Use this skill when:
- Setting up Entra ID app registrations for Defender API access
- Determining minimum permissions for a specific security workflow
- Choosing between Application vs. Delegated permissions
- Configuring authentication for production environments (managed identity, certificates)
- Deploying to government cloud or multi-tenant MSSP scenarios

## Environment Context

Check `.secops/identity/tenants.yaml` for tenant topology and cross-tenant access settings. For MSSP scenarios, each customer tenant requires its own app registration or Lighthouse delegation.

## Section 1: Complete Permissions Matrix

### Microsoft Graph Security API Permissions

| Permission | Type | Description | Admin Consent |
|---|---|---|---|
| `SecurityAlert.Read.All` | App / Delegated | Read security alerts (alerts_v2) | Yes |
| `SecurityAlert.ReadWrite.All` | App / Delegated | Read/write alerts — update status, assign, classify | Yes |
| `SecurityIncident.Read.All` | App / Delegated | Read XDR incidents | Yes |
| `SecurityIncident.ReadWrite.All` | App / Delegated | Read/write incidents — assign, classify, update | Yes |
| `SecurityEvents.Read.All` | App / Delegated | Read secure scores, legacy alerts | Yes |
| `SecurityEvents.ReadWrite.All` | App / Delegated | Read/write secure scores, legacy alerts | Yes |
| `SecurityActions.Read.All` | App / Delegated | Read security response actions | Yes |
| `SecurityActions.ReadWrite.All` | App / Delegated | Initiate security response actions | Yes |
| `ThreatHunting.Read.All` | App / Delegated | Run Advanced Hunting queries (XDR) | Yes |
| `ThreatIntelligence.Read.All` | App / Delegated | Read threat intelligence (indicators, articles, hosts) | Yes |
| `ThreatIndicators.ReadWrite.OwnedBy` | App / Delegated | Create/manage TI indicators owned by app | Yes |
| `AttackSimulation.Read.All` | App / Delegated | Read attack simulation training data | Yes |

### Defender for Endpoint (MDE) API Permissions

These are registered under the **WindowsDefenderATP** resource (`fc780465-2017-40d4-a0c5-307022471b92`).

| Permission | Type | Description | Admin Consent |
|---|---|---|---|
| `Alert.Read.All` | App | Read MDE alerts | Yes |
| `Alert.ReadWrite.All` | App | Read/write MDE alerts | Yes |
| `Machine.Read.All` | App | Read machine info, tags, groups | Yes |
| `Machine.ReadWrite.All` | App | Read/write machines — tags, groups, actions | Yes |
| `Machine.Isolate` | App | Isolate/unisolate machines | Yes |
| `Machine.RestrictExecution` | App | Restrict/unrestrict code execution | Yes |
| `Machine.Scan` | App | Run antivirus scans | Yes |
| `Machine.CollectForensics` | App | Collect investigation packages | Yes |
| `Machine.Offboard` | App | Offboard machines from MDE | Yes |
| `Machine.LiveResponse` | App | Initiate Live Response sessions | Yes |
| `AdvancedQuery.Read.All` | App | Run Advanced Hunting queries (MDE tables) | Yes |
| `Software.Read.All` | App | Read TVM software inventory | Yes |
| `Vulnerability.Read.All` | App | Read TVM vulnerabilities | Yes |
| `SecurityRecommendation.Read.All` | App | Read TVM security recommendations | Yes |
| `RemediationTasks.Read.All` | App | Read TVM remediation tasks | Yes |
| `Score.Read.All` | App | Read MDE exposure score | Yes |
| `Ti.ReadWrite` | App | Create/manage custom indicators | Yes |
| `Ti.ReadWrite.All` | App | Manage all custom indicators | Yes |
| `Library.Manage` | App | Upload files for Live Response library | Yes |

### Entra ID Protection Permissions

| Permission | Type | Description | Admin Consent |
|---|---|---|---|
| `IdentityRiskEvent.Read.All` | App / Delegated | Read risk detections | Yes |
| `IdentityRiskEvent.ReadWrite.All` | App / Delegated | Read/write risk detections | Yes |
| `IdentityRiskyUser.Read.All` | App / Delegated | Read risky users | Yes |
| `IdentityRiskyUser.ReadWrite.All` | App / Delegated | Dismiss/confirm risky users | Yes |
| `IdentityRiskyServicePrincipal.Read.All` | App / Delegated | Read risky service principals | Yes |
| `Policy.Read.All` | App / Delegated | Read Conditional Access policies | Yes |
| `Policy.ReadWrite.ConditionalAccess` | App / Delegated | Create/update CA policies | Yes |

### Defender for Cloud (ARM) Permissions

Defender for Cloud uses Azure RBAC, not Graph permissions.

| Role | Scope | Operations |
|---|---|---|
| `Security Reader` | Subscription | Read secure score, recommendations, alerts, policies |
| `Security Admin` | Subscription | All reader + dismiss alerts, apply recommendations, manage policies |
| `Contributor` | Resource Group | Enable/disable Defender plans, manage JIT policies |
| `Owner` | Subscription | Full control including RBAC assignments |

```powershell
# Assign Security Reader to the MCP service principal
$sp = Get-AzADServicePrincipal -DisplayName "SecOps-Squad-MCP-Defender"
New-AzRoleAssignment -ObjectId $sp.Id `
    -RoleDefinitionName "Security Reader" `
    -Scope "/subscriptions/$subscriptionId"
```

### Defender for Cloud Apps (MDCA) Permissions

| Permission | Type | Description |
|---|---|---|
| API Token (MDCA Portal) | App | Generated in Settings > Security extensions > API tokens |
| `CloudApp-API.Read` | App | Read activities, files, alerts |
| `CloudApp-API.ReadWrite` | App | Full management including governance actions |

> MDCA uses its own API tokens, not Graph permissions. Generate in the MDCA portal under Settings > Security Extensions > API tokens.

## Section 2: Least-Privilege Patterns

### By Workflow

| Workflow | Graph Permissions | MDE Permissions | ARM Roles |
|---|---|---|---|
| **Alert monitoring** | `SecurityAlert.Read.All` | `Alert.Read.All` | Security Reader |
| **Alert triage** | `SecurityAlert.ReadWrite.All` | `Alert.ReadWrite.All` | — |
| **Incident management** | `SecurityIncident.ReadWrite.All`, `SecurityAlert.ReadWrite.All` | — | — |
| **Advanced hunting** | `ThreatHunting.Read.All` | `AdvancedQuery.Read.All` | — |
| **Device investigation** | — | `Machine.Read.All`, `AdvancedQuery.Read.All` | — |
| **Device isolation** | — | `Machine.Isolate` | — |
| **Forensic collection** | — | `Machine.CollectForensics` | — |
| **AV scan** | — | `Machine.Scan` | — |
| **Live Response** | — | `Machine.LiveResponse`, `Library.Manage` | — |
| **IOC management** | `ThreatIndicators.ReadWrite.OwnedBy` | `Ti.ReadWrite` | — |
| **Vulnerability mgmt** | — | `Software.Read.All`, `Vulnerability.Read.All`, `SecurityRecommendation.Read.All` | — |
| **Posture assessment** | `SecurityEvents.Read.All` | `Score.Read.All` | Security Reader |
| **Identity risk** | `IdentityRiskEvent.Read.All`, `IdentityRiskyUser.Read.All` | — | — |
| **Identity remediation** | `IdentityRiskyUser.ReadWrite.All` | — | — |
| **Cloud security** | — | — | Security Reader |
| **Cloud remediation** | — | — | Security Admin |
| **Full IR** | `SecurityIncident.ReadWrite.All`, `SecurityAlert.ReadWrite.All`, `ThreatHunting.Read.All` | `Machine.ReadWrite.All`, `Machine.Isolate`, `Machine.CollectForensics`, `Machine.Scan`, `AdvancedQuery.Read.All` | Security Admin |

### Tiered App Registration Strategy

```
┌──────────────────────────────────────────────────────────────────┐
│  App: SecOps-MCP-ReadOnly                                        │
│  Purpose: Monitoring dashboards, posture reports, alert reads    │
│  Graph: SecurityAlert.Read.All, SecurityEvents.Read.All,         │
│         ThreatHunting.Read.All                                   │
│  MDE: Alert.Read.All, Machine.Read.All, AdvancedQuery.Read.All  │
│  ARM: Security Reader                                            │
│  Auth: Certificate (managed identity in production)              │
├──────────────────────────────────────────────────────────────────┤
│  App: SecOps-MCP-Triage                                          │
│  Purpose: Alert triage, incident assignment, hunting             │
│  Graph: SecurityAlert.ReadWrite.All,                             │
│         SecurityIncident.ReadWrite.All, ThreatHunting.Read.All   │
│  MDE: Alert.ReadWrite.All, Machine.Read.All,                     │
│       AdvancedQuery.Read.All                                     │
│  Auth: Certificate                                               │
├──────────────────────────────────────────────────────────────────┤
│  App: SecOps-MCP-Response                                        │
│  Purpose: Full incident response — isolate, collect, remediate  │
│  Graph: SecurityIncident.ReadWrite.All,                          │
│         SecurityAlert.ReadWrite.All, ThreatHunting.Read.All,     │
│         IdentityRiskyUser.ReadWrite.All                          │
│  MDE: Machine.ReadWrite.All, Machine.Isolate,                    │
│       Machine.CollectForensics, Machine.Scan, Machine.LiveResponse│
│  ARM: Security Admin                                             │
│  Auth: Certificate with PIM activation for IR scenarios          │
└──────────────────────────────────────────────────────────────────┘
```

## Section 3: App Registration Setup

### Step-by-Step Registration

```powershell
# 1. Create the app registration
Connect-MgGraph -Scopes "Application.ReadWrite.All"

$app = New-MgApplication -DisplayName "SecOps-Squad-MCP-Defender" `
    -SignInAudience "AzureADMyOrg" `
    -Web @{ RedirectUris = @("https://localhost") }

Write-Host "Application ID: $($app.AppId)"
Write-Host "Object ID: $($app.Id)"

# 2. Create a service principal
$sp = New-MgServicePrincipal -AppId $app.AppId
Write-Host "Service Principal ID: $($sp.Id)"

# 3. Add required permissions
$graphResourceId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
$mdeResourceId = "fc780465-2017-40d4-a0c5-307022471b92"   # WindowsDefenderATP

# Graph Security permissions
$graphPermissions = @(
    @{ Id = "bf394140-e372-4bf9-a898-299cfc7564e5"; Type = "Role" }  # SecurityIncident.ReadWrite.All
    @{ Id = "472e4a4d-bb4a-4026-98d1-0571f1840dc8"; Type = "Role" }  # SecurityAlert.ReadWrite.All
    @{ Id = "dd98c7f5-2d42-42d8-a6d0-1e30e91de81e"; Type = "Role" }  # ThreatHunting.Read.All
    @{ Id = "b9abcc4f-94fc-4457-9141-d20ce80ec952"; Type = "Role" }  # SecurityEvents.Read.All
)

# MDE permissions
$mdePermissions = @(
    @{ Id = "93489bf5-0fbc-4f2d-b901-33f2fe08ff05"; Type = "Role" }  # Machine.ReadWrite.All
    @{ Id = "37f71c98-d198-41ae-964d-7e2e4a3bbd05"; Type = "Role" }  # Alert.ReadWrite.All
    @{ Id = "a0e06b5e-7e90-4e80-87d7-7c4e2a046891"; Type = "Role" }  # AdvancedQuery.Read.All
)

$requiredAccess = @(
    @{ ResourceAppId = $graphResourceId; ResourceAccess = $graphPermissions }
    @{ ResourceAppId = $mdeResourceId; ResourceAccess = $mdePermissions }
)

Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $requiredAccess
Write-Host "Permissions configured — admin consent required"
```

### Grant Admin Consent

```powershell
# Grant admin consent (requires Global Admin or Privileged Role Admin)
# Option 1: Portal
# Entra admin center > App registrations > [app] > API permissions > Grant admin consent

# Option 2: PowerShell
$graphSpId = (Get-MgServicePrincipal -Filter "appId eq '$graphResourceId'").Id
$mdeSpId = (Get-MgServicePrincipal -Filter "appId eq '$mdeResourceId'").Id

foreach ($perm in $graphPermissions) {
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id `
        -PrincipalId $sp.Id `
        -ResourceId $graphSpId `
        -AppRoleId $perm.Id
}

foreach ($perm in $mdePermissions) {
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id `
        -PrincipalId $sp.Id `
        -ResourceId $mdeSpId `
        -AppRoleId $perm.Id
}
```

## Section 4: Authentication Methods

### Certificate-Based Authentication (Recommended)

```powershell
# Generate self-signed certificate
$cert = New-SelfSignedCertificate -Subject "CN=SecOps-MCP-Defender" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(2)

# Export public key (.cer) for upload to Entra ID
Export-Certificate -Cert $cert -FilePath ".\SecOps-MCP-Defender.cer"

# Upload to app registration
$certData = [System.Convert]::ToBase64String($cert.RawData)
Update-MgApplication -ApplicationId $app.Id -KeyCredentials @(
    @{
        Type = "AsymmetricX509Cert"
        Usage = "Verify"
        Key = [System.Text.Encoding]::ASCII.GetBytes($certData)
        DisplayName = "SecOps-MCP-Cert"
    }
)

# Authenticate with certificate
Connect-MgGraph -TenantId "<tenant-id>" `
    -ClientId $app.AppId `
    -CertificateThumbprint $cert.Thumbprint
```

### Client Secret (Dev/Test Only)

```powershell
# Add client secret — use ONLY for development/testing
$secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
    DisplayName = "MCP Dev Secret"
    EndDateTime = (Get-Date).AddMonths(6)
}

Write-Host "Secret Value: $($secret.SecretText)"
Write-Warning "Store securely — this value cannot be retrieved again"
Write-Warning "Rotate to certificate-based auth before production deployment"
```

### Managed Identity (Production)

```powershell
# Use system-assigned managed identity for Azure-hosted MCP servers
# No credentials to manage — Azure handles rotation automatically

# Enable on Azure Function / App Service
az functionapp identity assign --name "secops-mcp-server" --resource-group "rg-soc"

# Grant Graph permissions to managed identity
$miObjectId = (az functionapp identity show --name "secops-mcp-server" `
    --resource-group "rg-soc" --query principalId -o tsv)

# Assign Graph app roles to managed identity
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $miObjectId `
    -PrincipalId $miObjectId `
    -ResourceId $graphSp.Id `
    -AppRoleId "bf394140-e372-4bf9-a898-299cfc7564e5"  # SecurityIncident.ReadWrite.All

# ARM role assignment for Defender for Cloud
New-AzRoleAssignment -ObjectId $miObjectId `
    -RoleDefinitionName "Security Reader" `
    -Scope "/subscriptions/$subscriptionId"
```

```python
# Python — Acquire token with managed identity (no secrets)
from azure.identity import ManagedIdentityCredential

credential = ManagedIdentityCredential()
token = credential.get_token("https://graph.microsoft.com/.default")

# Use token for Graph Security API calls
headers = {"Authorization": f"Bearer {token.token}"}
```

### Authentication Method Comparison

| Method | Security | Rotation | Best For |
|---|---|---|---|
| **Managed Identity** | ★★★★★ | Automatic | Azure-hosted MCP servers (Functions, App Service) |
| **Certificate** | ★★★★ | Manual (1-2yr cycle) | On-prem MCP servers, hybrid environments |
| **Client Secret** | ★★ | Manual (must track expiry) | Dev/test only — never production |
| **Delegated (user)** | ★★★ | Per-session | Interactive tools, investigation consoles |

## Section 5: Multi-Tenant & MSSP Patterns

### Lighthouse-Delegated Access

```powershell
# For MSSP scenarios, use Lighthouse delegated access
# Check .secops/identity/tenants.yaml for delegation details

# Access customer tenant resources via Lighthouse (no separate login)
$customerSubscription = "customer-sub-id"
Select-AzSubscription -SubscriptionId $customerSubscription

# Defender for Cloud operations in customer tenant
$recommendations = Get-AzSecurityAssessment -SubscriptionId $customerSubscription
```

### Multi-Tenant App Registration

```powershell
# For MSSP managing multiple tenants directly:
# 1. Register app as multi-tenant
$app = New-MgApplication -DisplayName "MSSP-SecOps-MCP" `
    -SignInAudience "AzureADMultipleOrgs"

# 2. Each customer tenant must:
#    - Admin consent to the app
#    - App gets service principal in their tenant
#    - Permissions scoped per tenant

# 3. Acquire token per tenant
$tenants = @("tenant-a-id", "tenant-b-id", "tenant-c-id")
foreach ($tenantId in $tenants) {
    $token = Get-MsalToken -ClientId $app.AppId `
        -TenantId $tenantId `
        -ClientCertificate $cert
    # Use $token for API calls in that tenant
}
```

## Section 6: Government Cloud Considerations

### Permission Differences

| Feature | Commercial | GCC | GCC High | DoD |
|---|---|---|---|---|
| Graph Security API | ✅ Full | ✅ Full | ✅ Most | ⚠️ Limited |
| MDE API | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| MDCA API | ✅ Full | ✅ Full | ✅ Full | ❌ N/A |
| TI API | ✅ Full | ✅ Full | ⚠️ Limited | ❌ N/A |
| Advanced Hunting | ✅ Full | ✅ Full | ✅ Full | ✅ Full |

### Government Cloud Endpoints

```python
# Select correct endpoints based on .secops/environment.yaml → organization.cloud
GOV_ENDPOINTS = {
    "azure-government": {
        "graph": "https://graph.microsoft.us",
        "login": "https://login.microsoftonline.us",
        "mde": "https://api-gcc.securitycenter.microsoft.us",
        "arm": "https://management.usgovcloudapi.net",
        "scope_suffix": ".default"
    },
    "gcc-high": {
        "graph": "https://graph.microsoft.us",
        "login": "https://login.microsoftonline.us",
        "mde": "https://api-gcch.securitycenter.microsoft.us",
        "arm": "https://management.usgovcloudapi.net",
        "scope_suffix": ".default"
    }
}
```

## Section 7: Permission Auditing & Governance

### Audit App Permissions

```powershell
# Audit all service principals with Defender-related permissions
$securityApps = Get-MgServicePrincipal -All | ForEach-Object {
    $sp = $_
    $roles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
    $secRoles = $roles | Where-Object {
        $_.AppRoleId -in @(
            "bf394140-e372-4bf9-a898-299cfc7564e5",  # SecurityIncident.ReadWrite.All
            "472e4a4d-bb4a-4026-98d1-0571f1840dc8",  # SecurityAlert.ReadWrite.All
            "dd98c7f5-2d42-42d8-a6d0-1e30e91de81e"   # ThreatHunting.Read.All
        )
    }
    if ($secRoles) {
        [PSCustomObject]@{
            AppName = $sp.DisplayName
            AppId = $sp.AppId
            Roles = ($secRoles | ForEach-Object { $_.AppRoleId }) -join ", "
            CreatedDate = $sp.AdditionalProperties.createdDateTime
        }
    }
}

$securityApps | Format-Table -AutoSize
```

### Credential Expiry Monitoring

```powershell
# Monitor credential expiration for Defender API apps
$apps = Get-MgApplication -Filter "displayName eq 'SecOps-Squad-MCP-Defender'"

foreach ($app in $apps) {
    # Check secrets
    foreach ($secret in $app.PasswordCredentials) {
        $daysLeft = ($secret.EndDateTime - (Get-Date)).Days
        if ($daysLeft -lt 30) {
            Write-Warning "SECRET expiring in $daysLeft days: $($app.DisplayName) — $($secret.DisplayName)"
        }
    }
    # Check certificates
    foreach ($cert in $app.KeyCredentials) {
        $daysLeft = ($cert.EndDateTime - (Get-Date)).Days
        if ($daysLeft -lt 60) {
            Write-Warning "CERT expiring in $daysLeft days: $($app.DisplayName) — $($cert.DisplayName)"
        }
    }
}
```

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| `AADSTS700016` | App not found in tenant | Verify app is registered in the correct tenant |
| `AADSTS7000215` | Invalid client secret | Regenerate secret; check for expired credentials |
| `AADSTS650057` | Resource not found | Verify MDE resource ID `fc780465-2017-40d4-a0c5-307022471b92` |
| `InsufficientPrivileges` | Missing admin consent | Grant admin consent in Entra admin center |
| `UnauthorizedAccessToDeviceAction` | Missing MDE action permission | Add specific `Machine.Isolate`, `.Scan` etc. permissions |
| Managed identity 403 | Graph roles not assigned | Assign app roles to managed identity via PowerShell (portal doesn't support this) |
| GCC/GCCHigh 404 | Wrong API endpoint | Check `.secops/environment.yaml` cloud type; use `.us` endpoints |

## Related Skills

- **[Defender MCP Server](defender-mcp-server.md)** — API operations, workflows, rate limiting
- **[Microsoft Graph Security](microsoft-graph-security.md)** — Graph auth patterns, batch operations
- **[Entra ID Protection](entra-id-protection.md)** — Risk policies requiring Identity permissions
- **[Defender for Endpoint](defender-for-endpoint.md)** — MDE operations requiring MDE API permissions
- **[Defender for Cloud Policies](defender-for-cloud-policies.md)** — ARM RBAC for cloud security
