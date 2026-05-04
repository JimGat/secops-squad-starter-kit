---
title: Microsoft Security Connectivity Setup
category: msft-security
difficulty: beginner
mitre_attack:
  - T1078  # Valid Accounts — auth & permission validation
  - T1530  # Data from Cloud Storage — workspace connectivity
products:
  - Microsoft Sentinel
  - Microsoft Defender XDR
  - Microsoft Defender for Cloud
  - Microsoft Defender for Identity
  - Microsoft Defender for Endpoint
  - Microsoft Entra ID Protection
author: Kima
version: 1.0.0
last_updated: 2026-05-04
---

# Microsoft Security Connectivity Setup

## Overview

This skill is the definitive path from "secops-squad installed" to "all security products connected and verified." Use it after initial installation to confirm every product in the framework can authenticate, query data, and return results.

Each section provides the minimum required permissions, setup steps, and a copy-paste verification command. When a verification command succeeds, that product is ready for agent use.

Use this skill when:
- Setting up secops-squad in a new environment for the first time
- Diagnosing why an agent cannot query a specific product
- Validating connectivity after credential rotation or permission changes
- Onboarding a new analyst and confirming their tooling is wired up correctly
- Auditing which products are connected before a threat hunt or incident response

## Prerequisites

| Requirement | Detail |
|---|---|
| **Azure CLI** | `az --version` ≥ 2.50. Install: https://learn.microsoft.com/cli/azure/install-azure-cli |
| **Active login** | `az login` completed; `az account show` returns your tenant and subscription |
| **App registration** | Entra ID app registration for API-based products (Defender XDR, MDI, MDE, Entra ID Protection). See [Defender API Permissions Reference](defender-api-permissions.md) for full setup |
| **Correct tenant** | Verify `az account show --query tenantId` matches your security tenant |
| **.secops/ config** | Recommended: `secops-squad init --secops` generates starter config. Agents read tenant IDs, workspace names, and subscription IDs from `.secops/environment.yaml` |

## Environment Context

Before running connectivity tests, check `.secops/environment.yaml`:

- **Tenant ID** — read from `.secops/identity/tenants.yaml`; required for all `az rest` calls
- **Subscription ID** — read from `.secops/environment.yaml` `subscriptions[].id`
- **Workspace** — read from `.secops/workspaces/*.yaml`; required for Sentinel
- **Cloud type** — `cloud: azure-commercial` vs `azure-government` changes all API endpoints. See [Gov Cloud Support](gov-cloud-support.md) for GCC/DoD endpoint overrides.

If `.secops/` doesn't exist, proceed with the values you supply manually and run `secops-squad init --secops` afterward.

---

## Quick Connectivity Test

Run all six product checks in sequence. This is the "doctor command" for security product connectivity. Copy-paste the block and replace the four placeholder values at the top.

```powershell
# ── Replace these four values before running ──────────────────────────────────
$tenantId      = "YOUR-TENANT-ID"
$subscriptionId = "YOUR-SUBSCRIPTION-ID"
$workspaceRG   = "rg-sentinel-prod"
$workspaceName  = "law-sentinel-prod"
# ─────────────────────────────────────────────────────────────────────────────

$results = [ordered]@{}

# 1. Microsoft Sentinel
Write-Host "`n[1/6] Microsoft Sentinel..." -ForegroundColor Cyan
try {
    $ws = az monitor log-analytics workspace show `
        --resource-group $workspaceRG `
        --workspace-name $workspaceName `
        --query "{id:customerId, sku:sku.name, retention:retentionInDays}" `
        --output json 2>&1 | ConvertFrom-Json
    $results["Sentinel"] = "✅ Connected — Workspace ID: $($ws.id), SKU: $($ws.sku)"
} catch {
    $results["Sentinel"] = "❌ Failed — $_"
}

# 2. Microsoft Defender XDR (Graph Security API)
Write-Host "[2/6] Microsoft Defender XDR..." -ForegroundColor Cyan
try {
    $xdr = az rest --method get `
        --url "https://graph.microsoft.com/v1.0/security/alerts_v2?`$top=1" `
        --query "value[0].{id:id, severity:severity}" `
        --output json 2>&1 | ConvertFrom-Json
    $status = if ($xdr -and $xdr.id) { "1 alert returned" } else { "authenticated, 0 alerts" }
    $results["Defender XDR"] = "✅ Connected — $status"
} catch {
    $results["Defender XDR"] = "❌ Failed — $_"
}

# 3. Microsoft Defender for Cloud
Write-Host "[3/6] Microsoft Defender for Cloud..." -ForegroundColor Cyan
try {
    $mdc = az security assessment list `
        --subscription $subscriptionId `
        --query "[0].{name:displayName, status:status.code}" `
        --output json 2>&1 | ConvertFrom-Json
    $status = if ($mdc -and $mdc.name) { "assessments available" } else { "authenticated, no assessments" }
    $results["Defender for Cloud"] = "✅ Connected — $status"
} catch {
    $results["Defender for Cloud"] = "❌ Failed — $_"
}

# 4. Microsoft Defender for Identity
Write-Host "[4/6] Microsoft Defender for Identity..." -ForegroundColor Cyan
try {
    $mdi = az rest --method get `
        --url "https://graph.microsoft.com/v1.0/security/identities/healthIssues" `
        --query "value[0].{id:id, displayName:displayName}" `
        --output json 2>&1 | ConvertFrom-Json
    $status = if ($mdi -and $mdi.id) { "health issues returned" } else { "authenticated, no health issues" }
    $results["Defender for Identity"] = "✅ Connected — $status"
} catch {
    $results["Defender for Identity"] = "❌ Failed — $_"
}

# 5. Microsoft Defender for Endpoint
Write-Host "[5/6] Microsoft Defender for Endpoint..." -ForegroundColor Cyan
try {
    $mde = az rest --method get `
        --url "https://api.securitycenter.microsoft.com/api/machines?`$top=1" `
        --query "value[0].{id:id, health:healthStatus}" `
        --output json 2>&1 | ConvertFrom-Json
    $status = if ($mde -and $mde.id) { "machine returned" } else { "authenticated, 0 machines" }
    $results["Defender for Endpoint"] = "✅ Connected — $status"
} catch {
    $results["Defender for Endpoint"] = "❌ Failed — $_"
}

# 6. Microsoft Entra ID Protection
Write-Host "[6/6] Microsoft Entra ID Protection..." -ForegroundColor Cyan
try {
    $idp = az rest --method get `
        --url "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$top=1" `
        --query "value[0].{id:id, risk:riskLevel}" `
        --output json 2>&1 | ConvertFrom-Json
    $status = if ($idp -and $idp.id) { "risky user returned" } else { "authenticated, 0 risky users" }
    $results["Entra ID Protection"] = "✅ Connected — $status"
} catch {
    $results["Entra ID Protection"] = "❌ Failed — $_"
}

# Summary
Write-Host "`n═══════════════════════════════════════" -ForegroundColor White
Write-Host "  secops-squad Connectivity Summary" -ForegroundColor White
Write-Host "═══════════════════════════════════════" -ForegroundColor White
foreach ($product in $results.Keys) {
    $color = if ($results[$product].StartsWith("✅")) { "Green" } else { "Red" }
    Write-Host "  $product`: $($results[$product])" -ForegroundColor $color
}
Write-Host "═══════════════════════════════════════`n" -ForegroundColor White
```

**Expected output when all products are connected:**
```
  Sentinel:              ✅ Connected — Workspace ID: abc123..., SKU: PerGB2018
  Defender XDR:          ✅ Connected — authenticated, 0 alerts
  Defender for Cloud:    ✅ Connected — assessments available
  Defender for Identity: ✅ Connected — authenticated, no health issues
  Defender for Endpoint: ✅ Connected — machine returned
  Entra ID Protection:   ✅ Connected — authenticated, 0 risky users
```

Any `❌` line indicates a product needing attention. Jump to that product's section below.

---

## Product 1: Microsoft Sentinel

### Required Roles

| Role | Scope | Purpose |
|---|---|---|
| `Microsoft Sentinel Contributor` | Resource Group | Read/write analytics rules, incidents, watchlists |
| `Log Analytics Contributor` | Log Analytics Workspace | Query logs, manage workspace settings |
| `Microsoft Sentinel Reader` | Resource Group | Read-only access (minimum for agents querying incidents) |

> **Least privilege for agents:** `Microsoft Sentinel Reader` + `Log Analytics Reader` for query-only workflows. Upgrade to `Microsoft Sentinel Responder` when agents need to update incident status.

### Setup Steps

1. **Verify workspace exists:**
   ```bash
   az monitor log-analytics workspace show \
     --resource-group rg-sentinel-prod \
     --workspace-name law-sentinel-prod \
     --query "{id:customerId, sku:sku.name, retention:retentionInDays}"
   ```

2. **Check your role assignment:**
   ```bash
   az role assignment list \
     --assignee $(az ad signed-in-user show --query id -o tsv) \
     --scope "/subscriptions/SUB_ID/resourceGroups/rg-sentinel-prod" \
     --query "[].{role:roleDefinitionName}" \
     --output table
   ```

3. **Confirm Sentinel is enabled on the workspace:**
   ```bash
   az resource show \
     --resource-group rg-sentinel-prod \
     --name default \
     --resource-type "Microsoft.SecurityInsights/onboardingStates" \
     --namespace Microsoft.SecurityInsights \
     --parent "workspaces/law-sentinel-prod"
   ```

### Verification Commands

```bash
# Test query: count incidents by severity in the last 7 days
az monitor log-analytics query \
  --workspace WORKSPACE_CUSTOMER_ID \
  --analytics-query "SecurityIncident | where TimeGenerated > ago(7d) | summarize count() by Severity" \
  --output table
```

```bash
# Test via REST (useful for validating service principal auth)
az rest --method get \
  --url "https://management.azure.com/subscriptions/SUB_ID/resourceGroups/RG/providers/Microsoft.OperationalInsights/workspaces/WORKSPACE/providers/Microsoft.SecurityInsights/incidents?api-version=2024-03-01&%24top=1" \
  --query "value[0].{name:name, severity:properties.severity}"
```

### Common Issues & Fixes

| Issue | Cause | Fix |
|---|---|---|
| `ResourceNotFound` | Wrong resource group or workspace name | Run `az monitor log-analytics workspace list --query "[].{name:name,rg:resourceGroup}"` to list all workspaces |
| `AuthorizationFailed` | Missing role assignment | Assign `Microsoft Sentinel Reader` at the resource group scope |
| `WorkspaceNotOnboarded` | Sentinel not enabled on workspace | Enable via: `az resource create --resource-type Microsoft.SecurityInsights/onboardingStates ...` or Portal: Sentinel → Enable |
| Query returns empty | Workspace has no data | Verify data connectors in Portal: Sentinel → Data connectors; check `Usage` table for ingestion |
| `BadRequest` on KQL | Syntax error in query | Test query in Sentinel Logs blade first; validate with `secops-squad kql validate` |

### Related Skills

- [Sentinel Workspace Setup](sentinel-workspace-setup.md) — full workspace provisioning from scratch
- [Sentinel API Reference](sentinel-api-reference.md) — complete REST API quick reference
- [Sentinel MCP Server](sentinel-mcp-server.md) — MCP-based agent integration for query execution

---

## Product 2: Microsoft Defender XDR

### Required App Registration Permissions

Defender XDR uses the **Microsoft Graph Security API**. Your app registration needs:

| Permission | Resource | Type | Purpose |
|---|---|---|---|
| `SecurityAlert.Read.All` | Microsoft Graph | Application | Read security alerts |
| `SecurityIncident.Read.All` | Microsoft Graph | Application | Read XDR incidents |
| `ThreatHunting.Read.All` | Microsoft Graph | Application | Run Advanced Hunting queries |
| `SecurityEvents.Read.All` | Microsoft Graph | Application | Legacy alerts and secure scores |

> For write operations (update incidents, assign, classify), also add `SecurityAlert.ReadWrite.All` and `SecurityIncident.ReadWrite.All`.
>
> See [Defender API Permissions Reference](defender-api-permissions.md) for the complete permissions matrix and least-privilege patterns.

### Setup Steps

1. **Create app registration (if not already done):**
   ```bash
   # Create the app registration
   az ad app create --display-name "secops-squad-readonly" \
     --sign-in-audience AzureADMyOrg

   # Save the app ID
   APP_ID=$(az ad app list --display-name "secops-squad-readonly" --query "[0].appId" -o tsv)
   ```

2. **Add Graph Security API permissions:**
   ```bash
   # Add SecurityAlert.Read.All
   az ad app permission add --id $APP_ID \
     --api 00000003-0000-0000-c000-000000000000 \
     --api-permissions 472e4a4d-bb4a-4026-98d1-0b0d74cb74a5=Role

   # Add SecurityIncident.Read.All
   az ad app permission add --id $APP_ID \
     --api 00000003-0000-0000-c000-000000000000 \
     --api-permissions 45cc0394-e837-488b-a098-1918f48d186c=Role

   # Add ThreatHunting.Read.All
   az ad app permission add --id $APP_ID \
     --api 00000003-0000-0000-c000-000000000000 \
     --api-permissions dd98c7f5-2d42-42d3-a0e4-633161547251=Role
   ```

3. **Grant admin consent:**
   ```bash
   az ad app permission admin-consent --id $APP_ID
   ```

4. **Create client secret and login:**
   ```bash
   az ad app credential reset --id $APP_ID --append
   # Save the password from output; store in Key Vault, not in code

   # Authenticate as service principal
   az login --service-principal \
     --username $APP_ID \
     --password YOUR_CLIENT_SECRET \
     --tenant YOUR_TENANT_ID
   ```

### Verification Commands

```bash
# Test: retrieve one alert from alerts_v2
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/security/alerts_v2?\$top=1" \
  --query "value[0].{id:id, title:title, severity:severity, status:status}"
```

```bash
# Test: list one XDR incident
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/security/incidents?\$top=1" \
  --query "value[0].{id:id, name:displayName, status:status}"
```

```bash
# Test: run a simple Advanced Hunting query
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/security/runHuntingQuery" \
  --body '{"query":"DeviceInfo | take 1 | project DeviceName, OSPlatform"}' \
  --query "results"
```

### Common Issues & Fixes

| Issue | Cause | Fix |
|---|---|---|
| `Forbidden` / `403` | Admin consent not granted | Run `az ad app permission admin-consent --id APP_ID`; requires Global Admin or Application Administrator role |
| `InvalidAuthenticationToken` | Logged in as user, not service principal | Use `az login --service-principal` or switch accounts |
| `Authorization_RequestDenied` | Wrong tenant | Verify `az account show --query tenantId` matches the tenant where app is registered |
| `Unauthorized_Tenant` | Multi-tenant app in wrong tenant | Ensure `signInAudience: AzureADMyOrg` and app is registered in the security tenant |
| Empty `value[]` | No alerts in tenant | Expected for clean environments; confirms connectivity is working |
| `ServiceNotEnabled` | XDR not licensed | Verify Microsoft 365 E5 / Microsoft Defender for Endpoint P2 licensing |

### Related Skills

- [Defender XDR Configuration](defender-xdr-configuration.md) — full XDR unified portal setup
- [Defender API Permissions Reference](defender-api-permissions.md) — complete Graph Security permissions reference
- [Microsoft Graph Security](microsoft-graph-security.md) — Graph Security API patterns

---

## Product 3: Microsoft Defender for Cloud

### Required Roles

| Role | Scope | Purpose |
|---|---|---|
| `Security Reader` | Subscription | Read security assessments, recommendations, alerts |
| `Security Admin` | Subscription | Enable Defender plans, configure policies |
| `Contributor` | Subscription | Deploy Defender for Cloud automation resources |

> **Minimum for connectivity test:** `Security Reader` at the subscription scope.

### Setup Steps

1. **Assign Security Reader role:**
   ```bash
   az role assignment create \
     --assignee $(az ad signed-in-user show --query id -o tsv) \
     --role "Security Reader" \
     --scope "/subscriptions/SUB_ID"
   ```

2. **Verify Defender plans are enabled:**
   ```bash
   az security pricing list \
     --subscription SUB_ID \
     --query "[?pricingTier=='Standard'].{name:name, tier:pricingTier}" \
     --output table
   ```

   If the list is empty or all show `Free`, Defender plans are not enabled. Enable via:
   ```bash
   # Enable Defender for Servers (example)
   az security pricing create \
     --name VirtualMachines \
     --tier Standard \
     --subscription SUB_ID
   ```

### Verification Commands

```bash
# Test: list security assessments (recommendations)
az security assessment list \
  --subscription SUB_ID \
  --query "[?properties.status.code=='Unhealthy'] | [0].{name:displayName, status:properties.status.code, severity:properties.metadata.severity}" \
  --output json
```

```bash
# Test: retrieve Defender for Cloud secure score
az security secure-score show \
  --name "ascScore" \
  --subscription SUB_ID \
  --query "{score:properties.score.current, max:properties.score.max, percentage:properties.score.percentage}"
```

```bash
# Test: list active security alerts
az security alert list \
  --subscription SUB_ID \
  --query "[0].{name:alertDisplayName, severity:properties.severity, status:properties.status}" \
  --output json
```

### Common Issues & Fixes

| Issue | Cause | Fix |
|---|---|---|
| `AssessmentListEmpty` | Defender plans not enabled | Enable Standard tier plans via portal or `az security pricing create` |
| `AuthorizationFailed` | Missing Security Reader role | `az role assignment create --role "Security Reader" --scope /subscriptions/SUB_ID` |
| `ResourceGroupNotFound` | Wrong subscription context | Run `az account set --subscription SUB_ID` before commands |
| Secure score returns `null` | No resources or policies evaluated | Wait 24 hours after plan enablement for initial assessment run |
| Alerts list is empty | No active threats detected | Confirm Defender plans are Standard tier; free tier has no alert generation |
| `SubscriptionNotFound` | Service not registered | `az provider register --namespace Microsoft.Security` |

### Related Skills

- [Defender for Cloud Policies](defender-for-cloud-policies.md) — policy initiative configuration and compliance
- [Defender API Permissions Reference](defender-api-permissions.md) — ARM and REST permissions for automation

---

## Product 4: Microsoft Defender for Identity

### Required App Registration Permissions

MDI uses the **Microsoft Graph Security API** identity endpoints:

| Permission | Resource | Type | Purpose |
|---|---|---|---|
| `SecurityIdentitiesHealth.Read.All` | Microsoft Graph | Application | Read MDI health issues and sensor status |
| `SecurityIdentitiesSensors.Read.All` | Microsoft Graph | Application | Read sensor configuration |
| `IdentityRiskEvent.Read.All` | Microsoft Graph | Application | Read identity risk detections |
| `SecurityAlert.Read.All` | Microsoft Graph | Application | Read MDI-generated alerts |

### Setup Steps

1. **Find your MDI workspace name from portal:**
   - Navigate to [security.microsoft.com](https://security.microsoft.com)
   - Settings → Identities → Sensors
   - Note the workspace/service name displayed

2. **Add MDI permissions to your app registration:**
   ```bash
   # SecurityIdentitiesHealth.Read.All
   az ad app permission add --id $APP_ID \
     --api 00000003-0000-0000-c000-000000000000 \
     --api-permissions 3be0012a-cc4e-426e-8a5e-54a84d2e2c43=Role

   # Grant admin consent
   az ad app permission admin-consent --id $APP_ID
   ```

3. **Verify sensor deployment status (portal only initially):**
   - Settings → Identities → Sensors — each domain controller / ADFS server should show `Running`
   - If sensors show `Disconnected` or are missing, MDI API calls will return empty results

### Verification Commands

```bash
# Test: list MDI health issues
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/security/identities/healthIssues" \
  --query "{count:length(value), first:value[0].{id:id, displayName:displayName, severity:severity}}"
```

```bash
# Test: list MDI sensors
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/security/identities/sensors" \
  --query "value[].{name:displayName, status:deploymentStatus, version:version}" \
  --output table
```

```bash
# Test: retrieve identity-related alerts
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/security/alerts_v2?\$filter=serviceSource eq 'microsoftDefenderForIdentity'&\$top=1" \
  --query "value[0].{id:id, title:title, severity:severity}"
```

### Common Issues & Fixes

| Issue | Cause | Fix |
|---|---|---|
| `healthIssues` returns empty `value[]` | No sensors deployed | Deploy MDI sensor on domain controllers; download from portal: Settings → Identities → Sensors |
| `Forbidden` on identity endpoints | Missing `SecurityIdentitiesHealth.Read.All` | Add permission and regrant admin consent |
| Sensors show `Disconnected` | Workspace mismatch or network connectivity | Verify sensor installed on correct DC; check that DC can reach `<workspace>.atp.azure.com:443` |
| `WorkspaceNotFound` | MDI not provisioned | Navigate to security.microsoft.com → Settings → Identities to provision MDI workspace |
| No alerts from MDI | Sensors running but no detections | Normal in clean environments; confirm sensors are `Running` and domain traffic is flowing |
| `TenantNotFound` | App registered in wrong tenant | MDI workspace is tenant-specific; ensure app is registered in the same tenant as MDI |

### Related Skills

- [Defender for Identity](defender-for-identity.md) — MDI configuration, sensor deployment, detection tuning
- [Defender API Permissions Reference](defender-api-permissions.md) — Graph Security identity permissions

---

## Product 5: Microsoft Defender for Endpoint

### Required App Registration Permissions

MDE uses the **WindowsDefenderATP** resource (`fc780465-2017-40d4-a0c5-307022471b92`), separate from Microsoft Graph:

| Permission | Resource | Type | Purpose |
|---|---|---|---|
| `Machine.Read.All` | WindowsDefenderATP | Application | Read machine inventory, tags, groups |
| `Alert.Read.All` | WindowsDefenderATP | Application | Read MDE alerts |
| `AdvancedQuery.Read.All` | WindowsDefenderATP | Application | Run Advanced Hunting queries |
| `Software.Read.All` | WindowsDefenderATP | Application | Read TVM software inventory |
| `Vulnerability.Read.All` | WindowsDefenderATP | Application | Read TVM vulnerabilities |

> **Important:** MDE API permissions are on the `WindowsDefenderATP` resource, NOT on Microsoft Graph. They appear in a separate section in the app registration portal.
>
> See [Defender API Permissions Reference](defender-api-permissions.md) for the complete MDE permissions table.

### Setup Steps

1. **Add MDE API permissions to your app registration:**
   ```bash
   # Machine.Read.All (WindowsDefenderATP)
   az ad app permission add --id $APP_ID \
     --api fc780465-2017-40d4-a0c5-307022471b92 \
     --api-permissions ea8291d3-4b9a-44b5-bc57-1ae1f08f350a=Role

   # Alert.Read.All (WindowsDefenderATP)
   az ad app permission add --id $APP_ID \
     --api fc780465-2017-40d4-a0c5-307022471b92 \
     --api-permissions 93489bf5-0fbc-4f2d-b901-33f2fe08ff05=Role

   # Grant admin consent
   az ad app permission admin-consent --id $APP_ID
   ```

2. **Verify RBAC is configured in the Defender portal:**
   - Navigate to [security.microsoft.com](https://security.microsoft.com)
   - Settings → Endpoints → Roles
   - Confirm your service principal's corresponding group has a role assigned (or Global is enabled)
   - Settings → Endpoints → Advanced features → Enable API — confirm API access is enabled

3. **Authenticate against the MDE API:**
   ```bash
   # The MDE API requires a token for api.securitycenter.microsoft.com
   # az rest handles this automatically when logged in as service principal
   az login --service-principal \
     --username $APP_ID \
     --password YOUR_CLIENT_SECRET \
     --tenant YOUR_TENANT_ID
   ```

### Verification Commands

```bash
# Test: retrieve one machine
az rest --method get \
  --url "https://api.securitycenter.microsoft.com/api/machines?\$top=1" \
  --query "value[0].{id:id, name:computerDnsName, health:healthStatus, os:osPlatform}"
```

```bash
# Test: count machines by health status
az rest --method get \
  --url "https://api.securitycenter.microsoft.com/api/machines" \
  --query "{active:length(value[?healthStatus=='Active']), inactive:length(value[?healthStatus=='Inactive'])}"
```

```bash
# Test: run a simple Advanced Hunting query via MDE API
az rest --method post \
  --url "https://api.securitycenter.microsoft.com/api/advancedqueries/run" \
  --body '{"Query":"DeviceInfo | take 1 | project DeviceName, OSPlatform, LastSeen"}' \
  --query "Results"
```

```bash
# Test: list active MDE alerts
az rest --method get \
  --url "https://api.securitycenter.microsoft.com/api/alerts?\$top=1&\$filter=status+ne+'Resolved'" \
  --query "value[0].{id:id, title:title, severity:severity, status:status}"
```

### Common Issues & Fixes

| Issue | Cause | Fix |
|---|---|---|
| `Unauthorized` / `401` | API access not enabled in Defender portal | Settings → Endpoints → Advanced features → turn on "Microsoft Defender for Endpoint API" |
| `Forbidden` / `403` | RBAC not configured | Settings → Endpoints → Roles → assign a role to your app's service principal group |
| `machines` returns empty `value[]` | No onboarded devices | Onboard devices via Group Policy, Intune, or manual package; check Settings → Endpoints → Onboarding |
| `ResourceNotFound` on API | Wrong API endpoint | MDE API is `api.securitycenter.microsoft.com`, NOT Graph. Confirm URL |
| Permission mismatch | Added Graph permissions instead of MDE | Re-check app registration — MDE permissions are under `APIs my organization uses` → `WindowsDefenderATP` |
| Gov cloud endpoint error | Using commercial URL in GovCloud | GCC High/DoD use `api-gcc.securitycenter.microsoft.us` — see [Gov Cloud Support](gov-cloud-support.md) |

### Related Skills

- [Defender for Endpoint](defender-for-endpoint.md) — MDE onboarding, policy, and detection configuration
- [Defender API Permissions Reference](defender-api-permissions.md) — full WindowsDefenderATP permissions table
- [Defender API Wrapper](defender-api-wrapper.md) — PowerShell wrappers for MDE operations

---

## Product 6: Microsoft Entra ID Protection

### Required App Registration Permissions

Entra ID Protection uses the Microsoft Graph API:

| Permission | Resource | Type | Purpose |
|---|---|---|---|
| `IdentityRiskEvent.Read.All` | Microsoft Graph | Application | Read risk detections |
| `IdentityRiskyUser.Read.All` | Microsoft Graph | Application | Read risky users and risk history |
| `IdentityRiskyServicePrincipal.Read.All` | Microsoft Graph | Application | Read risky service principals (workload identities) |
| `Policy.Read.All` | Microsoft Graph | Application | Read Conditional Access policies and risk policies |

> **License requirement:** `IdentityRiskyUser.Read.All` requires **Microsoft Entra ID P2** (or E5 including P2). Without P2, the API returns `403 Forbidden` even with correct permissions.

### Setup Steps

1. **Verify P2 license is active:**
   ```bash
   # Check organization's subscribed SKUs for P2
   az rest --method get \
     --url "https://graph.microsoft.com/v1.0/subscribedSkus" \
     --query "value[?contains(skuPartNumber, 'AAD_PREMIUM_P2') || contains(skuPartNumber, 'EMSPREMIUM')].{sku:skuPartNumber, enabled:prepaidUnits.enabled, consumed:consumedUnits}"
   ```

2. **Add Identity Protection permissions:**
   ```bash
   # IdentityRiskEvent.Read.All
   az ad app permission add --id $APP_ID \
     --api 00000003-0000-0000-c000-000000000000 \
     --api-permissions 6e472fd1-ad78-48da-a0f0-97ab2c6b769e=Role

   # IdentityRiskyUser.Read.All
   az ad app permission add --id $APP_ID \
     --api 00000003-0000-0000-c000-000000000000 \
     --api-permissions dc5007c0-2d7d-4c42-879c-2dab87571379=Role

   # Grant admin consent
   az ad app permission admin-consent --id $APP_ID
   ```

3. **Verify Identity Protection is configured (portal):**
   - Navigate to [entra.microsoft.com](https://entra.microsoft.com)
   - Protection → Identity Protection
   - Confirm the blade loads and policies are configured (User risk policy, Sign-in risk policy)

### Verification Commands

```bash
# Test: retrieve risky users (requires P2)
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?\$top=1" \
  --query "value[0].{id:id, riskLevel:riskLevel, riskState:riskState, lastUpdated:riskLastUpdatedDateTime}"
```

```bash
# Test: retrieve risk detections
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?\$top=1" \
  --query "value[0].{id:id, type:riskEventType, level:riskLevel, user:userPrincipalName}"
```

```bash
# Test: retrieve risky service principals
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/identityProtection/riskyServicePrincipals?\$top=1" \
  --query "value[0].{id:id, appId:appId, riskLevel:riskLevel, riskState:riskState}"
```

### Common Issues & Fixes

| Issue | Cause | Fix |
|---|---|---|
| `403 Forbidden` on `riskyUsers` | Missing P2 license | Purchase Entra ID P2 or E5 licenses and assign to users; cannot be worked around |
| `403 Forbidden` on `riskDetections` | Permissions not consented | Grant admin consent: `az ad app permission admin-consent --id APP_ID` |
| `riskyUsers` returns empty `value[]` | No risky users detected | Normal in secure environments; verify sign-in risk policy is enabled in Identity Protection |
| `InvalidRequest` | Calling beta endpoint accidentally | Use `/v1.0/`, not `/beta/`, for production. Beta endpoints require different auth flows |
| Identity Protection blade not available | Entra ID P1 or Free tier | P2 is required; upgrade or use delegated permissions with a P2-licensed user |
| `ConditionalAccess_TenantNotRegistered` | Risk policies never configured | Open Identity Protection in portal to initialize; then confirm sign-in risk policy is not `Off` |

### Related Skills

- [Entra ID Protection](entra-id-protection.md) — risk policy configuration and Conditional Access integration
- [Defender API Permissions Reference](defender-api-permissions.md) — Graph Identity permissions reference

---

## Troubleshooting Matrix

Map common error messages directly to solutions.

| Error Message | Product(s) | Root Cause | Fix |
|---|---|---|---|
| `AADSTS700016: Application ... was not found in the directory` | All | App registered in wrong tenant | Ensure app registration is in the same tenant as your security data |
| `AADSTS65001: The user or administrator has not consented to use the application` | All Graph-based | Admin consent not granted | `az ad app permission admin-consent --id APP_ID` (requires Global Admin) |
| `AADSTS50034: The user account ... does not exist in the directory` | All | Signed into wrong account | `az account show` — verify tenant matches |
| `Forbidden (403)` on Graph | XDR / MDI / Entra IDP | Wrong application permissions or no consent | Re-check permissions in Azure portal under App registrations → API permissions; confirm status is "Granted" |
| `Unauthorized (401)` | MDE | az login token doesn't cover MDE API resource | Login as service principal: `az login --service-principal ...` |
| `AuthorizationFailed` | Sentinel / MDC | Missing Azure RBAC role | Assign appropriate role at correct scope (subscription vs. resource group) |
| `ResourceNotFound` | Sentinel | Wrong workspace name or RG | `az monitor log-analytics workspace list --query "[].{name:name,rg:resourceGroup}"` |
| `SubscriptionNotFound` | MDC | Subscription not set | `az account set --subscription SUB_ID` |
| `microsoft.security provider not registered` | MDC | Resource provider missing | `az provider register --namespace Microsoft.Security` |
| `LicenseRequired` / `FeatureNotAvailable` | Entra IDP / MDI | P2 license missing | Assign Entra ID P2 or Microsoft 365 E5 licenses |
| `WorkspaceAlreadyOnboarded` | Sentinel | Sentinel already enabled | Not an error — workspace is ready |
| `api.securitycenter.microsoft.com ... CORS` | MDE | Calling MDE API from browser/wrong client | Use `az rest` or PowerShell; MDE API is not browser-accessible |
| `sensors endpoint returns empty` | MDI | No sensors deployed | Deploy MDI sensor package on domain controllers from security.microsoft.com |
| `healthIssues endpoint returns empty` | MDI | Sensors healthy (no issues) | Not an error — indicates all sensors are running correctly |
| `GatewayTimeout (504)` on large queries | Sentinel / MDE | Query too broad | Add time filter (`ago(1d)`, `ago(7d)`) and `take 100` to limit result size |
| Token expiry errors | All | Long-running session | `az account get-access-token --force-refresh` |

---

## Authentication Summary

| Product | API Target | Auth Method | Token Resource |
|---|---|---|---|
| Microsoft Sentinel | `management.azure.com` | Azure RBAC | ARM (`https://management.azure.com/`) |
| Defender XDR | `graph.microsoft.com` | App + Admin Consent | Graph (`https://graph.microsoft.com/`) |
| Defender for Cloud | `management.azure.com` | Azure RBAC | ARM (`https://management.azure.com/`) |
| Defender for Identity | `graph.microsoft.com` | App + Admin Consent | Graph (`https://graph.microsoft.com/`) |
| Defender for Endpoint | `api.securitycenter.microsoft.com` | App + Admin Consent | MDE (`https://api.securitycenter.microsoft.com/`) |
| Entra ID Protection | `graph.microsoft.com` | App + Admin Consent | Graph (`https://graph.microsoft.com/`) |

**Key insight:** Products on `management.azure.com` (Sentinel, Defender for Cloud) use Azure RBAC — no app registration required for user-based access. Products on `graph.microsoft.com` and `api.securitycenter.microsoft.com` require an app registration with admin-consented application permissions for agent/service use.

---

## Environment Context

Before running connectivity tests, read `.secops/`:

1. **Tenant IDs:** `.secops/identity/tenants.yaml` — verify you're targeting the correct tenant
2. **Subscriptions:** `.secops/environment.yaml` `subscriptions[]` — get the right subscription ID for Sentinel and Defender for Cloud
3. **Workspace:** `.secops/workspaces/*.yaml` — workspace name and resource group for Sentinel queries
4. **Cloud type:** `.secops/environment.yaml` `cloud` field — GCC High/DoD use different API endpoints; see [Gov Cloud Support](gov-cloud-support.md)
5. **App registrations:** `.secops/identity/` — if existing app registrations are documented, use them rather than creating new ones

If `.secops/` doesn't exist, proceed manually but run `secops-squad init --secops` to generate the starter config.

See `.copilot/skills/secops-environment-context.md` for the full discovery flow.

## Related Skills

- [Defender API Permissions Reference](defender-api-permissions.md) — complete permissions matrix, tiered app registration patterns, MSSP/multi-tenant setup
- [Sentinel Workspace Setup](sentinel-workspace-setup.md) — full Sentinel provisioning from scratch
- [Sentinel MCP Server](sentinel-mcp-server.md) — MCP-based KQL execution for agents
- [Defender MCP Server](defender-mcp-server.md) — MCP-based Defender operations for agents
- [Gov Cloud Support](gov-cloud-support.md) — API endpoint overrides for GCC, GCC High, DoD, Azure Government
- [Defender API Wrapper](defender-api-wrapper.md) — production PowerShell wrappers using these connections
