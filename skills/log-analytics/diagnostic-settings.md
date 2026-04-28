---
title: Diagnostic Settings
category: log-analytics
difficulty: intermediate
mitre_attack:
  - General  # Visibility enablement — foundational for detection coverage
products:
  - Azure Monitor
  - Azure Monitor Log Analytics
  - Microsoft Sentinel
  - Azure Policy
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Diagnostic Settings

## Overview

Diagnostic settings are how Azure resource logs and metrics flow into Log Analytics. Without diagnostic settings, most Azure resource activity is invisible to Sentinel — you see the control plane (AzureActivity) but not the data plane (key vault access, storage blob reads, SQL queries, etc.). Enabling diagnostic settings is the single highest-impact visibility improvement for cloud-native detection.

Use this skill when:
- You need to enable logging for Azure resources (Key Vault, Storage, SQL, App Service, etc.)
- You are deploying diagnostic settings at scale using Azure Policy
- You need to route logs to multiple destinations (Log Analytics + Storage + Event Hub)
- You are auditing which resources have diagnostic settings configured

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Monitoring Contributor` on target resources; `Log Analytics Contributor` on workspace |
| **Workspace** | Log Analytics workspace as log destination |
| **Knowledge** | Understanding of Azure resource types and their log categories |

## Core Patterns

### Pattern 1 — Enabling Diagnostic Settings for Key Vault

Key Vault is one of the most security-critical resources. Without diagnostic settings, you cannot see who accessed secrets, keys, or certificates.

```bash
# Enable all diagnostic log categories for a Key Vault
az monitor diagnostic-settings create \
  --name "keyvault-to-sentinel" \
  --resource "/subscriptions/SUB_ID/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/kv-prod-secrets" \
  --workspace "/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-central" \
  --logs '[
    {"categoryGroup": "allLogs", "enabled": true}
  ]' \
  --metrics '[
    {"category": "AllMetrics", "enabled": true}
  ]'
```

```bicep
// Bicep: Diagnostic settings for Key Vault
param keyVaultName string
param workspaceId string

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'keyvault-to-sentinel'
  scope: keyVault
  properties: {
    workspaceId: workspaceId
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}
```

```kql
// Verify Key Vault diagnostic data is flowing
AzureDiagnostics
| where TimeGenerated > ago(1h)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| summarize
    EventCount = count(),
    Operations = make_set(OperationName, 20)
    by Resource
| order by EventCount desc
```

---

### Pattern 2 — Common Resource Types and Log Categories

Each Azure resource type supports different log categories. Here are the most security-relevant ones.

| Resource Type | Key Log Categories | Sentinel Table |
|---|---|---|
| Key Vault | `AuditEvent` | `AzureDiagnostics` (or resource-specific: `AZKVAuditLogs`) |
| Storage Account | `StorageRead`, `StorageWrite`, `StorageDelete` | `StorageBlobLogs`, `StorageFileLogs` |
| SQL Database | `SQLSecurityAuditEvents`, `AutomaticTuning` | `AzureDiagnostics` |
| App Service | `AppServiceHTTPLogs`, `AppServiceConsoleLogs`, `AppServiceAuditLogs` | `AppServiceHTTPLogs` |
| Firewall | `AZFWApplicationRule`, `AZFWNetworkRule`, `AZFWThreatIntel` | `AZFWNetworkRule`, etc. |
| NSG | `NetworkSecurityGroupEvent`, `NetworkSecurityGroupRuleCounter` | `AzureDiagnostics` |
| Container Registry | `ContainerRegistryRepositoryEvents`, `ContainerRegistryLoginEvents` | `ContainerRegistryRepositoryEvents` |

```bash
# List available diagnostic log categories for a resource
az monitor diagnostic-settings categories list \
  --resource "/subscriptions/SUB_ID/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/stproddata01/blobServices/default" \
  --output table
```

---

### Pattern 3 — Multi-Destination Routing

Route logs to multiple destinations for different purposes: Log Analytics for real-time detection, Storage for long-term compliance, Event Hub for SIEM integration.

```bicep
// Bicep: Route diagnostic logs to Log Analytics + Storage + Event Hub
param storageAccountName string
param keyVaultName string
param workspaceId string
param eventHubAuthRuleId string

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' existing = {
  name: storageAccountName
}

resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'multi-destination-diag'
  scope: keyVault
  properties: {
    workspaceId: workspaceId
    storageAccountId: storageAccount.id
    eventHubAuthorizationRuleId: eventHubAuthRuleId
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}
```

---

### Pattern 4 — At-Scale Deployment with Azure Policy

Manually configuring diagnostic settings on every resource doesn't scale. Use Azure Policy to automatically apply diagnostic settings to all resources of a given type.

```bash
# Assign built-in policy: "Deploy Diagnostic Settings for Key Vault to Log Analytics workspace"
az policy assignment create \
  --name "deploy-diag-keyvault" \
  --display-name "Deploy diagnostic settings for Key Vault" \
  --policy "951af2fa-529b-416e-ab6e-066fd85ac459" \
  --scope "/subscriptions/SUB_ID" \
  --mi-system-assigned \
  --location eastus2 \
  --params '{
    "logAnalytics": {
      "value": "/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-central"
    },
    "effect": {
      "value": "DeployIfNotExists"
    }
  }'

# Assign managed identity permissions for remediation
az policy assignment identity assign \
  --name "deploy-diag-keyvault" \
  --scope "/subscriptions/SUB_ID" \
  --role "Monitoring Contributor" \
  --identity-scope "/subscriptions/SUB_ID"

# Trigger remediation for existing non-compliant resources
az policy remediation create \
  --name "remediate-keyvault-diag" \
  --policy-assignment "deploy-diag-keyvault" \
  --scope "/subscriptions/SUB_ID"
```

**Common built-in diagnostic policy IDs:**

| Resource Type | Policy Definition ID |
|---|---|
| Key Vault | `951af2fa-529b-416e-ab6e-066fd85ac459` |
| Storage Account (Blob) | `b4fe1a3b-0715-4c6c-a5ea-ffc33cf823cb` |
| SQL Database | `b79fa14e-238a-4c2d-b376-442ce508fc84` |
| Network Security Group | `c9c56c90-7a84-4e1a-8523-63a7ba31227b` |

---

### Pattern 5 — Monitoring Diagnostic Setting Compliance

Audit which resources are missing diagnostic settings — these are your visibility gaps.

```kql
// Find Azure resources WITHOUT diagnostic settings configured
// Run in Azure Resource Graph Explorer
resources
| where type in (
    "microsoft.keyvault/vaults",
    "microsoft.storage/storageaccounts",
    "microsoft.sql/servers/databases",
    "microsoft.web/sites",
    "microsoft.network/networksecuritygroups"
  )
| join kind=leftouter (
    resources
    | where type == "microsoft.insights/diagnosticsettings"
    | extend TargetResourceId = tolower(tostring(split(id, '/providers/Microsoft.Insights/')[0]))
    | project TargetResourceId
  ) on $left.id == $right.TargetResourceId
| where isempty(TargetResourceId)
| project
    ResourceName = name,
    ResourceType = type,
    ResourceGroup = resourceGroup,
    Location = location,
    SubscriptionId = subscriptionId
| order by ResourceType asc, ResourceName asc
```

```bash
# Check Azure Policy compliance for diagnostic settings
az policy state list \
  --policy-assignment "deploy-diag-keyvault" \
  --filter "complianceState eq 'NonCompliant'" \
  --query "[].{Resource:resourceId, State:complianceState}" \
  --output table
```

```kql
// Verify diagnostic data freshness per resource type
AzureDiagnostics
| where TimeGenerated > ago(24h)
| summarize
    LastEvent = max(TimeGenerated),
    EventCount = count()
    by ResourceProvider, ResourceType, Resource
| extend
    HoursSinceLastEvent = datetime_diff('hour', now(), LastEvent),
    Status = iff(datetime_diff('hour', now(), LastEvent) > 4, "⚠️ STALE", "✅ OK")
| order by HoursSinceLastEvent desc
```

## Best Practices

1. **Use Azure Policy for enforcement** — Manual diagnostic settings will drift; policy ensures every new resource gets configured automatically
2. **Prefer resource-specific tables** — When available (e.g., `AZKVAuditLogs` vs. `AzureDiagnostics`), resource-specific tables are cheaper to query and have better schema
3. **Enable `allLogs` category group** — Don't cherry-pick log categories unless you have a clear cost reason; missing a category creates a detection gap
4. **Audit regularly** — Run the Resource Graph compliance query monthly to catch resources deployed outside of policy scope
5. **Test in non-production first** — Some log categories (like Storage data plane logs) can be extremely high volume; test in dev before enabling in production
6. **Document routing decisions** — Record why each resource type routes to which destinations in your architecture documentation

## Cost Implications

| Consideration | Impact |
|---|---|
| Storage data plane logs | Can be the highest-volume diagnostic source (100s of GB/day for busy storage accounts) |
| `allLogs` vs. specific categories | `allLogs` maximizes coverage but may include low-value categories |
| Multi-destination routing | Each destination incurs its own cost — Log Analytics ingestion + Storage write + Event Hub throughput |
| Resource-specific vs. AzureDiagnostics | Resource-specific tables often have lower ingestion cost due to better compression and schema |
| Policy remediation | One-time cost to backfill diagnostic settings on existing resources; no ongoing policy cost |

## Related Skills

- **[Data Connectors Setup](data-connectors-setup.md)** — Broader connector patterns including non-Azure sources.
- **[Cost Optimization](cost-optimization.md)** — How to manage costs from high-volume diagnostic logs.
- **[Workspace Architecture](workspace-architecture.md)** — Where diagnostic logs route depends on workspace topology.
- **[Custom Tables & DCR](custom-tables-dcr.md)** — DCR transforms can filter diagnostic data at ingestion.
- **[Cloud Security Posture](../kql/cloud-security-posture.md)** — KQL patterns that depend on diagnostic setting data.
