---
title: Purge & Export
category: log-analytics
difficulty: advanced
mitre_attack:
  - General  # Compliance and evidence management
products:
  - Azure Monitor Log Analytics
  - Microsoft Sentinel
  - Azure Storage (ADLS Gen2)
  - Azure Event Hubs
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Purge & Export

## Overview

Data export and purge are governance capabilities for Log Analytics. Export provides continuous streaming of workspace data to external storage for long-term retention, compliance archival, or integration with external analytics platforms. Purge removes specific records from the workspace to comply with data subject access requests (DSAR) under GDPR, CCPA, or other privacy regulations.

Use this skill when:
- You need to continuously export workspace data to Azure Storage or Event Hub
- You need to set up long-term archival to ADLS Gen2 for data beyond Log Analytics retention limits
- You received a GDPR/CCPA data subject deletion request
- You need to purge PII or sensitive data that was accidentally ingested
- You need to understand purge limitations for compliance planning

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Log Analytics Contributor` for export rules; special `Data Purger` role or workspace-level purge permission for purge operations |
| **Workspace** | Log Analytics workspace |
| **Storage** | Storage Account (ADLS Gen2 recommended) for export; Event Hub for streaming export |
| **Compliance** | Understanding of your organization's data privacy obligations |

## Core Patterns

### Pattern 1 — Continuous Data Export to Storage Account

Data export rules stream data from specific tables to an Azure Storage Account as it arrives. The data is stored in append blobs organized by table and time.

```bash
# Create a data export rule to Storage Account
az monitor log-analytics workspace data-export create \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --name "export-security-events" \
  --destination "/subscriptions/SUB_ID/resourceGroups/rg-storage/providers/Microsoft.Storage/storageAccounts/stsentinelexport" \
  --table-names SecurityEvent SignInLogs AuditLogs AzureActivity \
  --enable true

# List existing export rules
az monitor log-analytics workspace data-export list \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --output table
```

```bicep
// Bicep: Data export rule to Storage Account
param workspaceName string
param storageAccountId string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource dataExport 'Microsoft.OperationalInsights/workspaces/dataExports@2020-08-01' = {
  parent: workspace
  name: 'export-security-events'
  properties: {
    destination: {
      resourceId: storageAccountId
    }
    tableNames: [
      'SecurityEvent'
      'SignInLogs'
      'AuditLogs'
      'AzureActivity'
      'CommonSecurityLog'
    ]
    enable: true
  }
}
```

**Storage layout:** Exported data lands in append blobs at:
```
{StorageAccount}/am-{WorkspaceName}/{TableName}/y={Year}/m={Month}/d={Day}/h={Hour}/m={Minute}/{GUID}.json
```

---

### Pattern 2 — Continuous Data Export to Event Hub

Event Hub export enables real-time streaming to external SIEMs, analytics platforms, or custom processing pipelines.

```bash
# Create a data export rule to Event Hub
az monitor log-analytics workspace data-export create \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --name "export-to-siem" \
  --destination "/subscriptions/SUB_ID/resourceGroups/rg-eventhub/providers/Microsoft.EventHub/namespaces/eh-sentinel-export" \
  --table-names SecurityAlert SecurityIncident \
  --enable true
```

```bicep
// Bicep: Data export to Event Hub
param workspaceName string
param eventHubNamespaceId string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource dataExport 'Microsoft.OperationalInsights/workspaces/dataExports@2020-08-01' = {
  parent: workspace
  name: 'export-alerts-to-siem'
  properties: {
    destination: {
      resourceId: eventHubNamespaceId
    }
    tableNames: [
      'SecurityAlert'
      'SecurityIncident'
    ]
    enable: true
  }
}
```

**Event Hub behavior:**
- One Event Hub is created per exported table (auto-created if it doesn't exist)
- Event Hub name matches the table name (e.g., `SecurityAlert`)
- Data arrives in JSON format, same schema as the Log Analytics table
- Event Hub must be in the same region as the workspace for best performance

---

### Pattern 3 — Long-Term Archival to ADLS Gen2

For data that must be retained beyond Log Analytics limits (>12 years) or needs to be available for external analytics (Synapse, Databricks, ADX), export to ADLS Gen2 with hierarchical namespace enabled.

```bash
# Create ADLS Gen2 storage account with hierarchical namespace
az storage account create \
  --name stsentinelarchive \
  --resource-group rg-storage \
  --location eastus2 \
  --sku Standard_LRS \
  --kind StorageV2 \
  --hns true \
  --min-tls-version TLS1_2

# Create a container for archived logs
az storage fs create \
  --name sentinel-archive \
  --account-name stsentinelarchive

# Set up lifecycle management to tier old data to cool/archive storage
az storage account management-policy create \
  --account-name stsentinelarchive \
  --resource-group rg-storage \
  --policy '{
    "rules": [
      {
        "name": "tier-to-cool-after-90-days",
        "enabled": true,
        "type": "Lifecycle",
        "definition": {
          "filters": {
            "blobTypes": ["appendBlob"],
            "prefixMatch": ["sentinel-archive/"]
          },
          "actions": {
            "baseBlob": {
              "tierToCool": {
                "daysAfterCreationGreaterThan": 90
              },
              "tierToArchive": {
                "daysAfterCreationGreaterThan": 365
              }
            }
          }
        }
      }
    ]
  }'
```

---

### Pattern 4 — Purge API for GDPR/Compliance

The purge API removes specific records from a Log Analytics workspace. This is an irreversible operation designed for privacy compliance — not for general data management.

```bash
# Purge records for a specific user (GDPR right to erasure)
# Requires Data Purger role or Microsoft.OperationalInsights/workspaces/purge/action permission
az rest --method POST \
  --url "https://management.azure.com/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-central/purge?api-version=2020-08-01" \
  --body '{
    "table": "SignInLogs",
    "filters": [
      {
        "column": "UserPrincipalName",
        "operator": "==",
        "value": "user.to.purge@contoso.com"
      }
    ]
  }'
```

```bash
# Check purge operation status
# The POST returns an operation ID in the response header
az rest --method GET \
  --url "https://management.azure.com/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-central/operations/PURGE_OPERATION_ID?api-version=2020-08-01"
```

**Purge API filter operators:**

| Operator | Description | Example |
|---|---|---|
| `==` | Exact match | `UserPrincipalName == "user@contoso.com"` |
| `=~` | Case-insensitive match | `UserPrincipalName =~ "USER@contoso.com"` |
| `in` | Value in list | `UserPrincipalName in ["user1@contoso.com", "user2@contoso.com"]` |
| `>`, `>=`, `<`, `<=` | Comparison | `TimeGenerated >= "2026-01-01T00:00:00Z"` |

---

### Pattern 5 — Purge Limitations and Timing

Purge is not instant and has significant constraints. Plan accordingly.

| Limitation | Detail |
|---|---|
| **Completion time** | Up to 30 days (SLA). Typically completes within 5 days. |
| **Irreversible** | Purged data cannot be recovered. Test with a narrow filter first. |
| **One table at a time** | Each purge request targets one table. Multi-table purge requires multiple requests. |
| **No cascading** | Purging from `SignInLogs` does not purge from `AuditLogs` — submit separate requests. |
| **Exported data unaffected** | Purge does NOT remove data already exported to Storage or Event Hub. |
| **Archive data** | Purge applies to both interactive and archive tiers within the workspace. |
| **Audit trail** | Purge operations are logged in the Azure Activity Log for compliance. |
| **Rate limit** | Maximum 2 purge operations per day per workspace (soft limit — contact support for more). |

```kql
// Audit purge operations (Activity Log)
AzureActivity
| where TimeGenerated > ago(90d)
| where OperationNameValue == "MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/PURGE/ACTION"
| project
    TimeGenerated,
    Caller,
    ActivityStatusValue,
    Properties = parse_json(Properties)
| order by TimeGenerated desc
```

---

### Pattern 6 — Export Monitoring

Monitor export rules to ensure data is flowing to external storage and catch failures early.

```kql
// Monitor data export health via _LogOperation
_LogOperation
| where TimeGenerated > ago(24h)
| where Category == "DataExport"
| summarize
    SuccessCount = countif(Level == "Info"),
    WarningCount = countif(Level == "Warning"),
    ErrorCount = countif(Level == "Error")
    by Operation
| order by ErrorCount desc
```

```bash
# Check export rule status
az monitor log-analytics workspace data-export show \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --name "export-security-events" \
  --query "{Name:name, Enabled:properties.enable, Tables:properties.tableNames, LastModified:properties.lastModifiedDate}" \
  --output table
```

```kql
// Verify exported data volume matches workspace ingestion
// Run this to detect export drift
let WorkspaceVolume = (
    Usage
    | where TimeGenerated > ago(1d)
    | where IsBillable == true
    | where DataType in ("SecurityEvent", "SignInLogs", "AuditLogs")
    | summarize WorkspaceGB = round(sum(Quantity) / 1024.0, 2) by DataType
);
WorkspaceVolume
```

## Best Practices

1. **Use ADLS Gen2 for long-term archival** — Hierarchical namespace provides better query performance with Synapse/Databricks and tiered storage (hot → cool → archive) for cost optimization
2. **Export security-critical tables by default** — Even if you don't plan to query exported data today, having an immutable copy protects against workspace purge or accidental deletion
3. **Test purge with narrow filters** — Always start with the most specific filter possible; purge is irreversible
4. **Document purge requests** — Maintain a log of all purge operations with the legal basis (DSAR reference, ticket number, etc.)
5. **Remember exported data** — Purge does NOT affect already-exported data; you must separately delete from Storage/Event Hub
6. **Assign Data Purger role carefully** — This is a powerful role; assign it only to a dedicated compliance team
7. **Monitor export health daily** — Silent export failures create compliance risk if you're relying on exports for long-term retention

## Cost Implications

| Operation | Cost |
|---|---|
| Data export to Storage | Free (no additional Log Analytics charge); you pay standard Storage costs |
| Data export to Event Hub | Free (no additional Log Analytics charge); you pay standard Event Hub throughput costs |
| ADLS Gen2 hot tier | ~$0.0184/GB/month |
| ADLS Gen2 cool tier | ~$0.01/GB/month |
| ADLS Gen2 archive tier | ~$0.002/GB/month |
| Purge operations | No direct cost; operational overhead for compliance process |
| Storage lifecycle management | Free (policy evaluation); storage tiering saves cost on archived data |

## Related Skills

- **[Retention & Archive](retention-archive.md)** — In-workspace retention and archive tier (complement to external export).
- **[Cost Optimization](cost-optimization.md)** — Export to cheaper storage tiers reduces long-term retention costs.
- **[Workspace RBAC](workspace-rbac.md)** — Data Purger role assignment and access control for purge operations.
- **[ADX Integration](../kql/adx-integration.md)** — ADX as an alternative long-term retention and analytics platform for exported data.
