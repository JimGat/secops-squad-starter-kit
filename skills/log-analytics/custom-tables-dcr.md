---
title: Custom Tables & DCR
category: log-analytics
difficulty: advanced
mitre_attack:
  - General  # Custom data source ingestion — foundational capability
products:
  - Azure Monitor Log Analytics
  - Azure Monitor Agent (AMA)
  - Microsoft Sentinel
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Custom Tables & DCR

## Overview

Data Collection Rules (DCRs) are the modern configuration mechanism for controlling what data enters your Log Analytics workspace, how it gets transformed, and where it lands. Combined with custom tables, DCRs enable ingestion of any data source — internal APIs, SaaS platforms, IoT devices, or custom applications — with full control over schema, filtering, enrichment, and parsing at ingestion time.

Use this skill when:
- You need to ingest data from a custom or third-party source into Log Analytics
- You want to transform, filter, or enrich data at ingestion time (before it hits the workspace)
- You are designing custom table schemas for non-standard data sources
- You need to evolve a custom table's schema without breaking existing queries
- You are configuring AMA data collection for specific log types

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Monitoring Contributor` for DCR management; `Log Analytics Contributor` for custom table creation |
| **Workspace** | Log Analytics workspace |
| **Data Collection Endpoint** | Required for REST API ingestion (Logs Ingestion API) |
| **Tools** | Azure CLI 2.50+, Azure Portal, or Bicep/ARM templates |

## Core Patterns

### Pattern 1 — Custom Table Design

Custom tables use the `_CL` suffix (Custom Log) and support a defined set of column types. Design your schema around queryability — think about what you'll `where`, `summarize`, and `join` on.

```bash
# Create a custom table for application security audit events
az monitor log-analytics workspace table create \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --name AppSecurityAudit_CL \
  --columns \
    TimeGenerated=datetime \
    EventType=string \
    UserId=string \
    UserDisplayName=string \
    SourceIP=string \
    Action=string \
    ResourcePath=string \
    ResourceType=string \
    ResultStatus=string \
    ResultCode=int \
    RiskScore=real \
    AdditionalData=dynamic \
  --plan Analytics
```

**Schema design guidelines:**

| Column | Type | Purpose |
|---|---|---|
| `TimeGenerated` | `datetime` | **Required.** Primary time index; must be populated. |
| Entity identifiers | `string` | `UserId`, `SourceIP`, `DeviceId` — join keys for correlation |
| Categorical fields | `string` | `Action`, `EventType`, `ResultStatus` — for `where` and `summarize` |
| Numeric values | `int` / `real` | `ResultCode`, `RiskScore`, `Duration` — for aggregation |
| Complex data | `dynamic` | `AdditionalData` — JSON blobs for variable-schema fields |

**Naming conventions:**
- Table name: PascalCase with `_CL` suffix (e.g., `AppSecurityAudit_CL`)
- Column names: PascalCase, no underscores (e.g., `SourceIP`, not `source_ip`)
- Always include `TimeGenerated` as the first column

---

### Pattern 2 — DCR with Ingestion-Time Transformations

DCR transforms use KQL to modify data at ingestion time — before it's stored and billed. This is where you filter out noise, enrich with computed columns, parse semi-structured data, or map fields to a standard schema.

```bicep
// Bicep: DCR with KQL transformation for custom log ingestion
param workspaceResourceId string
param dceResourceId string

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: 'dcr-app-security-audit'
  location: resourceGroup().location
  properties: {
    dataCollectionEndpointId: dceResourceId
    streamDeclarations: {
      'Custom-RawAppEvents': {
        columns: [
          { name: 'timestamp', type: 'datetime' }
          { name: 'user', type: 'string' }
          { name: 'ip', type: 'string' }
          { name: 'action', type: 'string' }
          { name: 'path', type: 'string' }
          { name: 'status_code', type: 'int' }
          { name: 'raw_data', type: 'string' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspaceResourceId
          name: 'sentinelWorkspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Custom-RawAppEvents']
        destinations: ['sentinelWorkspace']
        outputStream: 'Custom-AppSecurityAudit_CL'
        // KQL transform: rename fields, compute risk score, filter noise
        transformKql: '''
          source
          | where status_code != 200 or action in ("Delete", "ModifyPermission", "Export")
          | extend
              TimeGenerated = timestamp,
              UserId = user,
              SourceIP = ip,
              Action = action,
              ResourcePath = path,
              ResultCode = status_code,
              ResultStatus = case(
                  status_code between (200 .. 299), "Success",
                  status_code between (400 .. 499), "ClientError",
                  status_code >= 500, "ServerError",
                  "Unknown"
              ),
              RiskScore = case(
                  action == "Delete" and status_code == 200, 8.0,
                  action == "ModifyPermission", 7.0,
                  action == "Export", 6.0,
                  status_code >= 500, 5.0,
                  1.0
              ),
              AdditionalData = parse_json(raw_data)
          | project
              TimeGenerated, UserId, SourceIP, Action, ResourcePath,
              ResultCode, ResultStatus, RiskScore, AdditionalData
        '''
      }
    ]
  }
}
```

**Transform capabilities:**

| Capability | KQL Example | Use Case |
|---|---|---|
| **Filtering** | `where severity != "Informational"` | Drop noisy events before billing |
| **Field mapping** | `extend TimeGenerated = timestamp` | Map source fields to standard schema |
| **Enrichment** | `extend GeoInfo = geo_info_from_ip_address(ip)` | Add computed columns at ingestion |
| **Parsing** | `parse RawData with * "user=" UserId:string " "` | Extract structured fields from raw text |
| **Aggregation** | Not supported | Use analytics rules post-ingestion instead |
| **Lookup/join** | Not supported | Use watchlists or analytics rules post-ingestion |

---

### Pattern 3 — Data Collection Endpoint (DCE) Setup

Every REST API ingestion path requires a Data Collection Endpoint. The DCE provides the ingestion URL that external systems POST data to.

```bash
# Create a Data Collection Endpoint
az monitor data-collection endpoint create \
  --name dce-custom-ingestion \
  --resource-group rg-sentinel \
  --location eastus2 \
  --public-network-access Enabled

# Get the DCE ingestion endpoint URL
az monitor data-collection endpoint show \
  --name dce-custom-ingestion \
  --resource-group rg-sentinel \
  --query "logsIngestion.endpoint" \
  --output tsv
```

```bicep
// Bicep: Data Collection Endpoint
resource dce 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: 'dce-custom-ingestion'
  location: resourceGroup().location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

output dceEndpoint string = dce.properties.logsIngestion.endpoint
output dceResourceId string = dce.id
```

---

### Pattern 4 — DCR Association for AMA-Based Collection

When using Azure Monitor Agent, DCRs must be associated with the monitored resources. A DCR Association links a DCR to a VM or VMSS.

```bash
# Associate a DCR with a VM (AMA must be installed)
az monitor data-collection rule association create \
  --name "assoc-syslog-collection" \
  --resource "/subscriptions/SUB_ID/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-app-server" \
  --rule-id "/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.Insights/dataCollectionRules/dcr-syslog-collection"

# List all DCR associations for a VM
az monitor data-collection rule association list \
  --resource "/subscriptions/SUB_ID/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-app-server" \
  --output table
```

```bicep
// Bicep: DCR Association for a VM
param vmResourceId string
param dcrResourceId string

resource dcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2023-03-11' = {
  name: 'assoc-syslog-collection'
  scope: resourceId('Microsoft.Compute/virtualMachines', last(split(vmResourceId, '/')))
  properties: {
    dataCollectionRuleId: dcrResourceId
  }
}
```

---

### Pattern 5 — Schema Evolution and Management

Custom table schemas will evolve as you add new fields. Log Analytics supports additive schema changes — you can add columns but cannot remove or rename existing ones.

```bash
# Add a new column to an existing custom table
az monitor log-analytics workspace table update \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --name AppSecurityAudit_CL \
  --columns \
    TimeGenerated=datetime \
    EventType=string \
    UserId=string \
    UserDisplayName=string \
    SourceIP=string \
    Action=string \
    ResourcePath=string \
    ResourceType=string \
    ResultStatus=string \
    ResultCode=int \
    RiskScore=real \
    AdditionalData=dynamic \
    ThreatIntelMatch=bool \
    GeoLocation=string
```

**Schema evolution rules:**

| Operation | Supported | Notes |
|---|---|---|
| Add new column | ✅ Yes | Existing rows will have `null` for the new column |
| Remove column | ❌ No | You can stop populating it; it stays in schema |
| Rename column | ❌ No | Add new column + update DCR transform + deprecate old column |
| Change column type | ❌ No | Add new column with desired type; stop populating old one |
| Change table plan | ✅ Yes | Can switch between Analytics and Basic Logs |

```kql
// Audit custom table schema and usage
Usage
| where TimeGenerated > ago(30d)
| where DataType endswith "_CL"
| summarize
    TotalGB = round(sum(Quantity) / 1024.0, 2),
    DailyAvgGB = round(avg(Quantity) / 1024.0, 3),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DataType
| order by TotalGB desc
```

## Best Practices

1. **Design schemas for queryability** — Put frequently filtered/grouped fields as top-level typed columns, not buried in `dynamic` blobs
2. **Use `dynamic` for variable data** — Fields that change per event type belong in a `dynamic` column; parse them at query time
3. **Filter at ingestion** — DCR transforms that drop unneeded events save money permanently; every byte not ingested is never billed
4. **Version your DCR transforms** — Keep transform KQL in source control alongside your Bicep/ARM templates
5. **Test transforms in Log Analytics** — Write and validate your transform KQL as a query before embedding it in a DCR
6. **Plan for schema evolution** — Use additive-only changes; document deprecated columns in your schema registry

## Cost Implications

| Factor | Impact |
|---|---|
| DCR transform filtering | Directly reduces ingestion cost — filtered events are never billed |
| Custom table plan (Analytics vs Basic) | Basic Logs is ~67% cheaper but limits query capabilities |
| Schema bloat | Wide tables with many unused columns increase storage; use `dynamic` for sparse fields |
| DCE costs | No cost for the DCE itself; you pay for data ingested through it |
| Transform compute | No additional cost — KQL transforms are included in ingestion pricing |

## Related Skills

- **[Data Connectors Setup](data-connectors-setup.md)** — Connector patterns that use DCRs for data collection.
- **[Cost Optimization](cost-optimization.md)** — Using DCR transforms and Basic Logs tier to reduce costs.
- **[Diagnostic Settings](diagnostic-settings.md)** — Azure resource diagnostic logs also flow through DCR-like pipelines.
- **[Retention & Archive](retention-archive.md)** — Retention policies apply per-table, including custom tables.
