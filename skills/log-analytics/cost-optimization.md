---
title: Cost Optimization
category: log-analytics
difficulty: intermediate
mitre_attack:
  - General  # Operational — cost management enables sustainable security operations
products:
  - Azure Monitor Log Analytics
  - Microsoft Sentinel
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Cost Optimization

## Overview

Log Analytics and Sentinel costs are primarily driven by data ingestion volume. Without active cost management, a Sentinel deployment can quickly become the largest line item in your Azure bill. This skill provides the KQL queries, architectural patterns, and decision frameworks to optimize costs without sacrificing detection coverage.

Use this skill when:
- Your Log Analytics or Sentinel costs are higher than expected
- You need to decide between Analytics and Basic Logs tiers for specific tables
- You want to implement commitment tiers for predictable pricing
- You need to identify and reduce high-volume, low-value data sources
- You are building cost monitoring dashboards

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Log Analytics Reader` for cost analysis queries; `Log Analytics Contributor` for table configuration changes |
| **Tables** | `Usage`, `_BilledSize` (virtual column), `LAQueryLogs` |
| **Knowledge** | Understanding of your data sources and their security value |

## Core Patterns

### Pattern 1 — Cost Analysis: Where Is the Money Going?

Start every cost optimization effort with data. These queries tell you exactly which tables and data types dominate your spending.

```kql
// Top 20 most expensive tables by ingestion volume (last 30 days)
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize
    TotalGB = round(sum(Quantity) / 1024.0, 2),
    DailyAvgGB = round(avg(Quantity) / 1024.0, 3),
    EstMonthlyCostUSD = round(sum(Quantity) / 1024.0 * 2.76, 2)  // ~$2.76/GB Sentinel pay-as-you-go
    by DataType
| order by TotalGB desc
| take 20
```

```kql
// Daily ingestion trend — spot spikes and anomalies
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize DailyGB = round(sum(Quantity) / 1024.0, 2) by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
| render timechart
```

```kql
// Per-table daily ingestion for the top 5 noisiest tables
let TopTables = (
    Usage
    | where TimeGenerated > ago(7d)
    | where IsBillable == true
    | summarize TotalGB = sum(Quantity) / 1024.0 by DataType
    | top 5 by TotalGB
    | project DataType
);
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| where DataType in (TopTables)
| summarize DailyGB = round(sum(Quantity) / 1024.0, 2) by bin(TimeGenerated, 1d), DataType
| render timechart
```

```kql
// Billable size per record — find tables with oversized events
union withsource=TableName *
| where TimeGenerated > ago(1d)
| summarize
    AvgRecordBytes = avg(_BilledSize),
    MaxRecordBytes = max(_BilledSize),
    TotalRecords = count(),
    TotalGB = round(sum(_BilledSize) / (1024.0 * 1024 * 1024), 3)
    by TableName
| extend AvgRecordKB = round(AvgRecordBytes / 1024.0, 1)
| order by TotalGB desc
| take 20
```

---

### Pattern 2 — Data Tier Selection

Sentinel and Log Analytics offer four data tiers for balancing cost, query capability, and retention. Choose the right tier based on how frequently you query data and whether analytics rules reference it.

| Feature | Analytics Logs | Basic Logs | Sentinel data lake | Archive |
|---|---|---|---|---|
| **Ingestion cost** | Full price (~$2.76/GB with Sentinel) | ~$0.88/GB | ~$0.75/GB | N/A (retention-only) |
| **Query cost** | Included in ingestion | $0.006/GB scanned per query | $0.006/GB scanned per query | Per-GB search job or restore |
| **KQL support** | Full KQL | Limited: `where`, `extend`, `project`, `parse`, `summarize` only | Search-only (very limited) | Search jobs or restore required |
| **Analytics rules** | ✅ Supported | ❌ Not supported | ❌ Not supported | ❌ Not supported |
| **Summary rules** | ✅ Source | ✅ Source | ❌ Not supported | ❌ Not supported |
| **Retention** | 30–730 days interactive | 30 days interactive only | Up to 12 years | Up to 12 years |
| **Archive** | ✅ Supported | ✅ Supported | Built-in (long-term by design) | — |
| **Best for** | Security detection, active hunting | Verbose debug logs, network flow data | Long-term retention, compliance, rarely-queried telemetry | Cold-case forensics, compliance archives |

**Tier selection order (modern):** Analytics Logs → Basic Logs → Sentinel data lake → Archive

> **💡 Summary rules** — For high-volume tables (>10 GB/day), consider using Sentinel summary rules to aggregate data into a compact Analytics-tier table, then ingest the raw data into Basic Logs or Sentinel data lake tier for low-cost retention.

```bash
# Convert a high-volume table to Basic Logs
az monitor log-analytics workspace table update \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --name ContainerLogV2 \
  --plan Basic

# Convert back to Analytics if you need full KQL / analytics rules
az monitor log-analytics workspace table update \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --name ContainerLogV2 \
  --plan Analytics
```

**Good candidates for Basic Logs:**

| Table | Reason |
|---|---|
| `ContainerLogV2` | High volume, mostly used for troubleshooting, not detection |
| `AppTraces` | Application trace logs — debug-level verbosity |
| `StorageBlobLogs` | Very high volume data plane logs |

**Good candidates for Sentinel data lake:**

| Table | Reason |
|---|---|
| `AzureNetworkAnalytics_CL` | Network flow logs — massive volume, rarely queried interactively |
| `NWConnectionMonitorPathResult` | Network monitoring operational data — compliance retention only |
| VPC flow logs, DNS logs | Very high volume, long retention requirements, infrequent queries |

**Do NOT use Basic Logs or Sentinel data lake for:**
- Any table used in Sentinel analytics rules (not supported)
- Tables you actively hunt in (query costs add up fast with frequent queries)
- Low-volume tables (savings are negligible, but you lose query flexibility)

---

### Pattern 3 — Commitment Tiers

Commitment tiers provide discounted pricing when you commit to a minimum daily ingestion volume. The more you commit, the bigger the discount.

| Commitment Tier | Effective Price per GB (Sentinel) | Discount vs Pay-as-you-go |
|---|---|---|
| Pay-as-you-go | ~$2.76/GB | — |
| 100 GB/day | ~$2.12/GB | ~23% |
| 200 GB/day | ~$1.96/GB | ~29% |
| 300 GB/day | ~$1.84/GB | ~33% |
| 400 GB/day | ~$1.76/GB | ~36% |
| 500 GB/day | ~$1.68/GB | ~39% |
| 1000 GB/day | ~$1.53/GB | ~45% |
| 2000 GB/day | ~$1.42/GB | ~49% |
| 5000 GB/day | ~$1.30/GB | ~53% |

```kql
// Calculate your average daily ingestion to determine optimal commitment tier
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize DailyGB = sum(Quantity) / 1024.0 by bin(TimeGenerated, 1d)
| summarize
    AvgDailyGB = round(avg(DailyGB), 1),
    P50DailyGB = round(percentile(DailyGB, 50), 1),
    P90DailyGB = round(percentile(DailyGB, 90), 1),
    P95DailyGB = round(percentile(DailyGB, 95), 1),
    MinDailyGB = round(min(DailyGB), 1),
    MaxDailyGB = round(max(DailyGB), 1)
```

**Commitment tier selection rule:** Choose the tier closest to your **P50 daily ingestion** without going above it. You pay the commitment price for all data up to the tier, and overage at the commitment rate (not pay-as-you-go).

```bash
# Set commitment tier on the workspace
az monitor log-analytics workspace update \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --set sku.name=CapacityReservation \
  --set sku.capacityReservationLevel=200
```

---

### Pattern 4 — Data Filtering at Ingestion (DCR Transforms)

The most powerful cost lever: prevent low-value data from being ingested at all. DCR transforms use KQL to filter, project, and transform data before it's stored and billed.

```bicep
// Bicep: DCR transform to filter noisy SecurityEvent data
// Drop event IDs that generate high volume with low security value
resource dcrSecurityEventFilter 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: 'dcr-security-event-filter'
  location: resourceGroup().location
  properties: {
    dataSources: {
      windowsEventLogs: [
        {
          name: 'securityEvents'
          streams: ['Microsoft-SecurityEvent']
          xPathQueries: ['Security!*']
        }
      ]
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
        streams: ['Microsoft-SecurityEvent']
        destinations: ['sentinelWorkspace']
        transformKql: '''
          source
          | where EventID !in (5156, 5157, 5158, 5159, 4688)
          | where not(EventID == 4624 and LogonType == 3 and TargetUserName endswith "$")
        '''
      }
    ]
  }
}
```

**High-impact filtering targets:**

| Table | Filter Target | Typical Savings |
|---|---|---|
| `SecurityEvent` | Event IDs 5156-5159 (Windows Filtering Platform) | 30–60% of SecurityEvent volume |
| `Syslog` | Facility/severity combinations (e.g., drop `info` from `daemon`) | 40–70% |
| `CommonSecurityLog` | Low-severity events from chatty firewalls | 20–50% |
| `SignInLogs` | Non-interactive service account sign-ins (if not needed for detection) | 10–30% |

---

### Pattern 5 — Sampling for High-Volume Tables

When filtering isn't granular enough, sample data to reduce volume while maintaining statistical validity for trend analysis.

```kql
// DCR transform: sample 10% of very high-volume operational events
// Use in a DCR transformKql property
// source
// | where rand() < 0.10 or severity in ("Error", "Critical")  // Keep all errors, sample the rest
```

**Sampling guidelines:**
- Never sample security-critical tables (SecurityEvent, SignInLogs, AuditLogs)
- Sampling works well for operational/performance data (Perf, InsightsMetrics)
- Always keep 100% of high-severity events even in sampled tables
- Document sampling rates for compliance and audit purposes

---

### Pattern 6 — Workspace and Table Retention Cost Impact

Retention costs compound. Every extra day of interactive retention multiplies your storage bill.

```kql
// Current retention configuration and estimated storage cost per table
// Run in Azure Resource Graph Explorer
resources
| where type == "microsoft.operationalinsights/workspaces/tables"
| extend
    WorkspaceName = tostring(split(id, '/')[8]),
    TableName = name,
    RetentionDays = toint(properties.retentionInDays),
    TotalRetentionDays = toint(properties.totalRetentionInDays),
    Plan = tostring(properties.plan)
| where RetentionDays > 90
| project WorkspaceName, TableName, Plan, RetentionDays, TotalRetentionDays
| order by RetentionDays desc
```

```kql
// Estimate storage costs: which tables are consuming the most stored data?
Usage
| where TimeGenerated > ago(1d)
| where IsBillable == true
| summarize DailyGB = sum(Quantity) / 1024.0 by DataType
| extend
    Est30DayStorageGB = round(DailyGB * 30, 1),
    Est90DayStorageGB = round(DailyGB * 90, 1),
    Est365DayStorageGB = round(DailyGB * 365, 1)
| order by DailyGB desc
| take 15
```

## Best Practices

1. **Measure before you cut** — Run the cost analysis queries above before making any changes; understand your baseline
2. **Start with DCR filtering** — Filtering at ingestion is free and permanent; it's the highest-ROI cost lever
3. **Use Basic Logs strategically** — Convert tables only after confirming they're not used in analytics rules or active hunts
4. **Review commitment tiers quarterly** — Ingestion patterns change as connectors are added/removed
5. **Set up cost alerts** — Azure Cost Management alerts trigger before budget overruns
6. **Tag data sources to cost centers** — Use resource tags to attribute ingestion costs to business units
7. **Don't sacrifice detection for cost** — A $5,000/month cost saving means nothing if it blinds you to a breach

## Cost Implications

This entire skill is about cost. Key numbers to remember:
- **Sentinel ingestion**: ~$2.76/GB pay-as-you-go (includes Log Analytics + Sentinel analytics)
- **Basic Logs**: ~$0.88/GB ingestion + $0.006/GB per query scan
- **Sentinel data lake**: ~$0.75/GB ingestion + $0.006/GB per query scan (long-term, low-cost tier)
- **Archive storage**: ~$0.02/GB/month
- **Interactive retention beyond 90 days**: ~$0.10/GB/month
- **Commitment tier discount**: 23–53% depending on tier

## Related Skills

- **[Retention & Archive](retention-archive.md)** — Archive tier strategy for long-term cost reduction.
- **[Custom Tables & DCR](custom-tables-dcr.md)** — DCR transforms for ingestion-time filtering.
- **[Workspace Architecture](workspace-architecture.md)** — Multi-workspace impacts on commitment tier pooling.
- **[Data Connectors Setup](data-connectors-setup.md)** — Connector volume drives cost; monitor connector health.
- **[Detection Tuning](../kql/detection-tuning.md)** — Tuning noisy detections reduces alert volume and investigation cost.

## Environment Context

Before executing this skill, check the customer's `.secops/` knowledge framework:

1. **Data location:** Read `.secops/data-sources/data-source-map.yaml` — tables may be in Sentinel, ADX, or external sources
2. **Active migrations:** Read `.secops/data-sources/migrations.yaml` — data may be moving between locations
3. **Workspace config:** Read `.secops/workspaces/` — know the workspace ID, tier, retention, and naming conventions
4. **Compliance:** Read `.secops/compliance/requirements.yaml` — respect data residency and regulatory constraints

If `.secops/` doesn't exist, proceed with defaults but suggest `secops-squad init --secops`.

See `.copilot/skills/secops-environment-context.md` for the full discovery flow.
