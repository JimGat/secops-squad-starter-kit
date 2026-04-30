---
title: Migration from Sentinel
category: Azure Data Explorer
difficulty: advanced
mitre_attack:
  - General  # Operational — platform migration and cost optimization
products:
  - Azure Data Explorer
  - Microsoft Sentinel
  - Azure Monitor Log Analytics
  - Azure Event Hubs
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Migration from Sentinel

## Overview

Not all security data belongs in Sentinel. Sentinel excels at real-time detection, incident management, and SOAR integration — but at $2.76/GB ingestion, storing high-volume or long-retention data there is cost-prohibitive. ADX offers 5–10x cheaper storage with the same KQL query language, making it the natural second tier for a mature security data lake. This skill covers when to migrate, how to run side-by-side, and the proxy functions that let analysts work seamlessly across both platforms.

Use this skill when:
- Your Sentinel bill is dominated by a few high-volume, low-alert-value data sources
- You need to retain data beyond Log Analytics limits (or beyond what is affordable there)
- You want to keep data in KQL-queryable form but do not need Sentinel analytics rules on it
- You are building a side-by-side architecture where Sentinel handles detection and ADX handles investigation
- You need a cost comparison framework to justify the migration to leadership

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Log Analytics Contributor` on the workspace; `Database Admin` on the ADX database; `Contributor` on Event Hub namespace |
| **Infrastructure** | ADX cluster (see [Cluster Architecture](cluster-architecture.md)), Event Hub namespace for data export |
| **Knowledge** | Understanding of which Sentinel tables drive your analytics rules vs. which are query-only |

## Core Patterns

### Pattern 1 — Decision Framework: What Stays in Sentinel vs. Moves to ADX

Not everything should move. The decision depends on whether Sentinel analytics rules, SOAR playbooks, or UEBA touch the data.

```kql
// Step 1: Identify your highest-volume tables and their detection coverage
// Run this in your Sentinel workspace to find migration candidates
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize DailyGB = round(sum(Quantity) / 1024.0 / 30.0, 2) by DataType
| join kind=leftouter (
    // Count analytics rules that reference each table
    SentinelAudit
    | where TimeGenerated > ago(30d)
    | where SentinelResourceType == "Analytic Rule"
    | distinct RuleName = SentinelResourceName
    | extend Tables = extract_all(@"(\w+Table|\w+Events|\w+Logs)", tostring(RuleName))
    | mv-expand Tables to typeof(string)
    | summarize RuleCount = dcount(RuleName) by DataType = Tables
) on DataType
| extend
    RuleCount = coalesce(RuleCount, 0),
    EstimatedMonthlyCostSentinel = round(DailyGB * 30 * 2.76, 0),
    EstimatedMonthlyCostADX = round(DailyGB * 30 * 0.25, 0),
    MonthlySavings = round(DailyGB * 30 * 2.51, 0)
| extend Recommendation = case(
    RuleCount > 5, "Keep in Sentinel — heavily referenced by detections",
    RuleCount > 0 and DailyGB < 1, "Keep in Sentinel — low volume, not worth migrating",
    DailyGB > 5 and RuleCount == 0, "Strong ADX candidate — high volume, no detections",
    DailyGB > 1 and RuleCount <= 2, "Consider ADX — moderate volume, few detections",
    "Evaluate case-by-case")
| project DataType, DailyGB, RuleCount, EstimatedMonthlyCostSentinel,
    EstimatedMonthlyCostADX, MonthlySavings, Recommendation
| order by DailyGB desc
```

**Migration decision matrix:**

| Data Characteristic | Sentinel | ADX | Notes |
|---|---|---|---|
| Triggers analytics rules | ✅ Keep | ❌ Don't move | Rules need interactive retention |
| Referenced by SOAR playbooks | ✅ Keep | ❌ Don't move | Logic Apps query Sentinel tables |
| UEBA baseline data | ✅ Keep | ⚠️ After profiling | UEBA needs recent data in Sentinel |
| > 5 GB/day, query-only | ❌ Expensive | ✅ Move | Biggest cost savings |
| Network flow / DNS / DHCP | ❌ Very expensive | ✅ Move | Classic ADX candidates |
| Compliance / audit (long retention) | ❌ Expensive at 7 years | ✅ Move | ADX + Archive storage |
| Threat intelligence | ✅ Keep (for TI matching) | ✅ Also export (for historical) | Keep in both |

---

### Pattern 2 — Data Export Pipeline (Sentinel → Event Hub → ADX)

The standard migration pattern uses Log Analytics data export to stream data to Event Hub, where ADX ingests it in near-real-time.

```bash
# Create Event Hub for each table being migrated
az eventhubs eventhub create \
  --name "networklogs-export" \
  --namespace-name "eh-security-export" \
  --resource-group "rg-adx-security" \
  --partition-count 16 \
  --message-retention 7

# Create data export rule from Log Analytics
az monitor log-analytics workspace data-export create \
  --resource-group "rg-sentinel" \
  --workspace-name "sentinel-central" \
  --name "export-network-to-adx" \
  --tables CommonSecurityLog \
  --destination "/subscriptions/SUB_ID/resourceGroups/rg-adx-security/providers/Microsoft.EventHub/namespaces/eh-security-export"
```

```kql
// Create the landing table in ADX with the same schema
.create table CommonSecurityLog (
    TimeGenerated: datetime,
    DeviceVendor: string,
    DeviceProduct: string,
    DeviceAction: string,
    SourceIP: string,
    DestinationIP: string,
    SourcePort: int,
    DestinationPort: int,
    Protocol: string,
    SentBytes: long,
    ReceivedBytes: long,
    Activity: string,
    Message: string,
    DeviceCustomString1: string,
    DeviceCustomString2: string
)

// Create ingestion mapping for the exported data
.create table CommonSecurityLog ingestion json mapping 'CSLMapping'
    '[{"column":"TimeGenerated","path":"$.TimeGenerated","datatype":"datetime"},'
    '{"column":"DeviceVendor","path":"$.DeviceVendor","datatype":"string"},'
    '{"column":"DeviceProduct","path":"$.DeviceProduct","datatype":"string"},'
    '{"column":"DeviceAction","path":"$.DeviceAction","datatype":"string"},'
    '{"column":"SourceIP","path":"$.SourceIP","datatype":"string"},'
    '{"column":"DestinationIP","path":"$.DestinationIP","datatype":"string"},'
    '{"column":"SourcePort","path":"$.SourcePort","datatype":"int"},'
    '{"column":"DestinationPort","path":"$.DestinationPort","datatype":"int"},'
    '{"column":"Protocol","path":"$.Protocol","datatype":"string"},'
    '{"column":"SentBytes","path":"$.SentBytes","datatype":"long"},'
    '{"column":"ReceivedBytes","path":"$.ReceivedBytes","datatype":"long"},'
    '{"column":"Activity","path":"$.Activity","datatype":"string"},'
    '{"column":"Message","path":"$.Message","datatype":"string"},'
    '{"column":"DeviceCustomString1","path":"$.DeviceCustomString1","datatype":"string"},'
    '{"column":"DeviceCustomString2","path":"$.DeviceCustomString2","datatype":"string"}]'
```

---

### Pattern 3 — Proxy Functions for Seamless Cross-Platform Queries

Create proxy functions in your ADX database that let analysts use the same table names whether querying Sentinel or ADX. Proxy functions also enable ADX-to-Sentinel queries using the `adx()` function.

```kql
// ADX proxy function: query Sentinel workspace from ADX for recent data
// Analysts call SecurityEvent_All() and get unified results
.create-or-alter function with (docstring = "Unified SecurityEvent: ADX historical + Sentinel recent", folder = "ProxyFunctions")
    SecurityEvent_All(LookbackDays: int = 90) {
    let ADXData = (
        SecurityEvent
        | where TimeGenerated > ago(totimespan(strcat(tostring(LookbackDays), "d")))
    );
    let SentinelData = (
        cluster('https://ade.loganalytics.io/subscriptions/SUB_ID/resourcegroups/rg-sentinel/providers/microsoft.operationalinsights/workspaces/sentinel-central')
            .database('sentinel-central').SecurityEvent
        | where TimeGenerated > ago(7d)
    );
    union ADXData, SentinelData
    | summarize arg_max(TimeGenerated, *) by Computer, EventID, CorrelationId
}
```

```kql
// In Log Analytics: query ADX from Sentinel using adx() proxy
// Analysts in Sentinel can seamlessly access historical ADX data
let RecentData = (
    CommonSecurityLog
    | where TimeGenerated > ago(7d)
    | where DeviceAction == "Deny"
    | project TimeGenerated, SourceIP, DestinationIP, DestinationPort, Protocol
);
let HistoricalData = (
    adx('https://securityadx.eastus.kusto.windows.net/SecurityLogs').CommonSecurityLog
    | where TimeGenerated between (ago(365d) .. ago(7d))
    | where DeviceAction == "Deny"
    | project TimeGenerated, SourceIP, DestinationIP, DestinationPort, Protocol
);
union RecentData, HistoricalData
| where SourceIP == "198.51.100.42"
| summarize ConnectionCount = count(), DistinctPorts = dcount(DestinationPort)
    by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
```

---

### Pattern 4 — Cost Comparison Framework

Present a clear cost comparison to justify the migration to leadership.

```kql
// Generate a per-table cost comparison report
// Run in Sentinel workspace — outputs data for executive presentation
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize MonthlyGB = round(sum(Quantity) / 1024.0, 1) by DataType
| extend
    SentinelMonthly = round(MonthlyGB * 2.76, 0),
    ADXMonthly = round(MonthlyGB * 0.25, 0),
    MonthlySavings = round(MonthlyGB * 2.51, 0),
    AnnualSavings = round(MonthlyGB * 2.51 * 12, 0)
| where MonthlyGB > 10  // Only show tables worth migrating
| project DataType, MonthlyGB,
    SentinelCost = strcat("$", tostring(SentinelMonthly)),
    ADXCost = strcat("$", tostring(ADXMonthly)),
    MonthlySavings = strcat("$", tostring(MonthlySavings)),
    AnnualSavings = strcat("$", tostring(AnnualSavings))
| order by MonthlyGB desc
```

**Cost comparison reference (per GB/month):**

| Cost Component | Sentinel (Pay-as-you-go) | ADX (estimated) | Difference |
|---|---|---|---|
| Ingestion | $2.76/GB | ~$0.10–0.25/GB (compute amortized) | 10–27x cheaper |
| Interactive retention (90d) | Included | Included (hot cache) | Parity |
| Archive retention (1–7y) | $0.02/GB/month | $0.002–0.01/GB/month (Azure Storage) | 2–10x cheaper |
| Query cost | Included | Included (cluster compute) | Parity |
| Analytics rules | Included | N/A — rules stay in Sentinel | Sentinel-only |

---

### Pattern 5 — Migration Validation and Completeness Monitoring

After migration, validate that ADX has complete data and no pipeline gaps exist.

```kql
// Data completeness check: compare Sentinel vs ADX record counts
// Run the Sentinel query first, then compare with the ADX query
// Sentinel side (run in Log Analytics):
// CommonSecurityLog | where TimeGenerated > ago(1h) | summarize SentinelCount = count()
// ADX side:
CommonSecurityLog
| where TimeGenerated > ago(1h)
| summarize ADXCount = count()
| extend ExpectedSentinelCount = 0  // Fill in from Sentinel query result
| extend CompletenessPercent = round(todouble(ADXCount) / max_of(todouble(ExpectedSentinelCount), 1) * 100, 2)
| extend Status = iff(CompletenessPercent >= 98.0, "Healthy", "Pipeline Gap Detected")
```

```kql
// Monitor ingestion latency: how far behind is ADX relative to the original event time?
CommonSecurityLog
| where TimeGenerated > ago(1h)
| extend IngestionLag = ingestion_time() - TimeGenerated
| summarize
    AvgLagMinutes = round(avg(IngestionLag) / 1m, 1),
    P95LagMinutes = round(percentile(IngestionLag, 95) / 1m, 1),
    MaxLagMinutes = round(max(IngestionLag) / 1m, 1),
    RecordCount = count()
    by bin(TimeGenerated, 5m)
| order by TimeGenerated desc
| take 20
```

## Best Practices

1. **Migrate query-only tables first** — tables with zero analytics rules are zero-risk migrations
2. **Keep the data export running for at least 30 days** before stopping Sentinel ingestion — validates pipeline completeness
3. **Create proxy functions** so analysts do not need to know where data lives
4. **Do not migrate tables referenced by SOAR playbooks** until you have refactored the Logic Apps to query ADX
5. **Monitor data completeness daily** — use a Logic App or Azure Function to alert on gaps > 2%
6. **Keep Sentinel for detection, ADX for investigation** — this side-by-side model is the most common mature architecture

## Cost Implications

| Scenario | Monthly Sentinel Cost | Monthly ADX Cost | Monthly Savings |
|---|---|---|---|
| 10 GB/day network logs | ~$828 | ~$150 | ~$678 (82%) |
| 50 GB/day firewall logs | ~$4,140 | ~$500 | ~$3,640 (88%) |
| 100 GB/day mixed logs | ~$8,280 | ~$1,200 | ~$7,080 (85%) |

*ADX costs include compute (amortized cluster), ingestion, and storage. Actual savings depend on cluster utilization and query load.*

**Break-even analysis:** ADX has a fixed compute cost (cluster nodes). The break-even point is typically around 5–10 GB/day — below that, the cluster cost exceeds Sentinel savings. Above 10 GB/day, savings grow linearly.

## Related Skills

- **[Cluster Architecture](cluster-architecture.md)** — Sizing the ADX cluster for migrated workloads.
- **[Data Ingestion](data-ingestion.md)** — Building the Event Hub pipeline from Sentinel to ADX.
- **[Long-Term Retention](long-term-retention.md)** — Extending retention on migrated data beyond hot cache.
- **[ADX Integration](../kql/adx-integration.md)** — `adx()` proxy for querying ADX data from Sentinel.
- **[Cost Optimization](../log-analytics/cost-optimization.md)** — Log Analytics cost reduction strategies that complement migration.
- **[Retention & Archive](../log-analytics/retention-archive.md)** — Compare Log Analytics archive tier with ADX retention.

## Environment Context

Before executing this skill, check the customer's `.secops/` knowledge framework:

1. **Data location:** Read `.secops/data-sources/data-source-map.yaml` — tables may be in Sentinel, ADX, or external sources
2. **Active migrations:** Read `.secops/data-sources/migrations.yaml` — data may be moving between locations
3. **Workspace config:** Read `.secops/workspaces/` — know the workspace ID, tier, retention, and naming conventions
4. **Compliance:** Read `.secops/compliance/requirements.yaml` — respect data residency and regulatory constraints

If `.secops/` doesn't exist, proceed with defaults but suggest `secops-squad init --secops`.

See `.copilot/skills/secops-environment-context.md` for the full discovery flow.
