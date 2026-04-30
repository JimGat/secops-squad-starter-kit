---
title: Retention & Archive
category: log-analytics
difficulty: intermediate
mitre_attack:
  - General  # Evidence preservation — applies to forensics and compliance
products:
  - Azure Monitor Log Analytics
  - Microsoft Sentinel
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Retention & Archive

## Overview

Log Analytics offers two retention tiers — interactive and archive — that together support up to 12 years of data retention. The right retention strategy balances investigation speed, compliance obligations, and cost. Security teams need fast access to recent data for active hunting, while compliance teams require long-term storage for audit and forensic evidence.

Use this skill when:
- You need to define per-table retention policies based on security value vs. cost
- You are implementing long-term archival for compliance (SOX, HIPAA, PCI-DSS, GDPR)
- You need to restore archived data for a forensic investigation
- You are optimizing costs by moving infrequently-queried data to the archive tier

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Log Analytics Contributor` for retention configuration |
| **Workspace** | Log Analytics workspace (Sentinel optional) |
| **Knowledge** | Understanding of your organization's data retention requirements |

## Core Patterns

### Pattern 1 — Retention Tier Comparison

| Feature | Interactive Retention | Archive Tier |
|---|---|---|
| **Retention period** | 30 – 730 days (default: 30, Sentinel tables: 90 free) | Up to 12 years total (interactive + archive) |
| **Query access** | Full KQL — instant, interactive queries | Search jobs or restore required before querying |
| **Query latency** | Seconds to minutes | Search jobs: minutes to hours; Restore: minutes |
| **Cost per GB/month** | Higher (included in analytics ingestion price for first 90 days with Sentinel) | ~$0.02/GB/month (significantly cheaper) |
| **Best for** | Active hunting, detection, investigation | Compliance, audit, cold-case forensics |

---

### Pattern 2 — Configuring Per-Table Retention

Different tables have different security value. Set aggressive retention on high-value tables, minimal retention on noisy operational tables.

```bash
# Set interactive retention to 180 days for security-critical tables
az monitor log-analytics workspace table update \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --name SecurityEvent \
  --retention-time 180 \
  --total-retention-time 730

# Set shorter retention for noisy operational tables
az monitor log-analytics workspace table update \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --name Perf \
  --retention-time 30 \
  --total-retention-time 90

# Set maximum archive for compliance-critical tables
az monitor log-analytics workspace table update \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --name AuditLogs \
  --retention-time 90 \
  --total-retention-time 2555  # ~7 years
```

```kql
// Review current retention settings across all tables
// Run in Azure Resource Graph Explorer
resources
| where type == "microsoft.operationalinsights/workspaces/tables"
| extend
    WorkspaceName = split(id, '/')[8],
    TableName = name,
    RetentionDays = toint(properties.retentionInDays),
    TotalRetentionDays = toint(properties.totalRetentionInDays),
    ArchiveDays = toint(properties.totalRetentionInDays) - toint(properties.retentionInDays),
    Plan = tostring(properties.plan)
| project WorkspaceName, TableName, Plan, RetentionDays, TotalRetentionDays, ArchiveDays
| order by TableName asc
```

**Recommended retention by table category:**

| Table Category | Tables | Interactive | Total (incl. Archive) |
|---|---|---|---|
| Identity (critical) | `SignInLogs`, `AuditLogs`, `AADNonInteractiveUserSignInLogs` | 180 days | 2 years |
| Endpoint (high-value) | `SecurityEvent`, `DeviceProcessEvents`, `DeviceNetworkEvents` | 90 days | 1 year |
| Network (high-volume) | `CommonSecurityLog`, `Syslog`, `AzureNetworkAnalytics_CL` | 90 days | 180 days |
| Cloud audit | `AzureActivity` | 90 days | 2 years |
| Office/collaboration | `OfficeActivity` | 90 days | 1 year |
| Performance/operational | `Perf`, `Heartbeat`, `InsightsMetrics` | 30 days | 90 days |

---

### Pattern 3 — Archive Tier Configuration

Data beyond the interactive retention period automatically moves to the archive tier. You set the total retention time — the difference between total and interactive becomes archive.

```bicep
// Bicep: Configure table retention with archive
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: 'sentinel-central'
}

resource signInLogsTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'SignInLogs'
  properties: {
    retentionInDays: 180          // Interactive — full KQL access
    totalRetentionInDays: 730     // Total — difference (550 days) goes to archive
  }
}

resource securityEventTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'SecurityEvent'
  properties: {
    retentionInDays: 90
    totalRetentionInDays: 365
  }
}
```

---

### Pattern 4 — Search Jobs (Query Archived Data)

Search jobs run asynchronously against archived data and store results in a new table you can then query interactively.

```bash
# Create a search job to find a specific user in archived SignInLogs
az monitor log-analytics workspace table search-job create \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --name "SearchJob_CompromisedUser_20260428" \
  --search-query "SignInLogs | where UserPrincipalName == 'compromised.user@contoso.com'" \
  --start-search-time "2025-10-01T00:00:00Z" \
  --end-search-time "2026-01-01T00:00:00Z" \
  --limit 50000
```

```kql
// After the search job completes, query the results table
// The results table name is: SearchJob_CompromisedUser_20260428_SRCH
SearchJob_CompromisedUser_20260428_SRCH
| summarize
    SignInCount = count(),
    DistinctIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 20),
    Apps = make_set(AppDisplayName, 20)
    by UserPrincipalName, ResultType
| order by SignInCount desc
```

```kql
// Monitor search job status
_LogOperation
| where TimeGenerated > ago(24h)
| where Category == "Search"
| project TimeGenerated, Operation, Detail, Status
| order by TimeGenerated desc
```

---

### Pattern 5 — Restore from Archive

Restore brings archived data back into full interactive access for a specified time range. Use restore for focused forensic investigations when you need full KQL power.

```bash
# Restore SecurityEvent data from archive for a specific time range
az monitor log-analytics workspace table restore create \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --name SecurityEvent \
  --restore-source-table SecurityEvent \
  --start-restore-time "2025-06-15T00:00:00Z" \
  --end-restore-time "2025-06-30T00:00:00Z"
```

**Search job vs. Restore comparison:**

| Feature | Search Job | Restore |
|---|---|---|
| **Purpose** | Find specific records matching a KQL filter | Bring back full table data for a time range |
| **KQL support** | Limited (simple filter expressions) | Full KQL on restored data |
| **Time to results** | Minutes to hours | Minutes (depends on data volume) |
| **Result location** | New `_SRCH` table | New `_RST` table |
| **Result retention** | Configurable | Up to 30 days |
| **Cost** | Per GB scanned | Per GB restored + interactive retention cost |
| **Best for** | Needle-in-haystack searches | Full forensic analysis of a time window |

---

### Pattern 6 — Data Lifecycle Management Strategy

```
┌──────────────────────────────────────────────────────────────────┐
│                     Data Lifecycle Timeline                       │
├──────────┬──────────────┬────────────────┬───────────────────────┤
│  Day 0   │  Day 90      │  Day 730       │  Day 2555 (7 years)   │
│  Ingest  │  Free with   │  Interactive   │  Archive expires      │
│          │  Sentinel    │  retention     │  (if configured)      │
│          │  ends        │  max           │                       │
├──────────┴──────────────┴────────────────┴───────────────────────┤
│ ◄── Interactive (full KQL) ──► ◄── Archive (search/restore) ──► │
│                                                                   │
│ ADX export for >7 year retention ──────────────────────────────► │
└──────────────────────────────────────────────────────────────────┘
```

```kql
// Analyze data age distribution to inform retention policy
Usage
| where TimeGenerated > ago(90d)
| where IsBillable == true
| summarize TotalGB = sum(Quantity) / 1024.0 by DataType
| order by TotalGB desc
| take 20
```

## Best Practices

1. **Match retention to compliance obligations** — Document which regulation requires which retention period for each data type
2. **Use archive tier aggressively** — Data beyond your active hunting window (typically 90 days) belongs in archive
3. **Test search jobs before you need them** — Run a search job during peacetime to understand latency and results format
4. **Export to ADX for >7 year retention** — Log Analytics caps at ~12 years total; for longer requirements, export to Azure Data Explorer
5. **Audit retention settings quarterly** — New tables from new connectors inherit workspace defaults, which may not match your policy
6. **Sentinel's 90-day free retention** — Sentinel-enabled tables get 90 days free interactive retention; factor this into cost calculations

## Cost Implications

| Tier | Cost (approximate) | Notes |
|---|---|---|
| Interactive (first 90 days with Sentinel) | Included in Sentinel per-GB price | Free for Sentinel analytics tables |
| Interactive (beyond 90 days) | ~$0.10/GB/month | Varies by region |
| Archive | ~$0.02/GB/month | 5x cheaper than interactive |
| Search job | Per GB scanned | Charged as data scan; results stored at interactive rate |
| Restore | Per GB restored/day | Charged for restoration and then interactive storage |

**Cost optimization formula:** For a table ingesting 100 GB/day:
- 90 days interactive + 275 days archive = ~$900/month interactive + ~$550/month archive
- vs. 365 days all interactive = ~$3,000/month
- **Savings: ~60%** by using archive tier beyond 90 days

## Related Skills

- **[Cost Optimization](cost-optimization.md)** — Broader cost management strategies including Basic Logs tier and commitment tiers.
- **[ADX Integration](../kql/adx-integration.md)** — Export to Azure Data Explorer for ultra-long-term retention beyond Log Analytics limits.
- **[Purge & Export](purge-and-export.md)** — Data export for external archival and GDPR purge operations.
- **[Workspace Architecture](workspace-architecture.md)** — Workspace topology affects how retention policies are applied.

## Environment Context

Before executing this skill, check the customer's `.secops/` knowledge framework:

1. **Data location:** Read `.secops/data-sources/data-source-map.yaml` — tables may be in Sentinel, ADX, or external sources
2. **Active migrations:** Read `.secops/data-sources/migrations.yaml` — data may be moving between locations
3. **Workspace config:** Read `.secops/workspaces/` — know the workspace ID, tier, retention, and naming conventions
4. **Compliance:** Read `.secops/compliance/requirements.yaml` — respect data residency and regulatory constraints

If `.secops/` doesn't exist, proceed with defaults but suggest `secops-squad init --secops`.

See `.copilot/skills/secops-environment-context.md` for the full discovery flow.
