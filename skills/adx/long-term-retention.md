---
title: Long-Term Retention
category: Azure Data Explorer
difficulty: advanced
mitre_attack:
  - General  # Evidence preservation — compliance and forensic readiness
products:
  - Azure Data Explorer
  - Azure Blob Storage
  - Microsoft Sentinel
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Long-Term Retention

## Overview

Security regulations (SOX, HIPAA, PCI-DSS, NIST 800-53) require years of log retention. For most organizations, the **Sentinel data lake** tier (formerly "Auxiliary Logs") is the modern default for long-term retention — providing up to 12 years of low-cost storage within Sentinel at ~$0.75/GB ingestion.

ADX long-term retention is the **advanced option** for organizations that need capabilities beyond Sentinel data lake: custom ML/anomaly detection over historical data, cross-organization federation, sub-second queries over petabyte-scale datasets, or retention exceeding 12 years via continuous export to Azure Storage.

> **💡 Decision guidance:** Start with Sentinel data lake for long-term retention. Move to ADX only when you confirm a concrete need that Sentinel data lake cannot satisfy.

Use this skill when:
- Sentinel data lake's 12-year limit or search-only query model is insufficient
- You need sub-second query performance over years of historical data (not just occasional search jobs)
- You need custom ML/anomaly detection over long-term security data
- You want hot/warm/cold tiering with continuous export to Azure Storage for decades-long archival
- You are comparing ADX long-term retention costs against Sentinel data lake and Log Analytics archive tier

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Database Admin` for retention and caching policies; `Storage Blob Data Contributor` on target storage account |
| **Infrastructure** | ADX cluster, Azure Storage account (in same region for cost efficiency) |
| **Knowledge** | Your organization's data retention requirements by regulation and data type |

## Core Patterns

### Pattern 1 — Retention and Caching Policy Hierarchy

ADX separates *retention* (how long data exists) from *caching* (how long data stays on fast SSD). Data beyond the cache period still exists — it just lives in Azure Blob Storage and loads on demand. Data beyond the retention period is permanently deleted.

```kql
// Set database-level defaults: 7-year retention, 30-day hot cache
.alter database SecurityLogs policy retention softdelete = 2555d

.alter database SecurityLogs policy caching hot = 30d

// Override per table based on security value
// High-value identity data: 7 years retention, 90 days hot
.alter table SignInEvents policy retention softdelete = 2555d
.alter table SignInEvents policy caching hot = 90d

// High-volume network data: 2 years retention, 7 days hot
.alter table NetworkEvents policy retention softdelete = 730d
.alter table NetworkEvents policy caching hot = 7d

// Threat intelligence: retain indefinitely (max ADX allows), keep hot
.alter table ThreatIntelligence policy retention softdelete = 36500d
.alter table ThreatIntelligence policy caching hot = 365d

// Verify all retention and cache policies
.show database SecurityLogs policy retention
.show table * policy caching
```

**Retention strategy by compliance framework:**

| Regulation | Required Retention | Recommended ADX Retention | Hot Cache |
|---|---|---|---|
| PCI-DSS | 1 year minimum | 2 years (safety margin) | 30 days |
| HIPAA | 6 years | 7 years | 14 days |
| SOX | 7 years | 7 years | 14 days |
| NIST 800-53 (moderate) | 3 years | 5 years | 30 days |
| GDPR | As short as needed | Per data category | 7 days |
| Internal SOC (no regulation) | 1–2 years | 2 years | 30 days |

---

### Pattern 2 — Continuous Export to Azure Storage

For retention beyond what you want to pay for in ADX, continuously export data to Azure Blob Storage. Exported data is queryable via external tables without re-ingestion.

```kql
// Create a continuous export rule for compliance archival
// Exports SignInEvents to Azure Blob Storage in Parquet format
.create-or-alter continuous-export SignInArchiveExport
    over (SignInEvents)
    to table ExternalSignInArchive
    with (intervalInMinutes=60, forcedLatency=5m, sizeLimit=1073741824)
    <| SignInEvents
    | project TimeGenerated, UserPrincipalName, IPAddress, Location,
        AppDisplayName, ResultType, RiskLevelDuringSignIn, CorrelationId
```

```bash
# Create the target storage account and container for archived data
az storage account create \
  --name "stgsecurityarchive" \
  --resource-group "rg-adx-security" \
  --location "eastus2" \
  --sku Standard_LRS \
  --kind StorageV2 \
  --access-tier Cool \
  --allow-blob-public-access false

az storage container create \
  --name "security-archive" \
  --account-name "stgsecurityarchive" \
  --auth-mode login

# Grant ADX managed identity access to write to the storage account
az role assignment create \
  --assignee-object-id $(az kusto cluster show --name securityadx --resource-group rg-adx-security --query identity.principalId -o tsv) \
  --role "Storage Blob Data Contributor" \
  --scope "/subscriptions/SUB_ID/resourceGroups/rg-adx-security/providers/Microsoft.Storage/storageAccounts/stgsecurityarchive"
```

```kql
// Define the external table pointing to archived data in Azure Storage
.create external table ExternalSignInArchive (
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    Location: string,
    AppDisplayName: string,
    ResultType: int,
    RiskLevelDuringSignIn: string,
    CorrelationId: string
)
kind=storage
partition by (Year: int = startofyear(TimeGenerated), Month: int = getmonth(TimeGenerated))
pathformat = ("year=" Year "/month=" Month)
dataformat=parquet
(
    h@'https://stgsecurityarchive.blob.core.windows.net/security-archive;managed_identity=system'
)

// Monitor continuous export health
.show continuous-export SignInArchiveExport
| project Name, State = CursorReturnedValue, ExportedTo, LastRunTime,
    LastRunResult, ExportedRecordsCount = StartCursor
```

---

### Pattern 3 — Querying Archived Data via External Tables

External tables let analysts query archived data in Azure Storage without loading it back into ADX. Query performance is slower than hot cache but sufficient for compliance audits and cold-case investigations.

```kql
// Query archived sign-in data for a compliance audit
// This reads directly from Azure Blob Storage — no re-ingestion needed
external_table('ExternalSignInArchive')
| where TimeGenerated between (datetime(2024-01-01) .. datetime(2024-12-31))
| where UserPrincipalName =~ "audited.user@contoso.com"
| summarize
    TotalSignIns = count(),
    FailedSignIns = countif(ResultType != 0),
    DistinctIPs = dcount(IPAddress),
    DistinctLocations = dcount(Location)
    by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
```

```kql
// Combine hot data (ADX) with cold data (external table) for full timeline
// Current year from ADX, previous years from archive
let HotData = (
    SignInEvents
    | where TimeGenerated > ago(365d)
    | where UserPrincipalName =~ "incident.user@contoso.com"
    | project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType
);
let ColdData = (
    external_table('ExternalSignInArchive')
    | where TimeGenerated between (datetime(2023-01-01) .. datetime(2025-04-28))
    | where UserPrincipalName =~ "incident.user@contoso.com"
    | project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType
);
union HotData, ColdData
| summarize
    TotalSignIns = count(),
    DistinctIPs = dcount(IPAddress),
    Locations = make_set(Location, 50)
    by bin(TimeGenerated, 30d)
| order by TimeGenerated asc
```

---

### Pattern 4 — Storage Lifecycle Management

Use Azure Storage lifecycle policies to automatically move exported data from Cool to Archive tier for maximum cost savings on multi-year retention.

```bash
# Create lifecycle policy: move data to Archive tier after 180 days, delete after 2555 days (7 years)
az storage account management-policy create \
  --account-name "stgsecurityarchive" \
  --resource-group "rg-adx-security" \
  --policy '{
    "rules": [{
      "enabled": true,
      "name": "security-archive-lifecycle",
      "type": "Lifecycle",
      "definition": {
        "filters": {
          "blobTypes": ["blockBlob"],
          "prefixMatch": ["security-archive/"]
        },
        "actions": {
          "baseBlob": {
            "tierToCool": {"daysAfterModificationGreaterThan": 30},
            "tierToArchive": {"daysAfterModificationGreaterThan": 180},
            "delete": {"daysAfterModificationGreaterThan": 2555}
          }
        }
      }
    }]
  }'
```

**Important:** Blobs in Archive tier cannot be queried directly by ADX external tables. You must rehydrate them first (takes up to 15 hours). For compliance data that may need urgent access, keep it in Cool tier and accept the slightly higher cost.

---

### Pattern 5 — Cost Comparison: ADX vs. Sentinel data lake vs. Log Analytics Retention

```markdown
| Retention Tier | ADX Cost (approx.) | Sentinel data lake (approx.) | Log Analytics Archive (approx.) | Notes |
|---|---|---|---|---|
| Hot cache (< 30d) | Included in compute | N/A | Included in ingestion | ADX: cluster cost; LA: per-GB price |
| Warm (30–90d) | Azure Storage ~$0.018/GB/mo | ~$0.75/GB ingestion (flat) | Included (Sentinel free 90d) | Sentinel data lake: pay at ingestion |
| Cool (90d–2y) | Azure Storage ~$0.01/GB/mo | Included (retention) | Archive tier ~$0.02/GB/mo | Sentinel data lake wins for simplicity |
| Cold archive (2–7y) | Azure Archive ~$0.002/GB/mo | Included (up to 12yr) | Archive tier ~$0.02/GB/mo | Sentinel data lake: no extra storage cost |
| Query (archive) | External table query (sub-second) | Search-only ($0.006/GB scanned) | Search job (slow, per-GB scan) | ADX wins for query performance |
```

**Rule of thumb:**
- **For retention-only (rare queries):** Sentinel data lake is the simplest and most cost-effective option — no cluster to manage, up to 12 years.
- **For active analytics over historical data:** ADX continuous export to Azure Storage + Archive tier provides the best query performance at scale.
- **ADX break-even:** ADX has a fixed compute cost (cluster nodes). The break-even vs. Sentinel data lake is typically around 50+ GB/day with active analytical workloads. Below that, Sentinel data lake is almost always cheaper.

## Best Practices

1. **Set retention policy before ingesting data** — changing retention on existing data does not retroactively delete (soft-delete has grace period)
2. **Use Parquet format for continuous export** — columnar, compressed, and natively queryable by ADX external tables
3. **Partition exports by year/month** — enables partition pruning on time-range queries over archive
4. **Monitor continuous export lag** — if export falls behind, you risk losing data if the source ADX retention expires first
5. **Keep a 30-day overlap** between ADX retention and continuous export — ensures no data gaps during export latency spikes
6. **Use managed identity** for ADX-to-storage authentication — avoid SAS token rotation headaches

## Cost Implications

| Data Volume | 2-Year ADX Only | 2-Year ADX + Archive | Savings |
|---|---|---|---|
| 100 GB/day | ~$2,200/mo compute + storage | ~$1,500/mo (90d hot, export rest) | ~32% |
| 500 GB/day | ~$8,000/mo | ~$5,000/mo | ~37% |
| 1 TB/day | ~$14,000/mo | ~$8,500/mo | ~39% |

*Estimates assume storage-optimized SKUs. Actual costs depend on query load and node count.*

## Related Skills

- **[Cluster Architecture](cluster-architecture.md)** — Cache tier sizing affects how much data stays hot vs. cold.
- **[Retention & Archive](../log-analytics/retention-archive.md)** — The Log Analytics approach to retention — compare and choose.
- **[Cost Optimization](../log-analytics/cost-optimization.md)** — Log Analytics cost strategies that complement ADX retention.
- **[Data Ingestion](data-ingestion.md)** — Continuous export depends on healthy ingestion pipelines.
- **[Migration from Sentinel](migration-from-sentinel.md)** — When to move Sentinel data to ADX for cost-effective long-term retention.
