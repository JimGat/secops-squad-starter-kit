---
title: Data Ingestion
category: Azure Data Explorer
difficulty: advanced
mitre_attack:
  - General  # Foundational — data ingestion underpins all detection and hunting
products:
  - Azure Data Explorer
  - Azure Event Hubs
  - Azure IoT Hub
  - Microsoft Sentinel
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Data Ingestion

## Overview

Getting security data into ADX reliably and efficiently is the foundation of a security data lake. ADX supports multiple ingestion methods — streaming for real-time threat detection, queued (batched) for high-throughput bulk loads, and Event Hub integration for pipeline-based architectures. Each has different latency, throughput, and cost characteristics. The wrong choice can mean missed detections (too slow) or unsustainable costs (too expensive).

Use this skill when:
- You are setting up initial data pipelines from Log Analytics, Event Hubs, or direct sources to ADX
- You need to ingest high-volume security logs (firewall, DNS, NetFlow) at TB/day scale
- You are designing ingestion mappings for JSON, CSV, or multi-line log formats
- You need to tune batching policies for optimal latency vs. throughput trade-offs
- You are building an Event Hub–based pipeline from Sentinel/Log Analytics to ADX

## Prerequisites

| Requirement | Detail |
|---|---|
| **Cluster** | ADX cluster with streaming ingestion enabled (for real-time patterns) |
| **Permissions** | `Database Ingestor` for data ingestion; `Database Admin` for table and policy creation |
| **Products** | Azure Data Explorer; Azure Event Hubs (for pipeline patterns); optionally IoT Hub |
| **Knowledge** | Familiarity with your log source formats (JSON, CEF, CSV, syslog) |

## Core Patterns

### Pattern 1 — Streaming vs. Queued Ingestion

Streaming ingestion provides < 10-second end-to-end latency — critical for real-time security alerting. Queued ingestion batches data for throughput efficiency and is appropriate for bulk historical loads or high-volume sources where seconds of delay are acceptable.

| Feature | Streaming Ingestion | Queued (Batched) Ingestion |
|---|---|---|
| **Latency** | < 10 seconds | 1–5 minutes (tunable via batching policy) |
| **Throughput** | Lower per-node (CPU intensive) | Higher — optimized for bulk |
| **Best for** | Real-time alerts, critical security events | Firewall logs, NetFlow, historical backfill |
| **CPU overhead** | ~2x per ingestion operation | Baseline |
| **Data completeness** | Slightly higher risk of gaps under extreme load | More reliable at very high volumes |

```kql
// Enable streaming ingestion on specific high-priority tables
.alter table SecurityAlert policy streamingingestion enable

// Disable streaming on high-volume, latency-tolerant tables
.alter table NetworkFlow policy streamingingestion disable

// Check current streaming ingestion policy across all tables
.show database SecurityLogs policy streamingingestion
```

---

### Pattern 2 — Event Hub Integration for Sentinel Export

The most common pattern for feeding ADX from Sentinel is Log Analytics data export to Event Hub, then Event Hub data connection to ADX. This creates a near-real-time replica of Sentinel data in ADX.

```bash
# Step 1: Create an Event Hub namespace and hub for security data export
az eventhubs namespace create \
  --name "eh-security-export" \
  --resource-group "rg-adx-security" \
  --location "eastus2" \
  --sku Standard \
  --enable-auto-inflate true \
  --maximum-throughput-units 20

az eventhubs eventhub create \
  --name "securityevent-export" \
  --namespace-name "eh-security-export" \
  --resource-group "rg-adx-security" \
  --partition-count 8 \
  --message-retention 3

# Step 2: Create data export rule from Log Analytics to Event Hub
az monitor log-analytics workspace data-export create \
  --resource-group "rg-sentinel" \
  --workspace-name "sentinel-central" \
  --name "export-security-events" \
  --tables SecurityEvent SignInLogs AuditLogs \
  --destination "/subscriptions/SUB_ID/resourceGroups/rg-adx-security/providers/Microsoft.EventHub/namespaces/eh-security-export"

# Step 3: Create ADX data connection from Event Hub
az kusto data-connection event-hub create \
  --cluster-name "securityadx" \
  --database-name "SecurityLogs" \
  --resource-group "rg-adx-security" \
  --name "eh-securityevent-connection" \
  --event-hub-resource-id "/subscriptions/SUB_ID/resourceGroups/rg-adx-security/providers/Microsoft.EventHub/namespaces/eh-security-export/eventhubs/securityevent-export" \
  --consumer-group "\$Default" \
  --data-format MULTIJSON \
  --table-name SecurityEvent \
  --mapping-rule-name SecurityEventMapping \
  --compression None
```

---

### Pattern 3 — Ingestion Mappings for Security Log Formats

Ingestion mappings transform raw data into structured ADX table columns. Security logs come in diverse formats — JSON (cloud-native), CSV (legacy SIEM exports), and multi-line (stack traces, PowerShell script blocks).

```kql
// JSON mapping for Sentinel SecurityEvent export
.create table SecurityEvent ingestion json mapping 'SecurityEventMapping'
    '[{"column":"TimeGenerated","path":"$.TimeGenerated","datatype":"datetime"},'
    '{"column":"Computer","path":"$.Computer","datatype":"string"},'
    '{"column":"EventID","path":"$.EventID","datatype":"int"},'
    '{"column":"Activity","path":"$.Activity","datatype":"string"},'
    '{"column":"Account","path":"$.Account","datatype":"string"},'
    '{"column":"AccountType","path":"$.AccountType","datatype":"string"},'
    '{"column":"LogonType","path":"$.LogonType","datatype":"int"},'
    '{"column":"SourceIP","path":"$.IpAddress","datatype":"string"},'
    '{"column":"ProcessName","path":"$.Process","datatype":"string"}]'

// CSV mapping for legacy firewall log ingestion
.create table FirewallLogs ingestion csv mapping 'FirewallCSVMapping'
    '[{"column":"Timestamp","ordinal":0,"datatype":"datetime"},'
    '{"column":"SourceIP","ordinal":1,"datatype":"string"},'
    '{"column":"DestinationIP","ordinal":2,"datatype":"string"},'
    '{"column":"SourcePort","ordinal":3,"datatype":"int"},'
    '{"column":"DestinationPort","ordinal":4,"datatype":"int"},'
    '{"column":"Protocol","ordinal":5,"datatype":"string"},'
    '{"column":"Action","ordinal":6,"datatype":"string"},'
    '{"column":"BytesSent","ordinal":7,"datatype":"long"},'
    '{"column":"BytesReceived","ordinal":8,"datatype":"long"}]'
```

```kql
// Ingest a sample file using the mapping (one-time or backfill)
.ingest into table SecurityEvent (
    'https://storageaccount.blob.core.windows.net/raw-logs/securityevent-20260101.json.gz'
) with (format='multijson', ingestionMappingReference='SecurityEventMapping', ignoreFirstRecord=false)
```

---

### Pattern 4 — Batching Policy Tuning

Batching policy controls how ADX groups incoming data before writing to storage. The three knobs — time, count, and size — determine the trade-off between latency and write efficiency.

```kql
// View current batching policies
.show table SecurityEvent policy ingestionbatching

// Real-time security events: aggressive batching for low latency
// Flush every 30 seconds OR 500 records OR 10MB — whichever comes first
.alter table SecurityAlert policy ingestionbatching
    '{"MaximumBatchingTimeSpan": "00:00:30", "MaximumNumberOfItems": 500, "MaximumRawDataSizeMB": 10}'

// High-volume network flow: optimize for throughput, accept higher latency
// Flush every 5 minutes OR 50,000 records OR 256MB
.alter table NetworkFlow policy ingestionbatching
    '{"MaximumBatchingTimeSpan": "00:05:00", "MaximumNumberOfItems": 50000, "MaximumRawDataSizeMB": 256}'
```

**Batching strategy for security data types:**

| Data Type | Max Time | Max Count | Max Size | Rationale |
|---|---|---|---|---|
| Security alerts | 30s | 500 | 10 MB | Real-time SOC response |
| Identity events | 1 min | 5,000 | 50 MB | Fast enough for hunting |
| Endpoint telemetry | 2 min | 10,000 | 100 MB | Balance latency and cost |
| Network flow / DNS | 5 min | 50,000 | 256 MB | Volume justifies batching |
| Historical backfill | 10 min | 100,000 | 1 GB | Throughput over latency |

---

### Pattern 5 — Monitoring Ingestion Health

A broken ingestion pipeline means blind spots in your security monitoring. Monitor ingestion continuously.

```kql
// Monitor ingestion failures and latency from the ADX system tables
.show ingestion failures
| where FailedOn > ago(24h)
| summarize FailureCount = count(), DistinctTables = dcount(Table)
    by Database, Table, FailureKind = FailedOn
| order by FailureCount desc
```

```kql
// Check ingestion latency: time from event generation to ADX availability
// Run this against your security tables to detect pipeline delays
SecurityEvent
| where TimeGenerated > ago(1h)
| extend IngestionDelay = ingestion_time() - TimeGenerated
| summarize
    AvgDelaySeconds = avg(IngestionDelay) / 1s,
    P95DelaySeconds = percentile(IngestionDelay, 95) / 1s,
    MaxDelaySeconds = max(IngestionDelay) / 1s,
    EventCount = count()
    by bin(TimeGenerated, 5m)
| order by TimeGenerated desc
```

## Best Practices

1. **Use streaming ingestion only for tables where < 10s latency matters** — it uses ~2x more CPU than queued
2. **Partition Event Hubs by table** — one Event Hub per exported table avoids routing complexity in ADX
3. **Test ingestion mappings with `.ingest inline`** before building production pipelines
4. **Monitor `.show ingestion failures` daily** — silent pipeline breaks are the #1 cause of detection blind spots
5. **Set `message-retention` on Event Hubs to ≥ 3 days** — allows recovery from ADX maintenance windows
6. **Use `MULTIJSON` format** for Sentinel data export — Log Analytics exports arrays of JSON objects, not newline-delimited

## Cost Implications

| Component | Cost Driver | Optimization |
|---|---|---|
| Event Hub throughput units | Per-TU hourly charge | Enable auto-inflate; start with fewer TUs |
| Streaming ingestion | ~2x CPU per operation vs. queued | Reserve streaming for high-priority tables only |
| Batching policy | Smaller batches = more write operations = more CPU | Tune batch size up for high-volume tables |
| Ingestion compute | CPU cycles for parsing and indexing | Use typed mappings (avoid dynamic columns) to reduce parse cost |

## Related Skills

- **[Cluster Architecture](cluster-architecture.md)** — Sizing the cluster to handle your ingestion volume.
- **[Security Data Modeling](security-data-modeling.md)** — Designing the tables that ingested data lands in.
- **[Data Connectors Setup](../log-analytics/data-connectors-setup.md)** — Getting data into Log Analytics before exporting to ADX.
- **[Long-Term Retention](long-term-retention.md)** — What happens to data after ingestion: tiering and archival.
- **[ADX Integration](../kql/adx-integration.md)** — Querying ingested ADX data from Log Analytics using `adx()` proxy.
