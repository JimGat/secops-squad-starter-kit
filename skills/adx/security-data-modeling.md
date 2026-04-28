---
title: Security Data Modeling
category: Azure Data Explorer
difficulty: advanced
mitre_attack:
  - T1078  # Valid Accounts — data model supports identity analytics
  - T1059  # Command and Scripting Interpreter — process event schemas
  - T1071  # Application Layer Protocol — network telemetry modeling
products:
  - Azure Data Explorer
  - Microsoft Sentinel
  - Microsoft Defender for Endpoint
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Security Data Modeling

## Overview

Good security data modeling in ADX means the difference between queries that run in 2 seconds and queries that time out. ADX is a columnar store — schema design, update policies for ingestion-time transformation, materialized views for pre-aggregation, and extent tagging for lifecycle management are all critical for a performant security data lake. Unlike Log Analytics (where Microsoft controls the schema), in ADX you own the data model entirely.

Use this skill when:
- You are designing ADX table schemas to receive security telemetry
- You need update policies to transform, enrich, or normalize data at ingestion time
- You want materialized views to pre-aggregate data for dashboards or trend analysis
- You need extent tagging for data lifecycle management (e.g., tag by source tenant, compliance tier)
- You are normalizing multi-vendor security events into a unified schema

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Database Admin` for table creation, update policies, and materialized views |
| **Cluster** | ADX cluster with an existing database (see [Cluster Architecture](cluster-architecture.md)) |
| **Knowledge** | Understanding of your security data sources and their native schemas |

## Core Patterns

### Pattern 1 — Security Event Table Schemas

Design tables with strong typing, minimal use of `dynamic` columns, and datetime partitioning for performance. Each security domain (identity, endpoint, network, cloud) gets its own table family.

```kql
// Identity events: sign-in and authentication telemetry
.create table SignInEvents (
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    Location: string,
    AppDisplayName: string,
    ClientAppUsed: string,
    ResultType: int,
    ResultDescription: string,
    ConditionalAccessStatus: string,
    RiskLevelDuringSignIn: string,
    RiskLevelAggregated: string,
    DeviceDetail: dynamic,
    MfaDetail: dynamic,
    CorrelationId: string,
    OriginalSource: string
)

// Endpoint process execution: normalized from Defender for Endpoint
.create table ProcessEvents (
    TimeGenerated: datetime,
    DeviceName: string,
    DeviceId: string,
    InitiatingProcessFileName: string,
    InitiatingProcessCommandLine: string,
    FileName: string,
    FolderPath: string,
    ProcessCommandLine: string,
    SHA256: string,
    MD5: string,
    AccountName: string,
    AccountDomain: string,
    LogonId: long,
    ProcessId: long,
    ParentProcessId: long,
    OriginalSource: string
)

// Network flow: firewall, NSG, and proxy telemetry
.create table NetworkEvents (
    TimeGenerated: datetime,
    SourceIP: string,
    DestinationIP: string,
    SourcePort: int,
    DestinationPort: int,
    Protocol: string,
    Action: string,
    BytesSent: long,
    BytesReceived: long,
    Direction: string,
    DeviceName: string,
    DeviceVendor: string,
    RuleName: string,
    OriginalSource: string
)
```

---

### Pattern 2 — Update Policies for Ingestion-Time Transformation

Update policies run a KQL query on newly ingested data and write the results to a target table. Use them to normalize, enrich, and filter data as it arrives — never store raw data if you can transform it at ingestion.

```kql
// Raw landing table: all security events arrive here in original format
.create table RawSecurityEvents (
    RawData: dynamic,
    IngestionTime: datetime,
    SourceSystem: string
)

// Transformation function: extract and normalize sign-in events
.create function
    with (docstring = "Extract sign-in events from raw ingestion", folder = "UpdatePolicies")
    ExtractSignInEvents() {
    RawSecurityEvents
    | where SourceSystem == "AzureAD"
    | where tostring(RawData.operationName) == "Sign-in activity"
    | project
        TimeGenerated = todatetime(RawData.time),
        UserPrincipalName = tostring(RawData.properties.userPrincipalName),
        IPAddress = tostring(RawData.callerIpAddress),
        Location = tostring(RawData.properties.location.countryOrRegion),
        AppDisplayName = tostring(RawData.properties.appDisplayName),
        ClientAppUsed = tostring(RawData.properties.clientAppUsed),
        ResultType = toint(RawData.properties.status.errorCode),
        ResultDescription = tostring(RawData.properties.status.failureReason),
        ConditionalAccessStatus = tostring(RawData.properties.conditionalAccessStatus),
        RiskLevelDuringSignIn = tostring(RawData.properties.riskLevelDuringSignIn),
        RiskLevelAggregated = tostring(RawData.properties.riskLevelAggregated),
        DeviceDetail = RawData.properties.deviceDetail,
        MfaDetail = RawData.properties.mfaDetail,
        CorrelationId = tostring(RawData.properties.correlationId),
        OriginalSource = "Sentinel-Export"
}

// Attach update policy: whenever data lands in RawSecurityEvents,
// matching rows are transformed and inserted into SignInEvents
.alter table SignInEvents policy update
    '[{"IsEnabled": true, "Source": "RawSecurityEvents", "Query": "ExtractSignInEvents()", "IsTransactional": false, "PropagateIngestionProperties": true}]'
```

---

### Pattern 3 — Materialized Views for Pre-Aggregation

Materialized views continuously aggregate data, keeping a pre-computed summary up to date. For security dashboards and trend analysis, they eliminate the need to scan billions of rows on every dashboard refresh.

```kql
// Materialized view: daily sign-in summary per user
// Dashboards query this view instead of scanning the full SignInEvents table
.create materialized-view with (backfill=true)
    DailySignInSummary on table SignInEvents {
    SignInEvents
    | summarize
        TotalSignIns = count(),
        FailedSignIns = countif(ResultType != 0),
        DistinctIPs = dcount(IPAddress),
        DistinctLocations = dcount(Location),
        DistinctApps = dcount(AppDisplayName),
        RiskySignIns = countif(RiskLevelDuringSignIn in ("medium", "high"))
        by UserPrincipalName, bin(TimeGenerated, 1d)
}

// Materialized view: hourly network traffic summary
// Powers the SOC war room bandwidth and anomaly dashboards
.create materialized-view with (backfill=true)
    HourlyNetworkSummary on table NetworkEvents {
    NetworkEvents
    | summarize
        TotalFlows = count(),
        TotalBytesSent = sum(BytesSent),
        TotalBytesReceived = sum(BytesReceived),
        DistinctSourceIPs = dcount(SourceIP),
        DistinctDestIPs = dcount(DestinationIP),
        BlockedFlows = countif(Action == "Deny")
        by bin(TimeGenerated, 1h), DeviceVendor
}
```

```kql
// Query the materialized view for dashboard data — sub-second response
DailySignInSummary
| where TimeGenerated > ago(30d)
| where RiskySignIns > 0
| order by RiskySignIns desc
| take 50
```

---

### Pattern 4 — Extent Tagging for Data Lifecycle Management

Extents (data shards) can be tagged with metadata for lifecycle operations. Tag data by source tenant, compliance tier, or ingestion batch to enable targeted retention, purging, or archival.

```kql
// Tag extents by source tenant during ingestion
// Use .set-or-append with tags for batch ingestion
.set-or-append SecurityEvent with (tags='["source:TenantA", "compliance:PCI"]') <|
    RawSecurityEvents
    | where SourceSystem == "TenantA"
    | project TimeGenerated, Computer, EventID, Activity, Account

// Query extent tags to understand data composition
.show table SecurityEvent extents
| summarize ExtentCount = count(), TotalRows = sum(RowCount),
    TotalSizeMB = round(sum(OriginalSize) / 1048576.0, 2)
    by tostring(Tags)

// Drop extents by tag — useful for tenant data removal (GDPR)
// CAUTION: This permanently deletes data
.drop extents <| .show table SecurityEvent extents
    | where Tags has "source:TenantA"
    | where MaxCreatedOn < ago(730d)
```

---

### Pattern 5 — ASIM-Aligned Normalization

Align your ADX schemas with Microsoft's Advanced Security Information Model (ASIM) for seamless interoperability with Sentinel analytics rules and cross-source correlation.

```kql
// ASIM-aligned DNS event table
.create table ASimDnsActivityLogs (
    TimeGenerated: datetime,
    EventType: string,
    EventResult: string,
    EventResultDetails: string,
    SrcIpAddr: string,
    SrcPortNumber: int,
    DstIpAddr: string,
    DstPortNumber: int,
    DnsQuery: string,
    DnsQueryType: int,
    DnsQueryTypeName: string,
    DnsResponseCode: int,
    DnsResponseCodeName: string,
    DnsFlags: string,
    UrlCategory: string,
    ThreatCategory: string,
    ThreatConfidence: int,
    Dvc: string,
    DvcAction: string,
    EventProduct: string,
    EventVendor: string,
    OriginalSource: string
)
```

## MITRE ATT&CK Context

| Technique | ID | How This Skill Helps |
|---|---|---|
| Valid Accounts | T1078 | `SignInEvents` schema captures risk levels, MFA detail, and conditional access — enabling detection of compromised credential use. |
| Command and Scripting Interpreter | T1059 | `ProcessEvents` schema with full command-line capture enables detection of LOLBin abuse and encoded payloads. |
| Application Layer Protocol | T1071 | `NetworkEvents` schema captures protocol, port, and byte counts for detecting C2 beacon patterns. |

## Tuning Guide

### Schema Design Principles

1. **Prefer `string` over `dynamic`** for fields you will filter on — `dynamic` columns cannot be indexed efficiently
2. **Use `datetime` for time fields** — never store timestamps as strings; ADX datetime partitioning depends on it
3. **Include `OriginalSource`** in every table — critical for tracing data provenance in multi-source environments
4. **Avoid wide tables** (> 100 columns) — split into core fields and a `dynamic ExtendedProperties` bag
5. **Name columns consistently** across tables — use ASIM naming where possible for cross-table joins

### Materialized View Limits

| Constraint | Value |
|---|---|
| Max materialized views per database | 50 |
| Max aggregation functions per view | 16 |
| Source table row limit | None (but large tables increase backfill time) |
| Backfill duration | Proportional to source data size; plan for hours on TB-scale tables |

## Related Skills

- **[Data Ingestion](data-ingestion.md)** — How data arrives in these tables — mappings, pipelines, and batching.
- **[Cluster Architecture](cluster-architecture.md)** — Sizing the cluster to support your data model.
- **[Cross-Cluster Queries](cross-cluster-queries.md)** — Querying across databases when tables are distributed.
- **[ADX Dashboards](adx-dashboards.md)** — Materialized views power efficient dashboard queries.
- **[UEBA Patterns](../kql/ueba-patterns.md)** — Behavioral analytics that depend on well-modeled identity and endpoint data.
