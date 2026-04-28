---
title: Cross-Cluster Queries
category: Azure Data Explorer
difficulty: advanced
mitre_attack:
  - T1078  # Valid Accounts — federated identity analysis across clusters
  - T1071  # Application Layer Protocol — cross-cluster network correlation
products:
  - Azure Data Explorer
  - Microsoft Sentinel
  - Azure Monitor Log Analytics
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Cross-Cluster Queries

## Overview

Enterprise and MSSP security operations rarely live in a single ADX cluster. Cross-cluster queries, follower databases, and data sharing patterns enable federated analysis across organizational boundaries — query production and DR clusters together, share threat intelligence databases across business units, or give SOC analysts read access to data owned by other teams without data duplication.

Use this skill when:
- You need to query across multiple ADX clusters (e.g., per-region or per-business-unit)
- You want read-only replicas of security data via follower databases
- You are designing data sharing between SOC teams and business unit security groups
- You need to correlate threat intelligence stored centrally with local security events
- You are building an MSSP platform that federates queries across customer clusters

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Database Viewer` on remote cluster databases; `AllDatabasesAdmin` for follower database configuration |
| **Networking** | Network connectivity between clusters (private endpoints or public access); cross-tenant requires AAD app registration |
| **Cluster** | At least two ADX clusters, or ADX + Log Analytics workspace for `adx()` proxy queries |

## Core Patterns

### Pattern 1 — Cross-Cluster Query Syntax

The `cluster()` function lets you reference tables on remote ADX clusters. Use it for ad-hoc federated hunting across organizational or geographic boundaries.

```kql
// Hunt for a compromised user across regional clusters
// Each region has its own ADX cluster with local sign-in data
let SuspiciousUser = "compromised.user@contoso.com";
let LookbackWindow = 30d;
// Query the US East cluster
let USActivity = (
    cluster('https://security-useast.eastus.kusto.windows.net')
        .database('SecurityLogs').SignInEvents
    | where TimeGenerated > ago(LookbackWindow)
    | where UserPrincipalName =~ SuspiciousUser
    | extend Region = "US-East"
    | project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, Region
);
// Query the EU West cluster
let EUActivity = (
    cluster('https://security-euwest.westeurope.kusto.windows.net')
        .database('SecurityLogs').SignInEvents
    | where TimeGenerated > ago(LookbackWindow)
    | where UserPrincipalName =~ SuspiciousUser
    | extend Region = "EU-West"
    | project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, Region
);
// Combine for complete user activity timeline
union USActivity, EUActivity
| summarize
    TotalSignIns = count(),
    DistinctIPs = dcount(IPAddress),
    Regions = make_set(Region),
    Locations = make_set(Location, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
```

**Performance rules for cross-cluster queries:**
- Always push `where` filters to the remote cluster (before any `project` or `join`)
- Use `project` early to reduce data transfer across the network
- Avoid `join` on remote tables — bring filtered subsets local first, then join

---

### Pattern 2 — Cross-Database Queries (Same Cluster)

When you have database-per-tenant or database-per-domain on the same cluster, use `database()` to query across them without network overhead.

```kql
// Correlate identity events with endpoint events stored in separate databases
// Both databases are on the same cluster — no network overhead
let TimeWindow = 1h;
let SuspiciousIP = "198.51.100.42";
// Identity events from the Identity database
let IdentityEvents = (
    database('IdentityLogs').SignInEvents
    | where TimeGenerated > ago(TimeWindow)
    | where IPAddress == SuspiciousIP
    | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType
);
// Endpoint events from the Endpoint database
let EndpointEvents = (
    database('EndpointLogs').ProcessEvents
    | where TimeGenerated > ago(TimeWindow)
    | project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
);
// Correlate: find endpoints where users from the suspicious IP logged in
IdentityEvents
| join kind=inner (
    EndpointEvents
) on $left.UserPrincipalName == $right.AccountName
| project TimeGenerated, UserPrincipalName, IPAddress, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```

---

### Pattern 3 — Follower Databases for Read Scaling

Follower databases create a read-only replica of a leader database on another cluster. The SOC gets low-latency read access without impacting the ingestion cluster. Data replication is automatic and near-real-time.

```bash
# Attach a follower database: the SOC analysis cluster follows the ingestion cluster
az kusto attached-database-configuration create \
  --cluster-name "soc-analysis-cluster" \
  --resource-group "rg-adx-soc" \
  --name "follow-security-logs" \
  --database-name "SecurityLogs" \
  --cluster-resource-id "/subscriptions/SUB_ID/resourceGroups/rg-adx-security/providers/Microsoft.Kusto/clusters/securityadx" \
  --default-principals-modification-kind "Union" \
  --table-level-sharing-properties \
    tables-to-include="SignInEvents" "ProcessEvents" "NetworkEvents" "SecurityAlert"
```

```kql
// On the follower cluster, verify the database is attached and tables are visible
.show follower databases

// Check replication lag — critical for SOC operations
.show follower database SecurityLogs replication-status
| project DatabaseName, ReplicationLag = ReplicationLagSeconds, State
```

**Follower database use cases:**

| Scenario | Leader Cluster | Follower Cluster | Benefit |
|---|---|---|---|
| SOC read scaling | Ingestion cluster | SOC analysis cluster | Heavy hunting queries don't impact ingestion |
| DR/HA | Primary region | Secondary region | Read access survives primary region outage |
| MSSP shared TI | Central TI cluster | Per-customer clusters | Customers query shared IOCs without data duplication |
| Business unit sharing | Central security lake | BU-specific clusters | BUs get relevant security data without full lake access |

---

### Pattern 4 — Cross-Cluster IOC Sweep

Sweep for indicators of compromise across all regional clusters simultaneously. This pattern is critical for incident response when you do not know which region the attacker targeted.

```kql
// Sweep for malicious IP addresses across all regional clusters
let MaliciousIPs = dynamic(["198.51.100.42", "203.0.113.88", "192.0.2.100"]);
let SweepWindow = 7d;
// Function to search one cluster's network events
let SearchCluster = (ClusterUri: string, ClusterRegion: string) {
    cluster(ClusterUri).database('SecurityLogs').NetworkEvents
    | where TimeGenerated > ago(SweepWindow)
    | where SourceIP in (MaliciousIPs) or DestinationIP in (MaliciousIPs)
    | extend MatchedIP = iff(SourceIP in (MaliciousIPs), SourceIP, DestinationIP)
    | extend Region = ClusterRegion
    | project TimeGenerated, SourceIP, DestinationIP, MatchedIP, DestinationPort,
        Protocol, Action, DeviceName, Region
};
union
    SearchCluster('https://security-useast.eastus.kusto.windows.net', 'US-East'),
    SearchCluster('https://security-euwest.westeurope.kusto.windows.net', 'EU-West'),
    SearchCluster('https://security-apac.southeastasia.kusto.windows.net', 'APAC')
| summarize
    HitCount = count(),
    Regions = make_set(Region),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    AffectedDevices = make_set(DeviceName, 50)
    by MatchedIP, DestinationPort, Protocol
| order by HitCount desc
```

---

### Pattern 5 — Centralized Threat Intelligence Sharing

Share a curated threat intelligence database across clusters using follower databases or materialized external tables.

```kql
// Create a centralized TI table on the leader cluster
.create table ThreatIntelligence (
    IndicatorType: string,
    IndicatorValue: string,
    ThreatType: string,
    Confidence: int,
    ValidFrom: datetime,
    ValidUntil: datetime,
    Source: string,
    Description: string,
    Tags: dynamic
)

// Enrich local security events with centrally managed TI
// The TI database is followed from the central TI cluster
let ActiveTI = (
    database('ThreatIntel').ThreatIntelligence
    | where ValidUntil > now() and Confidence >= 70
    | where IndicatorType == "ipv4-addr"
    | project IndicatorValue, ThreatType, Confidence, Source
);
NetworkEvents
| where TimeGenerated > ago(1d)
| join kind=inner (ActiveTI) on $left.DestinationIP == $right.IndicatorValue
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
    ThreatType, Confidence, TISource = Source, DeviceName
| order by Confidence desc, TimeGenerated desc
```

## MITRE ATT&CK Context

| Technique | ID | How This Skill Helps |
|---|---|---|
| Valid Accounts | T1078 | Cross-cluster identity federation reveals compromised accounts active across multiple geographic regions simultaneously. |
| Application Layer Protocol | T1071 | Cross-cluster IOC sweeps detect C2 infrastructure communicating with assets in different regions. |

## Tuning Guide

### Cross-Cluster Query Performance

| Optimization | Impact | How To |
|---|---|---|
| Push filters to remote | ⬆️ High — reduces data transfer | Place `where` before `project` in remote table references |
| Reduce columns with `project` | ⬆️ High — less data over the wire | Select only needed columns before cross-cluster boundary |
| Use `materialize()` for reused subqueries | ⬆️ Medium — avoids duplicate remote calls | Wrap shared subqueries in `materialize()` |
| Avoid cross-cluster `join` on large tables | ⬆️ High — join shuffles data | Filter both sides aggressively first |
| Set query timeout | ⚠️ Safety net | `set query_results_cache_max_age = 5m;` for repeated dashboards |

### Follower Database Replication

| Configuration | Default | Security Recommendation |
|---|---|---|
| Replication lag SLA | ~5 minutes | Monitor and alert if > 15 minutes |
| Table-level sharing | All tables | Restrict to only tables SOC needs |
| Cache override on follower | Inherits from leader | Set shorter cache on follower if budget-constrained |
| Principal modification | Union | Use "Union" to allow additional reader principals on follower |

## Related Skills

- **[Cluster Architecture](cluster-architecture.md)** — Multi-cluster topology decisions that drive cross-cluster query needs.
- **[Cross-Workspace Queries](../kql/cross-workspace-queries.md)** — The Log Analytics equivalent — querying across workspaces.
- **[ADX Integration](../kql/adx-integration.md)** — `adx()` proxy for querying ADX from Log Analytics.
- **[Security Data Modeling](security-data-modeling.md)** — Consistent schemas across clusters make cross-cluster queries reliable.
- **[Threat Hunting Foundations](../kql/threat-hunting-foundations.md)** — Hunting methodology that cross-cluster queries extend to global scope.
