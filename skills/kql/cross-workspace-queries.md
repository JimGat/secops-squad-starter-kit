---
title: Cross-Workspace Queries
category: kql
difficulty: advanced
mitre_attack:
  - T1078  # Valid Accounts
  - T1059  # Command and Scripting Interpreter
  - T1071  # Application Layer Protocol
  - T1021  # Remote Services
products:
  - Microsoft Sentinel
  - Azure Monitor Log Analytics
  - Azure Lighthouse
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Cross-Workspace Queries

## Overview

This skill covers querying across multiple Log Analytics workspaces from a single KQL query. In enterprise environments, telemetry is often distributed — security logs in one workspace, application logs in another, OT/IoT in a third. Cross-workspace queries let you correlate signals without centralizing all data.

Use this skill when:
- Your organization has multiple Sentinel workspaces (per-region, per-business-unit, or per-tenant)
- You need to correlate identity events from one workspace with endpoint events from another
- You are running threat hunts across a managed-services (MSSP) multi-tenant environment
- You need to validate that an IOC appears in any workspace under your control

## Prerequisites

| Requirement | Detail |
|---|---|
| **Tables** | Any table available in target workspaces (`SignInLogs`, `SecurityEvent`, `CommonSecurityLog`, etc.) |
| **Workspace** | ≥2 Log Analytics workspaces with appropriate data connectors |
| **Permissions** | `Log Analytics Reader` on every workspace you query. For cross-tenant, Azure Lighthouse delegation or B2B guest access. |
| **Data connectors** | Vary by workspace — each must have its own connectors configured |

## Core Patterns

### Pattern 1 — Basic Cross-Workspace Query with workspace()

The `workspace()` function references a remote workspace by name, ID, or qualified resource ID. Use the resource ID form in production — it is unambiguous and survives workspace renames.

```kql
// Query SecurityEvents from a remote workspace by resource ID.
// This is the most reliable form — immune to workspace name collisions.
let LookbackPeriod = 7d;
let RemoteWorkspaceResourceId = "/subscriptions/YOUR_SUB_ID/resourcegroups/YOUR_RG/providers/microsoft.operationalinsights/workspaces/YOUR_WORKSPACE";
workspace(RemoteWorkspaceResourceId).SecurityEvent
| where TimeGenerated > ago(LookbackPeriod)
| where EventID == 4625 // Failed logon attempts
| summarize
    FailedAttempts = count(),
    DistinctAccounts = dcount(TargetUserName),
    Accounts = make_set(TargetUserName, 10)
    by Computer, IpAddress
| where FailedAttempts > 10
| order by FailedAttempts desc
```

**Parameters to customize:**
- `RemoteWorkspaceResourceId` — Full Azure resource ID of the target workspace. Find it in the Azure portal under the workspace properties.
- `LookbackPeriod` — Cross-workspace scans are slower; keep this tight for interactive queries.

**Performance notes:**
- Cross-workspace queries add network latency per workspace. Each `workspace()` call opens a separate query context on the remote cluster.
- Always push `where TimeGenerated` and other high-selectivity filters into the remote leg before any `join` or `union`.

---

### Pattern 2 — Union Across Multiple Workspaces

When you need to search for an indicator across all your workspaces, `union` the same table from each. Name each workspace leg so you know where hits originate.

```kql
// Search for a suspicious IP across sign-in logs in three workspaces.
let SuspiciousIP = "198.51.100.77";
let LookbackPeriod = 14d;
let WS_HQ = "/subscriptions/SUB1/resourcegroups/RG1/providers/microsoft.operationalinsights/workspaces/sentinel-hq";
let WS_EU = "/subscriptions/SUB2/resourcegroups/RG2/providers/microsoft.operationalinsights/workspaces/sentinel-eu";
let WS_APAC = "/subscriptions/SUB3/resourcegroups/RG3/providers/microsoft.operationalinsights/workspaces/sentinel-apac";
union
    (workspace(WS_HQ).SignInLogs
        | where TimeGenerated > ago(LookbackPeriod)
        | where IPAddress == SuspiciousIP
        | extend SourceWorkspace = "HQ"),
    (workspace(WS_EU).SignInLogs
        | where TimeGenerated > ago(LookbackPeriod)
        | where IPAddress == SuspiciousIP
        | extend SourceWorkspace = "EU"),
    (workspace(WS_APAC).SignInLogs
        | where TimeGenerated > ago(LookbackPeriod)
        | where IPAddress == SuspiciousIP
        | extend SourceWorkspace = "APAC")
| summarize
    HitCount = count(),
    Users = make_set(UserPrincipalName, 20),
    Workspaces = make_set(SourceWorkspace)
    by IPAddress, AppDisplayName
| order by HitCount desc
```

**Parameters to customize:**
- `WS_HQ`, `WS_EU`, `WS_APAC` — Replace with your actual workspace resource IDs.
- `SuspiciousIP` — The IOC to sweep across all workspaces.

**Performance notes:**
- Each `union` leg executes in parallel on its respective cluster. Keep filters inside each leg — don't filter after the union.
- Maximum of 20 workspaces per query (Log Analytics limit). For larger estates, batch queries.

---

### Pattern 3 — Cross-Workspace Join for Identity-Endpoint Correlation

When identity logs (sign-ins) live in one workspace and endpoint logs (process events) in another, join them on a shared key such as user principal name or device ID.

```kql
// Correlate sign-ins from the identity workspace with process events from the endpoint workspace.
let LookbackPeriod = 3d;
let IdentityWS = "/subscriptions/SUB1/resourcegroups/RG1/providers/microsoft.operationalinsights/workspaces/identity-ws";
let EndpointWS = "/subscriptions/SUB2/resourcegroups/RG2/providers/microsoft.operationalinsights/workspaces/endpoint-ws";
// Stage 1: Find risky sign-ins in the identity workspace
let RiskySignIns = (workspace(IdentityWS).SignInLogs
    | where TimeGenerated > ago(LookbackPeriod)
    | where RiskLevelDuringSignIn in ("high", "medium")
    | project SignInTime = TimeGenerated, UserPrincipalName, IPAddress, RiskLevelDuringSignIn, AppDisplayName);
// Stage 2: Find processes run by those users in the endpoint workspace
let SuspiciousUsers = RiskySignIns | distinct UserPrincipalName;
workspace(EndpointWS).DeviceProcessEvents
| where TimeGenerated > ago(LookbackPeriod)
| where AccountUpn in (SuspiciousUsers)
// Only processes launched after the risky sign-in
| join kind=inner (RiskySignIns) on $left.AccountUpn == $right.UserPrincipalName
| where TimeGenerated >= SignInTime
| project
    TimeGenerated,
    UserPrincipalName = AccountUpn,
    DeviceName,
    FileName,
    ProcessCommandLine,
    SignInTime,
    RiskLevelDuringSignIn,
    IPAddress
| order by TimeGenerated asc
```

**Parameters to customize:**
- `IdentityWS`, `EndpointWS` — Resource IDs for identity and endpoint workspaces.
- `RiskLevelDuringSignIn` — Adjust risk threshold based on your environment's noise level.

**Performance notes:**
- The `let` + `in()` pattern reduces the join cardinality. Without it, a full cross-workspace join on UPN over 3 days can time out.
- Cross-workspace joins transfer intermediate results across the network. Always `project` down to only the columns you need before the join.
- Query timeout for cross-workspace queries is 10 minutes by default. Use `set query_take_max_records` to limit result sets during development.

---

### Pattern 4 — Cross-Tenant Query via Azure Lighthouse

For MSSPs managing multiple customer tenants, Azure Lighthouse enables cross-tenant workspace queries. The syntax is identical — Lighthouse makes remote workspaces appear as local resources.

```kql
// Query across customer tenants via Lighthouse-delegated workspaces.
// Each workspace() call targets a different customer's workspace.
let LookbackPeriod = 1d;
let Customer_A = "/subscriptions/CUST_A_SUB/resourcegroups/CUST_A_RG/providers/microsoft.operationalinsights/workspaces/cust-a-sentinel";
let Customer_B = "/subscriptions/CUST_B_SUB/resourcegroups/CUST_B_RG/providers/microsoft.operationalinsights/workspaces/cust-b-sentinel";
// Sweep for high-severity alerts across customer workspaces
union
    (workspace(Customer_A).SecurityAlert
        | where TimeGenerated > ago(LookbackPeriod)
        | where AlertSeverity == "High"
        | extend CustomerTenant = "Customer_A"),
    (workspace(Customer_B).SecurityAlert
        | where TimeGenerated > ago(LookbackPeriod)
        | where AlertSeverity == "High"
        | extend CustomerTenant = "Customer_B")
| summarize
    AlertCount = count(),
    AlertTypes = make_set(AlertName, 20)
    by CustomerTenant, ProviderName
| order by AlertCount desc
```

**Parameters to customize:**
- `Customer_A`, `Customer_B` — Resource IDs of Lighthouse-delegated workspaces.
- `AlertSeverity` — Filter to "High" and "Medium" for daily triage; widen for audits.

**Performance notes:**
- Lighthouse queries traverse Azure Resource Manager across tenant boundaries — expect ~2-5s additional latency per tenant.
- Cross-tenant queries count against the querying user's workspace limits, not the customer's.
- Azure Lighthouse delegation must include `Microsoft.OperationalInsights/workspaces/query/read` permission.

---

### Pattern 5 — Dynamic Workspace Discovery with Azure Resource Graph

For large estates, hard-coding workspace IDs is brittle. Use Azure Resource Graph to discover workspaces dynamically, then iterate queries across them.

```kql
// List all Sentinel-enabled workspaces you have access to.
// Run this in Azure Resource Graph Explorer, not Log Analytics.
resources
| where type == "microsoft.operationalinsights/workspaces"
| where properties.features.searchVersion == 2
| project
    WorkspaceName = name,
    ResourceId = id,
    ResourceGroup = resourceGroup,
    SubscriptionId = subscriptionId,
    Location = location,
    RetentionDays = properties.retentionInDays
| order by WorkspaceName asc
```

```kql
// After discovering workspaces, sweep a specific table across them.
// This example queries CommonSecurityLog for a firewall deny pattern.
let LookbackPeriod = 1d;
let TargetAction = "deny";
// Replace with resource IDs from discovery query
let WS1 = "RESOURCE_ID_1";
let WS2 = "RESOURCE_ID_2";
union
    (workspace(WS1).CommonSecurityLog
        | where TimeGenerated > ago(LookbackPeriod)
        | where DeviceAction =~ TargetAction
        | extend SourceWorkspace = "WS1"),
    (workspace(WS2).CommonSecurityLog
        | where TimeGenerated > ago(LookbackPeriod)
        | where DeviceAction =~ TargetAction
        | extend SourceWorkspace = "WS2")
| summarize
    DenyCount = count(),
    DistinctSources = dcount(SourceIP)
    by SourceWorkspace, DestinationIP, DestinationPort
| where DenyCount > 100
| order by DenyCount desc
```

**Parameters to customize:**
- `WS1`, `WS2` — Replace with discovered resource IDs.
- `TargetAction` — Change to match your firewall vendor's action naming ("block", "drop", "deny").

**Performance notes:**
- Azure Resource Graph queries are free and fast — use them for workspace discovery before running expensive cross-workspace sweeps.
- Automate the discovery → sweep pipeline in a Logic App or Azure Function for scheduled cross-estate hunting.

## MITRE ATT&CK Context

| Technique | ID | How This Skill Helps |
|---|---|---|
| Valid Accounts | T1078 | Cross-workspace identity correlation (Pattern 3) detects compromised credentials used across environments that share no single workspace. |
| Command and Scripting Interpreter | T1059 | Union queries (Pattern 2) find suspicious process execution even when endpoints report to different workspaces. |
| Remote Services | T1021 | Cross-workspace joins surface lateral movement from an identity workspace to endpoint telemetry in separate workspaces. |
| Application Layer Protocol | T1071 | Cross-tenant sweeps (Pattern 4) detect C2 beaconing across MSSP-managed customer environments. |

## False Positive Guidance

| Pattern | Common False Positives | Tuning Advice |
|---|---|---|
| Cross-workspace IOC sweep | Shared IP addresses (CDN, VPN) appearing in multiple workspaces | Filter out known corporate egress IPs and CDN ranges before the union. |
| Cross-workspace join on UPN | Service accounts with the same UPN format across environments | Exclude known service account patterns (e.g., `svc-*@contoso.com`) using a watchlist. |
| Cross-tenant alert sweep | Test/dev tenants generating high-severity alerts from lab activity | Tag customer workspaces with environment metadata; filter out non-production tenants. |
| Dynamic workspace discovery | Workspaces without Sentinel (monitoring-only) appearing in results | Add a filter for `properties.features.searchVersion == 2` to scope to Sentinel-enabled workspaces. |

## Tuning Guide

### Cross-Workspace Query Limits

| Limit | Value | Workaround |
|---|---|---|
| Max workspaces per query | 20 | Batch queries into groups of 20; union results in a downstream pipeline. |
| Query timeout | 10 minutes | Push filters into each workspace leg; reduce lookback periods. |
| Max rows returned | 500,000 | Use `summarize` to aggregate before returning; avoid raw row dumps. |
| Data transfer | Counted as query data scan | Pre-aggregate in each workspace leg to minimize cross-network data. |

### Performance Optimization Checklist

- [ ] Time filters (`where TimeGenerated > ago(...)`) are inside each workspace leg, not after the union
- [ ] `project` reduces columns before any `join` or `union`
- [ ] Resource ID form used for `workspace()` (avoids name-resolution ambiguity)
- [ ] Intermediate results materialized with `let` + `distinct` before `in()` filters
- [ ] Cross-workspace joins use the smaller result set on the right side of the join
- [ ] Lookback period is the minimum required for the hypothesis

## Related Skills

- **[Threat Hunting Foundations](threat-hunting-foundations.md)** — Core hunting patterns that these cross-workspace techniques extend.
- **[ADX Integration](adx-integration.md)** — When cross-workspace queries hit retention or performance limits, offload to Azure Data Explorer.
- **[Incident Investigation](incident-investigation.md)** — Use cross-workspace queries to scope incidents that span multiple environments.
