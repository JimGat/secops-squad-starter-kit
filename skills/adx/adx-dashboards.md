---
title: ADX Dashboards
category: Azure Data Explorer
difficulty: intermediate
mitre_attack:
  - General  # Operational — security monitoring and situational awareness
products:
  - Azure Data Explorer
  - Azure Data Explorer Dashboards
  - Azure Portal
  - Grafana
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# ADX Dashboards

## Overview

Real-time security dashboards are the heartbeat of a SOC war room. ADX Dashboards provide native KQL-powered visualization directly on your ADX data — no Power BI or third-party tools required. They support parameterized queries, auto-refresh, and dashboard-as-code export for version control. For SOC teams using ADX as their security data lake, ADX Dashboards eliminate the need for an intermediate analytics layer.

Use this skill when:
- You are building SOC war room dashboards that need near-real-time refresh
- You want parameterized dashboards for on-call analysts to investigate specific entities
- You need to export dashboards as code for version control and CI/CD deployment
- You are embedding ADX visuals in Azure portal for executive stakeholders
- You need to design refresh strategies that balance freshness against cluster load

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Database Viewer` on the ADX database; `Dashboard Editor` role for creating/editing dashboards |
| **Cluster** | ADX cluster with security data tables populated |
| **Knowledge** | KQL query authoring; familiarity with the security metrics your SOC tracks |

## Core Patterns

### Pattern 1 — SOC Overview Dashboard Queries

Every SOC needs a top-level dashboard showing security posture at a glance. These queries are designed to be dashboard-efficient — they leverage materialized views and pre-aggregated data.

```kql
// SOC Overview: Incident volume trend (last 30 days)
// Use materialized view if available for sub-second response
SecurityAlert
| where TimeGenerated > ago(30d)
| summarize
    AlertCount = count(),
    HighSeverity = countif(Severity == "High"),
    MediumSeverity = countif(Severity == "Medium"),
    LowSeverity = countif(Severity == "Low")
    by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
| render timechart
```

```kql
// Active threat map: sign-in locations with risk indicators
// Powers a geographic heat map on the dashboard
SignInEvents
| where TimeGenerated > ago(24h)
| where RiskLevelDuringSignIn in ("medium", "high")
| summarize
    RiskySignIns = count(),
    DistinctUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 10)
    by Location
| order by RiskySignIns desc
```

```kql
// Top 10 noisy detection rules: helps SOC leads tune alert fatigue
SecurityAlert
| where TimeGenerated > ago(7d)
| summarize AlertCount = count(), DistinctEntities = dcount(CompromisedEntity)
    by AlertName, Severity
| order by AlertCount desc
| take 10
```

---

### Pattern 2 — Parameterized Investigation Dashboards

Parameterized dashboards let analysts input an entity (user, IP, hostname) and see all related telemetry on one screen. ADX Dashboard parameters are declared in the dashboard JSON and bound to KQL queries.

```kql
// Parameter: _UserPrincipalName (type: string, default: "")
// User investigation timeline — all activity for the selected user
SignInEvents
| where TimeGenerated > ago(30d)
| where UserPrincipalName =~ _UserPrincipalName
| project TimeGenerated, IPAddress, Location, AppDisplayName, ResultType,
    RiskLevelDuringSignIn, ConditionalAccessStatus
| order by TimeGenerated desc
```

```kql
// Parameter: _IPAddress (type: string, default: "")
// IP address investigation: all network and identity activity for a specific IP
let IdentityActivity = (
    SignInEvents
    | where TimeGenerated > ago(30d)
    | where IPAddress == _IPAddress
    | project TimeGenerated, EventType = "SignIn", Detail = UserPrincipalName,
        Extra = AppDisplayName
);
let NetworkActivity = (
    NetworkEvents
    | where TimeGenerated > ago(30d)
    | where SourceIP == _IPAddress or DestinationIP == _IPAddress
    | project TimeGenerated, EventType = "Network", Detail = strcat(SourceIP, " -> ", DestinationIP),
        Extra = strcat(Protocol, "/", tostring(DestinationPort))
);
union IdentityActivity, NetworkActivity
| order by TimeGenerated desc
```

**Dashboard parameter types:**

| Type | Use Case | Example |
|---|---|---|
| String | User, IP, hostname investigation | `_UserPrincipalName`, `_IPAddress` |
| Timerange | Dynamic lookback window | `_TimeRange` (last 1h, 24h, 7d, 30d) |
| Dropdown (query-based) | Select from active alerts, tenants, regions | Populated by a KQL query returning distinct values |
| Multi-select | Filter by multiple severities or data sources | `_Severity` (High, Medium, Low) |

---

### Pattern 3 — Dashboard-as-Code Export and Version Control

ADX Dashboards can be exported as JSON and stored in Git. This enables version control, code review, and CI/CD deployment of dashboard changes.

```bash
# Export dashboard to JSON file for version control
# Use the ADX Dashboard UI: Share > Export to file
# The exported JSON includes all tiles, queries, parameters, and layout

# Store in your repo alongside your skills
# dashboards/
#   soc-overview.json
#   user-investigation.json
#   network-threat-map.json
#   compliance-posture.json

# Import a dashboard from JSON
# ADX Dashboard UI: Create dashboard > Import from file
# Or use the REST API:
curl -X POST "https://dashboards.kusto.windows.net/dashboards" \
  -H "Authorization: Bearer $ADX_TOKEN" \
  -H "Content-Type: application/json" \
  -d @dashboards/soc-overview.json
```

**Dashboard-as-code workflow:**

1. Create/edit dashboard in the ADX Dashboard UI
2. Export to JSON
3. Commit to Git with a descriptive message
4. PR review — security team reviews query changes
5. Import to production ADX Dashboard from the reviewed JSON

---

### Pattern 4 — Refresh Strategies for SOC War Rooms

War room dashboards need to be fresh but cannot overload the cluster with constant queries. Design refresh intervals based on data criticality and query cost.

```kql
// Use query results caching to reduce cluster load from repeated dashboard refreshes
// Set at the query level — cached results are returned for identical queries within the TTL
set query_results_cache_max_age = 5m;
SecurityAlert
| where TimeGenerated > ago(24h)
| summarize AlertCount = count() by bin(TimeGenerated, 1h), Severity
| render timechart
```

**Refresh strategy guidelines:**

| Dashboard Type | Recommended Refresh | Rationale |
|---|---|---|
| SOC war room overview | 1–5 minutes | Operational awareness needs freshness |
| Investigation dashboard | On-demand (manual) | Analyst-driven, avoid stale cache |
| Compliance posture | 1 hour | Compliance status changes slowly |
| Executive summary | 4 hours or daily | High-level metrics, not operational |
| Threat intelligence | 30 minutes | TI feeds update periodically |

**Reducing dashboard query cost:**
- Use materialized views for pre-aggregated data (see [Security Data Modeling](security-data-modeling.md))
- Apply `query_results_cache_max_age` for dashboards with fixed lookback windows
- Run expensive queries asynchronously and store results in a summary table

---

### Pattern 5 — Embedding in Azure Portal and Grafana

For organizations that standardize on Azure Portal or Grafana, ADX data can be surfaced without requiring analysts to use the ADX Dashboard UI directly.

```kql
// Grafana ADX plugin: uses the same KQL queries
// Configure the Azure Data Explorer datasource in Grafana:
// - Cluster URL: https://securityadx.eastus.kusto.windows.net
// - Database: SecurityLogs
// - Authentication: AAD App Registration or Managed Identity

// The same KQL queries work in Grafana panels — no modification needed
// Example: Grafana time series panel
SecurityAlert
| where $__timeFilter(TimeGenerated)
| summarize AlertCount = count() by bin(TimeGenerated, $__interval), Severity
```

```bash
# Register an AAD app for Grafana-to-ADX authentication
az ad app create --display-name "Grafana-ADX-Reader" \
  --required-resource-accesses '[{
    "resourceAppId": "00000003-0000-0000-c000-000000000000",
    "resourceAccess": [{"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope"}]
  }]'

# Grant the app Database Viewer on the ADX database
az kusto database add-principal \
  --cluster-name "securityadx" \
  --resource-group "rg-adx-security" \
  --database-name "SecurityLogs" \
  --value name="Grafana Reader" type="App" role="Viewer" \
    app-id="<grafana-app-client-id>"
```

## Best Practices

1. **Build dashboards on materialized views**, not raw tables — dashboard refresh should not trigger billion-row scans
2. **Use query results caching** (`set query_results_cache_max_age`) for dashboards with fixed lookback windows
3. **Store dashboard JSON in Git** — treat dashboards as code, review changes in PRs
4. **Set refresh intervals by dashboard purpose** — war room ≠ compliance ≠ executive
5. **Parameterize investigation dashboards** — let analysts input entities instead of building per-entity dashboards
6. **Test dashboard query cost** before deploying — use `.show queries` to measure resource consumption

## Cost Implications

| Factor | Impact | Mitigation |
|---|---|---|
| Dashboard refresh frequency | More refreshes = more query compute | Use caching and materialized views |
| Number of tiles per dashboard | Each tile is a separate query | Combine related metrics into single queries with multiple `render` outputs |
| Concurrent viewers | Multiplies query load | Query results caching eliminates duplicate queries |
| War room auto-refresh | Continuous background load | 5-minute minimum refresh with caching |

## Related Skills

- **[Security Data Modeling](security-data-modeling.md)** — Materialized views that power efficient dashboard queries.
- **[ADX ML & Anomaly Detection](adx-ml-anomaly.md)** — Anomaly detection results visualized in dashboards.
- **[Cluster Architecture](cluster-architecture.md)** — Cluster sizing must account for dashboard query load.
- **[Detection Tuning](../kql/detection-tuning.md)** — Dashboard data helps identify noisy rules for tuning.
- **[Cost Optimization](../log-analytics/cost-optimization.md)** — Dashboard efficiency affects overall platform cost.
