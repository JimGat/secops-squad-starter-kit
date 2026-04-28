---
title: Watchlist-Driven Detection
category: detection
difficulty: intermediate
mitre_attack:
  - T1078  # Valid Accounts
  - T1078.004  # Cloud Accounts
  - T1566  # Phishing
products:
  - Microsoft Sentinel
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# Watchlist-Driven Detection

## Overview

Sentinel watchlists let you bring external reference data — IP allowlists, VIP user lists, critical asset inventories — into your KQL detections without hardcoding values. This skill covers how to create, manage, and reference watchlists in analytics rules, plus automation patterns for keeping them current.

Use this skill when:
- A detection needs to reference a dynamic list (IPs, users, domains, assets)
- You want to maintain allowlists/blocklists without editing analytics rule queries
- VIP or high-value target monitoring requires a managed user list
- IOC feeds need to be operationalized in detection rules

## Prerequisites

| Requirement | Detail |
|---|---|
| **Workspace** | Sentinel-enabled Log Analytics workspace |
| **Permissions** | `Microsoft Sentinel Contributor` to create/manage watchlists |
| **Data format** | CSV file or inline data for watchlist content |
| **Threat model** | Completed for any detection that consumes the watchlist (team decision #7) |
| **MITRE mapping** | Documented for the consuming detection (team decision #8) |

## Watchlist Fundamentals

### Creating a Watchlist

**In the Sentinel portal:**

1. Navigate to **Microsoft Sentinel** → **Watchlist**
2. Click **+ New**
3. Configure:
   - **Name:** `VIP-Users` (no spaces, use hyphens)
   - **Alias:** `VIP-Users` (used in KQL with `_GetWatchlist('VIP-Users')`)
   - **Search key:** `UserPrincipalName` (the primary lookup column)
4. Upload CSV or enter data inline
5. Click **Create**

**CSV format example (`VIP-Users.csv`):**

```csv
UserPrincipalName,DisplayName,Department,RiskTier
ceo@contoso.com,Jane Smith,Executive,Critical
cfo@contoso.com,John Doe,Finance,Critical
ciso@contoso.com,Sarah Connor,Security,High
vp-engineering@contoso.com,Bob Builder,Engineering,High
```

### Querying Watchlists in KQL

```kql
// Basic watchlist lookup
_GetWatchlist('VIP-Users')
| project UserPrincipalName, DisplayName, RiskTier

// Join watchlist with sign-in logs
let VIPs = _GetWatchlist('VIP-Users') | project SearchKey;
SignInLogs
| where UserPrincipalName in (VIPs)
| where RiskLevelDuringSignIn in ("high", "medium")
```

**Important:** `SearchKey` is a built-in column that maps to the search key field you defined when creating the watchlist. Use it for efficient `in()` lookups.

## Detection Patterns

### Pattern 1 — VIP User Anomalous Sign-in

Detect when a VIP user signs in from an unusual location or a risky IP.

```kql
// VIP User Anomalous Sign-in Detection
// MITRE ATT&CK: T1078.004 (Valid Accounts: Cloud Accounts)
// Threat Model: credential-theft-vip-compromise
let VIPUsers = _GetWatchlist('VIP-Users')
    | project UPN = SearchKey, DisplayName, RiskTier;
let VIPBaseline = SignInLogs
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | where UserPrincipalName in (VIPUsers)
    | where ResultType == 0
    | summarize
        KnownCountries = make_set(tostring(LocationDetails.countryOrRegion), 50),
        KnownIPs = make_set(IPAddress, 100)
        by UserPrincipalName;
SignInLogs
| where TimeGenerated > ago(1d)
| where UserPrincipalName in (VIPUsers)
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| join kind=inner VIPBaseline on UserPrincipalName
| where Country !in (KnownCountries) or IPAddress !in (KnownIPs)
| join kind=inner VIPUsers on $left.UserPrincipalName == $right.UPN
| project
    TimeGenerated,
    UserPrincipalName,
    DisplayName,
    RiskTier,
    IPAddress,
    Country,
    AppDisplayName,
    NewCountry = iff(Country !in (KnownCountries), true, false),
    NewIP = iff(IPAddress !in (KnownIPs), true, false),
    RiskLevelDuringSignIn
| order by RiskTier asc, TimeGenerated desc
```

### Pattern 2 — Dynamic IP Blocklist

```kql
// Block known malicious IPs — NRT or Scheduled
// MITRE ATT&CK: T1071 (Application Layer Protocol)
// Threat Model: external-c2-known-ioc
let BlockedIPs = _GetWatchlist('ThreatIntel-BlockedIPs')
    | project SearchKey;
CommonSecurityLog
| where SourceIP in (BlockedIPs) or DestinationIP in (BlockedIPs)
| extend
    MaliciousIP = iff(SourceIP in (BlockedIPs), SourceIP, DestinationIP),
    Direction = iff(SourceIP in (BlockedIPs), "Inbound", "Outbound")
| project
    TimeGenerated,
    MaliciousIP,
    Direction,
    SourceIP,
    DestinationIP,
    DestinationPort,
    DeviceVendor,
    Activity
```

### Pattern 3 — Service Account Allowlist

Suppress false positives by excluding known service accounts from behavioral detections.

```kql
// Anomalous sign-in excluding known service accounts
// MITRE ATT&CK: T1078 (Valid Accounts)
let ServiceAccounts = _GetWatchlist('ServiceAccounts')
    | project SearchKey;
SignInLogs
| where UserPrincipalName !in (ServiceAccounts)
| where ResultType == 0
| where RiskLevelDuringSignIn == "high"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    RiskLevelDuringSignIn,
    ConditionalAccessStatus
```

### Pattern 4 — Critical Asset Monitoring

```kql
// Detect admin access to critical servers outside maintenance windows
// MITRE ATT&CK: T1078 (Valid Accounts)
let CriticalAssets = _GetWatchlist('CriticalAssets')
    | project HostName = SearchKey, AssetTier, Owner;
let MaintenanceWindow = _GetWatchlist('MaintenanceWindows')
    | project HostName = SearchKey, WindowStart, WindowEnd;
SecurityEvent
| where EventID == 4624 // Successful logon
| where LogonType == 10 // Remote interactive (RDP)
| where Computer in (CriticalAssets)
| join kind=leftouter MaintenanceWindow on $left.Computer == $right.HostName
| where isnull(WindowStart) or TimeGenerated !between (todatetime(WindowStart) .. todatetime(WindowEnd))
| join kind=inner CriticalAssets on $left.Computer == $right.HostName
| project
    TimeGenerated,
    Computer,
    Account,
    AssetTier,
    Owner,
    IpAddress,
    LogonProcessName
```

## Watchlist Management

### Sizing Limits

| Limit | Value |
|---|---|
| Max rows per watchlist | 10,000,000 |
| Max file upload size | 3.8 MB per CSV upload |
| Max watchlists per workspace | No hard limit (practical: ~50 for performance) |
| Max columns | No hard limit (keep under 20 for performance) |

### Update Automation

**Option 1 — Logic App CSV Upload:**

Use a Logic App to periodically download a CSV from a threat intelligence feed and upload it to the Sentinel watchlist API.

```
Trigger: Recurrence (every 6 hours)
  → HTTP GET: Download CSV from TI feed
  → Parse CSV
  → HTTP PUT: Update Sentinel Watchlist via REST API
      PUT https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/watchlists/{alias}?api-version=2023-02-01
```

See [SOAR skills](../soar/) for Logic App implementation patterns.

**Option 2 — PowerShell scheduled task:**

```powershell
# Update watchlist from CSV file
$watchlistAlias = "ThreatIntel-BlockedIPs"
$csvPath = "./blocked-ips.csv"
$workspace = "your-workspace-name"
$resourceGroup = "your-rg"

# Upload via Az module
Import-Module Az.SecurityInsights
$items = Import-Csv $csvPath
foreach ($item in $items) {
    New-AzSentinelWatchlistItem -ResourceGroupName $resourceGroup `
        -WorkspaceName $workspace `
        -WatchlistAlias $watchlistAlias `
        -ItemsKeyValue @{ SearchKey = $item.IP; ThreatType = $item.Category }
}
```

**Option 3 — Azure DevOps pipeline with CSV in Git:**

Store watchlist CSVs in your detection repository. A CI/CD pipeline syncs changes to Sentinel on merge to main.

### Watchlist Naming Convention

| Prefix | Use |
|---|---|
| `ThreatIntel-` | IOC feeds (IPs, domains, hashes) |
| `VIP-` | High-value user lists |
| `ServiceAccounts` | Service and automation accounts for allowlisting |
| `CriticalAssets` | High-value servers, databases, applications |
| `GeoBaseline-` | Expected geographic locations by user group |
| `MaintenanceWindows` | Scheduled maintenance periods for suppression |

## Best Practices

1. **Use `SearchKey` for lookups.** It's indexed and optimized for `in()` operations. Don't `join` on arbitrary columns when `SearchKey` is available.
2. **Keep watchlists focused.** One watchlist per use case. Don't combine VIP users and service accounts in one list.
3. **Automate updates.** Manual CSV uploads drift. Use Logic Apps or CI/CD to keep watchlists in sync with source-of-truth systems.
4. **Version watchlist CSVs.** Store the CSV files in Git alongside your analytics rules. Track who changed what and when.
5. **Document each watchlist.** Include a README in your repo documenting the purpose, schema, update cadence, and owner of each watchlist.
6. **Test watchlist performance.** Large watchlists (100k+ rows) in `in()` clauses can slow queries. Profile in Log Analytics before deploying to production rules.
7. **Set review cadence.** Stale IOC watchlists are worse than no watchlist — they create a false sense of coverage. Review monthly.

## Related Skills

- **[Scheduled Rule Pattern](scheduled-rule-pattern.md)** — How to use watchlists in scheduled analytics rules.
- **[NRT Rule Pattern](nrt-rule-pattern.md)** — `_GetWatchlist()` is the recommended IOC matching method for NRT rules.
- **[Detection Lifecycle](detection-lifecycle.md)** — Watchlist management is a Phase 4 tuning activity.
- **[MITRE ATT&CK Mapping](mitre-attack-mapping.md)** — Map the consuming detection, not the watchlist itself.
