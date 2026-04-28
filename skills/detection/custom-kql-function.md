---
title: Custom KQL Function Authoring
category: detection
difficulty: advanced
mitre_attack:
  - T1071  # Application Layer Protocol
  - T1078  # Valid Accounts
products:
  - Microsoft Sentinel
  - Azure Monitor
  - Log Analytics
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# Custom KQL Function Authoring

## Overview

Saved KQL functions in your Log Analytics workspace let you encapsulate reusable logic — enrichment lookups, normalization, scoring — and call them by name in any analytics rule or hunt query. This skill covers when to use functions, how to author and deploy them, and the versioning patterns that keep your detection library maintainable.

Use this skill when:
- Multiple analytics rules share the same enrichment or transformation logic
- You want to standardize entity normalization across detections
- A query is too complex for inline KQL and needs to be broken into composable parts
- You need to deploy reusable logic via infrastructure-as-code

## Prerequisites

| Requirement | Detail |
|---|---|
| **Workspace** | Log Analytics workspace (Sentinel-enabled) |
| **Permissions** | `Log Analytics Contributor` to create/modify saved functions |
| **Tables** | Depends on the function — documented per function |
| **Threat model** | If the function supports a detection, the parent detection must have a threat model (team decision #7) |

## When to Use Functions vs Inline KQL

| Scenario | Use | Rationale |
|---|---|---|
| Same enrichment logic in 3+ rules | **Saved function** | Single source of truth; update once, all rules benefit |
| One-off query logic for a specific rule | **Inline KQL** | No benefit to abstraction; keep it readable |
| Complex multi-step transformation | **Saved function** | Reduces rule query complexity; easier to test |
| Dynamic list that changes frequently | **Watchlist** | Functions are static; watchlists support dynamic updates |
| Cross-workspace query helper | **Saved function** | Encapsulate `workspace().` syntax in a callable function |

## Authoring Patterns

### Basic Saved Function (No Parameters)

```kql
// Function: EnrichedSignInLogs
// Purpose: SignInLogs with geo and risk enrichment, normalized schema
// Used by: Password spray, impossible travel, anomalous sign-in rules
SignInLogs
| where ResultType == 0
| extend
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    State = tostring(LocationDetails.state),
    Latitude = toreal(LocationDetails.geoCoordinates.latitude),
    Longitude = toreal(LocationDetails.geoCoordinates.longitude),
    OS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    DeviceTrust = tostring(DeviceDetail.trustType),
    CAStatus = ConditionalAccessStatus,
    RiskLevel = RiskLevelDuringSignIn
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    City, Country, State, Latitude, Longitude,
    OS, Browser, DeviceTrust,
    CAStatus, RiskLevel,
    CorrelationId
```

**Usage in a detection rule:**
```kql
EnrichedSignInLogs
| where Country != "US"
| where RiskLevel in ("high", "medium")
| summarize AttemptCount = count() by UserPrincipalName, Country
```

### Parameterized Function

```kql
// Function: EnrichIPAddress
// Parameters:
//   IPToEnrich: string — The IP address to look up
//   LookbackDays: int = 30 — How many days of history to check
// Purpose: Returns enrichment data for a given IP address across multiple tables
// MITRE context: Supports any detection involving IP-based indicators
let IPToEnrich = "0.0.0.0"; // Parameter placeholder
let LookbackDays = 30;      // Parameter with default
let IPSignIns = SignInLogs
    | where TimeGenerated > ago(1d * LookbackDays)
    | where IPAddress == IPToEnrich
    | summarize
        SignInCount = count(),
        UniqueUsers = dcount(UserPrincipalName),
        UserList = make_set(UserPrincipalName, 25),
        UniqueApps = dcount(AppDisplayName),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
    | extend Source = "SignInLogs";
let IPFirewall = CommonSecurityLog
    | where TimeGenerated > ago(1d * LookbackDays)
    | where SourceIP == IPToEnrich or DestinationIP == IPToEnrich
    | summarize
        ConnectionCount = count(),
        UniqueDestPorts = dcount(DestinationPort),
        PortList = make_set(DestinationPort, 25)
    | extend Source = "Firewall";
let IPThreatIntel = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(1d * LookbackDays)
    | where NetworkIP == IPToEnrich or NetworkSourceIP == IPToEnrich
    | summarize
        TIMatches = count(),
        ThreatTypes = make_set(ThreatType, 10),
        Confidence = max(ConfidenceScore)
    | extend Source = "ThreatIntel";
union IPSignIns, IPFirewall, IPThreatIntel
```

### Creating the Function in the Portal

1. Open **Log Analytics workspace** → **Logs**
2. Write and test your query
3. Click **Save** → **Save as function**
4. Configure:
   - **Function name:** `EnrichIPAddress`
   - **Legacy category:** `SecOps-Functions` (or your team convention)
   - **Parameters:** Add each parameter with name, type, and default value

### Creating the Function via ARM/Bicep

```json
{
  "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
  "apiVersion": "2020-08-01",
  "name": "[concat(parameters('workspaceName'), '/EnrichIPAddress')]",
  "properties": {
    "etag": "*",
    "displayName": "EnrichIPAddress",
    "category": "SecOps-Functions",
    "query": "let IPToEnrich = \"0.0.0.0\";\nlet LookbackDays = 30;\nlet IPSignIns = SignInLogs\n| where TimeGenerated > ago(1d * LookbackDays)\n| where IPAddress == IPToEnrich\n| summarize SignInCount = count(), UniqueUsers = dcount(UserPrincipalName), UserList = make_set(UserPrincipalName, 25), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)\n| extend Source = \"SignInLogs\";\nlet IPThreatIntel = ThreatIntelligenceIndicator\n| where TimeGenerated > ago(1d * LookbackDays)\n| where NetworkIP == IPToEnrich\n| summarize TIMatches = count(), ThreatTypes = make_set(ThreatType, 10), Confidence = max(ConfidenceScore)\n| extend Source = \"ThreatIntel\";\nunion IPSignIns, IPThreatIntel",
    "functionAlias": "EnrichIPAddress",
    "functionParameters": "IPToEnrich:string,LookbackDays:int = 30",
    "version": 2
  }
}
```

**Bicep equivalent:**

```bicep
resource enrichIPFunction 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
  parent: workspace
  name: 'EnrichIPAddress'
  properties: {
    etag: '*'
    displayName: 'EnrichIPAddress'
    category: 'SecOps-Functions'
    query: '''
      let IPToEnrich = "0.0.0.0";
      let LookbackDays = 30;
      SignInLogs
      | where TimeGenerated > ago(1d * LookbackDays)
      | where IPAddress == IPToEnrich
      | summarize SignInCount = count(), UniqueUsers = dcount(UserPrincipalName)
      | extend Source = "SignInLogs"
    '''
    functionAlias: 'EnrichIPAddress'
    functionParameters: 'IPToEnrich:string,LookbackDays:int = 30'
    version: 2
  }
}
```

## Function Versioning Patterns

### Naming Convention

```
FunctionName_v{major}    ← Breaking change: new version, keep old one
FunctionName             ← Always points to latest stable version
```

**Example:**
- `EnrichIPAddress` — current stable (v2)
- `EnrichIPAddress_v1` — deprecated, still referenced by legacy rules
- `EnrichIPAddress_v3` — testing, not yet promoted

### Version Lifecycle

| Stage | Action |
|---|---|
| **Development** | Create `FunctionName_v{next}` in dev workspace |
| **Testing** | Run dependent rules against the new version; compare output |
| **Promotion** | Update `FunctionName` alias to point to new version |
| **Deprecation** | Mark old version with `_DEPRECATED` suffix after all references updated |
| **Retirement** | Delete deprecated version after 30 days |

### Migration Checklist

When updating a function used by analytics rules:

- [ ] Identify all analytics rules that call the function (`search "FunctionName" in rule queries`)
- [ ] Test each rule with the new function version in dev
- [ ] Deploy new function to production
- [ ] Update analytics rule queries if function signature changed
- [ ] Monitor `SentinelHealth` for rule execution errors after deployment
- [ ] Retire old function version after 30 days

## Best Practices

1. **Name functions clearly.** `EnrichIPAddress` is better than `IPLookup`. Include the verb and the entity.
2. **Document parameters inline.** Use KQL comments at the top of the function with parameter names, types, defaults, and purpose.
3. **Set sensible defaults.** Every parameter should have a default value so the function works when called without arguments.
4. **Keep functions focused.** One function = one job. Don't build a function that enriches IPs *and* normalizes user names *and* calculates risk scores.
5. **Test independently.** Call the function in Log Analytics with test parameters before using it in an analytics rule.
6. **Deploy via infrastructure-as-code.** ARM/Bicep templates ensure functions are version-controlled and reproducible across environments.
7. **Category convention:** Use `SecOps-Functions` as the saved search category for all detection-related functions. This makes them discoverable in the portal.

## Related Skills

- **[Scheduled Rule Pattern](scheduled-rule-pattern.md)** — How to call functions from analytics rule queries.
- **[Detection Lifecycle](detection-lifecycle.md)** — Functions are Phase 2 artifacts that support detection development.
- **[Watchlist-Driven Detection](watchlist-driven-detection.md)** — When to use watchlists vs functions for dynamic data.
- **[Threat Hunting Foundations](../kql/threat-hunting-foundations.md)** — KQL patterns that benefit from function encapsulation.
