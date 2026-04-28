---
title: Near-Real-Time (NRT) Rule Pattern
category: detection
difficulty: advanced
mitre_attack:
  - T1190  # Exploit Public-Facing Application
  - T1078  # Valid Accounts
  - T1078.002  # Domain Accounts
  - T1133  # External Remote Services
products:
  - Microsoft Sentinel
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# Near-Real-Time (NRT) Rule Pattern

## Overview

NRT analytics rules in Microsoft Sentinel run every minute with no lookback window — they evaluate only the events ingested since the last execution. This makes them the fastest detection mechanism Sentinel offers, but they come with constraints that scheduled rules don't have.

Use NRT rules only when detection latency matters more than query flexibility. For everything else, use scheduled rules.

Use this skill when:
- You need sub-minute detection latency for a high-confidence indicator
- A scheduled rule's 5-minute minimum frequency isn't fast enough
- You have a known-bad indicator (IP, hash, domain) that demands immediate alerting
- You're building detections for active incident response

## Prerequisites

| Requirement | Detail |
|---|---|
| **Workspace** | Sentinel-enabled Log Analytics workspace |
| **Permissions** | `Microsoft Sentinel Contributor` or higher |
| **Data** | Tables with near-real-time ingestion (e.g., `SignInLogs`, `SecurityAlert`, `CommonSecurityLog`) |
| **Threat model** | Completed threat model for this detection (team decision #7) |
| **MITRE mapping** | Technique identified and documented (team decision #8) |

## Decision Framework: NRT vs Scheduled

Use this table to decide which rule type fits your detection:

| Criterion | NRT | Scheduled |
|---|---|---|
| **Detection latency** | ~1 minute | 5 minutes – 24 hours |
| **Lookback window** | None (current ingestion batch only) | Up to 14 days |
| **Aggregation** | Limited (`summarize` supported, but operates on tiny windows) | Full KQL aggregation |
| **Joins** | Supported but risky (right-side table must be small) | Full `join` support |
| **Threshold-based logic** | Not practical (window too small for meaningful counts) | Standard approach |
| **Performance cost** | Runs every minute — keep queries cheap | Runs on schedule — can afford heavier queries |
| **Use case** | Known-bad IOC match, high-confidence single-event detection | Behavioral analytics, anomaly detection, aggregation-based detection |

**Rule of thumb:** If your detection logic starts with "if we see *any single event* matching X, alert immediately" → NRT. If it starts with "if we see *a pattern across events* in the last N hours" → Scheduled.

## NRT-Specific Limitations

### What You Can't Do

| Limitation | Detail | Workaround |
|---|---|---|
| **No `ago()` lookback** | The query processes only the current ingestion batch (~1 minute of data) | Use scheduled rules for historical analysis |
| **No `query_period`** | There's no configurable lookback window | Design queries that match on individual events |
| **Limited KQL operators** | `mv-expand`, `externaldata`, and some `join` flavors may fail or perform poorly | Pre-compute via saved functions or watchlists |
| **No suppression** | Suppression is not available for NRT rules | Implement dedup logic in the query or use incident grouping |
| **Max 30 NRT rules** | Per workspace limit | Reserve NRT slots for your highest-priority detections |

### What You Can Do

- `where`, `extend`, `project`, `summarize` — all work normally
- `join` (inner, leftouter) — works if the right-side table query is small and fast
- `_GetWatchlist()` — works and is the recommended pattern for IOC matching
- Entity mappings — fully supported
- Alert details override — fully supported
- Custom details — fully supported

## Performance Considerations

NRT rules execute every ~60 seconds. A slow query blocks subsequent runs and can cause detection gaps.

**Performance checklist:**

- [ ] Query scans only the current ingestion batch (no `ago()` or time filters needed — Sentinel handles the window)
- [ ] No expensive `join` operations against large tables
- [ ] Watchlist lookups (`_GetWatchlist()`) are preferred over `externaldata` or large `in()` lists
- [ ] `project` is used early to drop unused columns
- [ ] Total query execution time stays under 10 seconds in testing

**Testing approach:** Run the query in Log Analytics with `| take 100` against 1 minute of data. If it takes more than 5 seconds, it's too slow for NRT.

## Patterns

### Pattern 1 — Known Malicious IP Hit (IOC Match)

The canonical NRT use case: match incoming telemetry against a maintained list of known-bad indicators.

```kql
// NRT Rule: Known Malicious IP — Inbound Connection
// MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
// Threat Model: external-exploit-known-ioc
let MaliciousIPs = _GetWatchlist('ThreatIntel-MaliciousIPs')
    | project SearchKey;
CommonSecurityLog
| where DeviceAction != "Deny"
| where SourceIP in (MaliciousIPs) or DestinationIP in (MaliciousIPs)
| extend
    MaliciousIP = iff(SourceIP in (MaliciousIPs), SourceIP, DestinationIP),
    Direction = iff(SourceIP in (MaliciousIPs), "Inbound", "Outbound")
| project
    TimeGenerated,
    MaliciousIP,
    Direction,
    SourceIP,
    DestinationIP,
    DestinationPort,
    DeviceVendor,
    DeviceProduct,
    Activity
```

### Pattern 2 — High-Confidence Single-Event Detection

Some events are so clearly malicious that a single occurrence warrants an immediate alert.

```kql
// NRT Rule: Successful Sign-in from Tor Exit Node
// MITRE ATT&CK: T1133 (External Remote Services), T1078 (Valid Accounts)
// Threat Model: credential-theft-anonymous-access
let TorExitNodes = _GetWatchlist('ThreatIntel-TorExitNodes')
    | project SearchKey;
SignInLogs
| where ResultType == 0 // Successful sign-in only
| where IPAddress in (TorExitNodes)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    DeviceDetail,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn
```

### Pattern 3 — Critical Security Event

```kql
// NRT Rule: Security Group Modification — Domain Admins
// MITRE ATT&CK: T1078.002 (Valid Accounts: Domain Accounts)
// Threat Model: privilege-escalation-group-modification
SecurityEvent
| where EventID in (4728, 4729, 4732, 4733, 4756, 4757)
| where TargetUserName has "Domain Admins" or TargetUserName has "Enterprise Admins"
| project
    TimeGenerated,
    Activity,
    TargetUserName,
    MemberName,
    SubjectUserName,
    Computer,
    EventID
```

## ARM Template — NRT Rule

```json
{
  "type": "Microsoft.SecurityInsights/alertRules",
  "apiVersion": "2023-02-01",
  "name": "[guid('NRT-MaliciousIP-Hit')]",
  "kind": "NRT",
  "properties": {
    "displayName": "NRT - Known Malicious IP Connection Detected",
    "description": "Fires immediately when a connection to or from a known malicious IP is observed. IOCs sourced from ThreatIntel-MaliciousIPs watchlist. MITRE ATT&CK: T1190.",
    "severity": "High",
    "enabled": true,
    "query": "let MaliciousIPs = _GetWatchlist('ThreatIntel-MaliciousIPs') | project SearchKey;\nCommonSecurityLog\n| where DeviceAction != \"Deny\"\n| where SourceIP in (MaliciousIPs) or DestinationIP in (MaliciousIPs)\n| extend MaliciousIP = iff(SourceIP in (MaliciousIPs), SourceIP, DestinationIP),\n    Direction = iff(SourceIP in (MaliciousIPs), \"Inbound\", \"Outbound\")\n| project TimeGenerated, MaliciousIP, Direction, SourceIP, DestinationIP, DestinationPort, DeviceVendor, DeviceProduct, Activity",
    "tactics": ["InitialAccess"],
    "techniques": ["T1190"],
    "incidentConfiguration": {
      "createIncident": true,
      "groupingConfiguration": {
        "enabled": true,
        "reopenClosedIncident": false,
        "lookbackDuration": "PT1H",
        "matchingMethod": "AllEntities",
        "groupByEntities": ["Ip"],
        "groupByAlertDetails": [],
        "groupByCustomDetails": []
      }
    },
    "eventGroupingSettings": {
      "aggregationKind": "AlertPerResult"
    },
    "entityMappings": [
      {
        "entityType": "IP",
        "fieldMappings": [
          { "identifier": "Address", "columnName": "MaliciousIP" }
        ]
      }
    ]
  }
}
```

> **Note:** NRT rules use `"kind": "NRT"` instead of `"kind": "Scheduled"`. They do not have `queryFrequency` or `queryPeriod` properties — Sentinel manages the execution cadence internally.

## Best Practices

1. **Reserve NRT for high-confidence, low-volume detections.** You have 30 slots per workspace — don't waste them on noisy rules.
2. **Use watchlists for IOC matching.** `_GetWatchlist()` is the fastest and most maintainable way to reference indicator lists in NRT rules.
3. **Keep queries simple.** Every minute of execution counts. Complex joins and aggregations belong in scheduled rules.
4. **Test with realistic data volumes.** A query that works on 10 events may choke on 10,000 events per minute during an attack.
5. **Use incident grouping as suppression.** Since NRT rules don't support native suppression, group incidents by entity to avoid alert storms.
6. **Monitor NRT rule health.** Check `SentinelHealth` for NRT execution failures — a failing NRT rule is a silent gap in your coverage.

## Related Skills

- **[Scheduled Rule Pattern](scheduled-rule-pattern.md)** — The standard rule type for most detections.
- **[Watchlist-Driven Detection](watchlist-driven-detection.md)** — How to build and maintain the watchlists used in NRT IOC matching.
- **[Detection Lifecycle](detection-lifecycle.md)** — NRT rules follow the same lifecycle but skip the frequency/lookback tuning phase.
- **[MITRE ATT&CK Mapping](mitre-attack-mapping.md)** — MITRE tagging is mandatory for all rules including NRT.
