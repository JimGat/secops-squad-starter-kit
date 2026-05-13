---
title: Scheduled Analytics Rule Pattern
category: detection
difficulty: intermediate
mitre_attack:
  - T1110  # Brute Force
  - T1110.003  # Password Spraying
  - T1078  # Valid Accounts
products:
  - Microsoft Sentinel
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# Scheduled Analytics Rule Pattern

## Overview

The scheduled analytics rule is the workhorse of Sentinel detection engineering. It runs a KQL query on a fixed cadence, evaluates results against a threshold, and creates alerts/incidents when conditions are met. This skill provides the complete template, configuration guidance, and a production-ready brute force detection example.

Use this skill when:
- Building a new detection rule in Microsoft Sentinel
- Standardizing analytics rule configuration across your team
- Deploying rules via ARM/Bicep templates (infrastructure-as-code)
- Tuning query frequency, lookback windows, and grouping

## Prerequisites

| Requirement | Detail |
|---|---|
| **Workspace** | Sentinel-enabled Log Analytics workspace |
| **Permissions** | `Microsoft Sentinel Contributor` or higher |
| **Threat model** | Completed threat model for this detection (team decision #7) |
| **MITRE mapping** | Technique identified and documented (team decision #8) |

## Rule Structure

### Full ARM Template

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.SecurityInsights/alertRules",
      "apiVersion": "2023-02-01",
      "name": "[guid('BruteForce-PasswordSpray')]",
      "kind": "Scheduled",
      "properties": {
        "displayName": "Brute Force - Password Spray Detected",
        "description": "Detects password spray attacks where a single IP attempts sign-ins against multiple accounts. Maps to MITRE ATT&CK T1110.003.",
        "severity": "High",
        "enabled": true,
        "query": "let FailureThreshold = 50;\nlet AccountThreshold = 5;\nlet TimeWindow = 10m;\nSignInLogs\n| where TimeGenerated > ago(query_period)\n| where ResultType in (\"50126\", \"50053\", \"50055\")\n| summarize\n    FailedAttempts = count(),\n    TargetAccounts = dcount(UserPrincipalName),\n    AccountList = make_set(UserPrincipalName, 25)\n    by IPAddress, bin(TimeGenerated, TimeWindow)\n| where FailedAttempts >= FailureThreshold\n| where TargetAccounts >= AccountThreshold",
        "queryFrequency": "PT5M",
        "queryPeriod": "PT15M",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "suppressionDuration": "PT1H",
        "suppressionEnabled": true,
        "tactics": ["CredentialAccess"],
        "techniques": ["T1110"],
        "subTechniques": ["T1110.003"],
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
        "alertDetailsOverride": {
          "alertDisplayNameFormat": "Password Spray from {{IPAddress}} - {{TargetAccounts}} accounts targeted",
          "alertDescriptionFormat": "IP {{IPAddress}} attempted {{FailedAttempts}} failed sign-ins against {{TargetAccounts}} distinct accounts within a 10-minute window.",
          "alertSeverityColumnName": null,
          "alertDynamicProperties": []
        },
        "entityMappings": [
          {
            "entityType": "IP",
            "fieldMappings": [
              {
                "identifier": "Address",
                "columnName": "IPAddress"
              }
            ]
          }
        ]
      }
    }
  ]
}
```

### Key Properties Explained

| Property | Purpose | Guidance |
|---|---|---|
| `queryFrequency` | How often the rule runs | ISO 8601 duration. Min: PT5M. Balance cost vs detection latency. |
| `queryPeriod` | How far back the query looks | Must be ≥ `queryFrequency`. Overlap prevents missed events at window edges. |
| `triggerOperator` / `triggerThreshold` | When to fire an alert | `GreaterThan 0` fires on any result. Use higher thresholds for aggregation queries. |
| `suppressionDuration` | Cool-down between alerts | Prevents alert storms. Set to the expected incident investigation time. |
| `tactics` / `techniques` | MITRE ATT&CK mapping | Populated in the Sentinel MITRE ATT&CK blade. Mandatory per team decision #8. |
| `eventGroupingSettings` | How results become alerts | `AlertPerResult` = one alert per row. `SingleAlert` = one alert for all results. |

## Configuration Patterns

### Query Frequency and Lookback Window

```
queryFrequency ──────────────────► How often it runs
queryPeriod    ──────────────────────────────► How far back it looks

                 |◄── overlap ──►|
    ─────────────┼───────────────┼──────────────┼─── time
              period_start    freq_start       now
```

**Rules of thumb:**

| Detection Type | Frequency | Lookback | Overlap | Rationale |
|---|---|---|---|---|
| Brute force / spray | 5 min | 15 min | 10 min | Fast detection needed; overlap catches split-window attacks |
| Anomalous behavior | 1 hour | 24 hours | 23 hours | Behavioral patterns need context; long lookback provides baseline |
| Rare event | 12 hours | 14 days | ~13.5 days | Rare signals need a large search window; frequency can be lower |
| Compliance violation | 24 hours | 25 hours | 1 hour | Daily check is sufficient; small overlap catches edge cases |

**Critical constraint:** `queryPeriod` cannot exceed 14 days for scheduled rules.

### Entity Mapping Patterns

Entity mappings connect your query results to Sentinel's entity model, enabling investigation graph, entity pages, and incident correlation.

| Entity Type | Identifier | Column Name Example | Notes |
|---|---|---|---|
| **Account** | `FullName` | `UserPrincipalName` | Use UPN format. Maps to Azure AD identity. |
| **Account** | `AadUserId` | `UserId` | Azure AD Object ID. More reliable than UPN. |
| **IP** | `Address` | `IPAddress` | Enables geo-lookup and TI matching. |
| **Host** | `HostName` | `Computer` | Device name. Pair with `DnsDomain` if available. |
| **Host** | `AzureID` | `_ResourceId` | Azure resource ID for cloud workloads. |
| **URL** | `Url` | `RemoteUrl` | Full URL including scheme. |
| **File** | `Name` | `FileName` | File name without path. Pair with `Directory`. |
| **FileHash** | `Value` | `SHA256` | Hash value. Set `Algorithm` to match. |

**Example — multi-entity mapping:**

```json
"entityMappings": [
  {
    "entityType": "Account",
    "fieldMappings": [
      { "identifier": "FullName", "columnName": "UserPrincipalName" }
    ]
  },
  {
    "entityType": "IP",
    "fieldMappings": [
      { "identifier": "Address", "columnName": "IPAddress" }
    ]
  },
  {
    "entityType": "Host",
    "fieldMappings": [
      { "identifier": "HostName", "columnName": "DeviceName" }
    ]
  }
]
```

### Alert Grouping Strategies

| Strategy | `matchingMethod` | Use When |
|---|---|---|
| Group by attacking IP | `AllEntities` with `groupByEntities: ["Ip"]` | Multiple targets from the same source — brute force, scanning |
| Group by target account | `AllEntities` with `groupByEntities: ["Account"]` | Multiple attacks against the same victim — targeted compromise |
| Group by custom field | `AnyAlert` with `groupByCustomDetails` | Business-logic grouping — e.g., by department or application |
| No grouping | `enabled: false` | Every alert is its own incident — use for high-severity, low-volume rules |

### Severity Mapping

| Severity | Use For | Expected Daily Volume |
|---|---|---|
| **High** | Confirmed malicious behavior, high confidence | < 5 |
| **Medium** | Suspicious behavior requiring investigation | 5–25 |
| **Low** | Informational, useful for correlation | 25–100 |
| **Informational** | Context enrichment, not actionable alone | 100+ |

If a rule produces more than 25 High-severity alerts per day, either the threshold needs tuning or the severity should be lowered.

## Example: Brute Force Detection — Complete Rule

### KQL Query

```kql
// Brute Force - Password Spray Detection
// MITRE ATT&CK: T1110.003 (Password Spraying)
// Threat Model: credential-theft-brute-force
let FailureThreshold = 50;
let AccountThreshold = 5;
let TimeWindow = 10m;
SignInLogs
| where TimeGenerated > ago(query_period)
| where ResultType in ("50126", "50053", "50055") // Invalid password, locked, account disabled
| summarize
    FailedAttempts = count(),
    TargetAccounts = dcount(UserPrincipalName),
    AccountList = make_set(UserPrincipalName, 25),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    ResultCodes = make_set(ResultType)
    by IPAddress, bin(TimeGenerated, TimeWindow)
| where FailedAttempts >= FailureThreshold
| where TargetAccounts >= AccountThreshold
| extend AttackDuration = datetime_diff('minute', LastAttempt, FirstAttempt)
| project
    IPAddress,
    FailedAttempts,
    TargetAccounts,
    AccountList,
    FirstAttempt,
    LastAttempt,
    AttackDuration,
    ResultCodes
```

### Sentinel UI Configuration

| Setting | Value |
|---|---|
| **Name** | Brute Force - Password Spray Detected |
| **Status** | Enabled |
| **Severity** | High |
| **MITRE ATT&CK** | Credential Access > T1110.003 |
| **Run query every** | 5 minutes |
| **Lookup data from** | 15 minutes |
| **Alert threshold** | Greater than 0 |
| **Event grouping** | Trigger an alert for each event |
| **Suppression** | On, 1 hour |
| **Entity mapping** | IP → IPAddress |
| **Incident grouping** | Enabled, group by IP, 1 hour lookback |

## Best Practices

1. **Always set `queryPeriod` > `queryFrequency`.** The overlap catches events at window boundaries. A 5-min frequency with a 5-min lookback has a blind spot.
2. **Use `AlertPerResult` for high-confidence rules.** Each row = one alert = one actionable item. Use `SingleAlert` only for summary-style rules.
3. **Map at least one entity.** Rules without entity mappings can't participate in incident correlation or investigation graphs.
4. **Test your query in Log Analytics first.** Replace `ago(query_period)` with `ago(15m)` to simulate the lookback window.
5. **Document the rule in the ARM template `description`.** Include the MITRE technique, the threat model reference, and the tuning thresholds.
6. **Suppression prevents alert fatigue.** For brute force, 1 hour suppression per IP is reasonable — the SOC doesn't need 12 alerts about the same spray.

## Related Skills

- **[NRT Rule Pattern](nrt-rule-pattern.md)** — When near-real-time detection is needed instead of scheduled.
- **[MITRE ATT&CK Mapping](mitre-attack-mapping.md)** — How to assign the right technique to this rule.
- **[Detection Lifecycle](detection-lifecycle.md)** — Where this rule fits in the build-test-deploy-tune cycle.
- **[Watchlist-Driven Detection](watchlist-driven-detection.md)** — Enhance this rule with dynamic IP allowlists.
- **[Threat Hunting Foundations](../kql/threat-hunting-foundations.md)** — The KQL patterns used in the query.

## Environment Context

Before executing this skill, check the customer's `.secops/` knowledge framework:

1. **Data location:** Read `.secops/data-sources/data-source-map.yaml` — tables may be in Sentinel (Analytics tier or Sentinel data lake), ADX, or external sources
2. **Active migrations:** Read `.secops/data-sources/migrations.yaml` — data may be moving between locations
3. **Workspace config:** Read `.secops/workspaces/` — know the workspace ID, tier, retention, and naming conventions
4. **Compliance:** Read `.secops/compliance/requirements.yaml` — respect data residency and regulatory constraints

If `.secops/` doesn't exist, proceed with defaults but suggest `secops-squad init --secops`.

See `.copilot/skills/secops-environment-context.md` for the full discovery flow.
