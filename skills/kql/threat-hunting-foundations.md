---
title: Threat Hunting Foundations
category: kql
difficulty: intermediate
mitre_attack:
  - T1078  # Valid Accounts
  - T1566  # Phishing
  - T1059  # Command and Scripting Interpreter
products:
  - Microsoft Sentinel
  - Microsoft Defender for Endpoint
  - Azure Active Directory
author: Freamon
version: 1.0.0
---

# Threat Hunting Foundations

## Overview

This skill teaches the core methodology for hypothesis-driven threat hunting using KQL in Microsoft Sentinel and related security data stores. It is the foundational skill — every other KQL detection and investigation pattern builds on the techniques here.

Use this skill when:
- Starting a proactive threat hunt (no incident — looking for unknowns)
- Building baseline behavioral models for users, devices, or processes
- Pivoting across entities to trace an attack chain
- Identifying rare or anomalous events that automated rules might miss

## Prerequisites

| Requirement | Detail |
|---|---|
| **Tables** | `SignInLogs`, `SecurityEvent`, `DeviceProcessEvents`, `IdentityInfo` |
| **Workspace** | Sentinel-connected Log Analytics workspace with ≥30 days retention |
| **Permissions** | `Microsoft Sentinel Reader` or higher on the workspace |
| **Data connectors** | Azure AD, Microsoft Defender for Endpoint, Windows Security Events |

## Core Patterns

### Pattern 1 — Hypothesis-Scoped Time-Boxed Hunt

Every hunt starts with a hypothesis and a time window. Unbounded queries are expensive and unfocused. Always scope with `let` parameters so the hunt is repeatable and adjustable.

```kql
// Hypothesis: An attacker is using compromised credentials outside business hours.
// Scope the hunt to a specific look-back window and define "off-hours."
let LookbackPeriod = 14d;
let OffHoursStart = 22; // 10 PM local
let OffHoursEnd = 6;    // 6 AM local
let TargetTenantId = "YOUR_TENANT_ID";
SignInLogs
| where TimeGenerated > ago(LookbackPeriod)
// Filter early to reduce scan cost
| where ResultType == 0 // Successful sign-ins only
| extend HourOfDay = hourofday(TimeGenerated)
| where HourOfDay >= OffHoursStart or HourOfDay < OffHoursEnd
| summarize
    SignInCount = count(),
    DistinctApps = dcount(AppDisplayName),
    Countries = make_set(LocationDetails.countryOrRegion, 10)
    by UserPrincipalName, IPAddress
| where SignInCount > 3
| order by SignInCount desc
```

**Parameters to customize:**
- `LookbackPeriod` — Increase for stealthy adversaries (30d+), decrease for quick sweeps (3d).
- `OffHoursStart` / `OffHoursEnd` — Adjust to the organization's actual working hours and timezone.
- `TargetTenantId` — Scope to a specific tenant in multi-tenant environments.

**Performance notes:**
- Cost is proportional to `LookbackPeriod` × daily `SignInLogs` volume. A 14d window on a 10k-user tenant typically scans ~5-20 GB.
- The `where ResultType == 0` filter before any `extend` or `summarize` dramatically reduces rows processed.

---

### Pattern 2 — Entity Pivoting (IP → User → Device → Process)

Entity pivoting is the technique of starting from one indicator and tracing relationships across tables to build the full attack chain. This pattern chains from a suspicious IP to the user who used it, the device they authenticated from, and the processes that ran on that device.

```kql
// Start from a suspicious IP address observed in threat intelligence or an alert.
let SuspiciousIP = "203.0.113.42";
let PivotWindow = 7d;
// Stage 1: Find users who authenticated from this IP
let AffectedUsers = SignInLogs
    | where TimeGenerated > ago(PivotWindow)
    | where IPAddress == SuspiciousIP
    | where ResultType == 0
    | distinct UserPrincipalName;
// Stage 2: Find devices those users signed into
let AffectedDevices = SignInLogs
    | where TimeGenerated > ago(PivotWindow)
    | where UserPrincipalName in (AffectedUsers)
    | where isnotempty(DeviceDetail.deviceId)
    | distinct tostring(DeviceDetail.deviceId);
// Stage 3: Find processes launched on those devices in the same window
DeviceProcessEvents
| where TimeGenerated > ago(PivotWindow)
| where DeviceId in (AffectedDevices)
| summarize
    ProcessCount = count(),
    UniqueProcesses = dcount(FileName),
    ProcessList = make_set(FileName, 25)
    by DeviceId, DeviceName, AccountName
| order by ProcessCount desc
```

**Parameters to customize:**
- `SuspiciousIP` — Replace with the IOC you are investigating.
- `PivotWindow` — Expand if the adversary may have been dormant between stages.

**Performance notes:**
- The `let` statements with `distinct` produce small intermediate result sets that make the final `in()` filters efficient.
- Avoid using `join` for this pattern; cascading `let` + `in()` is cheaper when each stage significantly reduces cardinality.

---

### Pattern 3 — Baseline Deviation Detection

Compare an entity's current behavior against its own historical baseline. This catches credential theft, insider threats, and living-off-the-land techniques that rules based on static thresholds miss.

```kql
// Detect users whose sign-in volume today is anomalously high vs. their 30-day baseline.
let BaselinePeriod = 30d;
let DetectionWindow = 1d;
let DeviationThreshold = 3.0; // Number of standard deviations
let Baselines = SignInLogs
    | where TimeGenerated between (ago(BaselinePeriod) .. ago(DetectionWindow))
    | where ResultType == 0
    | summarize
        DailyCount = count()
        by UserPrincipalName, bin(TimeGenerated, 1d)
    | summarize
        AvgDaily = avg(DailyCount),
        StdDevDaily = stdev(DailyCount)
        by UserPrincipalName;
let CurrentActivity = SignInLogs
    | where TimeGenerated > ago(DetectionWindow)
    | where ResultType == 0
    | summarize CurrentCount = count() by UserPrincipalName;
CurrentActivity
| join kind=inner Baselines on UserPrincipalName
// Guard against division by zero on users with constant behavior
| where StdDevDaily > 0
| extend ZScore = (CurrentCount - AvgDaily) / StdDevDaily
| where ZScore > DeviationThreshold
| project
    UserPrincipalName,
    CurrentCount,
    AvgDaily = round(AvgDaily, 1),
    StdDevDaily = round(StdDevDaily, 1),
    ZScore = round(ZScore, 2)
| order by ZScore desc
```

**Parameters to customize:**
- `BaselinePeriod` — 30d is a good default; shorten for new users, lengthen for highly variable environments.
- `DeviationThreshold` — Start at 3.0 (99.7th percentile); lower to 2.0 for higher sensitivity.

**Performance notes:**
- The inner `bin(TimeGenerated, 1d)` aggregation compresses the baseline to one row per user per day before the outer `summarize`, keeping memory use predictable.
- Estimated cost: ~2× a single-day query due to the 30d baseline scan.

---

### Pattern 4 — Rare Event Analysis

Rare events — commands, processes, or sign-in patterns seen infrequently — often indicate adversary activity. Use `arg_min`, `arg_max`, and `count()` thresholds to surface them.

```kql
// Find processes that have executed on fewer than 3 devices in the past 14 days.
// These rare processes can indicate malware, attacker tools, or LOLBin misuse.
let LookbackPeriod = 14d;
let RarityThreshold = 3; // Max distinct devices to be considered "rare"
DeviceProcessEvents
| where TimeGenerated > ago(LookbackPeriod)
| where isnotempty(FileName)
// Exclude known noisy system processes to reduce false positives
| where FileName !in ("svchost.exe", "conhost.exe", "RuntimeBroker.exe", "taskhostw.exe")
| summarize
    DeviceCount = dcount(DeviceName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SampleCommandLine = arg_min(TimeGenerated, ProcessCommandLine),
    ExecutingUsers = make_set(AccountName, 10)
    by FileName, FolderPath
| where DeviceCount <= RarityThreshold
| project
    FileName,
    FolderPath,
    DeviceCount,
    FirstSeen,
    LastSeen,
    SampleCommandLine = SampleCommandLine_ProcessCommandLine,
    ExecutingUsers
| order by DeviceCount asc, LastSeen desc
```

**Parameters to customize:**
- `RarityThreshold` — Lower to 1 for targeted hunts; raise to 5-10 for noisy environments.
- The `FileName !in (...)` exclusion list — Extend with your environment's known-good processes.

**Performance notes:**
- `dcount()` is an approximation; for exact counts on small cardinalities, use `count()` inside a nested `summarize`.
- `arg_min(TimeGenerated, ProcessCommandLine)` retrieves the command line from the earliest execution — a cheap way to get a sample without a separate `join`.

---

### Pattern 5 — Cross-Table Timeline Correlation

Hunt across multiple tables by building a unified timeline. This reveals attack chains that span authentication, endpoint, and network telemetry.

```kql
// Build a unified timeline for a specific user across sign-in, security, and process events.
let TargetUser = "jsmith@contoso.com";
let HuntWindow = 3d;
let SignIns = SignInLogs
    | where TimeGenerated > ago(HuntWindow)
    | where UserPrincipalName =~ TargetUser
    | project TimeGenerated, EventType = "SignIn",
        Detail = strcat("App=", AppDisplayName, " IP=", IPAddress, " Result=", ResultType),
        SourceTable = "SignInLogs";
let SecurityEvents = SecurityEvent
    | where TimeGenerated > ago(HuntWindow)
    | where Account contains TargetUser or TargetUserName contains "jsmith"
    | project TimeGenerated, EventType = strcat("SecurityEvent-", EventID),
        Detail = strcat("Process=", Process, " Computer=", Computer),
        SourceTable = "SecurityEvent";
let ProcessEvents = DeviceProcessEvents
    | where TimeGenerated > ago(HuntWindow)
    | where AccountUpn =~ TargetUser
    | project TimeGenerated, EventType = "ProcessExec",
        Detail = strcat(FileName, " ", ProcessCommandLine),
        SourceTable = "DeviceProcessEvents";
union SignIns, SecurityEvents, ProcessEvents
| order by TimeGenerated asc
| extend TimeDelta = datetime_diff('second', TimeGenerated, prev(TimeGenerated))
```

**Parameters to customize:**
- `TargetUser` — The UPN or account name of the entity under investigation.
- `HuntWindow` — Narrow for active incidents, expand for slow-burn campaigns.

**Performance notes:**
- `union` of pre-filtered, pre-projected tables is efficient because each leg scans independently and only the small result sets are merged.
- `prev()` is a window function — it requires the data to be sorted (`order by`) first.

## MITRE ATT&CK Context

| Technique | ID | How This Skill Helps |
|---|---|---|
| Valid Accounts | T1078 | Baseline deviation (Pattern 3) detects stolen credentials used outside normal patterns. Entity pivoting (Pattern 2) traces compromised accounts to lateral movement. |
| Phishing | T1566 | Off-hours sign-in hunting (Pattern 1) surfaces initial access from phishing-delivered credential harvests. Rare event analysis (Pattern 4) catches post-phishing payload execution. |
| Command and Scripting Interpreter | T1059 | Rare process analysis (Pattern 4) identifies unusual interpreters (powershell, wscript, cscript) running on endpoints. Timeline correlation (Pattern 5) links script execution to the originating sign-in. |

## False Positive Guidance

| Pattern | Common False Positives | Tuning Advice |
|---|---|---|
| Off-hours sign-ins | Employees in different time zones, automated service accounts, on-call engineers | Exclude known service accounts via a watchlist. Segment by timezone using `IdentityInfo` or Azure AD custom attributes. |
| Baseline deviation | Seasonal spikes (month-end accounting), org-wide events (password reset campaigns) | Increase `DeviationThreshold` or exclude known event dates. Use `weekofyear()` for cyclical baselines. |
| Rare processes | Legitimate new software deployments, IT admin tools used infrequently | Cross-reference with a software deployment log or CMDB. Add recently deployed binaries to the exclusion list. |
| Entity pivot — broad results | Shared IPs (VPN exit nodes, NAT gateways) map to many users | Exclude known corporate egress IPs. Pivot on device ID instead of IP when possible. |

## Tuning Guide

### Environment Sizing

| Environment | Recommended LookbackPeriod | DeviationThreshold | RarityThreshold |
|---|---|---|---|
| Small (< 500 users) | 30d | 2.5 | 2 |
| Medium (500–5,000 users) | 14d | 3.0 | 3 |
| Large (5,000+ users) | 7d | 3.5 | 5 |

### Iterative Tuning Workflow

1. **Run wide** — Start with relaxed thresholds to understand the noise floor.
2. **Review top results** — Triage the first 20 results. Tag true positives and false positives.
3. **Tighten** — Adjust thresholds and exclusions to suppress known FPs.
4. **Automate** — Promote validated queries to Sentinel analytics rules (see *Sentinel Analytics Rules*).
5. **Repeat** — Re-run weekly; threat actors change tactics, baselines shift.

### Performance Optimization Checklist

- [ ] `where` filters appear before `extend`, `join`, and `summarize`
- [ ] Time range filter (`TimeGenerated > ago(...)`) is the first predicate
- [ ] `let` statements produce small intermediate sets for `in()` predicates
- [ ] `project` removes unused columns before `join` or `union`
- [ ] `dcount()` is used instead of `count(distinct ...)` for large cardinalities

## Related Skills

- **[Sentinel Analytics Rules](sentinel-analytics-rules.md)** — Promote validated hunts into automated detection rules.
- **[Incident Investigation](incident-investigation.md)** — When a hunt finds something, use investigation patterns to scope the impact.

## Environment Context

Before executing this skill, check the customer's `.secops/` knowledge framework:

1. **Data location:** Read `.secops/data-sources/data-source-map.yaml` — tables may be in Sentinel, ADX, or external sources
2. **Active migrations:** Read `.secops/data-sources/migrations.yaml` — data may be moving between locations
3. **Workspace config:** Read `.secops/workspaces/` — know the workspace ID, tier, retention, and naming conventions
4. **Compliance:** Read `.secops/compliance/requirements.yaml` — respect data residency and regulatory constraints

If `.secops/` doesn't exist, proceed with defaults but suggest `secops-squad init --secops`.

See `.copilot/skills/secops-environment-context.md` for the full discovery flow.
