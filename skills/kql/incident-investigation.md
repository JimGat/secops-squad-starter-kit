---
title: Incident Investigation
category: kql
difficulty: advanced
mitre_attack:
  - T1021  # Remote Services
  - T1071  # Application Layer Protocol
  - T1048  # Exfiltration Over Alternative Protocol
products:
  - Microsoft Sentinel
  - Microsoft Defender for Endpoint
  - Azure Active Directory
  - Microsoft Defender for Cloud Apps
author: Freamon
version: 1.0.0
---

# Incident Investigation

## Overview

This skill provides the query sequences a SOC analyst uses when investigating a security incident in Microsoft Sentinel. Unlike threat hunting (proactive, hypothesis-driven), incident investigation is reactive — an alert has fired, an incident is open, and you need to determine scope, impact, root cause, and containment actions.

Use this skill when:
- Triaging a new Sentinel incident to determine severity and scope
- Pivoting from an IOC (IP, hash, domain) to find all related activity
- Tracing lateral movement through authentication and network logs
- Building an evidence timeline for a security incident report
- Assessing data exfiltration risk during an active compromise

## Prerequisites

| Requirement | Detail |
|---|---|
| **Tables** | `SecurityIncident`, `SecurityAlert`, `SignInLogs`, `AuditLogs`, `DeviceNetworkEvents`, `DeviceProcessEvents`, `CommonSecurityLog`, `DeviceFileEvents`, `AADNonInteractiveUserSignInLogs` |
| **Workspace** | Sentinel-enabled Log Analytics workspace with ≥90 days retention recommended |
| **Permissions** | `Microsoft Sentinel Responder` or higher |
| **Knowledge** | Familiarity with [Threat Hunting Foundations](threat-hunting-foundations.md) and [Sentinel Analytics Rules](sentinel-analytics-rules.md) |

## Core Patterns

### Pattern 1 — Initial Triage: Incident Timeline and Affected Entities

The first query in any investigation: pull the incident details, all associated alerts, and the entities involved. This gives you the timeline and scope before you dive into raw logs.

```kql
// Initial Triage — Pull incident, alerts, and entities for a specific incident.
let IncidentNumber = "12345"; // Sentinel incident number
// Get the incident metadata
let Incident = SecurityIncident
    | where IncidentNumber == IncidentNumber
    | project
        IncidentName,
        Title,
        Severity,
        Status,
        CreatedTime,
        LastModifiedTime,
        Owner = tostring(Owner.assignedTo),
        AlertIds = AlertIds;
// Get all alerts linked to this incident
let IncidentAlertIds = SecurityIncident
    | where IncidentNumber == IncidentNumber
    | mv-expand AlertId = AlertIds
    | project tostring(AlertId);
let Alerts = SecurityAlert
    | where SystemAlertId in (IncidentAlertIds)
    | project
        TimeGenerated,
        AlertName,
        AlertSeverity,
        Description,
        Tactics,
        Techniques,
        ProviderName,
        Entities,
        ExtendedProperties;
// Extract unique entities from all alerts
Alerts
| mv-expand Entity = parse_json(Entities)
| extend
    EntityType = tostring(Entity.Type),
    EntityValue = case(
        Entity.Type == "account", strcat(Entity.Name, "@", Entity.UPNSuffix),
        Entity.Type == "ip", tostring(Entity.Address),
        Entity.Type == "host", tostring(Entity.HostName),
        Entity.Type == "file", tostring(Entity.Name),
        Entity.Type == "filehash", tostring(Entity.Value),
        tostring(Entity.Name)
    )
| where isnotempty(EntityValue)
| summarize
    AlertCount = dcount(AlertName),
    AlertNames = make_set(AlertName, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by EntityType, EntityValue
| order by AlertCount desc
```

**Parameters to customize:**
- `IncidentNumber` — Replace with the incident you are investigating.

**Performance notes:**
- `SecurityIncident` and `SecurityAlert` are small tables; these queries are very cheap.
- `mv-expand` on `Entities` (JSON array) may multiply rows, but `summarize` collapses them back.

---

### Pattern 2 — IOC Pivot: IP, Hash, and Domain Correlation

Given an IOC, search across all relevant tables to find every touch point. This pattern uses `union` to search multiple data sources in a single query.

```kql
// IOC Pivot — Find all activity related to a suspicious IP across multiple tables.
let IOC_IP = "198.51.100.77";
let InvestigationWindow = 30d;
// Sign-in activity from this IP
let SignInActivity = SignInLogs
    | where TimeGenerated > ago(InvestigationWindow)
    | where IPAddress == IOC_IP
    | project TimeGenerated, Source = "SignInLogs",
        User = UserPrincipalName,
        Detail = strcat("App=", AppDisplayName, " Result=", ResultType),
        RawIP = IPAddress;
// Non-interactive sign-ins (service tokens, app-only auth)
let NonInteractiveActivity = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(InvestigationWindow)
    | where IPAddress == IOC_IP
    | project TimeGenerated, Source = "NonInteractiveSignIn",
        User = UserPrincipalName,
        Detail = strcat("App=", AppDisplayName, " Result=", ResultType),
        RawIP = IPAddress;
// Network connections to/from this IP on endpoints
let NetworkActivity = DeviceNetworkEvents
    | where TimeGenerated > ago(InvestigationWindow)
    | where RemoteIP == IOC_IP or LocalIP == IOC_IP
    | project TimeGenerated, Source = "DeviceNetwork",
        User = InitiatingProcessAccountName,
        Detail = strcat(DeviceName, " ", ActionType, " Port=", RemotePort,
            " Process=", InitiatingProcessFileName),
        RawIP = RemoteIP;
// Firewall / proxy logs via CommonSecurityLog (CEF)
let FirewallActivity = CommonSecurityLog
    | where TimeGenerated > ago(InvestigationWindow)
    | where SourceIP == IOC_IP or DestinationIP == IOC_IP
    | project TimeGenerated, Source = "Firewall/Proxy",
        User = SourceUserName,
        Detail = strcat(DeviceVendor, "/", DeviceProduct, " Action=", DeviceAction,
            " Dst=", DestinationIP, ":", DestinationPort),
        RawIP = iff(SourceIP == IOC_IP, SourceIP, DestinationIP);
union SignInActivity, NonInteractiveActivity, NetworkActivity, FirewallActivity
| order by TimeGenerated asc
| extend TimeSincePrev = datetime_diff('minute', TimeGenerated, prev(TimeGenerated))
```

**Variant — Hash pivot:**
```kql
// Swap the IOC and search file-related tables instead.
let IOC_Hash = "a1b2c3d4e5f6..."; // SHA256
DeviceFileEvents
| where TimeGenerated > ago(30d)
| where SHA256 == IOC_Hash
| project TimeGenerated, DeviceName, FileName, FolderPath,
    ActionType, InitiatingProcessFileName, AccountName
```

**Variant — Domain pivot:**
```kql
let IOC_Domain = "evil-c2.example.com";
DeviceNetworkEvents
| where TimeGenerated > ago(30d)
| where RemoteUrl has IOC_Domain
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
```

**Parameters to customize:**
- `IOC_IP` / `IOC_Hash` / `IOC_Domain` — The indicator you are investigating.
- `InvestigationWindow` — 30d default; extend for APT investigations, narrow for urgent triage.

**Performance notes:**
- Each leg of the `union` scans independently. The `where` on a specific IOC value is highly selective, so even 30-day scans are fast.
- `CommonSecurityLog` can be the largest table in many environments — ensure the `where` filter is the first operator.

---

### Pattern 3 — Lateral Movement Detection

Once an attacker has a foothold, they move laterally using remote services (RDP, SMB, WMI, PSRemoting). This pattern correlates authentication events with network connections to trace the movement path.

```kql
// Lateral Movement Tracing — Follow authentication chains across devices.
let CompromisedAccount = "jsmith@contoso.com";
let InvestigationWindow = 7d;
// Step 1: Find all devices this account authenticated to
let AuthenticatedDevices = SignInLogs
    | where TimeGenerated > ago(InvestigationWindow)
    | where UserPrincipalName =~ CompromisedAccount
    | where ResultType == 0
    | extend DeviceId = tostring(DeviceDetail.deviceId)
    | where isnotempty(DeviceId)
    | distinct DeviceId;
// Step 2: Find remote network connections initiated FROM those devices
// Focus on lateral movement protocols
let LateralPorts = dynamic([3389, 445, 5985, 5986, 22, 135]); // RDP, SMB, WinRM, SSH, RPC
DeviceNetworkEvents
| where TimeGenerated > ago(InvestigationWindow)
| where DeviceId in (AuthenticatedDevices)
| where RemotePort in (LateralPorts)
| where ActionType == "ConnectionSuccess"
| summarize
    ConnectionCount = count(),
    FirstConnection = min(TimeGenerated),
    LastConnection = max(TimeGenerated),
    ProcessesUsed = make_set(InitiatingProcessFileName, 10)
    by DeviceName, RemoteIP, RemotePort, AccountName = InitiatingProcessAccountName
| extend Protocol = case(
    RemotePort == 3389, "RDP",
    RemotePort == 445, "SMB",
    RemotePort in (5985, 5986), "WinRM",
    RemotePort == 22, "SSH",
    RemotePort == 135, "RPC",
    strcat("Port-", RemotePort)
)
| project
    DeviceName,
    RemoteIP,
    Protocol,
    ConnectionCount,
    FirstConnection,
    LastConnection,
    ProcessesUsed,
    AccountName
| order by FirstConnection asc
```

**Parameters to customize:**
- `CompromisedAccount` — The account under investigation.
- `LateralPorts` — Add ports for custom protocols used in your environment.

**Performance notes:**
- `AuthenticatedDevices` is built as a small `distinct` set, making the `in()` filter on `DeviceNetworkEvents` efficient.
- The `ActionType == "ConnectionSuccess"` filter removes connection attempts that failed, reducing noise.

---

### Pattern 4 — Evidence Timeline Construction

Build a single chronological timeline across all relevant data sources for an incident report. This is the query that feeds the incident summary.

```kql
// Evidence Timeline — Unified chronological view for an incident.
let TargetUser = "jsmith@contoso.com";
let TargetDevice = "WKSTN-042";
let TimelineStart = datetime(2025-03-15T08:00:00Z);
let TimelineEnd = datetime(2025-03-16T20:00:00Z);
// Authentication events
let AuthEvents = SignInLogs
    | where TimeGenerated between (TimelineStart .. TimelineEnd)
    | where UserPrincipalName =~ TargetUser
    | project TimeGenerated,
        Category = "Authentication",
        Action = strcat(iff(ResultType == 0, "✅ Success", "❌ Failure"), " → ", AppDisplayName),
        Actor = UserPrincipalName,
        Source = strcat("IP: ", IPAddress, " (", tostring(LocationDetails.city), ")"),
        SourceTable = "SignInLogs";
// Directory changes
let DirectoryEvents = AuditLogs
    | where TimeGenerated between (TimelineStart .. TimelineEnd)
    | where InitiatedBy.user.userPrincipalName =~ TargetUser
       or TargetResources has TargetUser
    | project TimeGenerated,
        Category = "DirectoryChange",
        Action = OperationName,
        Actor = tostring(InitiatedBy.user.userPrincipalName),
        Source = tostring(InitiatedBy.user.ipAddress),
        SourceTable = "AuditLogs";
// Process execution on target device
let ProcessEvents = DeviceProcessEvents
    | where TimeGenerated between (TimelineStart .. TimelineEnd)
    | where DeviceName =~ TargetDevice
    | project TimeGenerated,
        Category = "ProcessExecution",
        Action = strcat(FileName, " ", ProcessCommandLine),
        Actor = AccountUpn,
        Source = DeviceName,
        SourceTable = "DeviceProcessEvents";
// Network connections from target device
let NetworkEvents = DeviceNetworkEvents
    | where TimeGenerated between (TimelineStart .. TimelineEnd)
    | where DeviceName =~ TargetDevice
    | project TimeGenerated,
        Category = "NetworkConnection",
        Action = strcat(ActionType, " → ", RemoteIP, ":", RemotePort,
            " (", InitiatingProcessFileName, ")"),
        Actor = InitiatingProcessAccountName,
        Source = DeviceName,
        SourceTable = "DeviceNetworkEvents";
union AuthEvents, DirectoryEvents, ProcessEvents, NetworkEvents
| order by TimeGenerated asc
| extend
    EventIndex = row_number(),
    TimeDelta = iff(
        row_number() > 1,
        strcat(datetime_diff('second', TimeGenerated, prev(TimeGenerated)), "s"),
        "—"
    )
```

**Parameters to customize:**
- `TargetUser` / `TargetDevice` — The entities central to the incident.
- `TimelineStart` / `TimelineEnd` — Bracket the incident window tightly for readability.

**Performance notes:**
- `between()` on `TimeGenerated` is the most efficient time filter — it tells the engine the exact partition range.
- Each `union` leg projects to the same schema, keeping the merge lightweight.
- `row_number()` and `prev()` are window functions applied after the sort.

---

### Pattern 5 — Data Exfiltration Indicators

Detect signs of data exfiltration by analyzing outbound data volumes, new destinations, and unusual protocols.

```kql
// Data Exfiltration Assessment — Find unusual outbound data transfers.
let InvestigationWindow = 7d;
let BaselinePeriod = 30d;
let VolumeThresholdMB = 100; // Alert on transfers > 100 MB
// Current period: outbound transfers per device per destination
let CurrentTransfers = DeviceNetworkEvents
    | where TimeGenerated > ago(InvestigationWindow)
    | where ActionType == "ConnectionSuccess"
    | where isnotempty(RemoteIP)
    // Exclude internal RFC1918 ranges
    | where not(ipv4_is_private(RemoteIP))
    | summarize
        BytesSent = sum(SentBytes),
        ConnectionCount = count(),
        UniqueProcesses = make_set(InitiatingProcessFileName, 10)
        by DeviceName, RemoteIP, DeviceId;
// Baseline: what destinations did this device normally talk to?
let BaselineDestinations = DeviceNetworkEvents
    | where TimeGenerated between (ago(BaselinePeriod) .. ago(InvestigationWindow))
    | where ActionType == "ConnectionSuccess"
    | where not(ipv4_is_private(RemoteIP))
    | summarize BaselineBytes = sum(SentBytes) by DeviceName, RemoteIP;
// Find transfers to NEW destinations (not seen in baseline)
let NewDestinationTransfers = CurrentTransfers
    | join kind=leftanti BaselineDestinations on DeviceName, RemoteIP;
// Find transfers exceeding volume threshold (to any destination)
let HighVolumeTransfers = CurrentTransfers
    | extend SentMB = round(BytesSent / (1024.0 * 1024.0), 2)
    | where SentMB > VolumeThresholdMB;
// Combine both signals — new destinations OR high volume
union
    (NewDestinationTransfers
        | extend SentMB = round(BytesSent / (1024.0 * 1024.0), 2),
            ExfilIndicator = "NewDestination"),
    (HighVolumeTransfers
        | extend ExfilIndicator = "HighVolume")
| project
    DeviceName,
    RemoteIP,
    SentMB,
    ConnectionCount,
    UniqueProcesses,
    ExfilIndicator
| order by SentMB desc
```

**Parameters to customize:**
- `VolumeThresholdMB` — Adjust based on your environment's normal transfer sizes. Start high (500 MB) and lower after initial review.
- RFC1918 exclusion — Add any additional internal ranges specific to your network.

**Performance notes:**
- `leftanti` join is the most efficient join type here — it returns rows from the left side that have *no* match in the right side, with minimal memory.
- `ipv4_is_private()` is a built-in function that handles 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16.
- The two-pass approach (baseline + current) avoids scanning the full 30 days in a single aggregation.

### User Activity Profiling

Beyond volume-based detection, profile a user's behavior to compare normal vs. anomalous patterns.

```kql
// User Activity Profile — Compare current behavior to established baseline.
let TargetUser = "jsmith@contoso.com";
let ProfileWindow = 7d;
let BaselineWindow = 30d;
// Current profile
let CurrentProfile = SignInLogs
    | where TimeGenerated > ago(ProfileWindow)
    | where UserPrincipalName =~ TargetUser
    | where ResultType == 0
    | summarize
        CurrentSignIns = count(),
        CurrentApps = make_set(AppDisplayName, 50),
        CurrentIPs = make_set(IPAddress, 50),
        CurrentCountries = make_set(tostring(LocationDetails.countryOrRegion), 20),
        CurrentHours = make_set(hourofday(TimeGenerated), 24);
// Baseline profile
let BaselineProfile = SignInLogs
    | where TimeGenerated between (ago(BaselineWindow) .. ago(ProfileWindow))
    | where UserPrincipalName =~ TargetUser
    | where ResultType == 0
    | summarize
        BaselineSignIns = count(),
        BaselineDays = dcount(bin(TimeGenerated, 1d)),
        BaselineApps = make_set(AppDisplayName, 50),
        BaselineIPs = make_set(IPAddress, 50),
        BaselineCountries = make_set(tostring(LocationDetails.countryOrRegion), 20),
        BaselineHours = make_set(hourofday(TimeGenerated), 24);
// Compare: which elements are new (not in baseline)?
CurrentProfile
| extend placeholder = 1
| join kind=inner (BaselineProfile | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend
    NewApps = set_difference(CurrentApps, BaselineApps),
    NewIPs = set_difference(CurrentIPs, BaselineIPs),
    NewCountries = set_difference(CurrentCountries, BaselineCountries),
    NewHours = set_difference(CurrentHours, BaselineHours),
    AvgDailySignIns = round(BaselineSignIns * 1.0 / BaselineDays, 1),
    CurrentDailySignIns = round(CurrentSignIns * 1.0 / toint(ProfileWindow / 1d), 1)
| project
    CurrentSignIns,
    AvgDailySignIns,
    CurrentDailySignIns,
    NewApps,
    NewIPs,
    NewCountries,
    NewHours
```

**Parameters to customize:**
- `TargetUser` — The user under investigation.
- `ProfileWindow` vs. `BaselineWindow` — Keep the profile window short (1-7d) and the baseline long (30d+) for meaningful comparison.

**Performance notes:**
- The `extend placeholder = 1` with `join` is a standard pattern for cross-joining single-row result sets. It is cheap because both sides are a single row.
- `set_difference()` compares two dynamic arrays and returns elements in the first that are not in the second — purpose-built for "what's new" analysis.

## MITRE ATT&CK Context

| Technique | ID | Investigation Pattern |
|---|---|---|
| Remote Services | T1021 | Pattern 3 traces lateral movement via RDP (3389), SMB (445), WinRM (5985/5986), and SSH (22). The port-to-protocol mapping identifies the technique variant (T1021.001 through T1021.006). |
| Application Layer Protocol | T1071 | Pattern 2 (IOC pivot via `DeviceNetworkEvents`) identifies C2 communication over HTTP/HTTPS/DNS. Pattern 5 (exfiltration) catches data transfer over standard application protocols. |
| Exfiltration Over Alternative Protocol | T1048 | Pattern 5 detects exfiltration by comparing current outbound volumes and destinations against baselines. New destinations with high transfer volumes are strong indicators. |

## False Positive Guidance

| Pattern | Common False Positives | Tuning Advice |
|---|---|---|
| IOC pivot — broad matches | Shared hosting IPs serving thousands of domains; CDN IPs (Cloudflare, Akamai) matching many connections | Cross-reference IOC IPs against threat intelligence feeds. Exclude CDN IP ranges from automated pivots. |
| Lateral movement — internal RDP | Help desk using RDP for legitimate remote support; IT admin tools (SCCM, Intune) | Maintain a watchlist of authorized admin workstations. Filter by `AccountName` against a known-admins list. |
| Data exfiltration — high volume | Cloud backup agents, software update downloads, legitimate file-sharing services | Exclude known backup destination IPs. Filter by `InitiatingProcessFileName` to separate known-good processes (OneDrive, backup agents) from suspicious ones. |
| User profiling — new apps | Org-wide rollout of a new SaaS application, seasonal apps (tax software, annual review tools) | Check `AuditLogs` for app consent events that correlate with the new app usage. Exclude org-approved apps by `AppId`. |
| Timeline — high event volume | Noisy devices (domain controllers, file servers) generating thousands of process/network events | Pre-filter timeline queries by process name or remote port. Use `summarize` with `bin(TimeGenerated, 5m)` to bucket dense periods. |

## Tuning Guide

### Investigation Depth by Severity

| Incident Severity | Recommended Approach |
|---|---|
| **Informational** | Run Pattern 1 (triage). If entities are known-benign, close with notes. |
| **Low** | Patterns 1 + 2 (triage + IOC pivot). Check for related incidents. |
| **Medium** | Patterns 1-4 (full investigation). Build timeline, check lateral movement. |
| **High / Critical** | All patterns. Full user profiling, exfiltration assessment, 30d+ lookback. Engage IR team. |

### Retention and Performance Considerations

| Table | Typical Volume | Retention Needed | Notes |
|---|---|---|---|
| `SecurityIncident` | Low | 90d+ | Small table, cheap to query broadly |
| `SecurityAlert` | Low-Medium | 90d+ | Filter by `SystemAlertId` for precision |
| `SignInLogs` | Medium | 90d | High-value for authentication investigations |
| `DeviceProcessEvents` | High | 30d | Largest table in most MDE environments — always filter by device or user first |
| `DeviceNetworkEvents` | High | 30d | Similar to process events — filter early |
| `CommonSecurityLog` | Very High | 30d | CEF logs from firewalls/proxies — can be TB-scale |

### Cross-Workspace Investigation

When data is spread across multiple workspaces (e.g., separate Sentinel workspaces per business unit), use the `workspace()` function:

```kql
// Query across workspaces — replace with your workspace names
union
    (workspace("SOC-Workspace-Prod").SignInLogs
        | where TimeGenerated > ago(7d)
        | where IPAddress == "198.51.100.77"),
    (workspace("SOC-Workspace-Dev").SignInLogs
        | where TimeGenerated > ago(7d)
        | where IPAddress == "198.51.100.77")
| order by TimeGenerated asc
```

**Important:** Cross-workspace queries incur costs on *each* workspace scanned. Always apply tight `where` filters inside each `workspace()` leg, not after the `union`.

## Related Skills

- **[Threat Hunting Foundations](threat-hunting-foundations.md)** — The query primitives (entity pivoting, baseline deviation) used throughout this skill.
- **[Sentinel Analytics Rules](sentinel-analytics-rules.md)** — After an investigation reveals a repeatable pattern, codify it as an analytics rule to detect similar incidents automatically.
