---
title: Defender XDR Advanced Hunting
category: kql
difficulty: intermediate
mitre_attack:
  - T1059  # Command and Scripting Interpreter
  - T1071  # Application Layer Protocol
  - T1078  # Valid Accounts
  - T1566  # Phishing
  - T1053  # Scheduled Task/Job
products:
  - Microsoft Defender for Endpoint
  - Microsoft Defender for Office 365
  - Microsoft Defender for Identity
  - Microsoft Defender for Cloud Apps
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Defender XDR Advanced Hunting

## Overview

Microsoft Defender XDR's Advanced Hunting provides a unified query interface across endpoint, email, identity, and cloud app telemetry. This skill covers the key tables, their schemas, and proven hunting patterns for each domain.

Use this skill when:
- Hunting for threats across the Defender XDR dataset (endpoint + email + identity + cloud apps)
- Building custom detections for Defender XDR custom detection rules
- Investigating alerts that span multiple Defender products
- Tracing attack chains from initial access (email) to execution (endpoint) to persistence (identity)

## Prerequisites

| Requirement | Detail |
|---|---|
| **Tables** | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `IdentityLogonEvents`, `IdentityQueryEvents`, `IdentityDirectoryEvents`, `CloudAppEvents` |
| **Workspace** | Microsoft 365 Defender portal Advanced Hunting, or Sentinel with M365 Defender connector |
| **Permissions** | `Security Reader` or `Security Operator` in Microsoft 365 Defender |
| **Data connectors** | Microsoft 365 Defender data connector (if using from Sentinel) |

## Core Patterns

### Pattern 1 — Suspicious Process Execution Chains (Endpoint)

Detect process trees where a user-facing application spawns a suspicious child process — a common pattern in macro-based malware, exploit chains, and LOLBin abuse.

```kql
// Detect Office applications spawning suspicious child processes.
// Covers macro execution, DDE, and exploit-based code execution.
let LookbackPeriod = 7d;
let OfficeProcesses = dynamic(["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe"]);
let SuspiciousChildren = dynamic(["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe"]);
DeviceProcessEvents
| where TimeGenerated > ago(LookbackPeriod)
| where InitiatingProcessFileName in~ (OfficeProcesses)
| where FileName in~ (SuspiciousChildren)
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    ParentProcess = InitiatingProcessFileName,
    ChildProcess = FileName,
    CommandLine = ProcessCommandLine,
    FolderPath,
    SHA256 = SHA256
| summarize
    Occurrences = count(),
    Devices = make_set(DeviceName, 10),
    SampleCommandLine = arg_min(TimeGenerated, CommandLine)
    by ParentProcess, ChildProcess, AccountName
| order by Occurrences desc
```

**Parameters to customize:**
- `OfficeProcesses` — Add other document handlers relevant to your environment (e.g., `acrord32.exe` for PDF exploits).
- `SuspiciousChildren` — Extend with LOLBins specific to your threat model.

**Performance notes:**
- The `in~` operator performs case-insensitive matching against a dynamic array — efficient for small allow/block lists.
- `InitiatingProcessFileName` is indexed in DeviceProcessEvents; filtering on it first reduces the scan significantly.

---

### Pattern 2 — Phishing Email Analysis (Email Events)

Trace phishing campaigns from delivery through to user interaction, linking email events with URL and attachment metadata.

```kql
// Find emails delivered with suspicious URLs or attachments from external senders.
let LookbackPeriod = 7d;
let SuspiciousExtensions = dynamic(["exe", "scr", "js", "vbs", "bat", "ps1", "hta", "iso", "img", "vhd"]);
// Stage 1: Emails with suspicious attachments
let SuspiciousAttachments = (EmailAttachmentInfo
    | where Timestamp > ago(LookbackPeriod)
    | where FileType in~ (SuspiciousExtensions)
    | project NetworkMessageId, FileName, FileType, SHA256);
// Stage 2: Emails with recently registered or suspicious URLs
let SuspiciousUrls = (EmailUrlInfo
    | where Timestamp > ago(LookbackPeriod)
    | where UrlDomain !endswith ".microsoft.com"
        and UrlDomain !endswith ".office.com"
        and UrlDomain !endswith ".sharepoint.com"
    | project NetworkMessageId, Url, UrlDomain);
// Stage 3: Join with email delivery events
EmailEvents
| where Timestamp > ago(LookbackPeriod)
| where DeliveryAction == "Delivered"
| where SenderFromDomain != "" and SenderFromDomain !endswith "contoso.com"  // External senders
| join kind=leftouter SuspiciousAttachments on NetworkMessageId
| join kind=leftouter SuspiciousUrls on NetworkMessageId
| where isnotempty(FileName) or isnotempty(Url)
| project
    Timestamp,
    Subject,
    SenderFromAddress,
    RecipientEmailAddress,
    AttachmentName = FileName,
    AttachmentType = FileType,
    SuspiciousUrl = Url,
    UrlDomain,
    DeliveryAction,
    NetworkMessageId
| order by Timestamp desc
```

**Parameters to customize:**
- `SuspiciousExtensions` — Update based on current threat landscape; `.iso`, `.img`, and `.vhd` are increasingly used to bypass Mark of the Web.
- `SenderFromDomain` filter — Replace `contoso.com` with your organization's domain(s).

**Performance notes:**
- `EmailAttachmentInfo` and `EmailUrlInfo` are child tables — always join to `EmailEvents` on `NetworkMessageId` for context.
- Use `leftouter` join so emails with only URLs (no attachments) or only attachments (no URLs) are included.

---

### Pattern 3 — Identity Threat Detection (Defender for Identity)

Detect credential attacks, reconnaissance, and lateral movement using Defender for Identity tables.

```kql
// Detect potential LDAP reconnaissance — excessive LDAP queries from a single device.
let LookbackPeriod = 3d;
let QueryThreshold = 100;
IdentityQueryEvents
| where Timestamp > ago(LookbackPeriod)
| where ActionType == "LDAP query"
| summarize
    QueryCount = count(),
    DistinctQueries = dcount(QueryTarget),
    QueryTargets = make_set(QueryTarget, 25),
    DistinctProtocols = dcount(Protocol)
    by DeviceName, AccountUpn
| where QueryCount > QueryThreshold
| order by QueryCount desc
```

```kql
// Detect pass-the-hash and pass-the-ticket activity via identity logon anomalies.
let LookbackPeriod = 7d;
IdentityLogonEvents
| where Timestamp > ago(LookbackPeriod)
| where LogonType in ("Interactive", "RemoteInteractive", "NewCredentials")
// Focus on logons from unexpected protocols or unusual auth methods
| where Protocol in ("Ntlm", "Kerberos")
| summarize
    LogonCount = count(),
    DistinctDevices = dcount(DeviceName),
    Devices = make_set(DeviceName, 20),
    DistinctTargets = dcount(TargetDeviceName),
    Targets = make_set(TargetDeviceName, 20),
    LogonTypes = make_set(LogonType)
    by AccountUpn, Protocol
| where DistinctTargets > 5 // User authenticating to many targets may indicate lateral movement
| order by DistinctTargets desc
```

**Parameters to customize:**
- `QueryThreshold` — Adjust based on your environment's normal LDAP query volume.
- `DistinctTargets > 5` — Raise for admin accounts that legitimately access many servers.

**Performance notes:**
- `IdentityQueryEvents` can be high-volume in Active Directory environments. Always filter by `ActionType` first.
- `IdentityLogonEvents` records are generated by Defender for Identity sensors on domain controllers — ensure sensor health for complete coverage.

---

### Pattern 4 — Cloud App Shadow IT Detection (CASB)

Use `CloudAppEvents` from Defender for Cloud Apps to detect unauthorized application usage and data exfiltration to unmanaged cloud services.

```kql
// Detect uploads to unsanctioned cloud storage services.
let LookbackPeriod = 14d;
let SanctionedApps = dynamic(["Microsoft OneDrive for Business", "Microsoft SharePoint Online", "Microsoft Teams"]);
CloudAppEvents
| where Timestamp > ago(LookbackPeriod)
| where ActionType in ("FileUploaded", "FileShared", "FileSyncUploadedFull")
| where Application !in (SanctionedApps)
| summarize
    UploadCount = count(),
    TotalBytes = sum(RawEventData.FileSize),
    DistinctFiles = dcount(tostring(RawEventData.FileName)),
    SampleFiles = make_set(tostring(RawEventData.FileName), 10)
    by AccountDisplayName, Application, AccountObjectId
| where UploadCount > 5
| extend TotalMB = round(todouble(TotalBytes) / 1048576.0, 2)
| project AccountDisplayName, Application, UploadCount, DistinctFiles, TotalMB, SampleFiles
| order by TotalMB desc
```

**Parameters to customize:**
- `SanctionedApps` — Populate with your organization's approved cloud storage services.
- `UploadCount > 5` — Threshold to filter out incidental usage.

**Performance notes:**
- `CloudAppEvents` uses `RawEventData` for many fields — extract only what you need with `tostring()` to avoid schema issues.
- `RawEventData.FileSize` may not be populated for all cloud apps; handle nulls with `coalesce()`.

---

### Pattern 5 — Full Attack Chain: Email → Endpoint → Identity

The power of Defender XDR is correlating across domains. This pattern traces an attack from a phishing email to endpoint execution to identity compromise.

```kql
// Trace a full attack chain: phishing email → endpoint execution → credential access.
let LookbackPeriod = 7d;
let TargetRecipient = "victim@contoso.com";
// Stage 1: Find delivered emails to the target
let PhishingEmails = (EmailEvents
    | where Timestamp > ago(LookbackPeriod)
    | where RecipientEmailAddress =~ TargetRecipient
    | where DeliveryAction == "Delivered"
    | project EmailTimestamp = Timestamp, Subject, SenderFromAddress, NetworkMessageId);
// Stage 2: Did the user click any URLs from those emails?
let ClickedUrls = (EmailUrlInfo
    | where Timestamp > ago(LookbackPeriod)
    | join kind=inner PhishingEmails on NetworkMessageId
    | project NetworkMessageId, Url, UrlDomain, EmailTimestamp);
// Stage 3: Processes launched on the user's device after email delivery
let UserDevices = (DeviceLogonEvents
    | where Timestamp > ago(LookbackPeriod)
    | where AccountUpn =~ TargetRecipient
    | where LogonType == "Interactive"
    | distinct DeviceId, DeviceName);
DeviceProcessEvents
| where Timestamp > ago(LookbackPeriod)
| where DeviceId in ((UserDevices | project DeviceId))
// Focus on processes after the earliest email delivery
| join kind=inner (PhishingEmails | summarize EarliestEmail = min(EmailTimestamp)) on 1==1
| where Timestamp >= EarliestEmail
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "certutil.exe", "mshta.exe", "rundll32.exe")
| project
    Timestamp,
    DeviceName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    AccountName
| order by Timestamp asc
```

**Parameters to customize:**
- `TargetRecipient` — The user being investigated.
- `FileName in~(...)` — Expand the suspicious process list based on your threat intel.

**Performance notes:**
- This query chains multiple tables — each stage filters heavily before the next join to control cardinality.
- For large environments, add a device filter (specific `DeviceName`) to avoid scanning all endpoint telemetry.
- In Sentinel, the M365 Defender connector streams these tables with a `Timestamp` column (not `TimeGenerated`). Use `Timestamp` in Advanced Hunting; use `TimeGenerated` in Sentinel.

## MITRE ATT&CK Context

| Technique | ID | How This Skill Helps |
|---|---|---|
| Command and Scripting Interpreter | T1059 | Pattern 1 detects Office → script interpreter chains (PowerShell, cmd, wscript). |
| Phishing | T1566 | Patterns 2 and 5 trace phishing emails from delivery through URL clicks to payload execution. |
| Valid Accounts | T1078 | Pattern 3 detects credential theft via pass-the-hash/ticket through identity logon anomalies. |
| Application Layer Protocol | T1071 | Pattern 4 identifies data exfiltration to unsanctioned cloud apps via non-standard channels. |
| Scheduled Task/Job | T1053 | Extend Pattern 1 by adding `DeviceRegistryEvents` to detect persistence via scheduled tasks created after process execution. |

## False Positive Guidance

| Pattern | Common False Positives | Tuning Advice |
|---|---|---|
| Office → suspicious child process | Legitimate macros in finance/accounting (Excel → PowerShell for data ETL) | Whitelist specific command-line patterns tied to known-good scripts. Use `ProcessCommandLine contains` filters. |
| Phishing email detection | Internal phishing simulations from security awareness tools | Exclude sender domains used by your phishing simulation vendor. |
| LDAP reconnaissance | Service accounts performing directory sync or monitoring | Exclude known service accounts by UPN pattern; set higher threshold for accounts tagged in a watchlist. |
| Shadow IT uploads | Users uploading to personal OneDrive (consumer) for legitimate remote work | Distinguish between managed and unmanaged OneDrive instances via `Application` field. |

## Tuning Guide

### Table Reference Quick Guide

| Domain | Key Tables | Primary Keys |
|---|---|---|
| Endpoint | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `DeviceRegistryEvents` | `DeviceId`, `DeviceName` |
| Email | `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `EmailPostDeliveryEvents` | `NetworkMessageId` |
| Identity | `IdentityLogonEvents`, `IdentityQueryEvents`, `IdentityDirectoryEvents` | `AccountUpn`, `AccountObjectId` |
| Cloud Apps | `CloudAppEvents` | `AccountObjectId`, `Application` |

### Performance Optimization Checklist

- [ ] Time filter uses `Timestamp` (not `TimeGenerated`) in Advanced Hunting portal
- [ ] `in~` used for case-insensitive array matching instead of multiple `or` conditions
- [ ] Each stage in a multi-table chain filters independently before joins
- [ ] `project` removes unused columns before `join` or `union`
- [ ] Dynamic arrays used for allow/block lists instead of repeated `or` conditions
- [ ] Command-line analysis uses `contains` or `has` (not `matches regex`) for performance

## Related Skills

- **[Threat Hunting Foundations](threat-hunting-foundations.md)** — Core hunting methodology that applies across all Defender XDR tables.
- **[Entra Sign-In Analysis](entra-signin-analysis.md)** — Deep-dive into identity sign-in patterns beyond what Defender for Identity provides.
- **[Detection Tuning](detection-tuning.md)** — Techniques for reducing false positives in Defender XDR custom detection rules.
- **[Sentinel Analytics Rules](sentinel-analytics-rules.md)** — Promote validated hunts into scheduled analytics rules.
