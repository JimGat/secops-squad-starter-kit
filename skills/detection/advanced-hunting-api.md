---
title: Advanced Hunting API & Live Response
category: detection
difficulty: advanced
mitre_attack:
  - T1059      # Command and Scripting Interpreter
  - T1078      # Valid Accounts
  - T1566      # Phishing
  - T1053      # Scheduled Task/Job
  - T1021      # Remote Services
  - T1048      # Exfiltration Over Alternative Protocol
products:
  - Microsoft Defender for Endpoint
  - Microsoft Defender XDR
  - Microsoft Graph Security API
  - Microsoft Sentinel
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# Advanced Hunting API & Live Response

## Overview

Three API surfaces for running Advanced Hunting queries programmatically:

| Surface | Endpoint | Scope | Best For |
|---------|----------|-------|----------|
| **MDE** | `POST /api/advancedqueries/run` | Device tables only | Endpoint-focused sweeps |
| **XDR** | `POST /api/advancedhunting/run` | Cross-product | Multi-domain investigations |
| **Graph** | `POST /security/runHuntingQuery` | Unified (same as XDR) | CI/CD, Graph SDK integration |

**Complements:** [defender-xdr-hunting.md](../kql/defender-xdr-hunting.md) (KQL patterns), [defender-api-wrapper.md](../powershell/defender-api-wrapper.md) (PowerShell wrappers), [query-builder.md](../kql/query-builder.md) (template construction).

## Environment Context

Check `.secops/data-sources/data-source-map.yaml` before calling any API to verify table availability and active migrations.

## Unified Schema — Key Tables

| Table | Domain | Key Columns |
|-------|--------|-------------|
| `DeviceProcessEvents` | MDE | `ProcessCommandLine`, `InitiatingProcessFileName`, `SHA256` |
| `DeviceNetworkEvents` | MDE | `RemoteIP`, `RemotePort`, `RemoteUrl` |
| `DeviceFileEvents` | MDE | `FileName`, `FolderPath`, `SHA256` |
| `DeviceLogonEvents` | MDE | `LogonType`, `AccountName`, `RemoteIP` |
| `DeviceRegistryEvents` | MDE | `RegistryKey`, `RegistryValueName`, `RegistryValueData` |
| `DeviceEvents` | MDE | `ActionType`, `DeviceName`, `FileName` |
| `EmailEvents` | MDO | `SenderFromAddress`, `RecipientEmailAddress`, `DeliveryAction` |
| `EmailAttachmentInfo` | MDO | `FileName`, `FileType`, `SHA256` |
| `IdentityLogonEvents` | MDI | `AccountUpn`, `ActionType`, `Location` |
| `IdentityDirectoryEvents` | MDI | `ActionType`, `TargetAccountUpn` |
| `CloudAppEvents` | MDCA | `ActionType`, `AccountDisplayName`, `Application` |
| `AlertEvidence` | XDR | `EntityType`, `EvidenceRole`, `RemediationStatus` |

## API Endpoints

### MDE Advanced Hunting

```
POST https://api.securitycenter.microsoft.com/api/advancedqueries/run
Authorization: Bearer {token}
Content-Type: application/json

{ "Query": "DeviceProcessEvents | where Timestamp > ago(1h) | where FileName == 'powershell.exe' | take 100" }
```

**Auth:** `AdvancedQuery.Read.All` (app) or `AdvancedQuery.Read` (delegated).
**Limits:** 10K rows, 10-min timeout, 45 calls/min, 10,240 char max query.

### XDR Advanced Hunting

```
POST https://api.security.microsoft.com/api/advancedhunting/run
Authorization: Bearer {token}
Content-Type: application/json

{ "Query": "EmailEvents | where Timestamp > ago(24h) | join DeviceProcessEvents on $left.RecipientObjectId == $right.InitiatingProcessAccountObjectId | take 50" }
```

**Auth:** `AdvancedHunting.Read.All`. Same limits as MDE.

### Microsoft Graph

```
POST https://graph.microsoft.com/v1.0/security/runHuntingQuery
Authorization: Bearer {token}
Content-Type: application/json

{ "Query": "DeviceProcessEvents | where Timestamp > ago(1d) | summarize count() by DeviceName | top 10 by count_" }
```

**Auth:** `ThreatHunting.Read.All`.

## Query Packs

```powershell
# Create a query pack
function New-SecOpsQueryPack {
    param([Parameter(Mandatory)] [string]$PackName, [Parameter(Mandatory)] [string]$ResourceGroup)
    $subId = (Get-SecOpsConfig -File 'environment.yaml').subscription_id
    $uri = "/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/queryPacks/${PackName}?api-version=2019-09-01"
    Invoke-SecOpsRestMethod -Method PUT -Uri $uri -Body @{ location = 'eastus'; properties = @{} } -ApiType ARM
}

# Add a query to a pack
function Add-SecOpsQueryToQueryPack {
    param([string]$PackUri, [string]$DisplayName, [string]$QueryBody, [string[]]$MitreTags)
    Invoke-SecOpsRestMethod -Method PUT -Uri "$PackUri/queries/$(New-Guid)?api-version=2019-09-01" -Body @{
        properties = @{
            displayName = $DisplayName; body = $QueryBody
            tags = @{ mitre_attack = $MitreTags }
        }
    } -ApiType ARM
}
```

## Custom Detections

Create scheduled detection rules from hunting queries:

```json
POST https://api.security.microsoft.com/api/CustomDetections

{
    "queryText": "DeviceProcessEvents | where Timestamp > ago(1h) | where FileName in~ ('certutil.exe','bitsadmin.exe') | where ProcessCommandLine has_any ('http','ftp','urlcache')",
    "title": "LOLBin File Download",
    "severity": "Medium",
    "category": "Execution",
    "mitreTechniques": ["T1105", "T1059"],
    "schedule": { "period": "1H" },
    "impactedAssets": [
        { "assetIdentifier": "DeviceName", "assetType": "Device" }
    ]
}
```

**Actions:** Alert (default), Isolate Device (`Machine.Isolate`), Block File (`Ti.ReadWrite.All`), Restrict App Execution, Initiate Investigation.
**Schedules:** `1H` (high-sev), `3H` (medium), `12H` (low), `24H` (compliance).

## Live Response

### Session Management

```powershell
function New-SecOpsLiveResponseSession {
    param([Parameter(Mandatory)] [string]$MachineId)
    Invoke-SecOpsRestMethod -Method POST `
        -Uri "https://api.securitycenter.microsoft.com/api/machines/$MachineId/runliveresponse" `
        -Body @{ Commands = @(); Comment = "SecOps investigation" } -ApiType MDE
}
```

### Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `getfile` | Download file | `getfile "C:\Windows\Temp\sus.exe"` |
| `putfile` | Upload file to device | `putfile remediation.ps1` |
| `run` | Execute script | `run remediation.ps1` |
| `findfile` | Search for files | `findfile *.dmp` |
| `registry` | Query registry | `registry HKLM\...\Run` |
| `remediate` | Remove file + persistence | `remediate file C:\malware.exe` |

### Forensic Collection Pattern

```powershell
function Invoke-SecOpsForensicCollection {
    param([Parameter(Mandatory)] [string]$MachineId)
    $commands = @(
        @{ type = "GetFile"; params = @(@{ key = "Path"; value = "C:\Windows\System32\winevt\Logs\Security.evtx" }) },
        @{ type = "GetFile"; params = @(@{ key = "Path"; value = "C:\Windows\System32\winevt\Logs\PowerShell-Operational.evtx" }) },
        @{ type = "RunScript"; params = @(@{ key = "ScriptName"; value = "collect-artifacts.ps1" }) }
    )
    Invoke-SecOpsRestMethod -Method POST `
        -Uri "https://api.securitycenter.microsoft.com/api/machines/$MachineId/runliveresponse" `
        -Body @{ Commands = $commands; Comment = "Forensic collection" } -ApiType MDE
}
```

### Safety Considerations

1. `run`/`remediate` require **Security Administrator** role — separate from investigation RBAC
2. Sessions auto-terminate after **30 minutes** of inactivity
3. Every command logged in MDE **Action Center** — reference `MachineActionId` in tickets
4. Avoid `getfile` on multi-GB files during business hours (bandwidth impact)
5. All library scripts must pass code review before upload

## Hunting Patterns by MITRE ATT&CK

### Initial Access (TA0001)

```kql
// T1566 — Phishing with suspicious attachments
EmailEvents
| where Timestamp > ago(24h)
| where DeliveryAction == "Delivered"
| join kind=inner EmailAttachmentInfo on NetworkMessageId
| where FileType in ("exe", "dll", "scr", "js", "vbs", "hta", "ps1")
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, FileName, SHA256

// T1550.001 — OAuth token abuse
CloudAppEvents
| where Timestamp > ago(24h)
| where ActionType == "Consent to application."
| where RawEventData has "AllPrincipals"
| project Timestamp, AccountDisplayName, Application
```

### Execution (TA0002)

```kql
// T1059.001 — Encoded PowerShell
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "FromBase64String", "iex")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// T1218 — LOLBins
let lolbins = dynamic(["certutil.exe", "bitsadmin.exe", "msiexec.exe", "regsvr32.exe", "rundll32.exe"]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ (lolbins)
| where ProcessCommandLine has_any ("http", "ftp", "\\\\", "script:")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

### Persistence (TA0003)

```kql
// T1053.005 — Scheduled task creation
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "ScheduledTaskCreated"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, AdditionalFields

// T1547.001 — Registry run key modification
DeviceRegistryEvents
| where Timestamp > ago(24h)
| where RegistryKey has @"\CurrentVersion\Run"
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

### Lateral Movement (TA0008)

```kql
// T1021.001 — RDP lateral movement (admin pivoting)
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "RemoteInteractive"
| where IsLocalAdmin == true
| summarize Targets = make_set(DeviceName), Count = dcount(DeviceName) by AccountName
| where Count > 3

// T1021.002 — SMB/PsExec
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 445
| where InitiatingProcessFileName in~ ("psexec.exe", "psexesvc.exe")
| project Timestamp, DeviceName, RemoteIP, InitiatingProcessCommandLine
```

### Exfiltration (TA0010)

```kql
// T1041 — Large outbound transfers
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| summarize BytesSent = sum(SentBytes) by DeviceName, RemoteIP
| where BytesSent > 100000000  // 100 MB

// T1567 — Cloud storage exfil
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any ("dropbox.com", "mega.nz", "anonfiles.com", "file.io", "transfer.sh")
| project Timestamp, DeviceName, AccountName, RemoteUrl, SentBytes
```

## PowerShell Integration

```powershell
function Invoke-SecOpsAdvancedHunting {
    param(
        [Parameter(Mandatory)] [string]$Query,
        [ValidateSet('MDE','XDR','Graph')] [string]$ApiSurface = 'XDR'
    )
    $endpoints = @{
        MDE   = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
        XDR   = "https://api.security.microsoft.com/api/advancedhunting/run"
        Graph = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
    }
    # GCC-High endpoint override
    $env = Get-SecOpsConfig -File 'environment.yaml'
    if ($env.cloud -eq 'gcc-high') {
        $endpoints.MDE  = "https://api-gcc.securitycenter.microsoft.us/api/advancedqueries/run"
        $endpoints.XDR  = "https://api-gcc.security.microsoft.us/api/advancedhunting/run"
        $endpoints.Graph = "https://graph.microsoft.us/v1.0/security/runHuntingQuery"
    }
    $result = Invoke-SecOpsRestMethod -Method POST -Uri $endpoints[$ApiSurface] -Body @{ Query = $Query } -ApiType $ApiSurface
    if (-not $result.ok) { Write-Warning "Hunt failed: $($result.error)"; return $result }
    # Parse into typed objects
    $result.data.Results | ForEach-Object {
        $row = $_; $obj = [ordered]@{}
        foreach ($col in $result.data.Schema) { $obj[$col.Name] = $row.($col.Name) }
        [PSCustomObject]$obj
    }
}
```

## Rate Limits & Error Handling

| API | Limit | Max Rows | Timeout |
|-----|-------|----------|---------|
| MDE | 45/min tenant, 15/min user | 10,000 | 10 min |
| XDR | 45/min tenant, 15/min user | 10,000 | 10 min |
| Graph | Varies | 10,000 | 10 min |

| HTTP | Meaning | Action |
|------|---------|--------|
| 429 | Rate limited | Respect `Retry-After`, exponential backoff |
| 400 | Syntax error | Validate with `lib/kql-validator/` first |
| 403 | No permissions | Check app registration per API surface |
| 504 | Timeout | Add time filters, optimize KQL |

See [rate-limiting.md](../powershell/rate-limiting.md) for backoff implementation.

## Related Skills

- [defender-xdr-hunting.md](../kql/defender-xdr-hunting.md) — KQL patterns for XDR tables
- [threat-hunting-foundations.md](../kql/threat-hunting-foundations.md) — Hunting methodology
- [defender-api-wrapper.md](../powershell/defender-api-wrapper.md) — PowerShell Defender wrappers
- [query-builder.md](../kql/query-builder.md) — KQL template construction and validation
