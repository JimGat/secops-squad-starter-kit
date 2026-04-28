---
title: Defender for Endpoint
category: msft-security
difficulty: intermediate
mitre_attack:
  - T1059  # Command and Scripting Interpreter
  - T1203  # Exploitation for Client Execution
  - T1053  # Scheduled Task/Job
  - T1547  # Boot or Logon Autostart Execution
products:
  - Microsoft Defender for Endpoint
  - Microsoft Intune
  - Microsoft Defender XDR
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# Defender for Endpoint

## Overview

Microsoft Defender for Endpoint (MDE) provides endpoint protection, detection, and response across Windows, macOS, Linux, iOS, and Android devices. This skill covers onboarding methods, Attack Surface Reduction (ASR) rules, custom indicators, Live Response, device group configuration, and automated investigation.

Use this skill when:
- Onboarding devices to MDE via Intune, GPO, SCCM, or local script
- Designing and deploying ASR rules
- Creating custom indicators (IOCs) for threat response
- Performing remote investigation with Live Response
- Configuring device groups and RBAC for tiered SOC access

## Prerequisites

| Requirement | Detail |
|---|---|
| **Licensing** | Microsoft Defender for Endpoint P1/P2, M365 E5, or E5 Security |
| **Permissions** | `Security Administrator` for config; `Security Operator` for response |
| **Portal** | security.microsoft.com > Settings > Endpoints |
| **OS Support** | Windows 10/11, Server 2016+, macOS 12+, Linux (RHEL 7+, Ubuntu 18.04+) |

## Configuration Patterns

### Onboarding Methods

| Method | Best For | Scale | Automation |
|---|---|---|---|
| **Microsoft Intune** | Cloud-managed devices | Enterprise | Full — compliance policies enforce onboarding |
| **Group Policy (GPO)** | Domain-joined on-prem devices | Enterprise | Full — apply to OUs |
| **SCCM/MECM** | Hybrid environments | Enterprise | Full — task sequences |
| **Local script** | Lab/test environments, servers | Small | Manual per device |
| **VDI script** | Non-persistent VDI | Special | Per-session onboarding |

**Intune Onboarding:**

```powershell
# Create Intune endpoint detection and response policy
# Portal: Intune admin center > Endpoint security > Endpoint detection and response

# Intune configuration profile settings:
# - Microsoft Defender for Endpoint client configuration package type: Auto from connector
# - Sample sharing: All (send all file samples automatically)
# - Expedite telemetry reporting frequency: Enable

# Verify onboarding status
Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All"

$devices = Get-MgDeviceManagementManagedDevice -Filter "operatingSystem eq 'Windows'" -Top 100
$devices | Select-Object DeviceName, ComplianceState, 
    @{N='MDE_Onboarded';E={$_.DeviceHealthAttestationState}} | Format-Table
```

**GPO Onboarding:**

```powershell
# Download onboarding package from security.microsoft.com
# Settings > Endpoints > Onboarding > Select OS > Download package

# GPO deployment:
# 1. Create GPO: "MDE Onboarding"
# 2. Computer Configuration > Preferences > Windows Settings > Files
#    Source: \\share\mde\WindowsDefenderATPOnboardingScript.cmd
#    Destination: C:\Windows\Temp\MDE\OnboardingScript.cmd
# 3. Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks
#    Action: Create, Run once at startup
#    Program: cmd.exe /c C:\Windows\Temp\MDE\OnboardingScript.cmd

# Verify via device
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
$status = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
Write-Host "Onboarding State: $($status.OnboardingState)" # 1 = onboarded
Write-Host "Org ID: $($status.OrgId)"
```

**Local Script:**

```powershell
# For test/lab environments or individual servers
# Download from: security.microsoft.com > Settings > Endpoints > Onboarding

# Run the onboarding script
& "C:\path\to\WindowsDefenderATPLocalOnboardingScript.cmd"

# Verify connectivity
$testUrl = "https://winatp-gw-cus.microsoft.com/api/test"
$response = Invoke-WebRequest -Uri $testUrl -UseBasicParsing
Write-Host "Connectivity test: $($response.StatusCode)"
```

### Attack Surface Reduction (ASR) Rules

```powershell
# ASR Rule Configuration via PowerShell / Intune
# Mode: 0 = Disabled, 1 = Block, 2 = Audit, 6 = Warn

$asrRules = @{
    # Block abuse of exploited vulnerable signed drivers
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = 1
    
    # Block Adobe Reader from creating child processes
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = 1
    
    # Block all Office applications from creating child processes
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = 1
    
    # Block credential stealing from Windows LSASS
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = 1
    
    # Block executable content from email client and webmail
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = 1
    
    # Block execution of potentially obfuscated scripts
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = 2  # Audit first
    
    # Block JavaScript or VBScript from launching downloaded executable content
    "d3e037e1-3eb8-44c8-a917-57927947596d" = 1
    
    # Block Office applications from creating executable content
    "3b576869-a4ec-4529-8536-b80a7769e899" = 1
    
    # Block Office applications from injecting code into other processes
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = 1
    
    # Block persistence through WMI event subscription
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = 1
    
    # Block process creations originating from PSExec and WMI commands
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = 2  # Audit first
    
    # Block untrusted and unsigned processes that run from USB
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = 1
    
    # Block Win32 API calls from Office macros
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = 1
    
    # Use advanced protection against ransomware
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = 1
}

# Apply via PowerShell
foreach ($rule in $asrRules.GetEnumerator()) {
    Set-MpPreference -AttackSurfaceReductionRules_Ids $rule.Key `
        -AttackSurfaceReductionRules_Actions $rule.Value
}

# Verify ASR rules
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
```

**ASR Deployment Strategy:**

| Phase | Duration | Mode | Action |
|---|---|---|---|
| **Audit** | 2–4 weeks | Mode 2 (Audit) | Enable all rules in audit mode; collect telemetry |
| **Analyze** | 1 week | — | Review audit events; identify legitimate business processes triggering rules |
| **Exclude** | 1 week | — | Create exclusions for legitimate processes; document each exclusion |
| **Block (Pilot)** | 2 weeks | Mode 1 (Block) | Enable blocking on pilot group; monitor for impact |
| **Block (Production)** | Ongoing | Mode 1 (Block) | Roll out to production; keep 2–3 rules in audit if high noise |

```kql
// Monitor ASR rule audit events
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType startswith "Asr"
| summarize EventCount = count() by ActionType, FileName, FolderPath
| sort by EventCount desc
| take 50
```

### Custom Indicators (IOCs)

```powershell
# Create custom indicators via API
$token = Get-MdeAccessToken  # Your auth function

$indicators = @(
    @{
        indicatorValue = "44d88612fea8a8f36de82e1278abb02f"  # EICAR test hash
        indicatorType = "FileSha256"
        action = "AlertAndBlock"
        title = "Known malware hash — EICAR test"
        description = "Detected known malicious file hash. Incident: IR-2026-042"
        severity = "High"
        recommendedActions = "Isolate device and collect forensic triage"
        expirationTime = "2026-07-28T00:00:00Z"
    },
    @{
        indicatorValue = "192.168.100.50"
        indicatorType = "IpAddress"
        action = "Alert"
        title = "Suspicious C2 IP — ThreatIntel feed"
        description = "IP associated with APT group activity. Source: TI-Feed-2026-04"
        severity = "Medium"
        recommendedActions = "Investigate network connections to this IP"
        expirationTime = "2026-05-28T00:00:00Z"
    },
    @{
        indicatorValue = "evil-domain.example.com"
        indicatorType = "DomainName"
        action = "AlertAndBlock"
        title = "Known C2 domain"
        description = "Domain used for C2 communications. Source: OSINT"
        severity = "High"
        recommendedActions = "Block at firewall; investigate affected devices"
        expirationTime = "2026-06-28T00:00:00Z"
    }
)

foreach ($ioc in $indicators) {
    Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/indicators" `
        -Method Post `
        -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } `
        -Body ($ioc | ConvertTo-Json)
}
```

**Indicator types and actions:**

| Type | Values | Actions Available |
|---|---|---|
| **FileSha1 / FileSha256 / FileMd5** | Hash value | Alert, AlertAndBlock, Allowed |
| **IpAddress** | IPv4/IPv6 | Alert, AlertAndBlock, Allowed |
| **DomainName** | FQDN | Alert, AlertAndBlock, Allowed |
| **Url** | Full URL | Alert, AlertAndBlock, Allowed |
| **CertificateThumbprint** | Certificate hash | Alert, AlertAndBlock, Allowed |

### Live Response

```powershell
# Live Response commands for remote investigation
# Portal: security.microsoft.com > Device page > Live Response

# Common investigation commands:
# dir C:\Users\<user>\Downloads                    # Check recent downloads
# fileinfo C:\Windows\Temp\suspicious.exe          # Get file metadata
# getfile C:\Windows\Temp\suspicious.exe           # Download file for analysis
# run Get-Process | Where-Object {$_.Path}         # List running processes with paths
# run Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} # Active connections
# run Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'}          # Scheduled tasks
# trace -pid <PID>                                 # Process trace

# Remediation commands (require elevated Live Response):
# remediate file C:\Windows\Temp\malware.exe       # Quarantine file
# remediate process <PID>                          # Kill process
# undo file C:\Windows\Temp\malware.exe            # Restore from quarantine
```

### Device Groups and RBAC

```powershell
# Device group strategy for tiered access
# Portal: security.microsoft.com > Settings > Endpoints > Device groups

# Recommended device group structure:
# 1. "Tier 0 — Domain Controllers"     → Full access: Tier 0 SOC team only
# 2. "Tier 1 — Servers"                → Full access: SOC + Server admins
# 3. "Tier 2 — Executive Workstations" → Full access: SOC only (privacy)
# 4. "Standard Workstations"           → Full access: SOC + Help Desk
# 5. "BYOD / Unmanaged"                → Read-only: SOC; no remediation

# Device group membership rules (tag-based):
# Tier 0: Device tag = "DomainController" OR OS contains "Server" AND name starts with "DC"
# Tier 1: OS contains "Server" AND tag != "DomainController"  
# Executive: Tag = "Executive" OR user department = "C-Suite"
# Standard: Default group for remaining devices
```

### Automated Investigation and Remediation

| Level | What It Does | Best For |
|---|---|---|
| **No automation** | Manual only | Pilot phase |
| **Semi — require approval for all folders** | Investigate auto; all remediation needs approval | Standard workstations |
| **Semi — require approval for core folders** | Auto-remediate outside core folders | Trusted device groups |
| **Semi — require approval for non-temp folders** | Auto-remediate temp and download folders | Servers |
| **Full** | Investigate and remediate automatically | Low-risk devices, well-tuned environment |

## Integration Points

- **Defender XDR** — Device events and alerts flow into unified incident queue
- **Microsoft Intune** — Compliance policies enforce onboarding; device health attestation
- **Microsoft Sentinel** — Endpoint telemetry available via Defender XDR connector
- **Defender for Cloud** — Server protection via Defender for Servers plan
- **Threat Intelligence** — Custom indicators sync with TI feeds

## Operational Procedures

### Device Health Monitoring

```kql
// Check device onboarding health
DeviceInfo
| where Timestamp > ago(1h)
| summarize arg_max(Timestamp, *) by DeviceId
| summarize
    TotalDevices = count(),
    OnboardedWindows = countif(OSPlatform == "Windows"),
    OnboardedMacOS = countif(OSPlatform == "macOS"),
    OnboardedLinux = countif(OSPlatform == "Linux")
```

```kql
// ASR rule block events — what's being prevented
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType startswith "Asr" and ActionType endswith "Blocked"
| summarize BlockCount = count() by ActionType, DeviceName, FileName
| sort by BlockCount desc
| take 25
```

```kql
// Devices not seen in 7 days — potentially offline or de-onboarded
DeviceInfo
| summarize LastSeen = max(Timestamp) by DeviceName, DeviceId, OSPlatform
| where LastSeen < ago(7d)
| sort by LastSeen asc
```

### Incident Response Triage

```kql
// Investigate a compromised device — full activity timeline
let targetDevice = "WORKSTATION-001";
union DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents
| where Timestamp > ago(24h)
| where DeviceName == targetDevice
| project Timestamp, ActionType, FileName, ProcessCommandLine, 
    RemoteIP, RemoteUrl, RegistryKey, InitiatingProcessFileName
| sort by Timestamp desc
| take 200
```

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| Device not showing in portal | Onboarding failed or connectivity issue | Run `MDATPClientAnalyzer.cmd`; check outbound HTTPS |
| ASR rule blocking legitimate app | Rule too broad | Add process exclusion; test in audit mode first |
| Custom indicator not blocking | Indicator type mismatch or expired | Verify hash type matches; check expiration date |
| Live Response connection fails | Device offline or firewall blocking | Verify device is online; check Live Response is enabled in settings |
| Automated investigation stuck | Too many pending actions | Clear pending action queue; increase automation level |
| Sensor data delayed | High device volume or network throttling | Check Streaming API health; verify diagnostic data settings |

## Related Skills

- **[Defender XDR Configuration](defender-xdr-configuration.md)** — Endpoint alerts in the unified portal
- **[Defender for Cloud Policies](defender-for-cloud-policies.md)** — Server protection via Defender for Servers
- **[Defender for Identity](defender-for-identity.md)** — Identity + endpoint correlation
- **[Sentinel Workspace Setup](sentinel-workspace-setup.md)** — Endpoint data in Sentinel
- **[Scheduled Rule Pattern](../detection/scheduled-rule-pattern.md)** — Custom Sentinel rules from endpoint telemetry
- **[MITRE ATT&CK Mapping](../detection/mitre-attack-mapping.md)** — Map endpoint attack techniques
