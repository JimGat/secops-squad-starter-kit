---
title: Defender for Identity
category: msft-security
difficulty: advanced
mitre_attack:
  - T1078  # Valid Accounts
  - T1087  # Account Discovery
  - T1003  # OS Credential Dumping
  - T1558  # Steal or Forge Kerberos Tickets
products:
  - Microsoft Defender for Identity
  - Microsoft Defender XDR
  - Active Directory
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# Defender for Identity

## Overview

Microsoft Defender for Identity (formerly Azure ATP) monitors Active Directory domain controllers to detect identity-based threats — credential theft, lateral movement, privilege escalation, and domain dominance. Sensors installed on DCs parse network traffic and Windows events to build behavioral profiles and detect attacks in real time.

Use this skill when:
- Planning domain controller sensor deployment
- Tuning identity-based alerts to reduce false positives
- Configuring lateral movement path detection
- Integrating identity signals with Defender XDR
- Detecting Kerberoasting, Pass-the-Hash, DCSync, and Golden Ticket attacks

## Prerequisites

| Requirement | Detail |
|---|---|
| **Licensing** | Microsoft 365 E5, E5 Security, or standalone Defender for Identity |
| **Domain Controllers** | All DCs must have sensors installed for full coverage |
| **Permissions** | AD DS: read-only access to the domain; Azure: `Security Admin` |
| **Network** | Sensor needs outbound HTTPS to `*.atp.azure.com` (port 443) |
| **OS** | Windows Server 2016+ on DCs; Server 2012 R2 supported with limitations |
| **Capacity** | Sensor requires ~2 GB RAM and 2 CPU cores per DC |

## Configuration Patterns

### Sensor Installation Prerequisites

```powershell
# Pre-flight check for DC sensor installation
# Run on each domain controller

# 1. Verify .NET Framework 4.7+
$dotnet = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Release
$version = switch ($dotnet.Release) {
    { $_ -ge 528040 } { "4.8+" }
    { $_ -ge 461808 } { "4.7.2" }
    { $_ -ge 461308 } { "4.7.1" }
    { $_ -ge 460798 } { "4.7" }
    default { "Below 4.7 — UPGRADE REQUIRED" }
}
Write-Host ".NET Framework: $version"

# 2. Check available resources
$cpu = (Get-WmiObject Win32_Processor).NumberOfLogicalProcessors
$ram = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
Write-Host "CPU Cores: $cpu (need 2+), RAM: ${ram}GB (need 6GB+ total, 2GB for sensor)"

# 3. Verify network connectivity
$endpoints = @(
    "*.atp.azure.com:443",
    "login.microsoftonline.com:443",
    "graph.microsoft.com:443"
)
foreach ($ep in $endpoints) {
    $host = $ep.Split(':')[0].Replace('*', 'sensorapi')
    $port = $ep.Split(':')[1]
    $result = Test-NetConnection -ComputerName $host -Port $port -WarningAction SilentlyContinue
    Write-Host "$ep — $($result.TcpTestSucceeded)"
}

# 4. Check Windows Event Log auditing
$auditPolicies = auditpol /get /category:"Logon/Logoff","Account Logon","DS Access" /r | ConvertFrom-Csv
$auditPolicies | Where-Object { $_.'Inclusion Setting' -ne 'Success and Failure' } |
    Select-Object Subcategory, 'Inclusion Setting'
```

### Domain Controller Coverage Planning

| Environment Size | DCs | Sensor Strategy | Estimated Load |
|---|---|---|---|
| **Small** (< 1,000 users) | 2–4 DCs | Install on all DCs | Minimal impact |
| **Medium** (1,000–10,000 users) | 4–10 DCs | Install on all DCs; monitor performance for 48h | ~2–5% CPU overhead |
| **Large** (10,000–50,000 users) | 10–30 DCs | Phase rollout: PDC + GCs first, then remaining DCs | ~3–8% CPU overhead |
| **Enterprise** (50,000+ users) | 30+ DCs | Phase rollout by site; standalone sensors for ADFS/RADIUS | Plan capacity per site |

**Coverage requirements:**
- PDC Emulator: **must** have sensor
- Global Catalog servers: **must** have sensors
- ADFS servers: install standalone sensor
- RADIUS/VPN servers: install standalone sensor for RADIUS accounting
- RODC: not supported for sensor installation

### Sensor Installation

```powershell
# Download sensor from Defender for Identity portal
# Portal: security.microsoft.com > Settings > Identities > Sensors > Add sensor

# Get the access key from the portal
$accessKey = "<your-workspace-access-key>"

# Silent install on DC
$installerPath = "C:\Install\Azure ATP Sensor Setup.exe"
Start-Process -FilePath $installerPath -ArgumentList "/quiet", `
    "NetFrameworkCommandLineArguments=`"/q`"", `
    "AccessKey=$accessKey" -Wait

# Verify sensor health
Get-Service -Name "AATPSensor" | Select-Object Status, StartType
Get-Service -Name "AATPSensorUpdater" | Select-Object Status, StartType
```

### Alert Tuning — Reducing False Positives

**High-noise alerts to tune first:**

| Alert | Common False Positive Source | Tuning Action |
|---|---|---|
| **Suspicious service creation** | IT management tools (SCCM, Intune) | Exclude service accounts: `svc-sccm$`, `svc-intune$` |
| **Reconnaissance using DNS** | Network monitoring tools, vulnerability scanners | Exclude scanner IPs and monitoring service accounts |
| **Suspicious LDAP queries** | Line-of-business apps querying AD | Exclude app service accounts |
| **Pass-the-Hash** | Legitimate admin RDP sessions | Exclude known admin jump-box → DC patterns |
| **Brute force (Kerberos/NTLM)** | Service accounts with frequent auth | Exclude known service accounts |

```powershell
# Configure exclusions via the portal or API
# Portal: security.microsoft.com > Settings > Identities > Excluded entities

# Exclusion types:
# 1. Excluded users — skip alerts for specific accounts
# 2. Excluded computers — skip alerts from specific machines  
# 3. Excluded IP addresses — skip alerts from specific IPs

# Example: Exclude vulnerability scanner
# Settings > Identities > Excluded entities > IP addresses
# Add: 10.0.50.10 (Qualys scanner), 10.0.50.11 (Nessus scanner)

# Example: Exclude service accounts from reconnaissance alerts
# Settings > Identities > Excluded entities > Users
# Add: svc-sccm, svc-monitoring, svc-backup
```

**Alert priority for SOC triage:**

| Priority | Alert Type | MITRE Technique | Typical Action |
|---|---|---|---|
| **Critical** | Suspected DCSync attack | T1003.006 | Immediate investigation — potential domain compromise |
| **Critical** | Suspected Golden Ticket usage | T1558.001 | Isolate source; reset KRBTGT twice |
| **High** | Suspected identity theft (Pass-the-Hash) | T1550.002 | Investigate source device; check for malware |
| **High** | Suspected Kerberoasting | T1558.003 | Identify targeted SPNs; rotate service passwords |
| **Medium** | Suspicious LDAP query | T1087.002 | Check if source is known app; investigate if unknown |
| **Medium** | Unusual VPN authentication | T1078 | Verify with user; check location/device |
| **Low** | Account enumeration | T1087.001 | Context-dependent; often benign IT operations |

### Lateral Movement Path Detection

```
Portal: security.microsoft.com > Identities > Lateral movement paths
```

**Configuration:**
1. Ensure sensors are installed on **all DCs** (gaps in coverage = gaps in path detection)
2. Enable **SAM-R enumeration** for local admin group discovery:
   - Requires Group Policy: `Network access: Restrict clients allowed to make remote calls to SAM`
   - Add the Defender for Identity service account to the allowed list
3. Review paths weekly — focus on paths to Tier 0 assets (Domain Admins, DC computer accounts)

```kql
// KQL — Query lateral movement paths from Defender for Identity data
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Group Membership change" 
| where Application == "Active Directory"
| where TargetAccountUpn has "admin"
| project Timestamp, AccountName, TargetAccountUpn, ActionType, DeviceName
```

```kql
// Advanced Hunting — Identify over-privileged accounts
IdentityInfo
| where Timestamp > ago(1d)
| where IsAccountEnabled == true
| where AssignedRoles has_any ("Domain Admins", "Enterprise Admins", "Schema Admins")
| project AccountName, AccountDomain, AssignedRoles, Department
| sort by AccountName
```

### Integration with Defender XDR

Defender for Identity automatically feeds into the Defender XDR unified portal:

| Data Type | XDR Table | Use Case |
|---|---|---|
| Identity logon events | `IdentityLogonEvents` | Track authentication patterns across AD |
| Directory events | `IdentityDirectoryEvents` | Group membership changes, object modifications |
| Query events | `IdentityQueryEvents` | LDAP/DNS reconnaissance detection |
| Identity info | `IdentityInfo` | User/device entity enrichment |

**Verify integration:**

```kql
// Confirm Defender for Identity data is flowing to XDR
IdentityLogonEvents
| where Timestamp > ago(1h)
| summarize EventCount = count() by LogonType, Protocol
| sort by EventCount desc
```

## Integration Points

- **Defender XDR** — Identity alerts appear as incidents in the unified portal
- **Microsoft Sentinel** — Identity events flow via the Defender XDR connector
- **Entra ID Protection** — Cloud identity risks correlate with on-prem identity alerts
- **Defender for Endpoint** — Device context enriches identity compromise investigations
- **SIEM export** — Syslog/CEF for third-party SIEM integration

## Operational Procedures

### Daily Identity Threat Monitoring

```kql
// Defender for Identity — daily suspicious activity summary
AlertInfo
| where Timestamp > ago(24h)
| where ServiceSource == "Microsoft Defender for Identity"
| summarize AlertCount = count() by Title, Severity
| sort by Severity, AlertCount desc
```

```kql
// Detect Kerberoasting attempts
IdentityQueryEvents
| where Timestamp > ago(24h)
| where ActionType == "LDAP query"
| where QueryType == "Service Principal Name"
| summarize SPNsQueried = dcount(QueryTarget), QueryCount = count() by AccountName, DeviceName
| where SPNsQueried > 5
| sort by SPNsQueried desc
```

### Sensor Health Monitoring

```powershell
# Check all sensor statuses via API
Connect-MgGraph -Scopes "SecurityEvents.Read.All"

# Or check via portal: security.microsoft.com > Settings > Identities > Sensors
# Healthy sensors show green checkmark
# Monitor for: outdated sensors, high CPU/memory, packet loss
```

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| Sensor offline | Network connectivity or service crash | Check `AATPSensor` service status; verify outbound HTTPS to `*.atp.azure.com` |
| Missing alerts | Not all DCs have sensors | Install sensors on remaining DCs; check coverage in portal |
| High false positive rate | IT tools triggering alerts | Add exclusions for known service accounts and scanner IPs |
| Lateral movement paths not showing | SAM-R not configured | Enable SAM-R via Group Policy; add sensor account to allowed callers |
| Sensor high CPU | High LDAP query volume on DC | Increase DC resources; check for excessive LDAP-bound applications |
| NTLM alerts flooding | Legacy apps using NTLM | Exclude known legacy app service accounts; plan NTLM deprecation |

## Related Skills

- **[Entra ID Protection](entra-id-protection.md)** — Cloud identity protection complements on-prem Defender for Identity
- **[Defender XDR Configuration](defender-xdr-configuration.md)** — Identity alerts in the unified portal
- **[Sentinel Workspace Setup](sentinel-workspace-setup.md)** — Identity data ingestion into Sentinel
- **[MITRE ATT&CK Mapping](../detection/mitre-attack-mapping.md)** — Map identity attack techniques
- **[Threat Hunting Foundations](../kql/threat-hunting-foundations.md)** — KQL patterns for identity hunting
