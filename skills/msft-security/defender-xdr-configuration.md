---
title: Defender XDR Configuration
category: msft-security
difficulty: intermediate
mitre_attack:
  - T1566  # Phishing
  - T1078  # Valid Accounts
  - T1059  # Command and Scripting Interpreter
  - T1059.001  # PowerShell
  - T1486  # Data Encrypted for Impact
products:
  - Microsoft Defender XDR
  - Microsoft 365 Defender
  - Microsoft Sentinel
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# Defender XDR Configuration

## Overview

Microsoft Defender XDR (Extended Detection and Response) unifies signals from Defender for Endpoint, Defender for Office 365, Defender for Identity, Defender for Cloud Apps, and Microsoft Entra ID Protection into a single incident queue. This skill covers the unified portal configuration, custom detection rules, alert tuning, and cross-product correlation.

> **Unified SOC platform:** Defender XDR and Microsoft Sentinel now share a unified experience at [security.microsoft.com](https://security.microsoft.com). SOC analysts can manage Sentinel analytics rules, incidents, and hunting alongside Defender XDR in one portal.

Use this skill when:
- Configuring the unified security operations portal (security.microsoft.com)
- Building custom detection rules from Advanced Hunting queries
- Tuning alert suppression to reduce noise
- Integrating Defender XDR incidents with Microsoft Sentinel
- Setting up auto-investigation and remediation

## Prerequisites

| Requirement | Detail |
|---|---|
| **Licensing** | Microsoft 365 E5, E5 Security, or standalone Defender plans |
| **Permissions** | `Security Administrator` or `Security Operator` in Entra ID |
| **Portal** | Access to security.microsoft.com (unified portal) |
| **Sentinel** | Optional: workspace connected for bi-directional sync |

## Configuration Patterns

### Unified Portal Onboarding

```powershell
# Verify Defender XDR is activated
# Navigate: security.microsoft.com > Settings > Microsoft Defender XDR

# Check unified RBAC
Connect-MgGraph -Scopes "SecurityEvents.ReadWrite.All"

# Verify incident queue is receiving data from all products
$incidents = Get-MgSecurityIncident -Top 10 -OrderBy 'createdDateTime DESC'
$incidents | Select-Object DisplayName, Severity, Status, 
    @{N='Products';E={$_.AlertProducts -join ', '}} | Format-Table
```

**Portal Settings Checklist:**

| Setting | Path | Recommended Value |
|---|---|---|
| **Unified RBAC** | Settings > Endpoints > Roles | Enable unified roles across all Defender products |
| **Streaming API** | Settings > Microsoft Defender XDR > Streaming API | Enable for SIEM integration |
| **Preview features** | Settings > Endpoints > Advanced features | Enable for latest capabilities |
| **Automated investigation** | Settings > Endpoints > Advanced features | Full automation for approved device groups |
| **Live Response** | Settings > Endpoints > Advanced features | Enable for incident response |
| **Alert notifications** | Settings > Email notifications | Configure for High/Critical severity |

### Alert Suppression Rules

Create suppression rules to reduce false positive noise without disabling detections.

```powershell
# Example: Suppress known pen test tool alerts during authorized assessment
# Navigate: security.microsoft.com > Settings > Microsoft Defender XDR > Alert tuning

# Via API — create suppression rule
$suppressionRule = @{
    ruleName = "Suppress PenTest Tool Alerts"
    category = "SuspiciousActivity"
    title = "Suspicious process behavior" 
    scope = @{
        deviceGroups = @("PenTest-Devices")
    }
    conditions = @{
        ioaDefinitionId = @("alert-definition-id")
        deviceGroup = @("PenTest-Devices")
    }
    action = "hide"           # hide = suppress; resolve = auto-close
    expirationDate = "2026-05-15T00:00:00Z"  # Always set expiration
    comment = "Authorized penetration test - Engagement #PT-2026-04"
}
```

**Suppression Best Practices:**

| Practice | Why |
|---|---|
| Always set an expiration date | Prevents permanent blind spots |
| Scope to specific device groups | Avoids suppressing real attacks on production devices |
| Use `hide` not `resolve` for active pen tests | Alerts still exist if you need to review later |
| Document the engagement reference | Audit trail for compliance |
| Review monthly | Remove stale rules that no longer apply |

### Custom Detection Rules

Convert Advanced Hunting queries into scheduled custom detection rules.

```kql
// Custom detection: Suspicious PowerShell download cradle
// MITRE ATT&CK: T1059.001 (PowerShell)
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "DownloadString", "DownloadFile", "Invoke-WebRequest",
    "wget", "curl", "IEX", "Invoke-Expression",
    "Net.WebClient", "Start-BitsTransfer"
)
| where ProcessCommandLine !has "WindowsUpdate"  // Exclude legit updaters
| where ProcessCommandLine !has "Microsoft.ConfigurationManagement"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath
```

**Custom Detection Rule Settings:**

| Setting | Guidance |
|---|---|
| **Frequency** | Every hour for behavioral detections; every 24h for compliance checks |
| **Lookback** | Match the frequency + overlap (1h frequency → 1h 30m lookback) |
| **Severity** | High for confirmed download cradles; Medium if filtered |
| **Category** | Execution (matches MITRE tactic) |
| **Impacted entities** | Map DeviceName, AccountName for correlation |
| **Alert title** | Include the technique: "T1059.001 — PowerShell Download Cradle on {{DeviceName}}" |
| **Recommended actions** | Isolate device, collect forensic triage package |

### Incident Auto-Investigation Settings

```
Settings > Endpoints > Advanced features > Automated investigation
```

| Automation Level | Behavior | Use When |
|---|---|---|
| **No automation** | Alerts only, no auto-investigation | Pilot phase; security team wants full manual control |
| **Semi — require approval for all** | Investigation runs, all remediation needs approval | Production devices, early deployment |
| **Semi — require approval for core folders** | Auto-remediates non-core paths, approval for system folders | Standard production posture |
| **Semi — require approval for temp folders** | Auto-remediates most paths, approval for temp folders only | Mature SOC with established baselines |
| **Full automation** | Investigate and remediate without approval | Trusted device groups with strong detection confidence |

**Recommended rollout:**
1. Start all device groups at "Semi — require approval for all"
2. After 30 days of tuning, move low-risk groups to "Semi — require approval for core folders"
3. After 90 days with < 1% false positive rate, move to "Full automation"

### Email & Collaboration Protection

```powershell
# Configure Safe Attachments policy
New-SafeAttachmentPolicy -Name "Standard Protection" `
    -Enable $true `
    -Action "DynamicDelivery" `
    -ActionOnError $true `
    -Redirect $true `
    -RedirectAddress "secops@contoso.com"

New-SafeAttachmentRule -Name "Standard Protection Rule" `
    -SafeAttachmentPolicy "Standard Protection" `
    -RecipientDomainIs "contoso.com" `
    -Priority 0

# Configure Safe Links policy
New-SafeLinksPolicy -Name "Standard Protection" `
    -EnableSafeLinksForEmail $true `
    -EnableSafeLinksForTeams $true `
    -EnableSafeLinksForOffice $true `
    -TrackClicks $true `
    -AllowClickThrough $false `
    -ScanUrls $true `
    -EnableForInternalSenders $true `
    -DeliverMessageAfterScan $true

New-SafeLinksRule -Name "Standard Protection Rule" `
    -SafeLinksPolicy "Standard Protection" `
    -RecipientDomainIs "contoso.com" `
    -Priority 0

# Configure Anti-phishing policy
New-AntiPhishPolicy -Name "Strict Protection" `
    -EnableMailboxIntelligenceProtection $true `
    -EnableOrganizationDomainsProtection $true `
    -EnableSimilarUsersSafetyTips $true `
    -EnableSimilarDomainsSafetyTips $true `
    -EnableUnusualCharactersSafetyTips $true `
    -PhishThresholdLevel 3 `
    -EnableTargetedUserProtection $true `
    -TargetedUsersToProtect "CEO","ceo@contoso.com","CFO","cfo@contoso.com"
```

### Cross-Product Correlation Capabilities

| Correlation Type | Products Involved | Example |
|---|---|---|
| **Phishing → Endpoint compromise** | Defender for Office 365 + Defender for Endpoint | Email with malicious link → user clicks → malware downloads on device |
| **Identity compromise → Lateral movement** | Entra ID Protection + Defender for Identity | Risky sign-in → pass-the-hash on domain controller |
| **Cloud app abuse → Data exfiltration** | Defender for Cloud Apps + Defender for Endpoint | OAuth app consent → bulk file download from SharePoint |
| **Insider threat** | Purview + Defender for Endpoint + Defender for Cloud Apps | Sensitivity label downgrade → USB copy → cloud upload |

**Enable cross-product correlation:**

```powershell
# Verify all Defender products are reporting to the unified portal
# Settings > Microsoft Defender XDR > Account

# Check connected products
$connectedProducts = @(
    'MicrosoftDefenderForEndpoint',
    'MicrosoftDefenderForOffice365', 
    'MicrosoftDefenderForIdentity',
    'MicrosoftDefenderForCloudApps',
    'AzureActiveDirectoryIdentityProtection'
)

# Validate via Advanced Hunting — all tables should return data
$tables = @(
    'DeviceProcessEvents',      # Defender for Endpoint
    'EmailEvents',              # Defender for Office 365
    'IdentityLogonEvents',      # Defender for Identity
    'CloudAppEvents',           # Defender for Cloud Apps
    'AADSignInEventsBeta'       # Entra ID Protection
)
```

## Integration Points

- **Microsoft Sentinel** — Bi-directional incident sync; Defender XDR incidents appear in Sentinel
- **Defender for Cloud** — Cloud workload alerts correlate with endpoint and identity signals
- **Microsoft Purview** — DLP alerts enrich Defender XDR incidents with data context
- **Microsoft Graph Security API** — Programmatic access to incidents, alerts, and hunting

## Operational Procedures

### Daily Operations KQL

```kql
// Defender XDR — daily incident summary via Advanced Hunting
AlertInfo
| where Timestamp > ago(24h)
| summarize
    AlertCount = count(),
    HighSeverity = countif(Severity == "High"),
    MediumSeverity = countif(Severity == "Medium"),
    Products = make_set(ServiceSource)
    by Title
| sort by HighSeverity desc, AlertCount desc
| take 20
```

```kql
// Cross-product attack chain — phishing to endpoint compromise
EmailEvents
| where Timestamp > ago(24h)
| where ThreatTypes has "Phish"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(24h)
) on $left.RecipientEmailAddress == $right.AccountUpn
| project
    EmailTimestamp = EmailEvents_Timestamp,
    RecipientEmailAddress,
    Subject,
    DeviceName,
    ProcessCommandLine,
    FileName
| sort by EmailTimestamp desc
```

### Monthly Tuning Review

1. Review suppression rules — remove expired or unnecessary rules
2. Analyze auto-investigation results — adjust automation levels based on false positive rates
3. Update custom detections — add new threat intelligence, refine thresholds
4. Validate cross-product correlation — ensure all products are sending data

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| Incidents not appearing in Sentinel | Connector not enabled | Enable Microsoft Defender XDR connector via Sentinel Content Hub solution, then configure the data connector |
| Custom detection not firing | Query returns no results in hunting | Test query with explicit time range; verify table has data |
| Alert suppression too broad | Scope not limited to device group | Add device group or user scope constraints |
| Auto-investigation stuck | Pending actions queue full | Clear pending actions; review remediation backlog |
| Email protection not applying | Policy priority conflict | Check policy order; lower priority number = higher precedence |
| Advanced Hunting tables empty | Product license not activated | Verify E5 or standalone license is assigned to users |

## Related Skills

- **[Sentinel Workspace Setup](sentinel-workspace-setup.md)** — Connect Defender XDR to Sentinel
- **[Defender for Endpoint](defender-for-endpoint.md)** — Endpoint telemetry feeding into XDR
- **[Defender for Identity](defender-for-identity.md)** — Identity signals in the unified portal
- **[Entra ID Protection](entra-id-protection.md)** — Risk-based policies that trigger XDR alerts
- **[Scheduled Rule Pattern](../detection/scheduled-rule-pattern.md)** — Build Sentinel rules from XDR data
- **[Microsoft Graph Security](microsoft-graph-security.md)** — API access to XDR incidents
