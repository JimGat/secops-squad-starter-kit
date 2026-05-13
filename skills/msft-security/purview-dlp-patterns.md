---
title: Purview DLP Patterns
category: msft-security
difficulty: intermediate
mitre_attack:
  - T1567  # Exfiltration Over Web Service
  - T1048  # Exfiltration Over Alternative Protocol
  - T1537  # Transfer Data to Cloud Account
  - T1114  # Email Collection
  - T1565.001  # Stored Data Manipulation
products:
  - Microsoft Purview
  - Microsoft Purview Data Loss Prevention
  - Microsoft Defender for Cloud Apps
  - Microsoft Sentinel
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# Purview DLP Patterns

## Overview

Microsoft Purview Data Loss Prevention (DLP) prevents sensitive data from leaving the organization through email, cloud storage, endpoint devices, and collaboration platforms. This skill covers DLP policy design, sensitivity label architecture, sensitive information types, endpoint DLP, alert investigation, and Sentinel integration.

Use this skill when:
- Designing DLP policies across Exchange, SharePoint, OneDrive, Teams, and endpoints
- Architecting sensitivity labels for information classification
- Creating custom sensitive information types
- Configuring endpoint DLP for device-level protection
- Investigating DLP alerts and integrating with Sentinel

## Prerequisites

| Requirement | Detail |
|---|---|
| **Licensing** | Microsoft 365 E5, E5 Compliance, or E5 Information Protection & Governance |
| **Permissions** | `Compliance Administrator` or `DLP Compliance Management` role group |
| **Portal** | Microsoft Purview compliance portal (compliance.microsoft.com) |
| **Endpoint DLP** | Devices onboarded to Microsoft Defender for Endpoint |

## Configuration Patterns

### DLP Policy Design

**Policy architecture — layered approach:**

| Layer | Policy Name | Locations | Sensitivity | Action |
|---|---|---|---|---|
| **Foundation** | Block SSN/Credit Card external sharing | Exchange, SPO, OD, Teams | High confidence SIT match | Block external + notify user |
| **Regulatory** | PCI-DSS data protection | Exchange, SPO, OD, Endpoints | Credit card + bank account | Block + alert compliance team |
| **IP Protection** | Confidential document restrictions | Exchange, SPO, OD, Teams, Endpoints | "Confidential" label | Block external + encrypt |
| **Executive** | Highly Confidential lockdown | All locations | "Highly Confidential" label | Block all sharing + log |

```powershell
# Create a DLP policy for financial data protection
Connect-IPPSSession

# Policy: Block credit card numbers from leaving the organization
New-DlpCompliancePolicy -Name "PCI-DSS Data Protection" `
    -Comment "Prevents credit card and financial data from external sharing" `
    -ExchangeLocation All `
    -SharePointLocation All `
    -OneDriveLocation All `
    -TeamsLocation All `
    -Mode Enable

# Rule: High-confidence credit card match → block
New-DlpComplianceRule -Name "Block Credit Card External Sharing" `
    -Policy "PCI-DSS Data Protection" `
    -ContentContainsSensitiveInformation @{
        Name = "Credit Card Number"
        MinCount = 1
        MinConfidence = 85
    } `
    -BlockAccess $true `
    -BlockAccessScope "PerAnonymousUser" `
    -NotifyUser "SiteAdmin", "LastModifier" `
    -NotifyUserType "NotSet" `
    -GenerateAlert "SiteAdmin" `
    -ReportSeverityLevel "High" `
    -Comment "MITRE T1567 — Exfiltration prevention"

# Rule: Low-confidence match → notify but don't block
New-DlpComplianceRule -Name "Warn on Potential Financial Data" `
    -Policy "PCI-DSS Data Protection" `
    -ContentContainsSensitiveInformation @{
        Name = "Credit Card Number"
        MinCount = 1
        MinConfidence = 65
        MaxConfidence = 84
    } `
    -BlockAccess $false `
    -NotifyUser "LastModifier" `
    -GenerateAlert "SiteAdmin" `
    -ReportSeverityLevel "Low" `
    -Comment "Low-confidence match — user education"
```

### Sensitivity Label Design

**Label taxonomy:**

| Label | Sub-Label | Protection | Use Case |
|---|---|---|---|
| **Public** | — | None | Marketing materials, public docs |
| **General** | — | Footer marking | Internal general-purpose docs |
| **Confidential** | All Employees | Encrypt; all employees full control | Internal business docs |
| **Confidential** | Specific People | Encrypt; named users only | Project-specific restricted docs |
| **Highly Confidential** | All Employees | Encrypt; no copy/print/forward | Board materials, M&A docs |
| **Highly Confidential** | Specific People | Encrypt; named users, no forward | Executive compensation, legal hold |

```powershell
# Create sensitivity labels
Connect-IPPSSession

# Parent label: Confidential
New-Label -DisplayName "Confidential" `
    -Name "Confidential" `
    -Comment "Business data requiring protection" `
    -Tooltip "Apply to documents containing business-sensitive information" `
    -ContentType "File, Email"

# Sub-label: Confidential - All Employees
New-Label -DisplayName "All Employees" `
    -Name "Confidential-AllEmployees" `
    -ParentId (Get-Label -Identity "Confidential").Guid `
    -Comment "Encrypted for all employees" `
    -Tooltip "All employees can access; external users blocked" `
    -EncryptionEnabled $true `
    -EncryptionProtectionType "Template" `
    -EncryptionRightsDefinitions "domain:contoso.com:VIEW,VIEWRIGHTSDATA,DOCEDIT,EDIT,PRINT,EXTRACT,REPLY,REPLYALL,FORWARD,OBJMODEL" `
    -ContentType "File, Email"

# Sub-label: Highly Confidential - All Employees  
New-Label -DisplayName "All Employees" `
    -Name "HighlyConfidential-AllEmployees" `
    -ParentId (Get-Label -Identity "Highly Confidential").Guid `
    -Comment "Maximum protection — no copy, print, or forward" `
    -EncryptionEnabled $true `
    -EncryptionProtectionType "Template" `
    -EncryptionRightsDefinitions "domain:contoso.com:VIEW,VIEWRIGHTSDATA,DOCEDIT,EDIT" `
    -ContentType "File, Email"

# Publish labels via label policy
New-LabelPolicy -Name "Standard Label Policy" `
    -Labels "Public", "General", "Confidential", "Confidential-AllEmployees", `
        "HighlyConfidential-AllEmployees" `
    -ExchangeLocation All `
    -Comment "Standard sensitivity labels for all users" `
    -Settings @{
        "mandatory" = "true"              # Require label on save/send
        "defaultlabelid" = "<general-label-guid>"  # Default to General
        "requiredowngradejustification" = "true"    # Justify removing protection
    }
```

### Sensitive Information Types (SIT)

**Built-in SITs — most common for DLP:**

| SIT | ID | Use Case | Confidence Level |
|---|---|---|---|
| Credit Card Number | `50842eb7-edc8-4019-85dd-5a5c1f2bb085` | PCI-DSS | High (85+) |
| U.S. Social Security Number | `a44669fe-0d48-453d-a9b1-2cc83f2cba77` | PII protection | High (85+) |
| U.S. Bank Account Number | `a2ce32a8-f935-44c0-9b3b-d9380e27cb19` | Financial data | Medium (75+) |
| ABA Routing Number | `cb353f78-2b72-4c3c-8827-92bbe4f69086` | Financial data | Medium (75+) |
| International Banking Account Number (IBAN) | `0e9b3178-9678-47dd-a509-37222ca96b42` | Financial data | Medium (75+) |
| U.S. Passport Number | `21da8916-8910-4564-a277-ce4de21b7055` | Travel/immigration | Medium (75+) |

**Custom sensitive information type:**

```powershell
# Custom SIT: Internal project code names
New-DlpSensitiveInformationType -Name "Contoso Project Code" `
    -Description "Matches internal project code format: PROJ-XXXX-XXXX" `
    -SensitiveInformationTypeRuleCollection (
        New-DlpSensitiveInformationTypeRuleCollection -Rules @(
            New-DlpSensitiveInformationTypeRule -Name "Project Code Pattern" `
                -ContentMatchesPatterns @(
                    New-DlpSensitiveInformationTypeRuleContentMatchesPatterns `
                        -MainPattern "PROJ-[A-Z]{4}-[0-9]{4}" `
                        -IdMatch "ProjCode"
                ) `
                -CorroborativeEvidence @(
                    New-DlpSensitiveInformationTypeRuleCorroborativeEvidence `
                        -Keyword @("confidential", "internal only", "restricted") `
                        -Proximity 300
                ) `
                -Confidence 85
        )
    )
```

### Endpoint DLP Configuration

```powershell
# Endpoint DLP settings
# Portal: compliance.microsoft.com > Data loss prevention > Endpoint DLP settings

# Configure monitored activities:
# - Copy to clipboard → Audit
# - Copy to USB removable media → Block with override
# - Copy to network share → Audit
# - Print → Block with override (for Highly Confidential)
# - Upload to cloud service → Block (for unapproved services)
# - Access by unallowed apps → Block

# Unallowed apps — block these from accessing protected files
$unallowedApps = @(
    "telegram.exe",
    "discord.exe",
    "whatsapp.exe",
    "dropbox.exe",        # If not approved cloud storage
    "wetransfer.exe"
)

# Unallowed browsers — block upload via these browsers
$unallowedBrowsers = @(
    "tor.exe",
    "brave.exe"           # If not approved
)

# Service domains — allowed cloud services
$allowedDomains = @(
    "*.sharepoint.com",
    "*.onedrive.com",
    "*.office.com"
)

# Blocked domains — known exfiltration services
$blockedDomains = @(
    "*.mega.nz",
    "*.anonfiles.com",
    "*.sendspace.com",
    "*.file.io"
)
```

**Endpoint DLP Policy:**

```powershell
# Create endpoint-specific DLP rule
New-DlpComplianceRule -Name "Block USB Copy of Confidential Data" `
    -Policy "Endpoint Data Protection" `
    -ContentContainsSensitiveInformation @{
        Name = "Credit Card Number"
        MinCount = 1
        MinConfidence = 85
    } `
    -EndpointDlpRestrictions @(
        @{
            Setting = "CopyToRemovableMedia"
            Value = "Block"
        },
        @{
            Setting = "CopyToClipboard"
            Value = "Audit"
        },
        @{
            Setting = "Print"
            Value = "Warn"
        },
        @{
            Setting = "UploadToCloudService"
            Value = "Block"
        }
    ) `
    -NotifyUser "LastModifier" `
    -GenerateAlert "SiteAdmin" `
    -ReportSeverityLevel "High"
```

### DLP Alert Investigation Workflow

**Triage process:**

```
1. Alert received → DLP policy match
     ↓
2. Check match details:
   - What SIT matched? (SSN, credit card, custom)
   - Confidence level? (High vs. Low)
   - How many instances? (1 vs. 100+)
     ↓
3. Review context:
   - Who triggered it? (Employee, service account)
   - What action? (Email, share, USB copy, upload)
   - What content? (Document name, email subject)
     ↓
4. Classify:
   - True Positive → Escalate to data protection team
   - True Positive (business justified) → Override with justification
   - False Positive → Tune policy (add exclusion, adjust confidence)
     ↓
5. Remediate:
   - Block further sharing
   - Notify data owner
   - Document in incident record
```

```kql
// DLP alert investigation — Sentinel KQL
SecurityAlert
| where TimeGenerated > ago(24h)
| where ProviderName == "Microsoft Data Loss Prevention"
| extend AlertData = parse_json(ExtendedProperties)
| project
    TimeGenerated,
    AlertName,
    Severity,
    UserPrincipalName = tostring(AlertData.["User"]),
    PolicyName = tostring(AlertData.["PolicyName"]),
    SensitiveInfoType = tostring(AlertData.["SensitiveInformationType"]),
    Location = tostring(AlertData.["Workload"]),
    Action = tostring(AlertData.["Action"])
| sort by TimeGenerated desc
```

### Sentinel Integration

```bicep
@description('Configure DLP data connector for Sentinel')
// DLP alerts flow via the Microsoft 365 Defender connector
// Enable in Sentinel: Content Hub > Microsoft Defender XDR solution > Data connectors

// Or via Purview audit log integration:
// Sentinel > Data connectors > Office 365 > Enable SharePoint, Exchange, Teams
```

```kql
// Monitor DLP policy matches in Sentinel
OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation has "DLP"
| extend PolicyDetails = parse_json(PolicyDetails)
| mv-expand PolicyDetails
| extend
    PolicyName = tostring(PolicyDetails.PolicyName),
    Rules = tostring(PolicyDetails.Rules)
| summarize
    MatchCount = count(),
    UniqueUsers = dcount(UserId),
    Locations = make_set(Workload)
    by PolicyName
| sort by MatchCount desc
```

```kql
// Detect potential data exfiltration — high-volume DLP matches
OfficeActivity
| where TimeGenerated > ago(1h)
| where Operation has "DLP"
| summarize MatchCount = count() by UserId, Workload, bin(TimeGenerated, 10m)
| where MatchCount > 10  // Threshold: >10 DLP matches in 10 minutes
| project TimeGenerated, UserId, Workload, MatchCount
```

```kql
// Sensitivity label downgrade detection — potential data declassification
// MITRE T1565.001 — Stored Data Manipulation
InformationProtectionLogs_CL
| where TimeGenerated > ago(24h)
| where Activity == "SensitivityLabelChanged"
| extend
    OldLabel = tostring(parse_json(AuditData).OldSensitivityLabel),
    NewLabel = tostring(parse_json(AuditData).NewSensitivityLabel),
    Justification = tostring(parse_json(AuditData).Justification)
| where OldLabel has "Confidential" and NewLabel has "General"
| project TimeGenerated, UserId, FileName, OldLabel, NewLabel, Justification
```

## Integration Points

- **Microsoft Sentinel** — DLP alerts and audit events flow via M365 Defender connector
- **Defender XDR** — DLP incidents correlate with endpoint and identity signals
- **Defender for Cloud Apps** — Session-level DLP for cloud applications
- **Defender for Endpoint** — Endpoint DLP enforcement on managed devices
- **Microsoft Purview Information Protection** — Labels drive DLP policy conditions
- **Microsoft Purview Insider Risk Management** — DLP signals feed insider risk indicators

## Operational Procedures

### Weekly DLP Review

```powershell
# Export DLP policy match report
Connect-IPPSSession

# Get DLP incident report for the past 7 days
$startDate = (Get-Date).AddDays(-7)
$endDate = Get-Date

Get-DlpDetailReport -StartDate $startDate -EndDate $endDate |
    Group-Object PolicyName |
    Select-Object @{N='Policy';E={$_.Name}}, Count |
    Sort-Object Count -Descending |
    Format-Table

# Review false positive rate
Get-DlpDetailReport -StartDate $startDate -EndDate $endDate |
    Where-Object { $_.UserAction -eq "Override" } |
    Group-Object PolicyName |
    Select-Object @{N='Policy';E={$_.Name}},
        @{N='Overrides';E={$_.Count}} |
    Format-Table
```

### Monthly Policy Tuning

1. Review override justifications — are users consistently overriding the same policy?
2. Analyze false positive patterns — adjust confidence thresholds or add exclusions
3. Check for new SITs — Microsoft regularly adds new built-in sensitive information types
4. Validate endpoint DLP coverage — ensure new devices are onboarded
5. Update blocked domains — add newly identified exfiltration services

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| DLP policy not matching | Confidence threshold too high | Lower minimum confidence; add corroborative evidence keywords |
| Endpoint DLP not enforcing | Device not onboarded to MDE | Verify MDE onboarding; check endpoint DLP settings |
| False positives on credit card SIT | Test data or document numbers matching | Add exclusions for known test data patterns; use exact data match |
| Labels not appearing for users | Label policy not published or not synced | Check label policy assignment; wait up to 24h for sync |
| DLP alerts not in Sentinel | Connector not enabled | Enable Microsoft 365 Defender connector in Sentinel |
| Endpoint DLP blocking legitimate apps | App not in allowed list | Add app to allowed apps in endpoint DLP settings |

## Related Skills

- **[Sentinel Workspace Setup](sentinel-workspace-setup.md)** — DLP data ingestion into Sentinel
- **[Defender XDR Configuration](defender-xdr-configuration.md)** — DLP alerts in the unified portal
- **[Defender for Endpoint](defender-for-endpoint.md)** — Endpoint DLP requires MDE onboarding
- **[Entra ID Protection](entra-id-protection.md)** — Identity context for DLP investigations
- **[Microsoft Graph Security](microsoft-graph-security.md)** — DLP data accessible via Graph API
- **[Detection Lifecycle](../detection/detection-lifecycle.md)** — DLP rules follow the same tune cycle
