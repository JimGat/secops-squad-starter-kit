---
title: Purview API Wrapper
category: msft-security
difficulty: advanced
mitre_attack:
  - T1567  # Exfiltration Over Web Service
  - T1048  # Exfiltration Over Alternative Protocol
  - T1537  # Transfer Data to Cloud Account
  - T1114  # Email Collection
  - T1565.001  # Stored Data Manipulation
  - T1078  # Valid Accounts — insider threat
  - T1530  # Data from Cloud Storage
  - T1213  # Data from Information Repositories
products:
  - Microsoft Purview
  - Microsoft Purview Information Protection
  - Microsoft Purview Data Loss Prevention
  - Microsoft Purview Insider Risk Management
  - Microsoft Purview Compliance Manager
  - Microsoft Purview Records Management
  - Microsoft Graph Security API
  - Microsoft Sentinel
author: Kima
version: 1.0.0
last_updated: 2026-04-30
---

# Purview API Wrapper

## Overview

Microsoft Purview is the unified data governance and compliance platform spanning information protection, data loss prevention, insider risk management, records management, audit, and compliance posture. This skill covers the **API surface** for programmatic access — enabling SecOps Squad agents to automate the classify → label → protect → audit lifecycle.

Use this skill when:
- Automating sensitivity label management across the tenant
- Querying or configuring DLP policies via API (complements `purview-dlp-patterns.md` which covers policy *design*)
- Accessing insider risk alerts and cases programmatically
- Searching the Unified Audit Log for investigation or compliance
- Managing retention labels and disposition workflows
- Querying Compliance Manager scores and improvement actions

> **Scope boundary:** This skill focuses on API integration and agent automation. For DLP policy architecture, sensitivity label taxonomy, and endpoint DLP configuration, see `purview-dlp-patterns.md`.

## Environment Context

Check `.secops/compliance/requirements.yaml` for regulatory framework mappings (GDPR, PCI-DSS, NIS2, DORA, FedRAMP) that constrain Purview configuration. Check `.secops/identity/tenants.yaml` for multi-tenant topology — Purview policies are tenant-scoped. Check `.secops/data-sources/data-source-map.yaml` for data classification coverage gaps.

## Section 1: API Landscape

### Purview APIs by Domain

| Domain | Primary API | Endpoint | Auth |
|---|---|---|---|
| **Information Protection** | Microsoft Graph | `/informationProtection/policy/labels` | Graph App/Delegated |
| **Sensitivity Labels** | Microsoft Graph | `/security/informationProtection/sensitivityLabels` | Graph App/Delegated |
| **DLP Policies** | Security & Compliance PowerShell | `Connect-IPPSSession` | Delegated (EXO) |
| **DLP Alerts** | Microsoft Graph | `/security/alerts_v2` (filter by serviceSource) | Graph App |
| **Insider Risk** | Microsoft Graph (beta) | `/security/cases/ediscoveryCases` + IRM portal | Limited API |
| **Audit Log** | Office 365 Management API | `/api/v1.0/{tenant}/activity/feed` | App registration |
| **Audit Log (search)** | Security & Compliance PowerShell | `Search-UnifiedAuditLog` | Delegated (EXO) |
| **Records Management** | Microsoft Graph (beta) | `/security/labels/retentionLabels` | Graph App |
| **Compliance Manager** | Microsoft Graph (beta) | `/compliance/complianceManager` | Graph App |
| **Data Classification** | Microsoft Graph | `/dataClassification` | Graph App |

### Required Permissions

| Permission | Type | Use Case |
|---|---|---|
| `InformationProtectionPolicy.Read` | App / Delegated | Read sensitivity label definitions |
| `InformationProtectionPolicy.Read.All` | Application | Read all label policies tenant-wide |
| `SecurityAlert.Read.All` | Application | Read DLP alerts via Graph |
| `SecurityAlert.ReadWrite.All` | Application | Update DLP alert status |
| `RecordsManagement.Read.All` | Application | Read retention labels and policies |
| `RecordsManagement.ReadWrite.All` | Application | Create/update retention labels |
| `ComplianceManager.Read.All` | Application | Read compliance score, assessments |
| `ActivityFeed.Read` | Application | Office 365 Management Activity API |
| `ActivityFeed.ReadDlp` | Application | DLP-specific activity events |
| `AuditLogsQuery.Read.All` | Application | Query audit log via Graph |

## Section 2: Information Protection — Sensitivity Labels

### List Sensitivity Labels

```powershell
# --- Graph PowerShell SDK ---
Import-Module Microsoft.Graph.Security

Connect-MgGraph -Scopes "InformationProtectionPolicy.Read"

# List all published sensitivity labels
$labels = Get-MgSecurityInformationProtectionSensitivityLabel
$labels | Select-Object Id, Name, DisplayName, IsActive, @{N='Priority';E={$_.Priority}} | Format-Table
```

```powershell
# --- REST ---
$token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
$headers = @{ Authorization = "Bearer $token" }

$labels = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/security/informationProtection/sensitivityLabels" `
    -Headers $headers

$labels.value | ForEach-Object {
    [PSCustomObject]@{
        Id          = $_.id
        Name        = $_.name
        DisplayName = $_.displayName
        Priority    = $_.priority
        Parent      = $_.parent.id
    }
} | Format-Table
```

### Evaluate Label Application

```powershell
# Evaluate which label should be applied based on content
$evalBody = @{
    contentInfo = @{
        "@odata.type" = "#microsoft.graph.security.contentInfo"
        format        = "default"
        identifier    = $null
        state         = "rest"
    }
    discoveredSensitiveTypes = @(
        @{
            confidence = 95
            count      = 3
            id         = "50842eb7-edc8-4019-85dd-5a5c1f2bb085"  # Credit Card Number
        }
    )
} | ConvertTo-Json -Depth 5

$evaluation = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/security/informationProtection/sensitivityLabels/evaluateApplication" `
    -Method POST -Headers $headers -Body $evalBody -ContentType "application/json"

Write-Host "Recommended label: $($evaluation.value[0].label.name)"
```

### Auto-Labeling Configuration via PowerShell

```powershell
# Auto-labeling policy (applies labels without user action)
Connect-IPPSSession

New-AutoSensitivityLabelPolicy -Name "Auto-Label PCI Data" `
    -Comment "Automatically apply Confidential label to content with credit card numbers" `
    -ExchangeLocation All `
    -SharePointLocation All `
    -OneDriveLocation All `
    -Mode TestWithNotifications  # TestWithoutNotifications | TestWithNotifications | Enable

New-AutoSensitivityLabelRule -Name "Credit Card Auto-Label Rule" `
    -Policy "Auto-Label PCI Data" `
    -ContentContainsSensitiveInformation @{
        Name = "Credit Card Number"
        MinCount = 1
        MinConfidence = 85
    } `
    -SensitivityLabelId "<confidential-label-guid>" `
    -Comment "MITRE T1567 — classify before exfiltration possible"
```

## Section 3: Data Loss Prevention — API Access

### Read DLP Alerts via Graph

```powershell
# DLP alerts surface through the unified alerts_v2 endpoint
$dlpAlerts = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/security/alerts_v2?`$filter=serviceSource eq 'microsoftDataLossPrevention'&`$top=50&`$orderby=createdDateTime desc" `
    -Headers $headers

$dlpAlerts.value | ForEach-Object {
    [PSCustomObject]@{
        Id          = $_.id
        Title       = $_.title
        Severity    = $_.severity
        Status      = $_.status
        Created     = $_.createdDateTime
        Category    = $_.category
        User        = ($_.evidence | Where-Object { $_."@odata.type" -match "user" }).userAccount.accountName
    }
} | Format-Table
```

### Update DLP Alert Status

```powershell
# Classify and close a DLP alert
$updateBody = @{
    status         = "resolved"
    classification = "truePositive"  # truePositive | falsePositive | informationalExpectedActivity
    determination  = "confirmedActivity"
    assignedTo     = "soc-analyst@contoso.com"
    comment        = "Confirmed unauthorized external sharing. User notified. DLP policy override revoked."
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/security/alerts_v2/$alertId" `
    -Method PATCH -Headers $headers -Body $updateBody -ContentType "application/json"
```

### DLP Policy Management via PowerShell

```powershell
# List all DLP policies with status
Connect-IPPSSession

Get-DlpCompliancePolicy | Select-Object Name, Mode, Enabled, Workload,
    @{N='Rules';E={ (Get-DlpComplianceRule -Policy $_.Name).Count }} |
    Format-Table

# Get detailed rule configuration
Get-DlpComplianceRule -Policy "PCI-DSS Data Protection" |
    Select-Object Name, ContentContainsSensitiveInformation, BlockAccess,
    NotifyUser, ReportSeverityLevel | Format-List
```

## Section 4: Data Classification

### Query Sensitive Information Types

```powershell
# List all sensitive information types (built-in + custom)
$sits = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/dataClassification/sensitiveTypes" `
    -Headers $headers

Write-Host "Total SITs: $($sits.value.Count)"

# Filter to custom SITs only
$sits.value | Where-Object { $_.scope -eq "tenant" } |
    Select-Object Id, Name, Description | Format-Table

# Get classification statistics
$classStats = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/dataClassification/classifyText" `
    -Method POST -Headers $headers -ContentType "application/json" `
    -Body (@{
        text = "My credit card number is 4111-1111-1111-1111 and SSN is 123-45-6789"
    } | ConvertTo-Json)

$classStats.sensitiveTypeResults | ForEach-Object {
    [PSCustomObject]@{
        SensitiveType = $_.sensitiveType.name
        Confidence    = $_.confidence
        Count         = $_.count
    }
}
```

### Trainable Classifiers

```powershell
# List trainable classifiers
$classifiers = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/beta/dataClassification/classifyFileJobs" `
    -Headers $headers

# Built-in trainable classifiers relevant to SecOps:
# - Threat / Harassment
# - Profanity
# - Targeted Harassment
# - Intellectual Property (source code, patents)
# - Financial Statements
# - Resumes (PII detection)
# - Customer Complaints
```

### Exact Data Match (EDM)

```powershell
# EDM provides exact-match classification for structured data
# (employee IDs, patient numbers, custom identifiers)

# Step 1: Define EDM schema
Connect-IPPSSession

$edmSchema = @"
<?xml version="1.0" encoding="utf-8"?>
<EdmSchema xmlns="http://schemas.microsoft.com/office/2020/edm">
  <DataStore name="EmployeeRecords" description="Employee PII for DLP matching">
    <Field name="EmployeeId" searchable="true" caseInsensitive="true" />
    <Field name="SSN" searchable="true" />
    <Field name="FullName" searchable="true" caseInsensitive="true" />
    <Field name="Email" searchable="true" caseInsensitive="true" />
  </DataStore>
</EdmSchema>
"@

New-DlpEdmSchema -FileData ([System.Text.Encoding]::UTF8.GetBytes($edmSchema))
```

## Section 5: Records Management

### Retention Labels via Graph

```powershell
# List retention labels
$retentionLabels = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/beta/security/labels/retentionLabels" `
    -Headers $headers

$retentionLabels.value | Select-Object Id, DisplayName,
    @{N='RetentionDays';E={$_.retentionDuration.days}},
    @{N='Action';E={$_.actionAfterRetentionPeriod}},
    IsInUse | Format-Table
```

```powershell
# Create a retention label for incident evidence
$labelBody = @{
    displayName                  = "Incident Evidence — 7 Year Hold"
    descriptionForAdmins         = "Applied to content collected during security incident investigations"
    descriptionForUsers          = "This content is preserved as incident evidence. Do not delete."
    retentionDuration            = @{ days = 2555 }  # 7 years
    actionAfterRetentionPeriod   = "startDispositionReview"
    retentionTrigger             = "dateLabeled"
    defaultRecordBehavior        = "startLocked"
} | ConvertTo-Json -Depth 3

Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/beta/security/labels/retentionLabels" `
    -Method POST -Headers $headers -Body $labelBody -ContentType "application/json"
```

### Retention Policies via PowerShell

```powershell
Connect-IPPSSession

# Create retention policy for security logs
New-RetentionCompliancePolicy -Name "Security Incident Evidence Retention" `
    -Comment "7-year retention for incident evidence per compliance requirements" `
    -ExchangeLocation All `
    -SharePointLocation "https://contoso.sharepoint.com/sites/IncidentEvidence" `
    -Enabled $true

New-RetentionComplianceRule -Name "7-Year Evidence Hold" `
    -Policy "Security Incident Evidence Retention" `
    -RetentionDuration 2555 `
    -RetentionComplianceAction "KeepAndDelete" `
    -ExpirationDateOption "CreationAgeInDays" `
    -Comment "Aligned with .secops/compliance/requirements.yaml retention overrides"
```

## Section 6: Insider Risk Management

### API Access Patterns

> **Note:** Insider Risk Management has limited API coverage. Most operations require the Microsoft Purview portal. Available programmatic access:

```powershell
# Read insider risk alerts via Graph Security alerts
$irmAlerts = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/security/alerts_v2?`$filter=serviceSource eq 'microsoftInsiderRiskManagement'&`$top=25&`$orderby=createdDateTime desc" `
    -Headers $headers

$irmAlerts.value | ForEach-Object {
    [PSCustomObject]@{
        Id       = $_.id
        Title    = $_.title
        Severity = $_.severity
        Status   = $_.status
        Created  = $_.createdDateTime
        User     = ($_.evidence | Where-Object { $_."@odata.type" -match "user" }).userAccount.accountName
    }
} | Format-Table
```

### Insider Risk Signal Correlation

```kql
// Sentinel: Correlate insider risk alerts with DLP and identity signals
// MITRE: T1078 (Valid Accounts), T1567 (Exfiltration Over Web Service)
let insiderRiskUsers = SecurityAlert
    | where TimeGenerated > ago(7d)
    | where ProviderName == "Microsoft Insider Risk Management"
    | extend UserId = tostring(parse_json(ExtendedProperties).["UserPrincipalName"])
    | distinct UserId;
// Cross-reference with DLP matches
OfficeActivity
| where TimeGenerated > ago(7d)
| where UserId in (insiderRiskUsers)
| where Operation has "DLP"
| summarize
    DLPMatches = count(),
    Locations = make_set(Workload),
    Policies = make_set(tostring(parse_json(PolicyDetails)[0].PolicyName))
    by UserId
| sort by DLPMatches desc
```

### Insider Risk Policy Types

| Policy Template | Trigger | SecOps Relevance |
|---|---|---|
| Data theft by departing users | HR connector: resignation/termination | T1567 — Exfiltration before departure |
| Data leaks | DLP policy match | T1048 — Alternative protocol exfiltration |
| Security policy violations | Defender for Endpoint alerts | T1078 — Account misuse |
| Patient data misuse | Healthcare SIT match | HIPAA compliance |
| Priority user data leaks | Sensitive group membership | Executive protection |

## Section 7: Unified Audit Log

### Search via PowerShell

```powershell
Connect-ExchangeOnline

# Search audit log for specific user activity
$results = Search-UnifiedAuditLog `
    -StartDate (Get-Date).AddDays(-7) `
    -EndDate (Get-Date) `
    -UserIds "jsmith@contoso.com" `
    -Operations "FileDownloaded", "FileSyncDownloadedFull", "FileAccessed" `
    -RecordType SharePointFileOperation `
    -ResultSize 5000

$results | ForEach-Object {
    $auditData = $_.AuditData | ConvertFrom-Json
    [PSCustomObject]@{
        Timestamp = $_.CreationDate
        User      = $_.UserIds
        Operation = $_.Operations
        FileName  = $auditData.SourceFileName
        SiteUrl   = $auditData.SiteUrl
        ClientIP  = $auditData.ClientIP
    }
} | Sort-Object Timestamp -Descending | Format-Table
```

### Audit Log via Office 365 Management Activity API

```powershell
# Subscribe to audit content (one-time setup)
$mgmtToken = (Get-AzAccessToken -ResourceUrl "https://manage.office.com").Token
$mgmtHeaders = @{ Authorization = "Bearer $mgmtToken"; "Content-Type" = "application/json" }

# Start subscription for DLP events
Invoke-RestMethod `
    -Uri "https://manage.office.com/api/v1.0/$tenantId/activity/feed/subscriptions/start?contentType=DLP.All" `
    -Method POST -Headers $mgmtHeaders

# List available content blobs
$blobs = Invoke-RestMethod `
    -Uri "https://manage.office.com/api/v1.0/$tenantId/activity/feed/subscriptions/content?contentType=DLP.All&startTime=$(Get-Date (Get-Date).AddHours(-24) -Format 'yyyy-MM-ddTHH:mm:ss')&endTime=$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')" `
    -Headers $mgmtHeaders

# Retrieve content from each blob
foreach ($blob in $blobs) {
    $events = Invoke-RestMethod -Uri $blob.contentUri -Headers $mgmtHeaders
    $events | ForEach-Object {
        [PSCustomObject]@{
            Timestamp   = $_.CreationTime
            Operation   = $_.Operation
            UserId      = $_.UserId
            PolicyName  = $_.PolicyDetails[0].PolicyName
            RuleName    = $_.PolicyDetails[0].Rules[0].RuleName
            Severity    = $_.PolicyDetails[0].Rules[0].Severity
        }
    }
}
```

### Audit Log via Graph (Preview)

```powershell
# Graph audit log query (preview endpoint)
$queryBody = @{
    "@odata.type"            = "#microsoft.graph.security.auditLogQuery"
    displayName              = "DLP events for jsmith"
    filterStartDateTime      = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
    filterEndDateTime        = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    operationFilters         = @("DLPRuleMatch")
    userPrincipalNameFilters = @("jsmith@contoso.com")
    recordTypeFilters        = @("ComplianceDLPExchange", "ComplianceDLPSharePoint")
} | ConvertTo-Json

$auditQuery = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/beta/security/auditLog/queries" `
    -Method POST -Headers $headers -Body $queryBody -ContentType "application/json"

# Poll for completion and retrieve records
Start-Sleep -Seconds 15
$records = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/beta/security/auditLog/queries/$($auditQuery.id)/records" `
    -Headers $headers

$records.value | Select-Object createdDateTime, operation, userPrincipalName,
    @{N='Detail';E={$_.auditData}} | Format-Table
```

## Section 8: Compliance Manager

### Read Compliance Score

```powershell
# Get overall compliance score
$score = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/beta/compliance/complianceManager/complianceScore" `
    -Headers $headers

Write-Host "Compliance Score: $($score.score) / $($score.maxScore) ($([math]::Round($score.score/$score.maxScore*100,1))%)"
```

### List Assessments and Improvement Actions

```powershell
# List active compliance assessments
$assessments = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/beta/compliance/complianceManager/assessments" `
    -Headers $headers

$assessments.value | Select-Object Id, DisplayName, Status,
    @{N='Score';E={"$($_.complianceScore.achievedPoints)/$($_.complianceScore.maxPoints)"}},
    @{N='Regulation';E={$_.regulation.name}} | Format-Table

# List improvement actions (actionable items to increase score)
$actions = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/beta/compliance/complianceManager/improvementActions?`$filter=status ne 'completed'&`$orderby=pointsPossible desc&`$top=20" `
    -Headers $headers

$actions.value | Select-Object Id, DisplayName, PointsPossible, Status,
    @{N='Category';E={$_.category.name}},
    @{N='Regulation';E={$_.regulations[0].name}} | Format-Table
```

## Section 9: Production PowerShell Wrapper Functions

```powershell
function Get-SecOpsDlpAlerts {
    <#
    .SYNOPSIS Retrieves DLP alerts from Graph Security API.
    .DESCRIPTION Returns structured results following the secops-squad pattern.
    #>
    [CmdletBinding()]
    param(
        [int]$Hours = 24,
        [ValidateSet("high","medium","low","informational")][string]$MinSeverity,
        [int]$Top = 50,
        [string]$Token
    )

    if (-not $Token) { $Token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token }
    $headers = @{ Authorization = "Bearer $Token" }

    $filter = "serviceSource eq 'microsoftDataLossPrevention' and createdDateTime ge $((Get-Date).AddHours(-$Hours).ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    if ($MinSeverity) { $filter += " and severity eq '$MinSeverity'" }

    try {
        $result = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/security/alerts_v2?`$filter=$filter&`$top=$Top&`$orderby=createdDateTime desc" `
            -Headers $headers
        return @{ ok = $true; data = $result.value; count = $result.value.Count }
    }
    catch {
        return @{ ok = $false; error = $_.Exception.Message; status = $_.Exception.Response.StatusCode.value__ }
    }
}

function Get-SecOpsAuditLog {
    <#
    .SYNOPSIS Searches the Unified Audit Log with structured result output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Operations,
        [string]$UserId,
        [int]$Days = 7,
        [int]$MaxResults = 5000
    )

    try {
        $params = @{
            StartDate  = (Get-Date).AddDays(-$Days)
            EndDate    = Get-Date
            Operations = $Operations -join ","
            ResultSize = $MaxResults
        }
        if ($UserId) { $params.UserIds = $UserId }

        $results = Search-UnifiedAuditLog @params
        if (-not $results) {
            return @{ ok = $true; data = @(); count = 0 }
        }

        $parsed = $results | ForEach-Object {
            $ad = $_.AuditData | ConvertFrom-Json
            [PSCustomObject]@{
                Timestamp = $_.CreationDate
                User      = $_.UserIds
                Operation = $_.Operations
                Detail    = $ad
            }
        }
        return @{ ok = $true; data = $parsed; count = $parsed.Count }
    }
    catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
}

function Get-SecOpsComplianceScore {
    <#
    .SYNOPSIS Returns current Compliance Manager score with top improvement actions.
    #>
    [CmdletBinding()]
    param(
        [int]$TopActions = 10,
        [string]$Token
    )

    if (-not $Token) { $Token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token }
    $headers = @{ Authorization = "Bearer $Token" }

    try {
        $score = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/beta/compliance/complianceManager/complianceScore" `
            -Headers $headers

        $actions = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/beta/compliance/complianceManager/improvementActions?`$filter=status ne 'completed'&`$orderby=pointsPossible desc&`$top=$TopActions" `
            -Headers $headers

        return @{
            ok   = $true
            data = @{
                score      = $score.score
                maxScore   = $score.maxScore
                percentage = [math]::Round($score.score / $score.maxScore * 100, 1)
                topActions = $actions.value | Select-Object id, displayName, pointsPossible, status
            }
        }
    }
    catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
}
```

## Section 10: Agent Integration Workflows

### Workflow 1: Classify → Label → Protect → Audit

```
Data Governance Lifecycle (agent-driven):
  │
  ├─ 1. CLASSIFY: Scan content with dataClassification/classifyText API
  │    └─ Identify sensitive information types (SITs) and confidence levels
  ├─ 2. LABEL: Evaluate recommended label via sensitivityLabels/evaluateApplication
  │    └─ Apply label automatically if auto-labeling policy matches
  ├─ 3. PROTECT: DLP policies enforce protection based on applied labels
  │    └─ Monitor DLP alerts via alerts_v2 (serviceSource: microsoftDataLossPrevention)
  ├─ 4. AUDIT: Search Unified Audit Log for label changes, DLP matches, access events
  │    └─ Correlate with Insider Risk signals for behavioral context
  └─ 5. REPORT: Pull Compliance Manager score + improvement actions
       └─ Map to .secops/compliance/requirements.yaml frameworks
```

### Workflow 2: Incident-Triggered Data Investigation

```
MITRE: T1567 (Exfiltration), T1530 (Data from Cloud Storage)

Trigger: Sentinel incident — data exfiltration alert
  │
  ├─ 1. Get-SecOpsDlpAlerts — recent DLP matches for the user
  ├─ 2. Get-SecOpsAuditLog — FileDownloaded, FileSyncDownloadedFull events
  ├─ 3. Check sensitivity labels on affected files (Graph API)
  ├─ 4. Check insider risk alerts for correlated behavioral signals
  ├─ 5. If evidence warrants → escalate to eDiscovery case (see ediscovery-api-wrapper.md)
  ├─ 6. Apply retention label to preserve evidence
  └─ 7. Update Sentinel incident with Purview context
```

### Workflow 3: Compliance Posture Monitoring

```
Schedule: Weekly agent-driven compliance check
  │
  ├─ 1. Get-SecOpsComplianceScore — current score + top actions
  ├─ 2. Compare against .secops/compliance/requirements.yaml frameworks
  ├─ 3. For each applicable framework:
  │    └─ Check assessment status, identify score drops
  ├─ 4. Review retention policy compliance:
  │    └─ Validate retention settings against requirements.yaml overrides
  ├─ 5. Check DLP policy coverage:
  │    └─ Ensure all required SITs are covered by active policies
  └─ 6. Generate compliance drift report for SOC lead review
```

## Section 11: Sentinel Integration

```kql
// Monitor Purview label changes — detect potential data declassification
// MITRE: T1565.001 (Stored Data Manipulation)
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "SensitivityLabelApplied" or OperationName == "SensitivityLabelChanged"
| extend
    User = tostring(InitiatedBy.user.userPrincipalName),
    LabelId = tostring(TargetResources[0].modifiedProperties[0].newValue),
    OldLabelId = tostring(TargetResources[0].modifiedProperties[0].oldValue)
| summarize LabelChanges = count() by User, bin(TimeGenerated, 1h)
| where LabelChanges > 10  // Threshold: bulk relabeling
| project TimeGenerated, User, LabelChanges
```

```kql
// DLP policy bypass detection — users consistently overriding DLP
// MITRE: T1567 (Exfiltration Over Web Service)
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation has "DLP"
| extend PolicyDetails_parsed = parse_json(PolicyDetails)
| mv-expand PolicyDetails_parsed
| where tostring(PolicyDetails_parsed.Rules[0].Actions) has "Override"
| summarize
    OverrideCount = count(),
    Policies = make_set(tostring(PolicyDetails_parsed.PolicyName)),
    Justifications = make_set(tostring(PolicyDetails_parsed.Rules[0].OverrideJustification))
    by UserId
| where OverrideCount > 5
| sort by OverrideCount desc
```

## Rate Limits and Throttling

| API | Limit | Strategy |
|---|---|---|
| Graph Security alerts | 300 req / 10 min per app | Cache alert list; poll at intervals |
| Information Protection labels | 100 req / 10 min per app | Cache label definitions (change infrequently) |
| Data Classification | 100 req / 10 min per app | Batch classify operations |
| Compliance Manager | 60 req / 10 min per app | Cache scores; poll daily |
| Office 365 Management API | 60,000 req / min per tenant | Use content blob pagination |
| Search-UnifiedAuditLog | 3 concurrent sessions | Queue audit searches; limit ResultSize |

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| 403 on label read | Missing InformationProtectionPolicy.Read | Add Graph permission + admin consent |
| DLP alerts empty | serviceSource filter incorrect | Use `microsoftDataLossPrevention` exactly |
| Audit log returns empty | Audit not enabled or search window too narrow | Enable audit logging; expand date range |
| Compliance Manager 404 | Beta API endpoint change | Check Graph beta changelog for breaking changes |
| Auto-labeling not applying | Policy in test mode | Change mode from `TestWithNotifications` to `Enable` |
| Retention label create fails | Missing RecordsManagement.ReadWrite.All | Add permission + admin consent |

## Related Skills

- **[Purview DLP Patterns](purview-dlp-patterns.md)** — DLP policy architecture, sensitivity label taxonomy, endpoint DLP (design-focused)
- **[eDiscovery API Wrapper](ediscovery-api-wrapper.md)** — Content search, legal hold, evidence export
- **[Microsoft Graph Security](microsoft-graph-security.md)** — Graph API foundation
- **[Defender API Permissions](defender-api-permissions.md)** — App registration and permission patterns
- **[Sentinel Workspace Setup](sentinel-workspace-setup.md)** — Data connector setup for Purview events
- **[Defender XDR Configuration](defender-xdr-configuration.md)** — DLP alerts in unified XDR portal
