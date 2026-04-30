---
title: eDiscovery API Wrapper
category: msft-security
difficulty: advanced
mitre_attack:
  - T1114  # Email Collection
  - T1530  # Data from Cloud Storage
  - T1213  # Data from Information Repositories
  - T1567  # Exfiltration Over Web Service
  - T1048  # Exfiltration Over Alternative Protocol
  - T1078  # Valid Accounts — insider threat context
products:
  - Microsoft Purview eDiscovery
  - Microsoft Graph Security API
  - Microsoft 365 Compliance Center
  - Microsoft Sentinel
  - Microsoft Defender XDR
author: Kima
version: 1.0.0
last_updated: 2026-04-30
---

# eDiscovery API Wrapper

## Overview

Microsoft Purview eDiscovery (Premium) enables SecOps teams to identify, collect, preserve, and export electronic content across Microsoft 365 workloads. In a security operations context, eDiscovery is critical for:

- **Insider threat investigation** — Search a user's mailbox, OneDrive, and Teams after anomalous DLP or UEBA alerts
- **Data exfiltration forensics** — Collect evidence of data leaving the organization via email, SharePoint, or Teams
- **Legal hold** — Preserve content when an incident may lead to litigation or regulatory reporting
- **Compliance investigations** — Respond to regulator requests for communication records
- **Phishing campaign response** — Search all mailboxes for messages matching a phishing indicator (sender, subject, URL)
- **Incident evidence packaging** — Export mailbox artifacts, Teams conversations, and documents as forensic evidence

Use this skill when:
- An incident requires searching across Exchange, SharePoint, OneDrive, or Teams content
- Legal or HR requests preservation of a user's communications
- A phishing campaign requires organization-wide mailbox search
- Evidence must be exported in forensic formats (PST, MSG, native) for external counsel or regulators

## Environment Context

Check `.secops/identity/tenants.yaml` for tenant topology. eDiscovery cases are tenant-scoped — multi-tenant or MSSP environments require cases created in each tenant. Check `.secops/compliance/requirements.yaml` for data residency constraints that affect export destinations and review set locations.

## Section 1: API Architecture

### Graph Security eDiscovery APIs

All eDiscovery operations use the Microsoft Graph `/security/cases/ediscoveryCases` endpoint family:

```
Base URL: https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases
Beta URL: https://graph.microsoft.com/beta/security/cases/ediscoveryCases
```

**API Hierarchy:**

```
/security/cases/ediscoveryCases
├── /{caseId}
│   ├── /custodians              # People whose data is being searched
│   │   ├── /{custodianId}
│   │   │   ├── /siteSources     # SharePoint/OneDrive locations
│   │   │   ├── /unifiedGroupSources  # Teams/M365 Group locations
│   │   │   └── /userSources     # Exchange mailbox locations
│   │   └── /applyHold           # Legal hold on custodian
│   ├── /noncustodialDataSources # Data sources without a custodian
│   ├── /searches                # Content searches within the case
│   │   ├── /{searchId}
│   │   │   ├── /additionalSources
│   │   │   └── /addToReviewSetOperation
│   │   └── /estimate            # Estimate search results
│   ├── /reviewSets              # Collected content for review
│   │   ├── /{reviewSetId}
│   │   │   ├── /queries         # Filter/tag within review set
│   │   │   └── /export          # Export review set content
│   │   └── /addToReviewSetOperation
│   ├── /operations              # Long-running operation status
│   └── /tags                    # Tags for classifying content
└── (collection)                 # List/create cases
```

### Required Permissions

| Permission | Type | Scope | Use Case |
|---|---|---|---|
| `eDiscovery.Read.All` | Application | Read cases, searches, review sets | Monitoring / dashboards |
| `eDiscovery.ReadWrite.All` | Application | Full CRUD on eDiscovery resources | Case management, search, export |
| `User.Read.All` | Application | Resolve custodian identities | Adding custodians to cases |

> **Note:** Application permissions require admin consent. For delegated flows, the signed-in user must hold the **eDiscovery Manager** or **eDiscovery Administrator** role in the Microsoft Purview compliance portal.

### Role-Based Access

| Role | Scope | Capabilities |
|---|---|---|
| **eDiscovery Manager** | Own cases only | Create cases, add custodians, run searches, manage holds, export |
| **eDiscovery Administrator** | All cases in tenant | All Manager capabilities + access any case, assign Managers, delete cases |
| **Compliance Administrator** | Tenant-wide | Full compliance portal access including eDiscovery |
| **Global Administrator** | Tenant-wide | Can assign eDiscovery roles; not automatically an eDiscovery Manager |

## Section 2: Case Management

### Create an eDiscovery Case

```powershell
# --- Graph PowerShell SDK ---
Import-Module Microsoft.Graph.Security

Connect-MgGraph -Scopes "eDiscovery.ReadWrite.All"

# Create a new case for an insider threat investigation
$case = New-MgSecurityCaseEdiscoveryCase -DisplayName "IR-2026-0042: Insider Threat - jsmith" `
    -Description "Investigation of anomalous data access by jsmith following UEBA alert" `
    -ExternalId "IR-2026-0042"  # Link to your incident tracking system

Write-Host "Case created: $($case.Id)"
```

```powershell
# --- REST via Invoke-RestMethod ---
$token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

$body = @{
    displayName = "IR-2026-0042: Insider Threat - jsmith"
    description = "Investigation of anomalous data access by jsmith following UEBA alert"
    externalId  = "IR-2026-0042"
} | ConvertTo-Json

$case = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases" `
    -Method POST -Headers $headers -Body $body

Write-Host "Case ID: $($case.id)"
```

### List and Filter Cases

```powershell
# List all active cases
$cases = Get-MgSecurityCaseEdiscoveryCase -Filter "status eq 'active'" -OrderBy "createdDateTime desc"
$cases | Select-Object DisplayName, Id, CreatedDateTime, Status | Format-Table

# Get a specific case by external ID
$case = Get-MgSecurityCaseEdiscoveryCase -Filter "externalId eq 'IR-2026-0042'"
```

### Close and Delete Cases

```powershell
# Close a case (preserves data, prevents new searches)
Update-MgSecurityCaseEdiscoveryCase -EdiscoveryCaseId $caseId -Status "closed"

# Reopen if needed
Update-MgSecurityCaseEdiscoveryCase -EdiscoveryCaseId $caseId -Status "active"
```

## Section 3: Custodians and Legal Hold

### Add Custodians to a Case

```powershell
# Add a custodian (automatically discovers their mailbox, OneDrive, Teams)
$custodian = New-MgSecurityCaseEdiscoveryCaseCustodian `
    -EdiscoveryCaseId $caseId `
    -Email "jsmith@contoso.com"

Write-Host "Custodian added: $($custodian.Id)"

# Add a non-custodial data source (shared mailbox, team site)
$noncustodial = @{
    "@odata.type" = "#microsoft.graph.security.ediscoveryNoncustodialDataSource"
    dataSource    = @{
        "@odata.type" = "#microsoft.graph.security.siteSource"
        site          = @{ webUrl = "https://contoso.sharepoint.com/sites/FinanceTeam" }
    }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$caseId/noncustodialDataSources" `
    -Method POST -Headers $headers -Body $noncustodial
```

### Place Custodians on Legal Hold

```powershell
# Apply hold to a specific custodian — preserves all content in-place
# POST /security/cases/ediscoveryCases/{id}/custodians/applyHold
$holdBody = @{
    ids = @($custodianId)
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$caseId/custodians/applyHold" `
    -Method POST -Headers $headers -Body $holdBody

# Verify hold status
$custodian = Get-MgSecurityCaseEdiscoveryCaseCustodian -EdiscoveryCaseId $caseId -EdiscoveryCustodianId $custodianId
Write-Host "Hold status: $($custodian.HoldStatus)"
# Expected: "applied", "applying", "removing", "partial", "none"
```

### Legal Hold Best Practices

| Practice | Rationale |
|---|---|
| Apply hold **before** running searches | Prevents spoliation while you build queries |
| Document hold date and justification | Legal defensibility requires chain of custody |
| Use non-custodial sources for shared resources | Shared mailboxes and team sites need explicit hold |
| Monitor hold status for "partial" | Partial hold means some sources failed — investigate |
| Release holds promptly when case closes | Unnecessary holds increase storage costs and legal exposure |

## Section 4: Content Search

### Create and Run Searches

```powershell
# KQL-based search across all custodian sources
$searchBody = @{
    displayName       = "Search: Confidential data exfiltration keywords"
    description       = "Search for evidence of unauthorized data sharing"
    contentQuery      = '(subject:"confidential" OR subject:"internal only") AND (recipients:personal@gmail.com OR recipients:protonmail.com) AND sent>=2026-03-01 AND sent<=2026-04-30'
    dataSourceScopes  = "allCaseCustodians"
} | ConvertTo-Json

$search = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$caseId/searches" `
    -Method POST -Headers $headers -Body $searchBody

$searchId = $search.id
```

### KQL Query Syntax for eDiscovery

| Operator | Example | Description |
|---|---|---|
| `subject:` | `subject:"Q4 financials"` | Search email subject lines |
| `from:` | `from:jsmith@contoso.com` | Sender address |
| `recipients:` | `recipients:external@gmail.com` | Any recipient (To, CC, BCC) |
| `sent>=` / `sent<=` | `sent>=2026-01-01` | Date range filters |
| `kind:` | `kind:email` or `kind:microsoftteams` | Content type filter |
| `filetype:` | `filetype:xlsx` | File extension |
| `filename:` | `filename:"customer-list"` | Document name |
| `site:` | `site:https://contoso.sharepoint.com/sites/Finance` | SharePoint site scope |
| `participants:` | `participants:jsmith` | Any party (from, to, cc, bcc) |
| `HasAttachment:true` | `HasAttachment:true AND filetype:pdf` | Messages with attachments |

**Common investigation queries:**

```
# Phishing campaign — search all mailboxes for IOC
from:phishing-sender@evil.com OR subject:"Urgent: Verify your account"

# Data exfiltration — sensitive docs sent externally
(filetype:xlsx OR filetype:csv) AND recipients:gmail.com AND HasAttachment:true

# Insider threat — communication with competitor
participants:jsmith@contoso.com AND (recipients:competitor.com OR from:competitor.com)

# Teams messages during incident window
kind:microsoftteams AND participants:jsmith AND sent>=2026-04-01 AND sent<=2026-04-15
```

### Estimate Search Results

```powershell
# Estimate before collecting (check scope is reasonable)
Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$caseId/searches/$searchId/estimate" `
    -Method POST -Headers $headers

# Poll for estimate completion
do {
    Start-Sleep -Seconds 10
    $searchStatus = Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$caseId/searches/$searchId" `
        -Headers $headers
} while ($searchStatus.lastEstimateStatistics -eq $null)

Write-Host "Estimated items: $($searchStatus.lastEstimateStatistics.mailboxCount) mailbox items"
Write-Host "Estimated size: $([math]::Round($searchStatus.lastEstimateStatistics.sizeInBytes / 1GB, 2)) GB"
```

## Section 5: Review Sets

### Add Search Results to a Review Set

```powershell
# Create a review set
$reviewSet = @{
    displayName = "Evidence Collection: IR-2026-0042"
} | ConvertTo-Json

$rs = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$caseId/reviewSets" `
    -Method POST -Headers $headers -Body $reviewSet

$reviewSetId = $rs.id

# Add search results to the review set
$addBody = @{
    search = @{ id = $searchId }
    additionalDataOptions = "allVersions"  # or "linkedFiles"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$caseId/reviewSets/$reviewSetId/addToReviewSetOperation" `
    -Method POST -Headers $headers -Body $addBody
```

### Query Within a Review Set

```powershell
# Create a query to filter review set content
$queryBody = @{
    displayName  = "External recipients only"
    contentQuery = "recipients:gmail.com OR recipients:yahoo.com"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$caseId/reviewSets/$reviewSetId/queries" `
    -Method POST -Headers $headers -Body $queryBody
```

## Section 6: Export

### Export Review Set Content

```powershell
# Export from review set
$exportBody = @{
    outputName       = "IR-2026-0042-Export-01"
    description      = "Forensic export for legal review"
    exportOptions    = "originalFiles"     # originalFiles | text | pdfReplacement
    exportStructure  = "directory"         # directory | pst
} | ConvertTo-Json

$export = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$caseId/reviewSets/$reviewSetId/export" `
    -Method POST -Headers $headers -Body $exportBody

# Poll export operation status
$operationId = $export.id
do {
    Start-Sleep -Seconds 30
    $opStatus = Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$caseId/operations/$operationId" `
        -Headers $headers
    Write-Host "Export status: $($opStatus.status) — $($opStatus.percentProgress)%"
} while ($opStatus.status -notin @("succeeded", "failed"))

# Get download URL (available for ~24 hours)
if ($opStatus.status -eq "succeeded") {
    Write-Host "Download URL: $($opStatus.resultInfo.downloadUrl)"
}
```

### Export Format Options

| Option | Format | Use Case |
|---|---|---|
| `originalFiles` | Native format (DOCX, XLSX, MSG) | Full forensic review; preserves metadata |
| `text` | Plain text extraction | Keyword search and text analysis |
| `pdfReplacement` | PDF conversion | Legal review; consistent rendering |

| Structure | Description | Use Case |
|---|---|---|
| `directory` | Folder structure with load file | Forensic tools (Relativity, Nuix) |
| `pst` | Outlook PST archive | Email-centric review in Outlook |

## Section 7: End-to-End Agent Workflows

### Workflow 1: Phishing Campaign Response

```
MITRE: T1566.001 (Spearphishing Attachment), T1114 (Email Collection)

Trigger: Sentinel alert — phishing email reported by user
  │
  ├─ 1. Create eDiscovery case linked to Sentinel incident ID
  ├─ 2. Build KQL query from phishing IOCs:
  │      from:sender@evil.com OR subject:"exact subject line"
  ├─ 3. Run search across ALL mailboxes (dataSourceScopes: allTenantMailboxes)
  ├─ 4. Estimate results — validate scope before collection
  ├─ 5. Add results to review set
  ├─ 6. Tag messages: "Delivered + Opened", "Delivered + Not Opened", "Blocked"
  ├─ 7. Export evidence for incident record
  └─ 8. Cross-reference with Defender XDR for click/payload telemetry
```

### Workflow 2: Insider Threat Investigation

```
MITRE: T1567 (Exfiltration Over Web Service), T1530 (Data from Cloud Storage)

Trigger: UEBA alert — user accessing unusual volume of files + DLP match
  │
  ├─ 1. Create case; add user as custodian
  ├─ 2. Apply legal hold IMMEDIATELY (preserve all content)
  ├─ 3. Search 1: All emails sent externally in last 90 days
  │      from:user@contoso.com AND NOT recipients:contoso.com
  ├─ 4. Search 2: Files accessed/downloaded from SharePoint/OneDrive
  │      author:user AND (filetype:xlsx OR filetype:csv OR filetype:pdf)
  ├─ 5. Search 3: Teams DMs with external users
  │      kind:microsoftteams AND participants:user AND NOT participants:contoso.com
  ├─ 6. Collect all searches into review set
  ├─ 7. Review and tag evidence by severity
  ├─ 8. Export tagged evidence for HR/Legal
  └─ 9. Coordinate with Purview Insider Risk case if parallel investigation
```

### Workflow 3: Compliance / Regulator Request

```
Trigger: Regulator requests all communications regarding "Project Phoenix" for date range
  │
  ├─ 1. Create case with regulator reference number as externalId
  ├─ 2. Add relevant custodians (project team members)
  ├─ 3. Search: "Project Phoenix" AND sent>=2025-06-01 AND sent<=2026-03-31
  ├─ 4. Include Teams, email, SharePoint, and OneDrive
  ├─ 5. Estimate and validate scope with legal counsel
  ├─ 6. Collect to review set → attorney review → privilege tagging
  ├─ 7. Export non-privileged content in requested format
  └─ 8. Document chain of custody in case notes
```

## Section 8: Production PowerShell Wrapper Functions

```powershell
function New-SecOpsEdiscoveryCase {
    <#
    .SYNOPSIS Creates an eDiscovery case linked to a security incident.
    .DESCRIPTION Wrapper for Graph eDiscovery API with structured result pattern.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IncidentId,
        [Parameter(Mandatory)][string]$DisplayName,
        [string]$Description = "",
        [string]$Token
    )

    if (-not $Token) { $Token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token }
    $headers = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }

    $body = @{
        displayName = $DisplayName
        description = $Description
        externalId  = $IncidentId
    } | ConvertTo-Json

    try {
        $result = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases" `
            -Method POST -Headers $headers -Body $body
        return @{ ok = $true; data = $result }
    }
    catch {
        return @{ ok = $false; error = $_.Exception.Message; status = $_.Exception.Response.StatusCode.value__ }
    }
}

function Search-SecOpsMailboxes {
    <#
    .SYNOPSIS Runs a KQL content search within an eDiscovery case.
    .DESCRIPTION Creates a search, estimates results, and returns statistics.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CaseId,
        [Parameter(Mandatory)][string]$Query,
        [string]$DisplayName = "Agent Search $(Get-Date -Format 'yyyy-MM-dd-HHmm')",
        [string]$Scope = "allCaseCustodians",  # or "allTenantMailboxes"
        [string]$Token
    )

    if (-not $Token) { $Token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token }
    $headers = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }

    $body = @{
        displayName      = $DisplayName
        contentQuery     = $Query
        dataSourceScopes = $Scope
    } | ConvertTo-Json

    try {
        $search = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$CaseId/searches" `
            -Method POST -Headers $headers -Body $body

        # Trigger estimate
        Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$CaseId/searches/$($search.id)/estimate" `
            -Method POST -Headers $headers | Out-Null

        return @{ ok = $true; data = @{ searchId = $search.id; displayName = $search.displayName; query = $Query } }
    }
    catch {
        return @{ ok = $false; error = $_.Exception.Message; status = $_.Exception.Response.StatusCode.value__ }
    }
}

function Export-SecOpsReviewSet {
    <#
    .SYNOPSIS Exports a review set and polls until completion.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CaseId,
        [Parameter(Mandatory)][string]$ReviewSetId,
        [string]$OutputName = "Export-$(Get-Date -Format 'yyyyMMdd-HHmm')",
        [ValidateSet("originalFiles","text","pdfReplacement")][string]$Format = "originalFiles",
        [ValidateSet("directory","pst")][string]$Structure = "directory",
        [string]$Token,
        [int]$TimeoutMinutes = 60
    )

    if (-not $Token) { $Token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token }
    $headers = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }

    $body = @{
        outputName      = $OutputName
        exportOptions   = $Format
        exportStructure = $Structure
    } | ConvertTo-Json

    try {
        $export = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$CaseId/reviewSets/$ReviewSetId/export" `
            -Method POST -Headers $headers -Body $body

        $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
        do {
            Start-Sleep -Seconds 30
            $opStatus = Invoke-RestMethod `
                -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$CaseId/operations/$($export.id)" `
                -Headers $headers
        } while ($opStatus.status -notin @("succeeded","failed") -and (Get-Date) -lt $deadline)

        if ($opStatus.status -eq "succeeded") {
            return @{ ok = $true; data = $opStatus }
        }
        return @{ ok = $false; error = "Export $($opStatus.status): $($opStatus.resultInfo.message)" }
    }
    catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
}
```

## Section 9: Sentinel Integration — eDiscovery Monitoring

```kql
// Monitor eDiscovery case activity via Unified Audit Log
// MITRE: T1213 — detect unauthorized eDiscovery searches
CloudAppEvents
| where TimeGenerated > ago(24h)
| where ActionType has_any ("eDisco", "SearchCreated", "CaseCreated", "HoldCreated", "SearchExported")
| project
    TimeGenerated,
    ActionType,
    AccountDisplayName,
    AccountObjectId,
    IPAddress,
    CaseId = tostring(RawEventData.CaseId),
    SearchQuery = tostring(RawEventData.Query)
| sort by TimeGenerated desc
```

```kql
// Alert: eDiscovery export by non-eDiscovery team member
// Detects potential abuse of eDiscovery permissions
let authorizedEdiscoUsers = dynamic(["edisco-admin@contoso.com", "legal-hold@contoso.com"]);
CloudAppEvents
| where TimeGenerated > ago(1h)
| where ActionType == "SearchExported"
| where AccountUpn !in (authorizedEdiscoUsers)
| project TimeGenerated, AccountUpn, IPAddress, ActionType
```

## Section 10: Rate Limits and Throttling

| Resource | Limit | Strategy |
|---|---|---|
| eDiscovery API calls | 2,000 requests / 10 minutes per app | Implement exponential backoff on 429 |
| Concurrent searches per case | 10 | Queue searches; poll for completion |
| Concurrent exports | 1 per review set | Wait for current export before starting another |
| Review set max items | 1,000,000 items | Split large collections into multiple review sets |
| Export download link validity | ~24 hours | Download immediately after export completes |

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| 403 on case creation | Missing eDiscovery.ReadWrite.All or role assignment | Verify Graph permission + compliance portal role |
| Search returns 0 results | KQL syntax error or wrong date format | Use `sent>=2026-01-01` format, not `sent>="2026-01-01"` |
| Hold status stuck on "applying" | Large mailbox or indexing backlog | Wait up to 24h; check compliance portal for errors |
| Export fails with "content not indexed" | Items not yet indexed for search | Re-run indexing on custodian data sources |
| Review set collection incomplete | Partial hold on some sources | Check custodian hold status; re-apply hold if "partial" |

## Related Skills

- **[Purview DLP Patterns](purview-dlp-patterns.md)** — DLP alerts often trigger eDiscovery investigations
- **[Purview API Wrapper](purview-api-wrapper.md)** — Sensitivity labels, audit logs, insider risk integration
- **[Microsoft Graph Security](microsoft-graph-security.md)** — Graph API foundation for eDiscovery calls
- **[Defender API Permissions](defender-api-permissions.md)** — App registration and permission patterns
- **[Sentinel API Reference](sentinel-api-reference.md)** — Correlate eDiscovery activity with Sentinel incidents
- **[Defender XDR Configuration](defender-xdr-configuration.md)** — XDR incidents that trigger eDiscovery workflows
