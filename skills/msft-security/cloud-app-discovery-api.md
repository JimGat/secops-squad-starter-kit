---
title: Defender for Cloud Apps Discovery API
category: msft-security
difficulty: advanced
mitre_attack:
  - T1071   # Application Layer Protocol (shadow IT)
  - T1567   # Exfiltration Over Web Service
  - T1530   # Data from Cloud Storage
  - T1199   # Trusted Relationship (OAuth app abuse)
  - T1078   # Valid Accounts
  - T1098   # Account Manipulation (consent grant abuse)
  - T1537   # Transfer Data to Cloud Account
  - T1539   # Steal Web Session Cookie
products:
  - Microsoft Defender for Cloud Apps
  - Microsoft Defender XDR
  - Microsoft Sentinel
  - Microsoft Entra ID
author: Kima
version: 1.0.0
last_updated: 2026-05-04
---

# Defender for Cloud Apps Discovery API

## Overview

Shadow IT is the #1 unmanaged risk surface in most enterprises. Microsoft Defender for Cloud Apps (MDCA) Discovery API provides programmatic access to **discover unapproved cloud applications**, **score their risk**, **enforce governance policies**, and **monitor usage patterns** — all critical for reducing the attack surface created by employees adopting unsanctioned SaaS tools.

This skill covers the MDCA REST API surface for:
- **Cloud Discovery** — Upload firewall/proxy logs, enumerate discovered apps, track usage
- **App Governance** — Sanction/unsanction apps, apply custom tags, manage OAuth app permissions
- **Activity and Alert Monitoring** — Query user activities, file operations, and security alerts
- **DLP Integration** — File monitoring policies and data classification across cloud apps

Use this skill when:
- Building automated Shadow IT discovery pipelines from network logs
- Implementing app risk scoring and governance workflows
- Auditing OAuth app permissions across the tenant
- Integrating MDCA discovery data with Sentinel for SOC visibility
- Enforcing sanctioned app policies programmatically

## Environment Context

Before using MDCA Discovery APIs, check `.secops/`:

1. **`.secops/environment.yaml`** — Tenant ID, MDCA portal URL
2. **`.secops/identity/tenants.yaml`** — API token source, multi-tenant MDCA access
3. **`.secops/data-sources/data-source-map.yaml`** — MDCA tables in Sentinel (`McasShadowItReporting`)
4. **`.secops/compliance/requirements.yaml`** — Regulatory requirements driving shadow IT controls

## Section 1: API Authentication

### MDCA API Token

MDCA uses portal-generated API tokens (not standard OAuth), obtained from the MDCA portal under **Settings → API Tokens**.

```powershell
function Get-SecOpsMdcaHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantPortalUrl,  # e.g., contoso.portal.cloudappsecurity.com
        [Parameter(Mandatory)][string]$ApiToken
    )

    return @{
        Authorization = "Token $ApiToken"
        'Content-Type' = 'application/json'
    }
}
```

**Portal URL by cloud environment:**
| Cloud | Portal URL Format |
|---|---|
| Commercial | `{tenant}.portal.cloudappsecurity.com` |
| GCC | `{tenant}.portal.cloudappsecurity.us` |
| GCC High | Not available |
| DoD | Not available |

### Base API URL

```
Commercial: https://{tenant}.portal.cloudappsecurity.com/api/v1/
GCC:        https://{tenant}.portal.cloudappsecurity.us/api/v1/
```

## Section 2: Cloud Discovery

### Upload Discovery Logs

MDCA accepts firewall and proxy logs to discover cloud app usage. Supported formats include Palo Alto, Cisco ASA, Zscaler, Blue Coat, Squid, and generic CEF/W3C.

```powershell
function Import-SecOpsDiscoveryLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PortalUrl,
        [Parameter(Mandatory)][string]$ApiToken,
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string]$DataSourceName,
        [ValidateSet('PALO_ALTO','CISCO_ASA','ZSCALER','BLUECOAT',
                     'SQUID','CHECKPOINT','GENERIC_CEF','GENERIC_W3C')]
        [string]$LogFormat = 'GENERIC_CEF',
        [string]$ReceiverType = 'FTP'
    )

    $headers = Get-SecOpsMdcaHeaders -TenantPortalUrl $PortalUrl -ApiToken $ApiToken

    # Step 1: Initiate upload
    $initBody = @{
        uploadUrl  = $PortalUrl
        inputStreamName = $DataSourceName
        source     = $LogFormat
        receiverType = $ReceiverType
    } | ConvertTo-Json

    try {
        $initResult = Invoke-RestMethod `
            -Uri "https://$PortalUrl/api/v1/discovery/upload_url/" `
            -Headers $headers -Method Post -Body $initBody
    } catch {
        return @{ ok = $false; error = "Upload init failed: $($_.Exception.Message)" }
    }

    # Step 2: Upload file content
    $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    $uploadHeaders = @{
        Authorization = "Token $ApiToken"
        'Content-Type' = 'application/octet-stream'
    }

    try {
        $uploadResult = Invoke-RestMethod `
            -Uri $initResult.url `
            -Headers $uploadHeaders -Method Put -Body $fileBytes
    } catch {
        return @{ ok = $false; error = "File upload failed: $($_.Exception.Message)" }
    }

    # Step 3: Finalize
    $finalBody = @{ uploadUrl = $initResult.url } | ConvertTo-Json
    try {
        $finalResult = Invoke-RestMethod `
            -Uri "https://$PortalUrl/api/v1/discovery/done_upload/" `
            -Headers $headers -Method Post -Body $finalBody
        return @{ ok = $true; data = $finalResult }
    } catch {
        return @{ ok = $false; error = "Upload finalize failed: $($_.Exception.Message)" }
    }
}
```

### Get Discovered Apps

```powershell
function Get-SecOpsDiscoveredApps {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PortalUrl,
        [Parameter(Mandatory)][string]$ApiToken,
        [int]$MinRiskScore = 0,
        [int]$MaxRiskScore = 10,
        [int]$Limit = 100,
        [ValidateSet('all','sanctioned','unsanctioned','untagged')]
        [string]$SanctionFilter = 'all'
    )

    $headers = Get-SecOpsMdcaHeaders -TenantPortalUrl $PortalUrl -ApiToken $ApiToken

    $filters = @{
        score = @{ gte = $MinRiskScore; lte = $MaxRiskScore }
    }

    if ($SanctionFilter -ne 'all') {
        $sanctionMap = @{
            'sanctioned'   = $true
            'unsanctioned' = $false
            'untagged'     = $null
        }
        $filters['sanctioned'] = @{ eq = $sanctionMap[$SanctionFilter] }
    }

    $body = @{
        filters = $filters
        limit   = $Limit
        sortField = 'score'
        sortDirection = 'desc'
    } | ConvertTo-Json -Depth 5

    try {
        $result = Invoke-RestMethod `
            -Uri "https://$PortalUrl/api/v1/discovery/discovered_apps/" `
            -Headers $headers -Method Post -Body $body

        $apps = $result.data | ForEach-Object {
            @{
                appId       = $_.appId
                name        = $_.name
                category    = $_.category
                riskScore   = $_.score
                sanctioned  = $_.sanctioned
                users       = $_.userCount
                traffic     = $_.trafficTotalBytes
                lastSeen    = $_.lastSeen
            }
        }

        return @{ ok = $true; data = $apps; count = $apps.Count; total = $result.total }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
}
```

### Risk Score Breakdown

MDCA scores apps 1–10 across these categories:

| Category | Weight | Factors |
|---|---|---|
| General | 15% | Company founding, domain age, headquarters |
| Security | 35% | Encryption, MFA, audit log, data-at-rest encryption |
| Compliance | 15% | SOC 2, ISO 27001, HIPAA, GDPR certifications |
| Legal | 15% | Data ownership, DMCA compliance, privacy policy |
| User | 20% | Community rating, adoption patterns |

## Section 3: App Governance

### Sanction or Unsanction Apps

```powershell
function Set-SecOpsAppSanctionStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PortalUrl,
        [Parameter(Mandatory)][string]$ApiToken,
        [Parameter(Mandatory)][int[]]$AppIds,
        [Parameter(Mandatory)][ValidateSet('sanction','unsanction')]
        [string]$Action
    )

    $headers = Get-SecOpsMdcaHeaders -TenantPortalUrl $PortalUrl -ApiToken $ApiToken

    $endpoint = switch ($Action) {
        'sanction'   { 'https://{0}/api/v1/discovery/sanction/' -f $PortalUrl }
        'unsanction' { 'https://{0}/api/v1/discovery/unsanction/' -f $PortalUrl }
    }

    $body = @{ appIds = $AppIds } | ConvertTo-Json

    try {
        $result = Invoke-RestMethod -Uri $endpoint -Headers $headers -Method Post -Body $body
        return @{
            ok     = $true
            action = $Action
            appIds = $AppIds
            data   = $result
        }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
}
```

### OAuth App Management

```powershell
function Get-SecOpsOAuthApps {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PortalUrl,
        [Parameter(Mandatory)][string]$ApiToken,
        [ValidateSet('all','highPrivilege','community','rare')]
        [string]$Filter = 'all',
        [int]$Limit = 100
    )

    $headers = Get-SecOpsMdcaHeaders -TenantPortalUrl $PortalUrl -ApiToken $ApiToken

    $filters = @{}
    switch ($Filter) {
        'highPrivilege' { $filters['permissionLevel'] = @{ eq = 3 } }
        'community'     { $filters['appCategory']     = @{ eq = 'community' } }
        'rare'          { $filters['userCount']        = @{ lte = 5 } }
    }

    $body = @{
        filters       = $filters
        limit         = $Limit
        sortField     = 'permissionLevel'
        sortDirection = 'desc'
    } | ConvertTo-Json -Depth 5

    try {
        $result = Invoke-RestMethod `
            -Uri "https://$PortalUrl/api/v1/app_permissions/" `
            -Headers $headers -Method Post -Body $body

        $apps = $result.data | ForEach-Object {
            @{
                appId           = $_.clientId
                name            = $_.displayName
                publisher       = $_.publisher
                permissionLevel = $_.permissionLevel
                permissions     = $_.permissions
                userCount       = $_.userCount
                lastAuthorized  = $_.lastAuthorized
                isBanned        = $_.isBanned
            }
        }

        return @{ ok = $true; data = $apps; count = $apps.Count }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
}

function Set-SecOpsOAuthAppStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PortalUrl,
        [Parameter(Mandatory)][string]$ApiToken,
        [Parameter(Mandatory)][string]$AppClientId,
        [Parameter(Mandatory)][ValidateSet('approve','ban','revoke')]
        [string]$Action
    )

    $headers = Get-SecOpsMdcaHeaders -TenantPortalUrl $PortalUrl -ApiToken $ApiToken

    $endpoint = "https://$PortalUrl/api/v1/app_permissions/$AppClientId/$Action/"

    try {
        $result = Invoke-RestMethod -Uri $endpoint -Headers $headers -Method Post
        return @{ ok = $true; action = $Action; appId = $AppClientId; data = $result }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
}
```

## Section 4: Activity Logs and Alerts

### Query Activity Logs

```powershell
function Get-SecOpsMdcaActivities {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PortalUrl,
        [Parameter(Mandatory)][string]$ApiToken,
        [int]$HoursBack = 24,
        [string]$UserUpn,
        [ValidateSet('all','admin','login','access','failed')]
        [string]$ActivityType = 'all',
        [int]$Limit = 200
    )

    $headers = Get-SecOpsMdcaHeaders -TenantPortalUrl $PortalUrl -ApiToken $ApiToken

    $cutoff = [DateTimeOffset]::UtcNow.AddHours(-$HoursBack).ToUnixTimeMilliseconds()
    $filters = @{
        date = @{ gte = $cutoff }
    }

    if ($UserUpn)       { $filters['user.username'] = @{ eq = $UserUpn } }
    if ($ActivityType -ne 'all') {
        $typeMap = @{
            'admin'  = 'EVENT_CATEGORY_ADMIN'
            'login'  = 'EVENT_CATEGORY_LOGIN'
            'access' = 'EVENT_CATEGORY_ACCESS'
            'failed' = 'EVENT_CATEGORY_LOGIN_FAILED'
        }
        $filters['activity.eventType'] = @{ eq = $typeMap[$ActivityType] }
    }

    $body = @{
        filters       = $filters
        limit         = $Limit
        sortField     = 'date'
        sortDirection = 'desc'
    } | ConvertTo-Json -Depth 5

    try {
        $result = Invoke-RestMethod `
            -Uri "https://$PortalUrl/api/v1/activities/" `
            -Headers $headers -Method Post -Body $body
        return @{ ok = $true; data = $result.data; count = $result.total }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
}
```

### Query Alerts

```powershell
function Get-SecOpsMdcaAlerts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PortalUrl,
        [Parameter(Mandatory)][string]$ApiToken,
        [ValidateSet('all','open','dismissed','resolved')]
        [string]$Status = 'open',
        [ValidateSet('all','high','medium','low','informational')]
        [string]$Severity = 'all',
        [int]$Limit = 100
    )

    $headers = Get-SecOpsMdcaHeaders -TenantPortalUrl $PortalUrl -ApiToken $ApiToken

    $filters = @{}
    if ($Status -ne 'all') {
        $statusMap = @{ 'open' = 0; 'dismissed' = 1; 'resolved' = 2 }
        $filters['resolutionStatus'] = @{ eq = $statusMap[$Status] }
    }
    if ($Severity -ne 'all') {
        $sevMap = @{ 'high' = 2; 'medium' = 1; 'low' = 0; 'informational' = 3 }
        $filters['severity'] = @{ eq = $sevMap[$Severity] }
    }

    $body = @{
        filters       = $filters
        limit         = $Limit
        sortField     = 'date'
        sortDirection = 'desc'
    } | ConvertTo-Json -Depth 5

    try {
        $result = Invoke-RestMethod `
            -Uri "https://$PortalUrl/api/v1/alerts/" `
            -Headers $headers -Method Post -Body $body
        return @{ ok = $true; data = $result.data; count = $result.total }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
}
```

## Section 5: File Monitoring and DLP

### Query Monitored Files

```powershell
function Get-SecOpsMdcaFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PortalUrl,
        [Parameter(Mandatory)][string]$ApiToken,
        [string]$FileExtension,
        [ValidateSet('all','shared','private','sharedExternal')]
        [string]$SharingScope = 'all',
        [switch]$SensitiveOnly,
        [int]$Limit = 100
    )

    $headers = Get-SecOpsMdcaHeaders -TenantPortalUrl $PortalUrl -ApiToken $ApiToken

    $filters = @{}
    if ($FileExtension) { $filters['fileType'] = @{ eq = $FileExtension } }
    if ($SharingScope -ne 'all') {
        $scopeMap = @{ 'shared' = 1; 'private' = 0; 'sharedExternal' = 2 }
        $filters['sharing'] = @{ eq = $scopeMap[$SharingScope] }
    }
    if ($SensitiveOnly) { $filters['sensitivityLabel'] = @{ isset = $true } }

    $body = @{
        filters       = $filters
        limit         = $Limit
        sortField     = 'date'
        sortDirection = 'desc'
    } | ConvertTo-Json -Depth 5

    try {
        $result = Invoke-RestMethod `
            -Uri "https://$PortalUrl/api/v1/files/" `
            -Headers $headers -Method Post -Body $body
        return @{ ok = $true; data = $result.data; count = $result.total }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
}
```

## Section 6: Sentinel Integration

### Cloud App Security Connector

MDCA integrates with Sentinel via the **Microsoft Defender for Cloud Apps** data connector, which populates three tables:

| Sentinel Table | Content |
|---|---|
| `McasShadowItReporting` | Cloud Discovery data (app usage, traffic, users) |
| `SecurityAlert` | MDCA-generated alerts (filtered by `ProviderName == "MCAS"`) |
| `CloudAppEvents` | Unified activity log (in Defender XDR advanced hunting) |

### KQL: Shadow IT Detection

```kql
// Top unsanctioned apps by user count and traffic
McasShadowItReporting
| where TimeGenerated > ago(30d)
| where StreamName != "Win10 Endpoint Users"
| summarize
    Users = dcount(EnrichedUserName),
    TotalTrafficMB = sum(TotalBytes) / 1048576,
    LastSeen = max(TimeGenerated)
    by AppName, AppScore, AppCategory
| where AppScore < 6
| order by Users desc
| take 25
| project AppName, AppCategory, RiskScore = AppScore, Users, 
    TrafficMB = round(TotalTrafficMB, 2), LastSeen
```

### KQL: OAuth App Risk Detection

```kql
// High-privilege OAuth apps with low user adoption (potential abuse)
CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType == "ConsentToApplication"
| extend AppName = tostring(parse_json(RawEventData).AppDisplayName)
| extend Permissions = tostring(parse_json(RawEventData).Permissions)
| where Permissions has_any ("Mail.ReadWrite", "Files.ReadWrite.All", 
                              "Directory.ReadWrite.All", "full_access_as_app")
| summarize
    ConsentCount = count(),
    Users = make_set(AccountUpn),
    FirstSeen = min(TimeGenerated)
    by AppName, Permissions
| where ConsentCount <= 3
| project AppName, Permissions, ConsentCount, Users, FirstSeen,
    Risk = "High-privilege app with limited adoption"
```

### KQL: Alert Correlation Across MDCA and Defender

```kql
// Correlate MDCA alerts with Defender XDR incidents for unified view
let MdcaAlerts = SecurityAlert
| where TimeGenerated > ago(7d)
| where ProviderName == "MCAS"
| extend AlertEntities = parse_json(Entities)
| mv-expand Entity = AlertEntities
| where Entity.Type == "account"
| extend UserUPN = strcat(Entity.Name, "@", Entity.UPNSuffix)
| project MdcaAlertTime = TimeGenerated, MdcaAlertName = AlertName,
    MdcaSeverity = AlertSeverity, UserUPN;
let DefenderAlerts = SecurityAlert
| where TimeGenerated > ago(7d)
| where ProviderName in ("Microsoft 365 Defender", "MDATP")
| extend AlertEntities = parse_json(Entities)
| mv-expand Entity = AlertEntities
| where Entity.Type == "account"
| extend UserUPN = strcat(Entity.Name, "@", Entity.UPNSuffix)
| project DefenderAlertTime = TimeGenerated, DefenderAlertName = AlertName,
    DefenderSeverity = AlertSeverity, UserUPN;
MdcaAlerts
| join kind=inner DefenderAlerts on UserUPN
| where abs(datetime_diff('hour', MdcaAlertTime, DefenderAlertTime)) <= 24
| project UserUPN, MdcaAlertName, MdcaAlertTime, DefenderAlertName, 
    DefenderAlertTime, CorrelationWindow = "24h"
```

## Section 7: .secops/ Integration

### Discovery Configuration

Add to `.secops/environment.yaml`:

```yaml
# .secops/environment.yaml — MDCA Discovery
cloud_app_discovery:
  enabled: true
  portal_url: contoso.portal.cloudappsecurity.com
  api_token_keyvault: kv-secops-prod
  api_token_secret_name: mdca-api-token
  log_sources:
    - name: palo-alto-fw
      format: PALO_ALTO
      upload_frequency: daily
    - name: zscaler-proxy
      format: ZSCALER
      upload_frequency: daily
  auto_unsanction_threshold: 3     # Risk score <= 3 auto-unsanctioned
  review_required_threshold: 5     # Risk score 4-5 requires SOC review
```

### Sanctioned App List

```yaml
# .secops/sanctioned-apps.yaml
schema_version: "1.0"
sanctioned_apps:
  - name: Microsoft 365
    app_id: 11161
    category: productivity
    risk_score: 10
    approved_by: CISO
    approved_date: "2026-01-15"

  - name: Salesforce
    app_id: 11114
    category: crm
    risk_score: 9
    approved_by: IT-Director
    approved_date: "2026-02-01"

  - name: Slack
    app_id: 10051
    category: collaboration
    risk_score: 8
    approved_by: CISO
    approved_date: "2026-01-15"
    conditions:
      - "DLP policy required"
      - "External sharing disabled"

unsanctioned_apps:
  - name: WeTransfer
    app_id: 10904
    category: file_sharing
    risk_score: 4
    reason: "Unencrypted file transfer, no audit trail"
    blocked_date: "2026-03-01"

  - name: Mega
    app_id: 10375
    category: cloud_storage
    risk_score: 3
    reason: "No enterprise controls, high exfiltration risk"
    blocked_date: "2026-02-15"
```

### Risk Threshold Configuration

```yaml
# .secops/discovery-risk-thresholds.yaml
schema_version: "1.0"
risk_thresholds:
  auto_block: 3          # Score <= 3: auto-block and alert SOC
  soc_review: 5          # Score 4-5: queue for SOC analyst review
  monitor: 7             # Score 6-7: monitor usage trends
  approved: 8            # Score 8+: eligible for sanctioning

alert_rules:
  - trigger: new_app_discovered
    min_users: 5
    severity: medium
    action: create_sentinel_incident

  - trigger: high_risk_app_usage
    max_risk_score: 3
    severity: high
    action: auto_unsanction_and_alert

  - trigger: oauth_high_privilege
    permission_level: 3
    severity: high
    action: create_sentinel_incident
```

## Rate Limits

| Endpoint | Limit | Window |
|---|---|---|
| Discovery endpoints | 30 requests | 1 minute |
| Activity queries | 30 requests | 1 minute |
| Alert operations | 30 requests | 1 minute |
| File queries | 30 requests | 1 minute |
| Entity operations | 30 requests | 1 minute |

All endpoints return `429` with `Retry-After` header on throttle. Use the retry pattern from [defender-cloud-apps.md](defender-cloud-apps.md).

## Cross-References

- **[defender-cloud-apps.md](defender-cloud-apps.md)** — MDCA CASB fundamentals, policy types, session controls
- **[defender-api-permissions.md](defender-api-permissions.md)** — App registration for Graph-based MDCA operations
- **[sentinel-api-reference.md](sentinel-api-reference.md)** — Log Analytics queries for MDCA Sentinel tables
- **[microsoft-graph-security.md](microsoft-graph-security.md)** — Graph Security API for unified alert management
- **[purview-api-wrapper.md](purview-api-wrapper.md)** — DLP policy coordination with MDCA file monitoring
- **[copilot-for-security.md](copilot-for-security.md)** — AI-assisted shadow IT analysis
