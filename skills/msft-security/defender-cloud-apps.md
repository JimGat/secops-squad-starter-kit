---
title: Microsoft Defender for Cloud Apps (MDCA)
category: msft-security
difficulty: advanced
mitre_attack:
  - T1078   # Valid Accounts (OAuth app abuse)
  - T1550   # Use Alternate Authentication Material (token theft)
  - T1530   # Data from Cloud Storage (SaaS exfiltration)
  - T1199   # Trusted Relationship (OAuth consent grant)
  - T1071   # Application Layer Protocol (shadow IT)
  - T1567   # Exfiltration Over Web Service
  - T1098   # Account Manipulation (app consent abuse)
  - T1537   # Transfer Data to Cloud Account
products:
  - Microsoft Defender for Cloud Apps
  - Microsoft Defender XDR
  - Microsoft Sentinel
  - Microsoft Entra ID
  - Microsoft Purview
author: Kima
version: 1.0.0
last_updated: 2026-04-30
---

# Microsoft Defender for Cloud Apps (MDCA)

## Overview

Microsoft Defender for Cloud Apps is Microsoft's CASB providing visibility and control over cloud applications across four pillars: **Shadow IT Discovery**, **Information Protection** (DLP in cloud apps), **Threat Protection** (anomaly detection, compromised accounts, OAuth risk), and **Compliance** (app risk scoring, session controls).

Use this skill when:
- Assessing Shadow IT exposure via Cloud Discovery
- Building activity, file, or session policies for cloud app monitoring
- Automating OAuth app audits and governance actions via REST API
- Integrating MDCA alerts into Sentinel incident workflows
- Configuring Conditional Access App Control for real-time session policies

## Environment Context

Before using MDCA, check `.secops/`:

1. **`.secops/environment.yaml`** — Tenant ID, portal URL (`<tenant>.portal.cloudappsecurity.com`)
2. **`.secops/identity/tenants.yaml`** — Cross-tenant MDCA access for MSSP scenarios
3. **`.secops/data-sources/data-source-map.yaml`** — MDCA tables in Sentinel (`McasShadowItReporting`, `SecurityAlert`)
4. **`.secops/compliance/requirements.yaml`** — Regulatory frameworks driving MDCA policy requirements

## Section 1: Cloud Discovery and Shadow IT

### Discovery Data Sources

| Source | Collection Method | Coverage |
|---|---|---|
| **Defender for Endpoint** | Automatic (MDE integration) | Managed endpoints — best coverage |
| **Firewall/proxy logs** | Manual upload or log collector | Network perimeter — all devices |
| **Secure Web Gateway** | API integration (Zscaler, iboss) | Proxy-managed traffic |
| **Log collector** | Docker container on-premises | Continuous automated upload |

### App Risk Scoring

MDCA scores discovered apps on 90+ risk factors: security (encryption, MFA, pen testing), compliance (SOC 2, ISO 27001, GDPR, HIPAA), and legal (data ownership, retention). Scores range 1 (high risk) to 10 (low risk).

### Governance Actions

| Action | Effect | Reversible |
|---|---|---|
| **Sanctioned** | Marked approved; no enforcement | Yes |
| **Unsanctioned** | Blocked via MDE network protection or proxy | Yes |
| **Monitored** | No block; alerts on usage spikes | Yes |

### Shadow IT Assessment Workflow (T1071, T1567)

```
1. Enable Cloud Discovery → MDE integration or log collector
2. Review dashboard → sort by users/traffic volume
3. Filter high-risk apps (score < 5) with significant usage
4. Cross-reference with .secops/compliance/requirements.yaml
5. Sanction / Unsanction / Monitor each app
6. Enforce unsanctioned via MDE network protection
7. Create app discovery policy → alert on re-emergence
```

## Section 2: App Governance and OAuth Apps

OAuth apps with excessive permissions are a top attack vector (T1199, T1098).

### OAuth App Audit Workflow

```powershell
$headers = @{ Authorization = "Token $mdcaToken"; 'Content-Type' = 'application/json' }
$baseUrl = "https://<tenant>.portal.cloudappsecurity.com/api/v1"

# List high-privilege OAuth apps
$body = @{
    filters = @{ permission = @{ eq = @(3) } }   # 3 = High privilege
    sortField = "lastModifiedDate"; sortDirection = "desc"
} | ConvertTo-Json -Depth 5

$riskyApps = Invoke-RestMethod -Uri "$baseUrl/app_permissions/" -Method POST -Headers $headers -Body $body

foreach ($app in $riskyApps.data) {
    Write-Host "App: $($app.appName) | Publisher: $($app.publisherName) | Verified: $($app.isVerifiedPublisher)"
    Write-Host "  Permissions: $($app.scopes -join ', ')"
    
    # Revoke unverified apps with mail access
    if (-not $app.isVerifiedPublisher -and $app.scopes -contains 'Mail.ReadWrite') {
        Invoke-RestMethod -Uri "$baseUrl/app_permissions/$($app.id)/revoke" -Method POST -Headers $headers
        Write-Warning "REVOKED: $($app.appName)"
    }
}
```

### Consent Policy Integration (Entra)

```
Entra ID → Enterprise Applications → Consent and Permissions
→ User consent: Allow for verified publishers with low-risk permissions
→ Admin consent workflow: Require approval for high-risk permissions
→ MDCA app governance: Auto-revoke apps matching risk criteria
```

## Section 3: Policies

| Policy Type | Trigger | Use Case | MITRE |
|---|---|---|---|
| **Activity** | Real-time user/admin actions | Mass download, admin role changes | T1530, T1098 |
| **File** | File creation/modification/sharing | Block external sharing of labeled files | T1567, T1537 |
| **Session** | Real-time proxy session events | Block download from unmanaged devices | T1530 |
| **Anomaly Detection** | ML behavioral analysis | Impossible travel, ransomware patterns | T1078, T1550 |
| **App Discovery** | New app in discovery logs | Alert on new high-risk apps | T1071 |
| **OAuth App** | Permission changes | High-privilege consent alerts | T1199, T1098 |

### Activity Policy Example

```json
{
  "name": "Mass Download Alert",
  "description": "Alert on >50 file downloads in 5 minutes",
  "severity": "MEDIUM",
  "filters": {
    "activity.actionType": { "eq": ["download"] },
    "activity.repeatCount": { "gte": 50 }
  },
  "timeWindow": 5,
  "governanceActions": {
    "notify": { "emails": ["soc@contoso.com"] }
  }
}
```

### Built-in Anomaly Detection Policies

| Policy | Detection | Tuning |
|---|---|---|
| **Impossible travel** | Geographically distant sign-ins | Sensitivity slider, trusted IP exclusions |
| **Ransomware activity** | File encryption patterns | Sensitivity, file extension filters |
| **Unusual file share** | Abnormal sharing volume | Sensitivity, group exclusions |
| **Suspicious inbox forwarding** | External forwarding rules | Automatic |
| **Multiple failed logins** | Brute force across cloud apps | Sensitivity, lockout threshold |

## Section 4: REST API (`/api/v1/`)

### Authentication

MDCA uses portal-generated API tokens, not OAuth.

```powershell
# Generate: MDCA Portal → Settings → Security Extensions → API Tokens
$mdcaToken = "your-api-token"  # Store in Key Vault
$headers = @{ Authorization = "Token $mdcaToken"; 'Content-Type' = 'application/json' }
$baseUrl = "https://<tenant>.portal.cloudappsecurity.com/api/v1"
```

### Rate Limits

All endpoints: **30 requests/minute**, 10 concurrent. Returns `429` with `Retry-After` header.

### Activities API

```powershell
$body = @{
    filters = @{
        service  = @{ eq = @(11161) }        # Microsoft 365 app ID
        activity = @{ actionType = @{ eq = @("download") } }
        date     = @{ gte_nDaysAgo = 7 }
    }
    sortField = "date"; sortDirection = "desc"; limit = 100
} | ConvertTo-Json -Depth 5

$activities = Invoke-RestMethod -Uri "$baseUrl/activities/" -Method POST -Headers $headers -Body $body
$activities.data | ForEach-Object { Write-Host "$($_.timestamp) | $($_.user.name) | $($_.description)" }
```

### Alerts API

```powershell
# List open alerts
$alerts = Invoke-RestMethod -Uri "$baseUrl/alerts/" -Method POST -Headers $headers -Body (@{
    filters = @{ resolutionStatus = @{ eq = @(0) } }   # 0 = Open
    sortField = "severity"; sortDirection = "desc"; limit = 50
} | ConvertTo-Json -Depth 5)

# Dismiss false positive
Invoke-RestMethod -Uri "$baseUrl/alerts/$alertId/dismiss/" -Method POST -Headers $headers -Body (@{
    comment = "False positive — approved admin activity per CHG-12345"; filters = @{}
} | ConvertTo-Json)

# Resolve true positive
Invoke-RestMethod -Uri "$baseUrl/alerts/$alertId/resolve/" -Method POST -Headers $headers -Body (@{
    comment = "Confirmed compromise — remediation complete"; filters = @{}
} | ConvertTo-Json)
```

### Files API

```powershell
# Files with sensitivity labels shared externally
$files = Invoke-RestMethod -Uri "$baseUrl/files/" -Method POST -Headers $headers -Body (@{
    filters = @{ sharing = @{ eq = @(2) }; fileLabels = @{ isset = $true } }
    sortField = "modifiedDate"; sortDirection = "desc"; limit = 50
} | ConvertTo-Json -Depth 5)

foreach ($file in $files.data) {
    if ($file.fileLabels -match 'Confidential') {
        Invoke-RestMethod -Uri "$baseUrl/files/$($file._id)/governance/" `
            -Method POST -Headers $headers -Body (@{ action = "removeExternalSharing" } | ConvertTo-Json)
        Write-Warning "Removed external sharing: $($file.name)"
    }
}
```

### Discovery API

```powershell
# Upload firewall log for Cloud Discovery
$uploadUrl = Invoke-RestMethod -Uri "$baseUrl/discovery/upload_url/" -Method GET -Headers $headers `
    -Body (@{ filename = "firewall.log"; source = "PALO_ALTO" } | ConvertTo-Json)
Invoke-RestMethod -Uri $uploadUrl.url -Method PUT `
    -Headers @{ 'Content-Type' = 'application/octet-stream' } `
    -Body ([System.IO.File]::ReadAllBytes("./firewall.log"))

# Get discovery summary
$discovery = Invoke-RestMethod -Uri "$baseUrl/discovery/" -Method GET -Headers $headers
Write-Host "Apps: $($discovery.totalApps) | High-risk: $($discovery.highRiskApps)"
```

### Entities API

```powershell
$userEntity = Invoke-RestMethod -Uri "$baseUrl/entities/" -Method POST -Headers $headers -Body (@{
    filters = @{ entity = @{ eq = @("user:john.doe@contoso.com") } }
} | ConvertTo-Json -Depth 3)

Write-Host "Risk: $($userEntity.data[0].threatScore) | Apps: $($userEntity.data[0].appCount)"
```

## Section 5: Conditional Access App Control

Routes user sessions through MDCA's reverse proxy for real-time session controls.

```
User → Entra ID (CA policy) → MDCA reverse proxy → Cloud App
                                      ↓
                            Session policy evaluation
```

### Session Policy Actions

| Action | Use Case |
|---|---|
| **Monitor only** | Audit before enforcement |
| **Block download** | Unmanaged device access |
| **Protect download** | Apply encryption/label on download (BYOD) |
| **Block upload** | Prevent data upload to unsanctioned storage |
| **Block copy/cut/print** | Protect sensitive data in browser |

### Configuration

```
1. Entra ID → Conditional Access → New Policy
   → Conditions: Browser, Unmanaged device
   → Session: Use Conditional Access App Control

2. MDCA → Conditional Access App Control → Connected Apps
   → Verify app appears after first user session

3. MDCA → Policies → Session Policy → Create
   → Activity type: Download files → Action: Block
```

## Section 6: SIEM Integration

### Sentinel Data Connector

```
Sentinel → Data Connectors → Microsoft Defender for Cloud Apps
→ Enable: Alerts (SecurityAlert table)
→ Enable: Discovery logs (McasShadowItReporting table)
```

### Sentinel Tables

| Table | Content | Source |
|---|---|---|
| `SecurityAlert` | MDCA alerts (`ProviderName == 'MCAS'`) | Native connector |
| `McasShadowItReporting` | Cloud Discovery data | Native connector |
| `CloudAppEvents` | User/app activities (Advanced Hunting) | XDR connector |

### KQL: Shadow IT Hunting

```kql
McasShadowItReporting
| where TimeGenerated > ago(30d)
| summarize Users = dcount(EnrichedUserName), Traffic = sum(TotalBytes)
    by AppName, AppScore = RiskScore
| where AppScore < 5
| order by Users desc
| take 20
```

### KQL: MDCA Alert Correlation

```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| where ProviderName == "MCAS"
| join kind=inner (
    SecurityIncident | where TimeGenerated > ago(7d)
    | mv-expand AlertIds | extend AlertId = tostring(AlertIds)
) on $left.SystemAlertId == $right.AlertId
| project IncidentNumber, AlertName = DisplayName, AlertSeverity, AlertTime = TimeGenerated
```

## Section 7: Agent Workflows

### Workflow 1: Shadow IT Assessment (T1071, T1567)

```
Agent receives: "Assess Shadow IT exposure"
1. Check .secops/environment.yaml for tenant context
2. GET /discovery/ → summary
3. POST /discovery/ → apps with score < 5
4. Cross-reference .secops/compliance/requirements.yaml
5. Sanction / Unsanction / Monitor decisions
6. Create app discovery policy for re-emergence alerts
7. Output: Report with risk scores, user counts, recommendations
```

### Workflow 2: OAuth App Audit (T1199, T1098)

```
Agent receives: "Audit OAuth apps for excessive permissions"
1. POST /app_permissions/ → all consented OAuth apps
2. Filter: unverified publishers + high-privilege permissions
3. Decision matrix:
   - Unverified + High priv + Low community → REVOKE
   - Unverified + High priv + High community → MONITOR + alert
   - Verified + Expected permissions → SANCTION
4. POST /app_permissions/{id}/revoke/ for targets
5. Output: Audit report with actions taken
```

### Workflow 3: Incident Correlation (T1078, T1530)

```
Agent receives: MDCA alert "Impossible travel activity"
1. GET /alerts/{alertId}/ → extract user, IPs
2. Query Sentinel: SecurityAlert | where Entities contains "<user>"
3. Check Entra sign-in logs for same time window
4. Query MDE for device activity from both IPs
5. If true positive: resolve alert, create Sentinel incident, contain (revoke sessions)
6. If false positive: dismiss with comment, add trusted IP to exclusions
```

## Section 8: `.secops/` Integration

```yaml
# .secops/environment.yaml
defender_for_cloud_apps:
  portal_url: "https://contoso.portal.cloudappsecurity.com"
  api_url: "https://contoso.us.portal.cloudappsecurity.com/api/v1"
  discovery_sources:
    - type: defender_for_endpoint
      status: active
    - type: log_collector
      name: "dc-logcollector-01"
      format: palo_alto
  conditional_access_app_control: true
  sentinel_connector:
    enabled: true
    workspace_ref: "workspaces/production.yaml"
    data_types: [alerts, discovery_logs]
```

```yaml
# .secops/data-sources/data-source-map.yaml
- table: McasShadowItReporting
  location: sentinel
  workspace_ref: workspaces/production.yaml
  tier: analytics
  retention_days: 90
  source_product: defender_for_cloud_apps

- table: CloudAppEvents
  location: defender_xdr
  tier: analytics
  retention_days: 30
  source_product: defender_for_cloud_apps
```

## Section 9: MITRE ATT&CK Coverage

| Technique | ID | MDCA Detection | Policy Type |
|---|---|---|---|
| Application Layer Protocol | T1071 | Shadow IT discovery, app blocking | App Discovery |
| Exfiltration Over Web Service | T1567 | File policy, session policy | File, Session |
| Transfer Data to Cloud Account | T1537 | Mass upload detection | Activity |
| Data from Cloud Storage | T1530 | Block/protect download | File, Session |
| Valid Accounts | T1078 | Impossible travel, anomalous activity | Anomaly Detection |
| Alternate Auth Material | T1550 | OAuth token abuse, session anomaly | Anomaly Detection |
| Trusted Relationship | T1199 | OAuth consent monitoring | OAuth App |
| Account Manipulation | T1098 | Admin role change, consent grants | Activity |

## Section 10: Rate Limit Handler

```powershell
function Invoke-MdcaApiWithRetry {
    param([string]$Uri, [string]$Method = 'POST', [hashtable]$Headers, [string]$Body, [int]$MaxRetries = 3)
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            $params = @{ Uri = $Uri; Method = $Method; Headers = $Headers }
            if ($Body) { $params.Body = $Body }
            return @{ ok = $true; data = (Invoke-RestMethod @params) }
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -eq 429) {
                $wait = [int]($_.Exception.Response.Headers['Retry-After'] ?? 30)
                Write-Warning "Rate limited (attempt $attempt). Waiting ${wait}s..."
                Start-Sleep -Seconds $wait
                continue
            }
            return @{ ok = $false; error = $_.Exception.Message; status = $_.Exception.Response.StatusCode.value__ }
        }
    }
    return @{ ok = $false; error = "Max retries exhausted" }
}
```

## Related Skills

- **[Defender MCP Server](defender-mcp-server.md)** — MCP-based MDCA operations and multi-product workflows
- **[Defender API Permissions](defender-api-permissions.md)** — MDCA API token management and RBAC
- **[Sentinel Workspace Setup](sentinel-workspace-setup.md)** — Configure MDCA data connector
- **[Entra ID Protection](entra-id-protection.md)** — CA policies triggering MDCA session controls
- **[Purview DLP Patterns](purview-dlp-patterns.md)** — Sensitivity labels enforced through MDCA
- **[Copilot for Security](copilot-for-security.md)** — Copilot enrichment of MDCA alerts
