---
title: Sentinel REST API Quick Reference
category: msft-security
difficulty: intermediate
mitre_attack:
  - T1059  # Command and Scripting Interpreter (automation context)
  - T1078  # Valid Accounts (auth/RBAC context)
  - T1190  # Exploit Public-Facing Application (incident ops)
products:
  - Microsoft Sentinel
  - Azure Resource Manager
  - Azure Monitor
author: Kima
version: 1.0.0
last_updated: 2026-04-30
---

# Sentinel REST API Quick Reference

## Overview

This is a field reference for the Microsoft Sentinel REST API — the `Microsoft.SecurityInsights` resource provider. Covers the endpoints you actually use in production: incidents, analytics rules, data connectors, watchlists, threat intelligence, automation rules, and hunting bookmarks.

Use this skill when:
- Building direct REST integrations with Sentinel (Logic Apps, Functions, custom tools)
- Falling back from MCP to REST when MCP server is unavailable
- Understanding which RBAC roles are needed for specific operations
- Debugging API responses or troubleshooting permission errors
- Migrating automation between API versions

**Complements:** [Sentinel MCP Server](sentinel-mcp-server.md) (for MCP-native operations), [Microsoft Graph Security API](microsoft-graph-security.md) (for Graph-based security data)

## Prerequisites

| Requirement | Detail |
|---|---|
| **Authentication** | Bearer token from `https://management.azure.com/.default` |
| **Base URL** | `https://management.azure.com` (commercial) or `https://management.usgovcloudapi.net` (gov) |
| **API Version** | `2024-03-01` (stable) — always pass `?api-version=` parameter |
| **Permissions** | See RBAC matrix below |

## Environment Context

Before calling Sentinel APIs, check the `.secops/` framework:

1. **`.secops/environment.yaml`** — Cloud type determines base URL
2. **`.secops/workspaces/*.yaml`** — Subscription, resource group, workspace name
3. **`.secops/identity/rbac-conventions.yaml`** — Verify caller has required roles

---

## Base URL Pattern

All Sentinel API calls follow this pattern:

```
{baseUrl}/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/{resource}?api-version={apiVersion}
```

**Shorthand used in this document:**

```
{workspace} = /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}
{sentinel}  = {workspace}/providers/Microsoft.SecurityInsights
```

---

## RBAC Permissions Matrix

| Operation | Sentinel Reader | Sentinel Responder | Sentinel Contributor | Sentinel Automation Contributor |
|---|:---:|:---:|:---:|:---:|
| List/get incidents | ✅ | ✅ | ✅ | ❌ |
| Update incident (assign, status) | ❌ | ✅ | ✅ | ❌ |
| Add incident comments | ❌ | ✅ | ✅ | ❌ |
| List/get analytics rules | ✅ | ✅ | ✅ | ❌ |
| Create/update/delete analytics rules | ❌ | ❌ | ✅ | ❌ |
| List/get data connectors | ✅ | ✅ | ✅ | ❌ |
| Enable/disable data connectors | ❌ | ❌ | ✅ | ❌ |
| List/get watchlists | ✅ | ✅ | ✅ | ❌ |
| Create/update/delete watchlists | ❌ | ❌ | ✅ | ❌ |
| List/get TI indicators | ✅ | ✅ | ✅ | ❌ |
| Create/update/delete TI indicators | ❌ | ❌ | ✅ | ❌ |
| List/get automation rules | ✅ | ✅ | ✅ | ✅ |
| Create/update/delete automation rules | ❌ | ❌ | ❌ | ✅ |
| Run hunting queries | ✅ | ✅ | ✅ | ❌ |
| Create/delete bookmarks | ❌ | ❌ | ✅ | ❌ |

**Key roles:**
- `Microsoft Sentinel Reader` — read-only access to all Sentinel data
- `Microsoft Sentinel Responder` — Reader + incident management (update, assign, comment)
- `Microsoft Sentinel Contributor` — Responder + create/modify rules, connectors, watchlists, TI
- `Microsoft Sentinel Automation Contributor` — Manage automation rules and playbook permissions

Additionally, `Log Analytics Reader` is needed for KQL query execution, and `Log Analytics Contributor` for workspace settings.

---

## API Versions

| API Version | Status | Notes |
|---|---|---|
| `2024-03-01` | **Stable (recommended)** | Current GA version, full feature set |
| `2023-11-01` | Stable | Previous GA version |
| `2024-09-01` | Preview | New features in preview |
| `2023-02-01` | Deprecated | Avoid for new integrations |

**Breaking change awareness:**
- `2023-11-01` → `2024-03-01`: Entity mapping schema changed for analytics rules
- Always pin `api-version` in automation; never use floating versions
- Preview APIs (`-preview`) may change without notice — avoid in production automation

---

## Incidents API

### List Incidents

```bash
# List all open incidents
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com{sentinel}/incidents?api-version=2024-03-01&\$filter=properties/status ne 'Closed'&\$orderby=properties/lastActivityTimeUtc desc&\$top=50"
```

```powershell
# PowerShell — List high-severity incidents
$params = @{
    ResourceGroupName = "rg-soc-prod"
    WorkspaceName     = "soc-sentinel-prod"
}
Get-AzSentinelIncident @params -Filter "properties/severity eq 'High'" -OrderBy "properties/createdTimeUtc desc" -Top 20
```

**Filter operators:** `eq`, `ne`, `gt`, `lt`, `ge`, `le`, `and`, `or`, `not`

**Filterable properties:**
- `properties/severity` — Informational, Low, Medium, High
- `properties/status` — New, Active, Closed
- `properties/title` — Free text (use `contains` cautiously — slow)
- `properties/createdTimeUtc` — ISO 8601 datetime
- `properties/lastActivityTimeUtc` — ISO 8601 datetime

### Get Incident

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com{sentinel}/incidents/{incidentId}?api-version=2024-03-01"
```

### Create Incident

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://management.azure.com{sentinel}/incidents/{newIncidentId}?api-version=2024-03-01" \
  -d '{
    "properties": {
      "title": "Manual - Suspicious lateral movement detected",
      "description": "SOC analyst detected unusual RDP patterns from workstation WKS-042.",
      "severity": "High",
      "status": "New",
      "classification": null,
      "classificationComment": null,
      "owner": {
        "assignedTo": null,
        "objectId": null
      }
    }
  }'
```

### Update Incident

```bash
# Assign incident and change status
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://management.azure.com{sentinel}/incidents/{incidentId}?api-version=2024-03-01" \
  -d '{
    "etag": "{etag-from-get}",
    "properties": {
      "title": "Existing title",
      "severity": "High",
      "status": "Active",
      "owner": {
        "assignedTo": "analyst@contoso.com",
        "objectId": "user-object-guid"
      }
    }
  }'
```

**Important:** Always include `etag` from the GET response to avoid overwriting concurrent changes.

### Close Incident

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://management.azure.com{sentinel}/incidents/{incidentId}?api-version=2024-03-01" \
  -d '{
    "etag": "{etag}",
    "properties": {
      "title": "Existing title",
      "severity": "High",
      "status": "Closed",
      "classification": "TruePositive",
      "classificationReason": "SuspiciousActivity",
      "classificationComment": "Confirmed credential compromise. Remediation complete."
    }
  }'
```

**Classification values:** `BenignPositive`, `FalsePositive`, `TruePositive`, `Undetermined`

**Classification reasons (per classification):**
- TruePositive: `SuspiciousActivity`, `SuspiciousButExpected`, `ConfirmedActivity`
- FalsePositive: `IncorrectAlertLogic`, `InaccurateData`
- BenignPositive: `ConfirmedUserActivity`, `SuspiciousButExpected`

### Add Incident Comment

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://management.azure.com{sentinel}/incidents/{incidentId}/comments/{commentId}?api-version=2024-03-01" \
  -d '{
    "properties": {
      "message": "Investigated source IP 203.0.113.50. Confirmed malicious per TI feed. Blocked at firewall."
    }
  }'
```

### List Incident Alerts and Entities

```bash
# Get alerts related to an incident
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com{sentinel}/incidents/{incidentId}/alerts?api-version=2024-03-01"

# Get entities related to an incident
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com{sentinel}/incidents/{incidentId}/entities?api-version=2024-03-01"
```

---

## Analytics Rules API

### List Rules

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com{sentinel}/alertRules?api-version=2024-03-01"
```

```powershell
Get-AzSentinelAlertRule -ResourceGroupName "rg-soc-prod" -WorkspaceName "soc-sentinel-prod"
```

### Create Scheduled Rule

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://management.azure.com{sentinel}/alertRules/{ruleId}?api-version=2024-03-01" \
  -d '{
    "kind": "Scheduled",
    "properties": {
      "displayName": "High-CredentialAccess-MultipleFailedLogons",
      "description": "Detects multiple failed logon attempts indicating brute force.",
      "severity": "High",
      "enabled": false,
      "query": "SigninLogs\n| where TimeGenerated > ago(1h)\n| where ResultType != \"0\"\n| summarize FailureCount=count() by UserPrincipalName, IPAddress\n| where FailureCount > 10",
      "queryFrequency": "PT5M",
      "queryPeriod": "PT1H",
      "triggerOperator": "GreaterThan",
      "triggerThreshold": 0,
      "suppressionDuration": "PT5H",
      "suppressionEnabled": false,
      "tactics": ["CredentialAccess"],
      "techniques": ["T1110"],
      "incidentConfiguration": {
        "createIncident": true,
        "groupingConfiguration": {
          "enabled": true,
          "reopenClosedIncident": false,
          "lookbackDuration": "PT5H",
          "matchingMethod": "AllEntities",
          "groupByEntities": ["Account", "Ip"],
          "groupByAlertDetails": [],
          "groupByCustomDetails": []
        }
      },
      "entityMappings": [
        {
          "entityType": "Account",
          "fieldMappings": [
            { "identifier": "FullName", "columnName": "UserPrincipalName" }
          ]
        },
        {
          "entityType": "IP",
          "fieldMappings": [
            { "identifier": "Address", "columnName": "IPAddress" }
          ]
        }
      ],
      "eventGroupingSettings": {
        "aggregationKind": "SingleAlert"
      }
    }
  }'
```

### Enable/Disable Rule

```powershell
# Disable a rule
Update-AzSentinelAlertRule -ResourceGroupName "rg-soc-prod" -WorkspaceName "soc-sentinel-prod" `
    -RuleId "{ruleId}" -Enabled $false

# Enable a rule
Update-AzSentinelAlertRule -ResourceGroupName "rg-soc-prod" -WorkspaceName "soc-sentinel-prod" `
    -RuleId "{ruleId}" -Enabled $true
```

### Delete Rule

```bash
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com{sentinel}/alertRules/{ruleId}?api-version=2024-03-01"
```

---

## Data Connectors API

### List Connectors

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com{sentinel}/dataConnectors?api-version=2024-03-01"
```

```powershell
Get-AzSentinelDataConnector -ResourceGroupName "rg-soc-prod" -WorkspaceName "soc-sentinel-prod"
```

### Connector Kinds

| Kind | Description | Key Config |
|---|---|---|
| `AzureActiveDirectory` | Entra ID sign-in/audit logs | `tenantId`, `alerts` state |
| `MicrosoftDefenderAdvancedThreatProtection` | MDE alerts | `tenantId` |
| `MicrosoftCloudAppSecurity` | Defender for Cloud Apps | `tenantId`, `dataTypes` |
| `AzureSecurityCenter` | Defender for Cloud | `subscriptionId` |
| `Office365` | Exchange, SharePoint, Teams | `tenantId`, `dataTypes` per service |
| `ThreatIntelligence` | Microsoft TI platform | `tenantId`, `dataTypes` |
| `AmazonWebServicesCloudTrail` | AWS CloudTrail | `roleArn`, `awsAccountId` |
| `CEF` | CEF via AMA | Requires DCR + AMA agent |
| `Syslog` | Syslog via AMA | Requires DCR + AMA agent |

### Enable Connector

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://management.azure.com{sentinel}/dataConnectors/{connectorId}?api-version=2024-03-01" \
  -d '{
    "kind": "AzureActiveDirectory",
    "properties": {
      "tenantId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      "dataTypes": {
        "alerts": { "state": "Enabled" },
        "signInLogs": { "state": "Enabled" },
        "auditLogs": { "state": "Enabled" }
      }
    }
  }'
```

---

## Watchlists API

### List Watchlists

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com{sentinel}/watchlists?api-version=2024-03-01"
```

### Create Watchlist

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://management.azure.com{sentinel}/watchlists/{watchlistAlias}?api-version=2024-03-01" \
  -d '{
    "properties": {
      "displayName": "Blocked IPs",
      "source": "Local file",
      "itemsSearchKey": "IPAddress",
      "contentType": "Text/Csv",
      "rawContent": "IPAddress,Reason,AddedBy\n203.0.113.50,C2 callback,SOC-Analyst1\n198.51.100.25,Port scan source,SOC-Analyst2"
    }
  }'
```

### Add Watchlist Item

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://management.azure.com{sentinel}/watchlists/{alias}/watchlistItems/{itemId}?api-version=2024-03-01" \
  -d '{
    "properties": {
      "itemsKeyValue": {
        "IPAddress": "192.0.2.100",
        "Reason": "Phishing infrastructure",
        "AddedBy": "SOC-Analyst3"
      }
    }
  }'
```

### Delete Watchlist Item

```bash
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com{sentinel}/watchlists/{alias}/watchlistItems/{itemId}?api-version=2024-03-01"
```

### Query Watchlist in KQL

```kql
_GetWatchlist('wl-blocked-ips')
| where IPAddress == "203.0.113.50"
```

---

## Threat Intelligence API

### List Indicators

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com{sentinel}/threatIntelligence/main/indicators?api-version=2024-03-01&\$top=50&\$orderby=properties/lastUpdatedTimeUtc desc"
```

### Create Indicator

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://management.azure.com{sentinel}/threatIntelligence/main/createIndicator?api-version=2024-03-01" \
  -d '{
    "kind": "indicator",
    "properties": {
      "displayName": "APT29 C2 Server",
      "pattern": "[ipv4-addr:value = '\''203.0.113.50'\'']",
      "patternType": "ipv4-addr",
      "source": "SOC Investigation INC-2026-0042",
      "threatTypes": ["malicious-activity"],
      "confidence": 85,
      "validFrom": "2026-04-30T00:00:00Z",
      "validUntil": "2026-07-30T00:00:00Z",
      "description": "C2 callback server observed during incident investigation",
      "killChainPhases": [
        {
          "killChainName": "lockheed-martin-cyber-kill-chain",
          "phaseName": "C2"
        }
      ]
    }
  }'
```

### Bulk Import (Query Indicators)

```bash
# POST to query and filter indicators
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://management.azure.com{sentinel}/threatIntelligence/main/queryIndicators?api-version=2024-03-01" \
  -d '{
    "sources": ["SOC Investigation"],
    "minConfidence": 75,
    "patternTypes": ["ipv4-addr", "domain-name"],
    "sortBy": [{ "itemKey": "lastUpdatedTimeUtc", "sortOrder": "descending" }],
    "pageSize": 100
  }'
```

### Delete Indicator

```bash
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com{sentinel}/threatIntelligence/main/indicators/{indicatorId}?api-version=2024-03-01"
```

---

## Automation Rules API

### List Automation Rules

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com{sentinel}/automationRules?api-version=2024-03-01"
```

### Create Automation Rule

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://management.azure.com{sentinel}/automationRules/{ruleId}?api-version=2024-03-01" \
  -d '{
    "properties": {
      "displayName": "Auto-assign high severity incidents",
      "order": 1,
      "triggeringLogic": {
        "isEnabled": true,
        "triggersOn": "Incidents",
        "triggersWhen": "Created",
        "conditions": [
          {
            "conditionType": "Property",
            "conditionProperties": {
              "propertyName": "IncidentSeverity",
              "operator": "Equals",
              "propertyValues": ["High"]
            }
          }
        ]
      },
      "actions": [
        {
          "order": 1,
          "actionType": "ModifyProperties",
          "actionConfiguration": {
            "status": "Active",
            "owner": {
              "assignedTo": "tier2-oncall@contoso.com",
              "objectId": "user-guid"
            }
          }
        }
      ]
    }
  }'
```

---

## Bookmarks API

### Create Bookmark

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://management.azure.com{sentinel}/bookmarks/{bookmarkId}?api-version=2024-03-01" \
  -d '{
    "properties": {
      "displayName": "Suspicious PowerShell execution on SRV-DC01",
      "query": "SecurityEvent | where EventID == 4688 | where Process == \"powershell.exe\" | where Computer == \"SRV-DC01\"",
      "queryResult": "TimeGenerated=2026-04-30T14:22:00Z, Process=powershell.exe, CommandLine=IEX (New-Object Net.WebClient).DownloadString...",
      "notes": "Part of threat hunt TH-2026-015. Encoded command decodes to C2 beacon.",
      "labels": ["threat-hunt", "c2-beacon"],
      "tactics": ["Execution"],
      "techniques": ["T1059.001"]
    }
  }'
```

---

## Log Analytics Query API

Not part of `Microsoft.SecurityInsights` but essential for Sentinel operations.

### Run Query

```bash
# Base URL differs — uses Log Analytics workspace ID (GUID), not ARM path
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://api.loganalytics.io/v1/workspaces/{workspaceId}/query" \
  -d '{
    "query": "SecurityEvent | where TimeGenerated > ago(1h) | summarize count() by EventID | top 10 by count_",
    "timespan": "PT1H"
  }'
```

```powershell
# PowerShell — Run KQL query
$query = @"
SecurityIncident
| where TimeGenerated > ago(7d)
| summarize Count=count() by Severity
| sort by Count desc
"@

Invoke-AzOperationalInsightsQuery -WorkspaceId "aabbccdd-1234-5678-abcd-ef0123456789" -Query $query |
    Select-Object -ExpandProperty Results
```

**Auth scope for query API:** `https://api.loganalytics.io/.default` (different from ARM scope)

**Government cloud query endpoint:** `https://api.loganalytics.us/v1/workspaces/{workspaceId}/query`

---

## Pagination

All list endpoints support pagination via `$top` and `$skipToken`:

```bash
# First page
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com{sentinel}/incidents?api-version=2024-03-01&\$top=50"

# Response includes nextLink if more pages exist:
# "nextLink": "https://management.azure.com{sentinel}/incidents?api-version=2024-03-01&$top=50&$skipToken=..."

# Follow nextLink for subsequent pages
```

```powershell
# PowerShell handles pagination automatically with -Top
$allIncidents = @()
$incidents = Get-AzSentinelIncident -ResourceGroupName "rg-soc-prod" -WorkspaceName "soc-sentinel-prod" -Top 200
$allIncidents += $incidents

# For manual pagination with REST:
$nextLink = $response.nextLink
while ($nextLink) {
    $response = Invoke-AzRestMethod -Uri $nextLink -Method GET
    $allIncidents += ($response.Content | ConvertFrom-Json).value
    $nextLink = ($response.Content | ConvertFrom-Json).nextLink
}
```

---

## Error Handling

### Common Error Codes

| HTTP Status | Error Code | Cause | Action |
|---|---|---|---|
| 400 | `BadRequest` | Invalid filter, malformed JSON | Fix request body/params |
| 401 | `Unauthorized` | Expired or invalid token | Re-authenticate |
| 403 | `Forbidden` | Insufficient RBAC permissions | Check role assignments |
| 404 | `NotFound` | Resource doesn't exist | Verify resource ID |
| 409 | `Conflict` | Etag mismatch (concurrent update) | Re-GET, merge changes, retry |
| 429 | `TooManyRequests` | Rate limit exceeded | Honor `Retry-After` header |
| 500 | `InternalServerError` | Service error | Retry with backoff |

### Structured Error Response

```json
{
  "error": {
    "code": "Forbidden",
    "message": "The client does not have authorization to perform action 'Microsoft.SecurityInsights/incidents/write' over scope '...'.",
    "details": [
      {
        "code": "AuthorizationFailed",
        "message": "..."
      }
    ]
  }
}
```

### PowerShell Error Handling Pattern

```powershell
try {
    $incident = Get-AzSentinelIncident -ResourceGroupName $rg -WorkspaceName $ws -IncidentId $id -ErrorAction Stop
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    switch ($statusCode) {
        403 { Write-Warning "Insufficient permissions. Need 'Microsoft Sentinel Responder' role." }
        404 { Write-Warning "Incident $id not found in workspace $ws." }
        429 {
            $retryAfter = $_.Exception.Response.Headers.GetValues('Retry-After')[0]
            Write-Warning "Throttled. Retry after $retryAfter seconds."
            Start-Sleep -Seconds ([int]$retryAfter + 1)
        }
        default { throw }
    }
}
```

---

## Quick Reference: PowerShell Module Commands

The `Az.SecurityInsights` module wraps these REST APIs:

| Cmdlet | API Equivalent |
|---|---|
| `Get-AzSentinelIncident` | GET incidents |
| `Update-AzSentinelIncident` | PUT incidents/{id} |
| `New-AzSentinelIncidentComment` | PUT incidents/{id}/comments/{cid} |
| `Get-AzSentinelAlertRule` | GET alertRules |
| `New-AzSentinelAlertRule` | PUT alertRules/{id} |
| `Update-AzSentinelAlertRule` | PUT alertRules/{id} |
| `Remove-AzSentinelAlertRule` | DELETE alertRules/{id} |
| `Get-AzSentinelDataConnector` | GET dataConnectors |
| `Get-AzSentinelWatchlist` | GET watchlists |
| `New-AzSentinelWatchlist` | PUT watchlists/{alias} |
| `Get-AzSentinelThreatIntelligenceIndicator` | GET threatIntelligence/main/indicators |
| `New-AzSentinelThreatIntelligenceIndicator` | POST threatIntelligence/main/createIndicator |
| `Get-AzSentinelAutomationRule` | GET automationRules |
| `Get-AzSentinelBookmark` | GET bookmarks |
| `New-AzSentinelBookmark` | PUT bookmarks/{id} |
| `Invoke-AzOperationalInsightsQuery` | POST query (Log Analytics) |

**Install:**

```powershell
Install-Module Az.SecurityInsights -Scope CurrentUser -Force
Install-Module Az.OperationalInsights -Scope CurrentUser -Force
```

---

## Related Skills

- **[Sentinel MCP Server](sentinel-mcp-server.md)** — MCP-based operations (preferred for agent workflows)
- **[Sentinel Workspace Setup](sentinel-workspace-setup.md)** — Workspace provisioning and configuration
- **[Microsoft Graph Security API](microsoft-graph-security.md)** — Alternative API for cross-product security data
- **[Detection Lifecycle](../detection/detection-lifecycle.md)** — Rule deployment workflow using these APIs
- **[Scheduled Rule Pattern](../detection/scheduled-rule-pattern.md)** — ARM template format for analytics rules

## References

- [Microsoft Sentinel REST API — Microsoft Learn](https://learn.microsoft.com/en-us/rest/api/securityinsights/)
- [Az.SecurityInsights PowerShell Module](https://learn.microsoft.com/en-us/powershell/module/az.securityinsights/)
- [Log Analytics Query API](https://learn.microsoft.com/en-us/rest/api/loganalytics/dataaccess/query/execute)
- [ARM Rate Limiting](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling)
- [Sentinel RBAC Roles](https://learn.microsoft.com/en-us/azure/sentinel/roles)
