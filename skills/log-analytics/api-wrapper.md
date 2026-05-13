---
title: Log Analytics API Wrapper
category: log-analytics
difficulty: advanced
mitre_attack:
  - T1059  # Command and Scripting Interpreter — API automation context
  - T1078  # Valid Accounts — auth and RBAC patterns
products:
  - Azure Monitor Log Analytics
  - Microsoft Sentinel
  - Azure Monitor Data Collection Rules
  - Azure Monitor Query Packs
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# Log Analytics API Wrapper

## Overview

The Log Analytics REST API surface spans seven functional areas: querying data, saving searches, managing query packs, creating alert rules, configuring data collection rules, exporting data, and respecting rate limits. This skill teaches the practical patterns for each area — the endpoints, authentication, request/response shapes, error handling, and how to wire everything together with the `.secops/` customer knowledge framework.

Use this skill when:
- Building automated KQL query pipelines (scheduled hunts, reporting)
- Creating or managing saved searches and query packs programmatically
- Provisioning scheduled query alert rules via code (infrastructure-as-code)
- Ingesting custom logs via the Logs Ingestion API (DCR-based)
- Exporting data continuously to Storage, Event Hub, or SIEM
- Understanding rate limits and cost trade-offs for high-volume scenarios

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Log Analytics Reader` for queries; `Log Analytics Contributor` for saved searches; `Monitoring Contributor` for alert rules and DCRs |
| **Authentication** | Azure AD token via `az login`, managed identity, or service principal (MSAL) |
| **SDK (PowerShell)** | `Az.OperationalInsights`, `Az.Monitor` modules |
| **SDK (Python)** | `azure-monitor-query`, `azure-identity`, `azure-mgmt-monitor` |
| **Environment** | `.secops/workspaces/*.yaml` populated with workspace IDs |

## Environment Context

Before calling any Log Analytics API, consult the `.secops/` framework:

1. **Workspace IDs** — Read from `.secops/workspaces/<name>.yaml` → `workspace_id` field. Never hardcode workspace GUIDs.
2. **Data source locations** — Check `.secops/data-sources/data-source-map.yaml` to know which workspace holds each table.
3. **Data tiers** — The `tier` field (Analytics, Basic, Sentinel data lake, Archive) determines which query operations are allowed.
4. **Alert routing** — Check `.secops/alerting/routing.yaml` before creating alert rules to ensure correct action group binding.
5. **Compliance** — Check `.secops/compliance/requirements.yaml` for data residency constraints before cross-workspace queries.

---

## Section 1: Query API

### Endpoint

```
POST https://api.loganalytics.io/v1/workspaces/{workspaceId}/query
```

The `workspaceId` is the Log Analytics workspace GUID (not the resource ID). Read it from `.secops/workspaces/<name>.yaml` → `workspace_id`.

### Request Body

```json
{
  "query": "SecurityEvent | where TimeGenerated > ago(1h) | summarize count() by EventID",
  "timespan": "PT1H",
  "workspaces": [
    "aabbccdd-1234-5678-abcd-ef0123456789",
    "11223344-5566-7788-99aa-bbccddeeff00"
  ]
}
```

| Parameter | Required | Description |
|---|---|---|
| `query` | Yes | KQL query string |
| `timespan` | No | ISO 8601 duration (e.g., `PT1H`, `P7D`) or `start/end` range. Overrides `ago()` in query. |
| `workspaces` | No | Additional workspace GUIDs for cross-workspace queries. Primary workspace is always included. |

### Response Parsing

The response returns a `tables` array. Each table has `columns` (name + type) and `rows` (arrays of values):

```json
{
  "tables": [
    {
      "name": "PrimaryResult",
      "columns": [
        { "name": "EventID", "type": "int" },
        { "name": "count_", "type": "long" }
      ],
      "rows": [
        [4624, 1523],
        [4625, 87],
        [4688, 4201]
      ]
    }
  ]
}
```

### PowerShell — Invoke-AzRestMethod

```powershell
# Read workspace ID from .secops config
$workspaceConfig = Get-Content ".secops/workspaces/example-workspace.yaml" -Raw |
    ConvertFrom-Yaml
$workspaceId = $workspaceConfig.workspace_id

# Build and execute query
$body = @{
    query    = "SecurityEvent | where TimeGenerated > ago(1h) | summarize count() by EventID"
    timespan = "PT1H"
} | ConvertTo-Json

$response = Invoke-AzRestMethod -Method POST `
    -Uri "https://api.loganalytics.io/v1/workspaces/$workspaceId/query" `
    -Payload $body

$result = $response.Content | ConvertFrom-Json

# Parse response into objects
$table = $result.tables[0]
$columns = $table.columns.name
$rows = $table.rows | ForEach-Object {
    $obj = [ordered]@{}
    for ($i = 0; $i -lt $columns.Count; $i++) {
        $obj[$columns[$i]] = $_[$i]
    }
    [PSCustomObject]$obj
}
$rows | Format-Table -AutoSize
```

### PowerShell — Az.OperationalInsights (Native Cmdlet)

```powershell
# Simpler approach using the built-in cmdlet
$results = Invoke-AzOperationalInsightsQuery `
    -WorkspaceId $workspaceId `
    -Query "SecurityEvent | where TimeGenerated > ago(1h) | summarize count() by EventID" `
    -Timespan (New-TimeSpan -Hours 1)

# Results are already parsed into objects
$results.Results | Format-Table -AutoSize
```

### Python — azure-monitor-query SDK

```python
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from datetime import timedelta
import yaml

# Read workspace ID from .secops config
with open(".secops/workspaces/example-workspace.yaml") as f:
    ws_config = yaml.safe_load(f)
workspace_id = ws_config["workspace_id"]

credential = DefaultAzureCredential()
client = LogsQueryClient(credential)

response = client.query_workspace(
    workspace_id=workspace_id,
    query="SecurityEvent | where TimeGenerated > ago(1h) | summarize count() by EventID",
    timespan=timedelta(hours=1),
)

if response.status == LogsQueryStatus.SUCCESS:
    for row in response.tables[0].rows:
        print(dict(zip([col.name for col in response.tables[0].columns], row)))
elif response.status == LogsQueryStatus.PARTIAL:
    print(f"Partial results: {response.partial_error}")
    for row in response.partial_data[0].rows:
        print(row)
```

### Batch Query Support

Execute up to 200 queries in a single request:

```
POST https://api.loganalytics.io/v1/$batch
```

```json
{
  "requests": [
    {
      "id": "1",
      "headers": { "Content-Type": "application/json" },
      "body": { "query": "SecurityEvent | summarize count()" },
      "workspace": "aabbccdd-1234-5678-abcd-ef0123456789"
    },
    {
      "id": "2",
      "headers": { "Content-Type": "application/json" },
      "body": { "query": "SigninLogs | summarize count()" },
      "workspace": "aabbccdd-1234-5678-abcd-ef0123456789"
    }
  ]
}
```

```python
# Python batch query
responses = client.query_batch([
    {"workspace_id": workspace_id, "query": "SecurityEvent | summarize count()", "timespan": timedelta(hours=1)},
    {"workspace_id": workspace_id, "query": "SigninLogs | summarize count()", "timespan": timedelta(hours=1)},
])

for resp in responses:
    if resp.status == LogsQueryStatus.SUCCESS:
        print(resp.tables[0].rows)
```

### Error Handling

| HTTP Status | Meaning | Action |
|---|---|---|
| 200 + `error` in body | Partial error — some data returned | Parse `error.details` for affected workspaces |
| 400 | Malformed query (syntax error) | Check `innererror.message` for KQL parse error location |
| 403 | Insufficient permissions | Verify RBAC role on target workspace |
| 429 | Rate limit exceeded | Retry with exponential backoff; check `Retry-After` header |
| 504 | Query timeout (> 10 min default) | Add `| take` or narrow time range; use `set query_take_max_records` |

```python
# Robust error handling pattern
from azure.core.exceptions import HttpResponseError

try:
    response = client.query_workspace(
        workspace_id=workspace_id,
        query=query,
        timespan=timedelta(hours=1),
        server_timeout=600,  # 10 min max
    )
    if response.status == LogsQueryStatus.PARTIAL:
        # Some workspaces returned data, others failed
        error = response.partial_error
        print(f"Partial failure: {error.code} — {error.message}")
        # Process available data anyway
        data = response.partial_data
    elif response.status == LogsQueryStatus.SUCCESS:
        data = response.tables
except HttpResponseError as e:
    if e.status_code == 429:
        retry_after = int(e.response.headers.get("Retry-After", 30))
        print(f"Rate limited. Retry in {retry_after}s")
    else:
        print(f"Query failed: {e.status_code} — {e.message}")
```

---

## Section 2: Saved Searches API

### Endpoint

```
PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/savedSearches/{savedSearchId}?api-version=2020-08-01
```

### CRUD Operations

```powershell
# CREATE a saved search
$savedSearch = @{
    properties = @{
        displayName          = "Failed Logons — Last 24h"
        category             = "Security Hunting"
        query                = "SecurityEvent | where EventID == 4625 | summarize FailCount=count() by TargetAccount, IpAddress | where FailCount > 10"
        version              = 2
        functionAlias        = "FailedLogonsSummary"
        functionParameters   = "threshold:int = 10"
        tags                 = @(
            @{ name = "mitre_technique"; value = "T1110" }
            @{ name = "author"; value = "Freamon" }
        )
    }
} | ConvertTo-Json -Depth 5

$resourceId = "/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$wsName"

Invoke-AzRestMethod -Method PUT `
    -Path "$resourceId/savedSearches/freamon-failed-logons?api-version=2020-08-01" `
    -Payload $savedSearch

# LIST all saved searches
$all = Invoke-AzRestMethod -Method GET `
    -Path "$resourceId/savedSearches?api-version=2020-08-01"
($all.Content | ConvertFrom-Json).value | Select-Object name, @{N='Display';E={$_.properties.displayName}}

# DELETE a saved search
Invoke-AzRestMethod -Method DELETE `
    -Path "$resourceId/savedSearches/freamon-failed-logons?api-version=2020-08-01"
```

### Function-Based Saved Searches

Saved searches with `functionAlias` become KQL functions callable in any query:

```powershell
# Create a parameterized function
$functionSearch = @{
    properties = @{
        displayName        = "Anomalous Sign-In Detection"
        category           = "Security Functions"
        query              = @"
let lookback = timespan_param;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType != 0
| summarize FailCount=count(), DistinctIPs=dcount(IPAddress) by UserPrincipalName
| where FailCount > threshold_param
"@
        functionAlias      = "AnomalousSignIns"
        functionParameters = "timespan_param:timespan = 24h, threshold_param:int = 5"
        version            = 2
    }
} | ConvertTo-Json -Depth 5
```

After creation, call it in KQL as:
```kql
AnomalousSignIns(timespan_param=7d, threshold_param=3)
```

### Migration Pattern — Export and Import Across Workspaces

```powershell
# Export all saved searches from source workspace
$sourceResourceId = "/subscriptions/$srcSubId/resourceGroups/$srcRg/providers/Microsoft.OperationalInsights/workspaces/$srcWs"
$searches = (Invoke-AzRestMethod -Method GET `
    -Path "$sourceResourceId/savedSearches?api-version=2020-08-01").Content |
    ConvertFrom-Json

# Import into target workspace
$targetResourceId = "/subscriptions/$tgtSubId/resourceGroups/$tgtRg/providers/Microsoft.OperationalInsights/workspaces/$tgtWs"
foreach ($search in $searches.value) {
    $searchName = $search.name.Split("/")[-1]
    $body = @{ properties = $search.properties } | ConvertTo-Json -Depth 5
    Invoke-AzRestMethod -Method PUT `
        -Path "$targetResourceId/savedSearches/$searchName`?api-version=2020-08-01" `
        -Payload $body
}
```

---

## Section 3: Query Packs

Query packs are Azure resources that store and share KQL queries across workspaces, unlike saved searches which are workspace-scoped.

### Endpoint

```
PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/queryPacks/{queryPackName}?api-version=2019-09-01
```

### Creating a Query Pack

```powershell
# Create the query pack resource
$queryPack = @{
    location   = "eastus2"
    properties = @{}
} | ConvertTo-Json

Invoke-AzRestMethod -Method PUT `
    -Path "/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/queryPacks/secops-hunting-queries?api-version=2019-09-01" `
    -Payload $queryPack
```

### Adding Queries to a Pack

```powershell
# Add a query to the pack
$query = @{
    properties = @{
        displayName = "Brute Force Detection"
        description = "Detect password spray and brute force attacks across identity sources"
        body        = @"
let threshold = 20;
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1h)
| where ResultType in ('50126', '50053', '50074')
| summarize FailureCount=count(), DistinctUsers=dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 5m)
| where FailureCount > threshold
"@
        related     = @{
            categories    = @("Security")
            resourceTypes = @("microsoft.operationalinsights/workspaces")
            solutions     = @("SecurityInsights")
        }
        tags        = @{
            "mitre_tactic"    = "CredentialAccess"
            "mitre_technique" = "T1110"
        }
    }
} | ConvertTo-Json -Depth 5

$packResourceId = "/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/queryPacks/secops-hunting-queries"
Invoke-AzRestMethod -Method PUT `
    -Path "$packResourceId/queries/brute-force-detect?api-version=2019-09-01" `
    -Payload $query
```

### Default Query Pack

Every subscription has a default query pack named `DefaultQueryPack`. Queries added here automatically appear in the Logs blade for all workspaces in that subscription. Use the default pack for team-wide hunting queries; use custom packs for project- or customer-specific queries.

### Integration with Sentinel Hunting

Sentinel hunting queries are stored in query packs. Queries with `solutions: ["SecurityInsights"]` and `categories: ["Hunting Queries"]` appear in the Sentinel Hunting blade:

```powershell
$huntingQuery = @{
    properties = @{
        displayName = "Suspicious PowerShell Download Cradle"
        description = "Detects common PowerShell download patterns used by malware"
        body        = "DeviceProcessEvents | where ProcessCommandLine has_any ('Invoke-WebRequest','wget','curl','DownloadString','DownloadFile') | where ProcessCommandLine has_any ('.exe','.dll','.ps1','.bat') | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine"
        related     = @{
            categories    = @("Hunting Queries")
            resourceTypes = @("microsoft.operationalinsights/workspaces")
            solutions     = @("SecurityInsights")
        }
        tags = @{ "mitre_technique" = "T1059.001" }
    }
} | ConvertTo-Json -Depth 5
```

---

## Section 4: Alerts API

### Scheduled Query Rules (V2 API)

The current API for log search alerts is Scheduled Query Rules V2:

```
PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Insights/scheduledQueryRules/{ruleName}?api-version=2023-03-15-preview
```

### Creating an Alert Rule

```powershell
# Read alert routing from .secops config
# Check .secops/alerting/routing.yaml to determine the correct action group

$alertRule = @{
    location   = "eastus2"
    properties = @{
        displayName         = "High-Volume Failed Sign-Ins"
        description         = "Triggers when failed sign-in count exceeds threshold in 15-minute window"
        severity            = 2  # 0=Critical, 1=Error, 2=Warning, 3=Informational, 4=Verbose
        enabled             = $true
        evaluationFrequency = "PT5M"      # Check every 5 minutes
        windowSize          = "PT15M"     # Look back 15 minutes
        scopes              = @(
            "/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$wsName"
        )
        criteria            = @{
            allOf = @(
                @{
                    query           = "SigninLogs | where ResultType != '0' | summarize FailCount=count() by UserPrincipalName | where FailCount > 50"
                    timeAggregation = "Count"
                    operator        = "GreaterThan"
                    threshold       = 0
                    dimensions      = @(
                        @{
                            name     = "UserPrincipalName"
                            operator = "Include"
                            values   = @("*")
                        }
                    )
                    failingPeriods = @{
                        numberOfEvaluationPeriods = 1
                        minFailingPeriodsToAlert  = 1
                    }
                }
            )
        }
        autoMitigate        = $true
        actions             = @{
            actionGroups    = @(
                "/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.Insights/actionGroups/soc-identity-alerts"
            )
            customProperties = @{
                "mitre_tactic"    = "CredentialAccess"
                "mitre_technique" = "T1110"
                "runbook_url"     = "https://wiki.contoso.com/runbooks/brute-force"
            }
        }
    }
    tags = @{
        "managed-by" = "secops-squad"
    }
} | ConvertTo-Json -Depth 10

Invoke-AzRestMethod -Method PUT `
    -Path "/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.Insights/scheduledQueryRules/alert-high-failed-signins?api-version=2023-03-15-preview" `
    -Payload $alertRule
```

### Alert Condition Types

| Type | `timeAggregation` | Use Case |
|---|---|---|
| **Number of Results** | `Count` | Alert when query returns rows (any match = fire) |
| **Metric Measurement** | `Total`, `Average`, `Minimum`, `Maximum` | Alert on numeric aggregation thresholds per dimension |

### Severity Levels and `.secops/` Integration

Map alert severities to `.secops/alerting/routing.yaml` routes:

| Severity | Value | Maps to `.secops/` routing |
|---|---|---|
| Critical | 0 | `severity: ["Critical"]` routes in `routing.yaml` |
| Error | 1 | `severity: ["High"]` routes |
| Warning | 2 | `severity: ["Medium"]` routes |
| Informational | 3 | Below `default_severity_threshold` — may be suppressed |
| Verbose | 4 | Log-only, no notification |

### Python — Scheduled Query Rule Creation

```python
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient

credential = DefaultAzureCredential()
monitor_client = MonitorManagementClient(credential, subscription_id)

rule = monitor_client.scheduled_query_rules.create_or_update(
    resource_group_name="rg-soc-prod",
    rule_name="alert-suspicious-process",
    parameters={
        "location": "eastus2",
        "properties": {
            "displayName": "Suspicious Process Execution",
            "severity": 1,
            "enabled": True,
            "evaluationFrequency": "PT5M",
            "windowSize": "PT15M",
            "scopes": [workspace_resource_id],
            "criteria": {
                "allOf": [{
                    "query": "DeviceProcessEvents | where FileName in~ ('mimikatz.exe','procdump.exe')",
                    "timeAggregation": "Count",
                    "operator": "GreaterThan",
                    "threshold": 0,
                }]
            },
            "autoMitigate": True,
            "actions": {
                "actionGroups": [action_group_resource_id],
            },
        },
    },
)
```

---

## Section 5: Data Collection Rules (DCR)

### Architecture

```
Data Sources → DCR (Transform KQL) → Destinations (Log Analytics Tables)
     │                  │                          │
  AMA Agent        Ingestion-time             Analytics / Basic
  REST API         filtering, parsing,        / Sentinel data lake
  Event Hub        enrichment, routing        tier tables
```

### Creating a DCR via REST API

```powershell
$dcr = @{
    location   = "eastus2"
    properties = @{
        dataCollectionEndpointId = "/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.Insights/dataCollectionEndpoints/dce-soc-prod"
        streamDeclarations       = @{
            "Custom-CustomThreatIntel_CL" = @{
                columns = @(
                    @{ name = "TimeGenerated"; type = "datetime" }
                    @{ name = "IndicatorType"; type = "string" }
                    @{ name = "IndicatorValue"; type = "string" }
                    @{ name = "Confidence"; type = "int" }
                    @{ name = "Source"; type = "string" }
                    @{ name = "ExpirationDateTime"; type = "datetime" }
                )
            }
        }
        destinations = @{
            logAnalytics = @(
                @{
                    workspaceResourceId = "/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$wsName"
                    name                = "la-destination"
                }
            )
        }
        dataFlows = @(
            @{
                streams      = @("Custom-CustomThreatIntel_CL")
                destinations = @("la-destination")
                transformKql = "source | extend Confidence = toint(Confidence) | where Confidence > 50"
                outputStream = "Custom-CustomThreatIntel_CL"
            }
        )
    }
} | ConvertTo-Json -Depth 10

Invoke-AzRestMethod -Method PUT `
    -Path "/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.Insights/dataCollectionRules/dcr-threat-intel?api-version=2022-06-01" `
    -Payload $dcr
```

### Custom Log Ingestion via Logs Ingestion API

```python
import json, requests, yaml
from azure.identity import DefaultAzureCredential

# Read DCE endpoint from .secops workspace config
with open(".secops/workspaces/example-workspace.yaml") as f:
    ws = yaml.safe_load(f)

# Find the DCE endpoint for the custom table
dce_endpoint = None
for table in ws.get("custom_tables", []):
    if table["name"] == "CustomThreatIntel_CL":
        dce_endpoint = table.get("dce_endpoint")
        break

dcr_immutable_id = "dcr-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
stream_name = "Custom-CustomThreatIntel_CL"

credential = DefaultAzureCredential()
token = credential.get_token("https://monitor.azure.com/.default")

# Ingest a batch of records
records = [
    {
        "TimeGenerated": "2026-04-30T17:00:00Z",
        "IndicatorType": "ipv4-addr",
        "IndicatorValue": "198.51.100.42",
        "Confidence": 85,
        "Source": "OSINT-Feed-Alpha",
        "ExpirationDateTime": "2026-05-30T00:00:00Z",
    }
]

response = requests.post(
    f"{dce_endpoint}/dataCollectionRules/{dcr_immutable_id}/streams/{stream_name}?api-version=2023-01-01",
    headers={
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json",
    },
    data=json.dumps(records),
)
# 204 = success (no content), 413 = payload too large (max 1 MB per request)
print(f"Ingestion status: {response.status_code}")
```

### Transformation KQL in DCRs

The `transformKql` field accepts a subset of KQL. The source stream is referenced as `source`:

```kql
source
| extend TimeGenerated = now()
| extend GeoInfo = geo_info_from_ip_address(SourceIP)
| extend Country = tostring(GeoInfo.country)
| where Severity != "Informational"
| project-away RawData
```

**Allowed in DCR transforms:** `extend`, `project`, `project-away`, `project-rename`, `where`, `parse`, `parse-where`, `drop-columns`, `keep-columns`

**NOT allowed:** `join`, `union`, `summarize`, `sort`, `top`, `mv-expand`, `external_data`

### DCR Associations

Bind a DCR to a resource (e.g., a VM running AMA):

```bash
az monitor data-collection rule association create \
  --name "assoc-vm-soc" \
  --resource "/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.Compute/virtualMachines/soc-collector-01" \
  --rule-id "/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.Insights/dataCollectionRules/dcr-security-events"
```

---

## Section 6: Webhooks & Export

### Data Export Rules (Continuous Export)

Continuously stream data from Log Analytics to Azure Storage or Event Hub:

```powershell
# Create a data export rule to Event Hub
$exportRule = @{
    properties = @{
        destination = @{
            resourceId = "/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.EventHub/namespaces/eh-soc-export"
            metaData   = @{ eventHubName = "security-events" }
        }
        tableNames  = @("SecurityEvent", "SigninLogs", "CommonSecurityLog")
        enabled     = $true
    }
} | ConvertTo-Json -Depth 5

Invoke-AzRestMethod -Method PUT `
    -Path "/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$wsName/dataExports/export-to-eventhub?api-version=2020-08-01" `
    -Payload $exportRule
```

### Webhook Actions for Alert Rules

Webhooks are configured through Action Groups, not directly on alert rules:

```powershell
$actionGroup = @{
    location   = "global"
    properties = @{
        groupShortName  = "soc-wh"
        enabled         = $true
        webhookReceivers = @(
            @{
                name                 = "SIEM-Webhook"
                serviceUri           = "https://siem.contoso.com/api/alerts/ingest"
                useCommonAlertSchema = $true
                useAadAuth           = $true
                objectId             = "aaaabbbb-cccc-dddd-eeee-ffff00001111"
                tenantId             = $tenantId
            }
        )
    }
} | ConvertTo-Json -Depth 5
```

### Event Hub Streaming for SIEM Integration

Pattern: Log Analytics → Data Export → Event Hub → External SIEM

```python
# Consumer reading exported events from Event Hub
from azure.eventhub import EventHubConsumerClient
import json

def on_event(partition_context, event):
    records = json.loads(event.body_as_str())
    for record in records.get("records", [records]):
        table = record.get("Type", "Unknown")
        time = record.get("TimeGenerated", "")
        print(f"[{table}] {time}: {json.dumps(record)[:200]}")
    partition_context.update_checkpoint()

client = EventHubConsumerClient.from_connection_string(
    conn_str=eventhub_conn_str,
    consumer_group="$Default",
    eventhub_name="security-events",
)

with client:
    client.receive(on_event=on_event, starting_position="-1")
```

### Logic App Integration Pattern

Trigger a Logic App from a scheduled query alert, then call the Log Analytics query API from within the Logic App for enrichment:

```json
{
    "definition": {
        "triggers": {
            "When_alert_fires": {
                "type": "Request",
                "kind": "Http"
            }
        },
        "actions": {
            "Run_enrichment_query": {
                "type": "ApiConnection",
                "inputs": {
                    "host": { "connection": { "name": "@parameters('$connections')['azuremonitorlogs']['connectionId']" } },
                    "method": "post",
                    "path": "/queryData",
                    "body": {
                        "query": "SigninLogs | where UserPrincipalName == '@{triggerBody()?['data']?['essentials']?['monitorConditionResolvedDateTime']}' | take 10",
                        "timerange": "Last 24 hours"
                    }
                }
            }
        }
    }
}
```

---

## Section 7: Rate Limits & Best Practices

### Query API Rate Limits

| Limit | Value | Scope |
|---|---|---|
| **Concurrent queries** | 200 per user per 30s | Per AAD identity |
| **Max response size** | 64 MB uncompressed | Per query |
| **Max rows returned** | 500,000 rows | Per query result |
| **Query timeout** | 10 minutes (default), 600s max via `server_timeout` | Per query |
| **CPU limit** | 600 seconds total CPU | Per query |
| **Batch queries** | 200 queries per batch | Per batch request |

### Ingestion Rate Limits

| Limit | Value | Notes |
|---|---|---|
| **Logs Ingestion API** | 1 MB per request body | Split large payloads into batches |
| **Per-minute ingestion rate** | ~6 GB/min per DCR | May throttle with 429 responses |
| **Column limit** | 500 columns per table | Applies to custom tables |
| **Column name length** | 45 characters max | Use concise names |
| **Field value size** | 32 KB max per field | Truncated silently if exceeded |

### Best Practices for High-Volume Queries

```powershell
# 1. Use server-side timeouts for long queries
$body = @{
    query   = $query
    options = @{ server_timeout = 600 }
} | ConvertTo-Json

# 2. Paginate large result sets with search jobs for Archive-tier data
$searchJob = @{
    properties = @{
        query   = "search in (SecurityEvent) 'mimikatz' | take 10000"
        limit   = 10000
        startSearchTime = "2025-01-01T00:00:00Z"
        endSearchTime   = "2026-04-30T00:00:00Z"
    }
} | ConvertTo-Json
```

### Cost Optimization Decision Matrix

| Scenario | Recommended Approach | Why |
|---|---|---|
| **Real-time detection** | Scheduled query rules | Near real-time (5-min eval), no extra cost beyond ingestion |
| **Dashboards (hourly refresh)** | Workbook + scheduled query | Avoid repeated ad-hoc queries |
| **SIEM forwarding (all events)** | Data export rules | Streaming; no per-query cost |
| **Ad-hoc hunting (Archive tier)** | Search jobs / restore | Cheaper than keeping data in Analytics tier |
| **High-volume daily reports** | ADX continuous export → external tables | Query ADX or Storage — avoids Log Analytics query costs |
| **Cross-workspace correlation** | `workspace()` function | Free for queries; consider consolidation if constant |

### Retry Strategy

```python
import time
from azure.core.exceptions import HttpResponseError

def query_with_retry(client, workspace_id, query, max_retries=3):
    """Query with exponential backoff for rate limits."""
    for attempt in range(max_retries):
        try:
            return client.query_workspace(
                workspace_id=workspace_id,
                query=query,
                timespan=timedelta(hours=1),
            )
        except HttpResponseError as e:
            if e.status_code == 429:
                wait = int(e.response.headers.get("Retry-After", 2 ** attempt * 5))
                print(f"Rate limited (attempt {attempt+1}). Waiting {wait}s...")
                time.sleep(wait)
            else:
                raise
    raise RuntimeError(f"Query failed after {max_retries} retries")
```

---

## Related Skills

| Skill | Relationship |
|---|---|
| [Workspace Architecture](workspace-architecture.md) | Workspace topology that determines API target |
| [Custom Tables & DCR](custom-tables-dcr.md) | Deep dive on DCR schema design and AMA integration |
| [Cost Optimization](cost-optimization.md) | Cost implications of query patterns vs. export patterns |
| [Retention & Archive](retention-archive.md) | Archive tier search jobs referenced in Query API section |
| [Query Patterns](query-patterns.md) | Advanced KQL patterns used within Query API calls |
| [Microsoft Graph Security API](../msft-security/microsoft-graph-security.md) | Complementary API surface for security data |
