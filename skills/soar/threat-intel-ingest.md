---
title: "Threat Intelligence Ingest — TAXII/STIX to Sentinel TI"
category: soar
difficulty: advanced
trigger_type: scheduled
products:
  - Microsoft Sentinel
api_connections:
  - azuresentinel
author: Herc
version: 1.0.0
last_updated: 2026-04-28
mitre_attack: []
---

# Threat Intelligence Ingest — TAXII/STIX to Sentinel TI

## Overview

This playbook automates the ingestion of Indicators of Compromise (IOCs) from external TAXII 2.1 servers into Microsoft Sentinel's Threat Intelligence platform. It runs on a schedule (hourly or daily), connects to one or more TAXII feeds, parses STIX 2.1 bundles, maps indicators to Sentinel's TI format, deduplicates against existing indicators, and batch-uploads with proper expiration dates and source tagging.

**Business justification:** Threat intelligence is only useful if it's current, comprehensive, and integrated into your detection platform. Manually importing IOC feeds is unsustainable — feeds update hourly, contain thousands of indicators, and require format translation. This playbook ensures Sentinel TI stays current with zero manual effort, giving detection rules and hunting queries access to the latest threat intelligence automatically.

**What it does:**
1. Runs on schedule (configurable: hourly, every 6 hours, or daily)
2. Connects to TAXII 2.1 server(s) and discovers available collections
3. Fetches STIX bundles with pagination (only new/modified since last run)
4. Parses STIX indicator objects (IPv4, IPv6, domain, URL, file hash, email)
5. Maps to Sentinel TI indicator format with proper threat types and confidence
6. Deduplicates against existing Sentinel TI indicators
7. Batch-uploads via the Upload Indicators API (up to 100 per request)
8. Sets expiration dates and source tags for lifecycle management
9. Logs ingestion metrics (count, errors, duration) to the incident/workspace

## Architecture

```
┌────────────────────────────┐
│  Scheduled Trigger         │
│  (Recurrence: hourly/daily)│
└──────────┬─────────────────┘
           │
           ▼
┌──────────────────────────┐
│  1. Load Configuration   │
│  - TAXII server URL      │
│  - Collection IDs        │
│  - Last run timestamp    │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐     ┌───────────────────────────┐
│  2. Fetch STIX Bundles   │────▶│  TAXII 2.1 Server         │
│  - Discovery endpoint    │     │  GET /collections/{id}/   │
│  - Paginated retrieval   │     │      objects?added_after=  │
│  - Filter: added_after   │     └───────────────────────────┘
│    last_run_time          │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  3. Parse STIX Objects   │
│  - Extract indicators    │
│  - Map pattern types:    │
│    ipv4-addr, domain,    │
│    url, file:hashes      │
│  - Extract TLP, labels   │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  4. Deduplicate          │
│  - Check existing TI     │
│  - Skip duplicates       │
│  - Update if modified    │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐     ┌───────────────────────────┐
│  5. Batch Upload to      │────▶│  Sentinel TI Upload API   │
│     Sentinel TI          │     │  POST /threatIntelligence/│
│  - 100 per batch         │     │       uploadIndicators    │
│  - Set expiration        │     └───────────────────────────┘
│  - Tag with source       │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  6. Update State         │
│  - Save last_run_time    │
│  - Log metrics           │
│  - Report errors         │
└──────────────────────────┘
```

## Prerequisites

### API Connections

| Connection          | Purpose                                    | Auth Method           |
|---------------------|--------------------------------------------|-----------------------|
| `azuresentinel`     | Upload TI indicators, query existing TI    | Managed Identity      |

### Required Permissions

| Permission                              | Type        | Justification                       |
|-----------------------------------------|-------------|-------------------------------------|
| `Microsoft Sentinel Contributor`        | Azure RBAC  | Upload TI indicators                |

### Managed Identity Setup

```bash
# Enable system-assigned managed identity
az logic workflow identity assign \
  --resource-group rg-soc-automation \
  --name la-ti-ingest \
  --system-assigned

# Grant Sentinel Contributor
az role assignment create \
  --assignee <logic-app-principal-id> \
  --role "Microsoft Sentinel Contributor" \
  --scope /subscriptions/<sub>/resourceGroups/rg-soc/providers/Microsoft.OperationalInsights/workspaces/law-soc
```

### Key Vault Secrets

| Secret Name                | Description                                   |
|----------------------------|-----------------------------------------------|
| `TAXII-Server-URL`        | TAXII 2.1 API root (e.g., `https://taxii.example.com/taxii2/`) |
| `TAXII-Username`          | TAXII server username (HTTP Basic Auth)       |
| `TAXII-Password`          | TAXII server password                         |
| `TAXII-Collection-IDs`    | Comma-separated collection UUIDs              |

### TAXII Server Compatibility

This playbook supports TAXII 2.1 servers. Tested with:
- **Anomali STAXX** (free community server)
- **MITRE ATT&CK TAXII server** (`cti-taxii.mitre.org`)
- **AlienVault OTX** (via TAXII adapter)
- **Abuse.ch** (via TAXII adapter)
- **Custom STIX/TAXII implementations** (OpenCTI, MISP with TAXII export)

## Logic Apps Design

### Trigger

**Type:** `Recurrence`
**Trigger name:** `Recurrence_Schedule`

```json
{
  "type": "Recurrence",
  "recurrence": {
    "frequency": "Hour",
    "interval": 6,
    "timeZone": "UTC"
  }
}
```

Adjust frequency based on feed update cadence:
- High-volume feeds (abuse.ch, OTX): hourly
- Curated feeds (MITRE, commercial TI): every 6 hours or daily

### Step 1: Load Configuration and State

**Action:** `HTTP` — retrieve last run timestamp from a Storage Table or Logic App state

```json
{
  "Get_Last_Run_Time": {
    "type": "Http",
    "inputs": {
      "method": "GET",
      "uri": "https://@{parameters('storage_account')}.table.core.windows.net/TIIngestState(PartitionKey='taxii',RowKey='last_run')",
      "headers": {
        "Accept": "application/json;odata=noresolve"
      },
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://storage.azure.com"
      }
    }
  }
}
```

Initialize the `added_after` timestamp:
```json
{
  "Set_Added_After": {
    "type": "InitializeVariable",
    "inputs": {
      "variables": [{
        "name": "added_after",
        "type": "string",
        "value": "@{coalesce(body('Get_Last_Run_Time')?['Timestamp'], addHours(utcNow(), -24))}"
      }]
    }
  }
}
```

### Step 2: Fetch STIX Bundles from TAXII Server

#### 2a. Discover Collections (optional, for dynamic feeds)

```json
{
  "TAXII_Discovery": {
    "type": "Http",
    "inputs": {
      "method": "GET",
      "uri": "@{body('Get_TAXII_URL')?['value']}collections/",
      "headers": {
        "Accept": "application/taxii+json;version=2.1",
        "Authorization": "Basic @{base64(concat(body('Get_TAXII_User')?['value'], ':', body('Get_TAXII_Pass')?['value']))}"
      }
    }
  }
}
```

#### 2b. Fetch Objects (paginated)

**Action:** `Until` loop — fetch pages until no more objects or `next` link is absent

```json
{
  "Fetch_STIX_Objects": {
    "type": "Until",
    "expression": "@equals(variables('has_more_pages'), false)",
    "limit": { "count": 100, "timeout": "PT1H" },
    "actions": {
      "GET_Objects_Page": {
        "type": "Http",
        "inputs": {
          "method": "GET",
          "uri": "@{coalesce(variables('next_url'), concat(body('Get_TAXII_URL')?['value'], 'collections/', items('For_each_collection'), '/objects/?added_after=', variables('added_after'), '&limit=100'))}",
          "headers": {
            "Accept": "application/taxii+json;version=2.1",
            "Authorization": "Basic @{base64(concat(body('Get_TAXII_User')?['value'], ':', body('Get_TAXII_Pass')?['value']))}"
          }
        },
        "retryPolicy": {
          "type": "exponential",
          "count": 3,
          "interval": "PT30S",
          "minimumInterval": "PT15S",
          "maximumInterval": "PT10M"
        }
      },
      "Append_Objects": {
        "type": "AppendToArrayVariable",
        "inputs": {
          "name": "all_stix_objects",
          "value": "@body('GET_Objects_Page')?['objects']"
        }
      },
      "Check_Pagination": {
        "type": "SetVariable",
        "inputs": {
          "name": "has_more_pages",
          "value": "@not(empty(body('GET_Objects_Page')?['next']))"
        }
      },
      "Set_Next_URL": {
        "type": "SetVariable",
        "inputs": {
          "name": "next_url",
          "value": "@body('GET_Objects_Page')?['next']"
        }
      }
    }
  }
}
```

### Step 3: Parse STIX Indicators

**Action:** `Filter array` + `Select` — extract indicator patterns and map to Sentinel format

Filter for indicator objects only (skip reports, malware objects, etc.):
```json
{
  "Filter_Indicators": {
    "type": "Query",
    "inputs": {
      "from": "@variables('all_stix_objects')",
      "where": "@equals(item()?['type'], 'indicator')"
    }
  }
}
```

Parse STIX patterns into Sentinel TI fields:

```json
{
  "Parse_Indicator": {
    "type": "Compose",
    "inputs": {
      "networkIPv4": "@if(contains(item()?['pattern'], 'ipv4-addr'), replace(replace(item()?['pattern'], '[ipv4-addr:value = ''', ''), ''']', ''), null)",
      "domainName": "@if(contains(item()?['pattern'], 'domain-name'), replace(replace(item()?['pattern'], '[domain-name:value = ''', ''), ''']', ''), null)",
      "url": "@if(contains(item()?['pattern'], 'url:value'), replace(replace(item()?['pattern'], '[url:value = ''', ''), ''']', ''), null)",
      "fileHashValue": "@if(contains(item()?['pattern'], 'file:hashes'), replace(replace(last(split(item()?['pattern'], '= ''')), ''']', ''), '''', ''), null)",
      "fileHashType": "@if(contains(item()?['pattern'], 'SHA-256'), 'SHA-256', if(contains(item()?['pattern'], 'SHA-1'), 'SHA-1', if(contains(item()?['pattern'], 'MD5'), 'MD5', null)))",
      "threatType": "@coalesce(first(item()?['labels']), 'unknown')",
      "confidence": "@coalesce(item()?['confidence'], 50)",
      "description": "@coalesce(item()?['description'], item()?['name'], 'TAXII imported indicator')",
      "validFrom": "@item()?['valid_from']",
      "validUntil": "@coalesce(item()?['valid_until'], addDays(utcNow(), 90))",
      "tlpLevel": "@if(contains(string(item()?['object_marking_refs']), 'marking-definition--613f2e26'), 'white', if(contains(string(item()?['object_marking_refs']), 'marking-definition--34098fce'), 'green', if(contains(string(item()?['object_marking_refs']), 'marking-definition--f88d31f6'), 'amber', 'red')))",
      "stix_id": "@item()?['id']",
      "source": "@coalesce(item()?['created_by_ref'], 'taxii-feed')"
    }
  }
}
```

### Step 4: Deduplicate

Before uploading, check if indicators already exist in Sentinel TI to avoid duplicates:

```json
{
  "Check_Existing_Indicator": {
    "type": "Http",
    "inputs": {
      "method": "POST",
      "uri": "https://api.loganalytics.io/v1/workspaces/@{parameters('workspace_id')}/query",
      "body": {
        "query": "ThreatIntelligenceIndicator | where ExternalIndicatorId == '@{outputs('Parse_Indicator')?['stix_id']}' | project IndicatorId, ExternalIndicatorId, TimeGenerated | take 1"
      },
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://api.loganalytics.io"
      }
    }
  }
}
```

Skip upload if indicator already exists with the same STIX ID. If it exists but was modified (check `modified` timestamp), update it instead.

### Step 5: Batch Upload to Sentinel TI

**Action:** `HTTP` — Sentinel Upload Indicators API (batch of up to 100)

```json
{
  "Upload_TI_Batch": {
    "type": "Http",
    "inputs": {
      "method": "POST",
      "uri": "https://sentinelus.azure-api.net/workspaces/@{parameters('workspace_id')}/threatIntelligence/uploadIndicators?api-version=2022-07-01",
      "headers": {
        "Content-Type": "application/json"
      },
      "body": {
        "sourceName": "@{parameters('ti_source_name')}",
        "indicators": "@take(variables('parsed_indicators'), 100)"
      },
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://management.azure.com"
      }
    },
    "retryPolicy": {
      "type": "exponential",
      "count": 3,
      "interval": "PT30S"
    }
  }
}
```

> **Note:** The Upload Indicators API accepts up to 100 indicators per request. For larger feeds, batch the upload in chunks using an `Until` loop.

Each indicator in the batch uses this format:
```json
{
  "action": "alert",
  "activityGroupNames": [],
  "confidence": 75,
  "description": "Imported from TAXII feed",
  "expirationDateTime": "2026-07-28T00:00:00Z",
  "externalId": "indicator--abc123",
  "networkIPv4": "203.0.113.50",
  "threatType": "C2",
  "tlpLevel": "amber",
  "tags": ["taxii-import", "source:my-feed-name"]
}
```

### Step 6: Update State and Log Metrics

**Action:** `HTTP` — save last run timestamp to Storage Table

```json
{
  "Save_Last_Run_Time": {
    "type": "Http",
    "inputs": {
      "method": "PUT",
      "uri": "https://@{parameters('storage_account')}.table.core.windows.net/TIIngestState(PartitionKey='taxii',RowKey='last_run')",
      "headers": {
        "Content-Type": "application/json",
        "If-Match": "*"
      },
      "body": {
        "Timestamp": "@{utcNow()}",
        "IndicatorsIngested": "@{variables('total_ingested')}",
        "IndicatorsSkipped": "@{variables('total_skipped')}",
        "Errors": "@{variables('error_count')}"
      },
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://storage.azure.com"
      }
    }
  }
}
```

Log metrics to Log Analytics (optional, for dashboarding):
```json
{
  "Log_Metrics": {
    "type": "Http",
    "inputs": {
      "method": "POST",
      "uri": "https://@{parameters('workspace_id')}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
      "headers": {
        "Content-Type": "application/json",
        "Log-Type": "TIIngestMetrics_CL"
      },
      "body": [
        {
          "SourceName_s": "@{parameters('ti_source_name')}",
          "IndicatorsIngested_d": "@{variables('total_ingested')}",
          "IndicatorsSkipped_d": "@{variables('total_skipped')}",
          "ErrorCount_d": "@{variables('error_count')}",
          "DurationSeconds_d": "@{variables('run_duration')}",
          "RunTime_t": "@{utcNow()}"
        }
      ]
    }
  }
}
```

### Error Handling

```json
{
  "Scope_Error_Handler": {
    "type": "Scope",
    "actions": {
      "Send_Error_Alert": {
        "type": "Http",
        "inputs": {
          "method": "POST",
          "uri": "@{parameters('alert_webhook_url')}",
          "body": {
            "title": "🚨 TI Ingest Failure",
            "message": "Threat Intelligence ingestion failed: @{result('Scope_TI_Ingest')?['error']?['message']}. TAXII source: @{parameters('ti_source_name')}. Last successful run: @{variables('added_after')}."
          }
        }
      }
    },
    "runAfter": {
      "Scope_TI_Ingest": ["Failed", "TimedOut"]
    }
  }
}
```

Critical: If TI ingestion stops, detection rules relying on TI matching will have stale data. Alert on failures immediately.

## Bicep Template Reference

```bicep
@description('Threat Intelligence Ingest SOAR Playbook')
param location string = resourceGroup().location
param workspaceName string
param workspaceResourceGroup string
param workspaceId string
param storageAccountName string
param tiSourceName string = 'taxii-feed'
param ingestionFrequencyHours int = 6

var playbookName = 'la-ti-ingest'
var sentinelConnectionName = 'azuresentinel-${playbookName}'

// --- API Connections ---

resource sentinelConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: sentinelConnectionName
  location: location
  kind: 'V1'
  properties: {
    displayName: sentinelConnectionName
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
    }
    parameterValueType: 'Alternative'
  }
}

// --- Storage Account for State ---

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: storageAccountName
}

// --- Logic App ---

resource playbook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: playbookName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
        workspace_id: {
          defaultValue: workspaceId
          type: 'String'
        }
        storage_account: {
          defaultValue: storageAccountName
          type: 'String'
        }
        ti_source_name: {
          defaultValue: tiSourceName
          type: 'String'
        }
      }
      triggers: {
        Recurrence_Schedule: {
          type: 'Recurrence'
          recurrence: {
            frequency: 'Hour'
            interval: ingestionFrequencyHours
            timeZone: 'UTC'
          }
        }
      }
      actions: {}
    }
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: sentinelConnection.id
            connectionName: sentinelConnectionName
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
          }
        }
      }
    }
  }
}

// --- Role Assignments ---

resource sentinelContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(playbook.id, 'sentinel-contributor')
  scope: resourceId(workspaceResourceGroup, 'Microsoft.OperationalInsights/workspaces', workspaceName)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ab8e14d6-4a74-4a29-9ba8-549422addade')
    principalId: playbook.identity.principalId
    principalType: 'ServicePrincipal'
  }
}
```

## Rollback / Destroy

### Remove the Automation

```bash
# 1. Disable the playbook
az logic workflow update \
  --resource-group rg-soc-automation \
  --name la-ti-ingest \
  --state Disabled

# 2. Wait for in-flight runs
az logic workflow run list \
  --resource-group rg-soc-automation \
  --workflow-name la-ti-ingest \
  --filter "status eq 'Running'" \
  --query "[].name"

# 3. Remove role assignments
az role assignment delete \
  --assignee <logic-app-principal-id> \
  --role "Microsoft Sentinel Contributor" \
  --scope /subscriptions/<sub>/resourceGroups/rg-soc/providers/Microsoft.OperationalInsights/workspaces/law-soc

# 4. Delete Logic App and connections
az logic workflow delete \
  --resource-group rg-soc-automation \
  --name la-ti-ingest --yes

az resource delete --ids <sentinel-connection-resource-id>

# 5. Clean up state table
az storage entity delete \
  --table-name TIIngestState \
  --partition-key taxii \
  --row-key last_run \
  --account-name <storage-account>
```

### Bulk Delete Ingested Indicators

If the feed ingested bad data (false positives, incorrect IOCs), remove all indicators from that source:

```bash
# Find indicators by source tag
az sentinel threat-indicator list \
  --workspace-name law-soc \
  --resource-group rg-soc \
  --query "[?contains(tags, 'taxii-import') && contains(tags, 'source:my-feed-name')].name" \
  --output tsv > indicators-to-delete.txt

# Bulk delete (PowerShell)
$indicators = Get-Content indicators-to-delete.txt
foreach ($id in $indicators) {
  az sentinel threat-indicator delete \
    --workspace-name law-soc \
    --resource-group rg-soc \
    --name $id
  Start-Sleep -Milliseconds 200  # Rate limiting
}

# Alternative: Delete by time window using Log Analytics
az monitor log-analytics query \
  --workspace law-soc \
  --analytics-query "ThreatIntelligenceIndicator
    | where SourceSystem == 'SecurityGraph'
    | where Tags has 'source:my-feed-name'
    | where TimeGenerated between (datetime(2026-04-28) .. datetime(2026-04-29))
    | project IndicatorId" \
  --output tsv
```

## Testing Checklist

> For Carver (Detection/Validation Engineer) to verify before production deployment.

- [ ] **TAXII connectivity:** Playbook connects to TAXII server and discovers collections successfully
- [ ] **STIX parsing:** Submit a STIX bundle with IPv4, domain, URL, and file hash indicators → all types parsed correctly
- [ ] **Pagination:** Feed with >100 indicators → all pages fetched and processed
- [ ] **Added_after filter:** Run twice with same data → second run fetches zero new indicators (incremental sync works)
- [ ] **TI upload:** Parsed indicators appear in Sentinel Threat Intelligence blade within 5 minutes
- [ ] **Expiration:** Indicators have correct expiry dates (from STIX `valid_until` or default 90 days)
- [ ] **Source tagging:** All uploaded indicators have `taxii-import` and `source:{feed-name}` tags
- [ ] **Deduplication:** Submit same STIX bundle twice → no duplicate indicators created
- [ ] **TLP mapping:** STIX TLP markings correctly mapped to Sentinel TLP levels
- [ ] **Error handling:** Simulate TAXII server timeout → playbook logs error and retries, sends alert on final failure
- [ ] **State persistence:** After successful run, last_run_time is updated in Storage Table
- [ ] **Metrics logging:** TIIngestMetrics_CL table receives ingestion statistics
- [ ] **Rollback:** Bulk delete all indicators from test source → Sentinel TI clean

## Related Skills

- [Sentinel Enrichment — IP](./sentinel-enrichment-ip.md) — uses TI indicators for enrichment lookups
- [Phishing Response](./phishing-response.md) — pushes per-incident IOCs complementing bulk TI ingest
- [Auto-Triage](./auto-triage.md) — uses TI matches for known-bad entity identification
