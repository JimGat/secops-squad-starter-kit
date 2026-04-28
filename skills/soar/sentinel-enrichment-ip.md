---
title: "Sentinel Enrichment — IP Address Threat Intelligence"
category: soar
difficulty: intermediate
trigger_type: sentinel-entity
products:
  - Microsoft Sentinel
  - Microsoft Defender Threat Intelligence
  - VirusTotal
api_connections:
  - azuresentinel
  - virustotal
author: Herc
version: 1.0.0
last_updated: 2026-04-28
mitre_attack:
  - T1071  # Application Layer Protocol
  - T1090  # Proxy
  - T1573  # Encrypted Channel
  - T1105  # Ingress Tool Transfer
---

# Sentinel Enrichment — IP Address Threat Intelligence

## Overview

This playbook enriches IP address entities attached to Sentinel incidents with multi-source threat intelligence. It is triggered by the Sentinel entity trigger (IP address) and queries VirusTotal, Microsoft Defender Threat Intelligence (MDTI), and GeoIP services to build a comprehensive risk profile for each IP. Results are written back to the incident as structured comments and, when warranted, new TI indicators are created in Sentinel.

**Business justification:** IP addresses appear in nearly every security incident — C2 callbacks, brute force sources, lateral movement destinations, exfiltration endpoints. Analysts spend 3-5 minutes per IP manually querying threat intel platforms. With 10-20 IPs per incident across 30+ daily incidents, that's 15-50 analyst-hours/week on copy-paste enrichment. This playbook delivers instant, consistent enrichment with zero analyst effort.

**What it does:**
1. Receives an IP address entity from a Sentinel incident
2. Queries VirusTotal for detection stats, last analysis, and community score
3. Queries MDTI for reputation, threat actors, and associated articles
4. Performs GeoIP lookup for country, ASN, and ISP
5. Checks against Sentinel watchlists (known-bad IPs, allowlists, TOR exit nodes)
6. Creates TI indicators for confirmed malicious IPs
7. Updates the incident with a structured enrichment comment

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Microsoft Sentinel                            │
│  Incident with IP entity → Entity trigger fires                 │
└──────────────┬───────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────┐
│  1. Extract IP Address   │
│  From entity trigger     │
│  body                    │
└──────────┬───────────────┘
               │
               ├──────────────────┬──────────────────┐
               ▼                  ▼                  ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│  2a. VirusTotal  │ │  2b. MDTI        │ │  2c. GeoIP       │
│  - Detections    │ │  - Reputation    │ │  - Country       │
│  - Community     │ │  - Threat actors │ │  - ASN / ISP     │
│  - Last analysis │ │  - Articles      │ │  - Org            │
└────────┬─────────┘ └────────┬─────────┘ └────────┬─────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
                              ▼
               ┌──────────────────────────┐
               │  3. Watchlist Check      │
               │  - Known-bad list        │
               │  - Allowlist             │
               │  - TOR exit nodes        │
               └──────────┬───────────────┘
                              │
                              ▼
               ┌──────────────────────────┐
               │  4. Verdict + Actions    │
               │  Malicious → Create TI   │
               │  Suspicious → Flag       │
               │  Clean → Document        │
               └──────────┬───────────────┘
                              │
                              ▼
               ┌──────────────────────────┐
               │  5. Update Incident      │
               │  - Structured comment    │
               │  - Tags                  │
               └──────────────────────────┘
```

## Prerequisites

### API Connections

| Connection          | Purpose                                    | Auth Method           |
|---------------------|--------------------------------------------|-----------------------|
| `azuresentinel`     | Read entities, update incidents, create TI | Managed Identity      |
| VirusTotal (HTTP)   | IP reputation and detection stats          | API Key (Key Vault)   |

### Required Permissions

| Permission                              | Type        | Justification                       |
|-----------------------------------------|-------------|-------------------------------------|
| `Microsoft Sentinel Responder`          | Azure RBAC  | Update incidents, run playbooks     |
| `Microsoft Sentinel Contributor`        | Azure RBAC  | Create TI indicators                |
| `ThreatIndicators.ReadWrite.OwnedBy`    | Application | Push indicators to Sentinel TI      |

### Managed Identity Setup

```bash
# Enable system-assigned managed identity
az logic workflow identity assign \
  --resource-group rg-soc-automation \
  --name la-enrich-ip \
  --system-assigned

# Grant Sentinel Contributor on the workspace
az role assignment create \
  --assignee <logic-app-principal-id> \
  --role "Microsoft Sentinel Contributor" \
  --scope /subscriptions/<sub>/resourceGroups/rg-soc/providers/Microsoft.OperationalInsights/workspaces/law-soc
```

### Key Vault Secrets

| Secret Name             | Description                    |
|-------------------------|--------------------------------|
| `VirusTotal-ApiKey`     | VT API key (free tier: 4 req/min) |

## Logic Apps Design

### Trigger

**Type:** `Microsoft Sentinel entity` (IP address)
**Trigger name:** `Microsoft_Sentinel_entity`

```json
{
  "type": "ApiConnectionWebhook",
  "inputs": {
    "host": {
      "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" }
    },
    "body": {
      "callback_url": "@listCallbackUrl()"
    },
    "path": "/entity/@{triggerBody()?['Entity']?['Type']}"
  }
}
```

The entity trigger receives the IP address in `triggerBody()?['Entity']?['properties']?['address']`.

### Step 1: Extract IP Address

**Action:** `Initialize variable`

```json
{
  "Initialize_IP": {
    "type": "InitializeVariable",
    "inputs": {
      "variables": [{
        "name": "ip_address",
        "type": "string",
        "value": "@triggerBody()?['Entity']?['properties']?['address']"
      }]
    }
  }
}
```

Validate the IP format (skip private/RFC1918 ranges — no point enriching 10.x.x.x or 192.168.x.x):
```json
{
  "Condition_Skip_Private": {
    "type": "If",
    "expression": {
      "or": [
        { "startsWith": ["@variables('ip_address')", "10."] },
        { "startsWith": ["@variables('ip_address')", "172.16."] },
        { "startsWith": ["@variables('ip_address')", "192.168."] },
        { "startsWith": ["@variables('ip_address')", "127."] }
      ]
    },
    "actions": {
      "Add_private_IP_comment": {
        "type": "ApiConnection",
        "inputs": {
          "body": { "message": "ℹ️ IP @{variables('ip_address')} is a private/RFC1918 address — skipping external enrichment." }
        }
      },
      "Terminate_skip": { "type": "Terminate", "inputs": { "runStatus": "Succeeded" } }
    }
  }
}
```

### Step 2: Multi-Source Enrichment (Parallel)

Run VirusTotal, MDTI, and GeoIP queries in parallel using a `Parallel` branch.

#### 2a. VirusTotal IP Report

**Action:** `HTTP`

```json
{
  "VT_IP_Report": {
    "type": "Http",
    "inputs": {
      "method": "GET",
      "uri": "https://www.virustotal.com/api/v3/ip_addresses/@{variables('ip_address')}",
      "headers": {
        "x-apikey": "@body('Get_VT_Key')?['value']"
      }
    },
    "retryPolicy": {
      "type": "exponential",
      "count": 3,
      "interval": "PT20S",
      "minimumInterval": "PT10S",
      "maximumInterval": "PT1H"
    }
  }
}
```

Extract:
- `last_analysis_stats.malicious` — number of engines flagging as malicious
- `last_analysis_stats.suspicious` — number flagging as suspicious
- `reputation` — community reputation score
- `as_owner` — ASN owner
- `country` — country code

#### 2b. MDTI Reputation

**Action:** `HTTP` — Microsoft Defender Threat Intelligence

```json
{
  "MDTI_IP_Reputation": {
    "type": "Http",
    "inputs": {
      "method": "GET",
      "uri": "https://graph.microsoft.com/beta/security/threatIntelligence/hosts/@{variables('ip_address')}",
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://graph.microsoft.com"
      }
    }
  }
}
```

Extract:
- `reputation` — MDTI reputation score
- `firstSeenDateTime` / `lastSeenDateTime`
- Associated threat components and articles

#### 2c. GeoIP Lookup

**Action:** `HTTP` — ip-api.com (free tier, no key required)

```json
{
  "GeoIP_Lookup": {
    "type": "Http",
    "inputs": {
      "method": "GET",
      "uri": "http://ip-api.com/json/@{variables('ip_address')}?fields=status,country,countryCode,region,city,isp,org,as,query"
    }
  }
}
```

> **Note:** For production, consider a paid GeoIP service (MaxMind, IPinfo) to avoid rate limits. ip-api.com free tier allows 45 req/min.

### Step 3: Watchlist Check

**Action:** `HTTP` — query Sentinel watchlists via Log Analytics

```json
{
  "Check_Known_Bad_Watchlist": {
    "type": "Http",
    "inputs": {
      "method": "POST",
      "uri": "https://api.loganalytics.io/v1/workspaces/@{parameters('workspace_id')}/query",
      "headers": {
        "Content-Type": "application/json"
      },
      "body": {
        "query": "_GetWatchlist('IP-KnownBad') | where IPAddress == '@{variables('ip_address')}' | project IPAddress, ThreatType, Source, AddedDate"
      },
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://api.loganalytics.io"
      }
    }
  }
}
```

Also check allowlists:
```json
{
  "Check_Allowlist": {
    "type": "Http",
    "inputs": {
      "body": {
        "query": "_GetWatchlist('IP-Allowlist') | where IPAddress == '@{variables('ip_address')}'"
      }
    }
  }
}
```

And TOR exit nodes (if watchlist maintained):
```json
{
  "Check_TOR_Exit": {
    "type": "Http",
    "inputs": {
      "body": {
        "query": "_GetWatchlist('TOR-ExitNodes') | where IPAddress == '@{variables('ip_address')}'"
      }
    }
  }
}
```

### Step 4: Verdict and TI Indicator Creation

**Action:** `Condition` + `ApiConnection`

If VT malicious detections > 5 OR IP is on the known-bad watchlist OR MDTI reputation is malicious, create a TI indicator:

```json
{
  "Condition_Create_TI": {
    "type": "If",
    "expression": {
      "or": [
        { "greater": ["@body('VT_IP_Report')?['data']?['attributes']?['last_analysis_stats']?['malicious']", 5] },
        { "greater": ["@length(body('Check_Known_Bad_Watchlist')?['tables']?[0]?['rows'])", 0] }
      ]
    },
    "actions": {
      "Create_TI_Indicator": {
        "type": "ApiConnection",
        "inputs": {
          "host": {
            "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" }
          },
          "method": "post",
          "path": "/threatintelligence/createIndicator",
          "body": {
            "action": "alert",
            "networkIPv4": "@variables('ip_address')",
            "description": "Auto-enriched: VT detections=@{body('VT_IP_Report')?['data']?['attributes']?['last_analysis_stats']?['malicious']}, Country=@{body('GeoIP_Lookup')?['country']}",
            "expirationDateTime": "@{addDays(utcNow(), 30)}",
            "threatType": "C2",
            "tlpLevel": "amber",
            "confidence": "@min(add(mul(body('VT_IP_Report')?['data']?['attributes']?['last_analysis_stats']?['malicious'], 5), 20), 100)",
            "tags": ["auto-enriched", "soar-playbook"]
          }
        }
      }
    }
  }
}
```

### Step 5: Update Incident Comment

**Action:** `Microsoft Sentinel - Add comment`

```
## IP Enrichment Report: @{variables('ip_address')}

### Geolocation
- **Country:** @{body('GeoIP_Lookup')?['country']} (@{body('GeoIP_Lookup')?['countryCode']})
- **City:** @{body('GeoIP_Lookup')?['city']}
- **ISP:** @{body('GeoIP_Lookup')?['isp']}
- **ASN:** @{body('GeoIP_Lookup')?['as']}
- **Organization:** @{body('GeoIP_Lookup')?['org']}

### VirusTotal
- **Malicious detections:** @{body('VT_IP_Report')?['data']?['attributes']?['last_analysis_stats']?['malicious']}
- **Suspicious detections:** @{body('VT_IP_Report')?['data']?['attributes']?['last_analysis_stats']?['suspicious']}
- **Community score:** @{body('VT_IP_Report')?['data']?['attributes']?['reputation']}
- **VT Link:** https://www.virustotal.com/gui/ip-address/@{variables('ip_address')}

### MDTI (Microsoft Defender Threat Intelligence)
- **Reputation:** @{body('MDTI_IP_Reputation')?['reputation']}
- **First seen:** @{body('MDTI_IP_Reputation')?['firstSeenDateTime']}
- **Last seen:** @{body('MDTI_IP_Reputation')?['lastSeenDateTime']}

### Watchlist Matches
- **Known-bad list:** @{if(greater(length(body('Check_Known_Bad_Watchlist')?['tables']?[0]?['rows']), 0), '⚠️ MATCH FOUND', '✅ No match')}
- **Allowlist:** @{if(greater(length(body('Check_Allowlist')?['tables']?[0]?['rows']), 0), '✅ On allowlist', 'Not on allowlist')}
- **TOR exit node:** @{if(greater(length(body('Check_TOR_Exit')?['tables']?[0]?['rows']), 0), '⚠️ TOR EXIT NODE', 'Not a TOR exit node')}

### Actions Taken
- @{if(greater(body('VT_IP_Report')?['data']?['attributes']?['last_analysis_stats']?['malicious'], 5), '☑ TI indicator created (30-day expiry)', '☐ No TI indicator created (below threshold)')}
```

### Error Handling

```json
{
  "Scope_Error_Handler": {
    "type": "Scope",
    "actions": {
      "Add_error_comment": {
        "type": "ApiConnection",
        "inputs": {
          "body": {
            "message": "⚠️ IP enrichment playbook error for @{variables('ip_address')}: @{result('Scope_Enrichment')?['error']?['message']}. Partial results may be available above."
          }
        }
      }
    },
    "runAfter": {
      "Scope_Enrichment": ["Failed", "TimedOut"]
    }
  }
}
```

Each enrichment source is independent — if VirusTotal fails, MDTI and GeoIP results are still posted. Use `Configure run after` on each action to handle partial failures gracefully.

## Bicep Template Reference

```bicep
@description('Sentinel IP Enrichment SOAR Playbook')
param location string = resourceGroup().location
param workspaceName string
param workspaceResourceGroup string
param workspaceId string

@secure()
param virusTotalApiKey string

var playbookName = 'la-enrich-ip'
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
      }
      triggers: {
        Microsoft_Sentinel_entity: {
          type: 'ApiConnectionWebhook'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            body: {
              callback_url: '@listCallbackUrl()'
            }
            path: '/entity/@{triggerBody()?[\'Entity\']?[\'Type\']}'
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

// --- Key Vault Secret Reference ---

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: 'kv-soc-automation'
}

resource vtApiKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'VirusTotal-ApiKey'
  properties: {
    value: virusTotalApiKey
  }
}
```

## Rollback / Destroy

### Remove the Automation

```bash
# 1. Disable the playbook
az logic workflow update \
  --resource-group rg-soc-automation \
  --name la-enrich-ip \
  --state Disabled

# 2. Wait for in-flight runs
az logic workflow run list \
  --resource-group rg-soc-automation \
  --workflow-name la-enrich-ip \
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
  --name la-enrich-ip --yes

az resource delete --ids <sentinel-connection-resource-id>
```

### Remove Added TI Indicators

If the playbook created incorrect TI indicators:

```bash
# Find indicators created by this playbook
az sentinel threat-indicator list \
  --workspace-name law-soc \
  --resource-group rg-soc \
  --query "[?contains(tags, 'auto-enriched') && contains(tags, 'soar-playbook')].[name, properties.networkIPv4]" \
  --output table

# Delete specific indicators
az sentinel threat-indicator delete \
  --workspace-name law-soc \
  --resource-group rg-soc \
  --name <indicator-id>

# Bulk delete by tag (PowerShell)
$indicators = az sentinel threat-indicator list \
  --workspace-name law-soc --resource-group rg-soc \
  --query "[?contains(tags, 'soar-playbook')].name" -o tsv
foreach ($id in $indicators) {
  az sentinel threat-indicator delete --workspace-name law-soc --resource-group rg-soc --name $id
}
```

## Testing Checklist

> For Carver (Detection/Validation Engineer) to verify before production deployment.

- [ ] **Trigger test:** Run playbook on a test incident with IP entity → playbook triggers and processes the IP
- [ ] **Private IP skip:** Submit a 10.0.0.1 entity → playbook adds "private IP" comment and terminates gracefully
- [ ] **VirusTotal enrichment:** Submit a known-malicious IP (e.g., from VT samples) → detections returned and parsed correctly
- [ ] **MDTI enrichment:** Submit an IP with MDTI data → reputation and first/last seen dates populated
- [ ] **GeoIP lookup:** Submit a public IP → country, city, ISP, ASN correctly returned
- [ ] **Watchlist match:** Add a test IP to the `IP-KnownBad` watchlist → playbook detects the match
- [ ] **Allowlist match:** Add a test IP to the `IP-Allowlist` watchlist → correctly flagged as allowed
- [ ] **TI indicator creation:** Submit IP with VT malicious > 5 → TI indicator created with correct expiry and tags
- [ ] **TI indicator skip:** Submit IP with VT malicious = 0 → no TI indicator created
- [ ] **Incident comment:** Verify structured enrichment comment appears with all sections populated
- [ ] **Partial failure:** Disable VT API key → GeoIP and MDTI still enrich, error noted in comment
- [ ] **Rate limiting:** Submit 5 IPs in sequence → no VT rate limit errors (concurrency = 1 with delays)
- [ ] **Rollback:** Delete test TI indicators created during testing

## Related Skills

- [Sentinel Enrichment — User](./sentinel-enrichment-user.md) — companion enrichment for user/account entities
- [Phishing Response](./phishing-response.md) — uses IP enrichment as part of URL/domain analysis
- [Threat Intel Ingest](./threat-intel-ingest.md) — bulk TI ingestion complements per-incident enrichment
