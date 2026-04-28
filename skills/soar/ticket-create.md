---
title: "ITSM Ticket Creation — ServiceNow / JIRA Bi-Directional Sync"
category: soar
difficulty: intermediate
trigger_type: sentinel-incident
products:
  - Microsoft Sentinel
  - ServiceNow
  - JIRA
api_connections:
  - azuresentinel
  - service-now
author: Herc
version: 1.0.0
last_updated: 2026-04-28
mitre_attack: []
---

# ITSM Ticket Creation — ServiceNow / JIRA Bi-Directional Sync

## Overview

This playbook automatically creates ITSM tickets (ServiceNow or JIRA) from Microsoft Sentinel incidents and maintains bi-directional synchronization between the incident and the ticket. Every Sentinel incident gets a corresponding ticket with mapped severity, extracted details, and a direct link back to the incident.

**Business justification:** SOC teams don't work in Sentinel alone — they live in ServiceNow or JIRA for ticket tracking, SLA management, and audit trails. Manually creating tickets for every incident wastes 3-5 minutes per incident and introduces human error (wrong severity mapping, missing details, no backlink). This playbook ensures 100% ticket coverage with zero manual effort, and the bi-directional sync keeps both systems in lockstep.

**What it does:**
1. Triggers on any new Sentinel incident
2. Maps Sentinel severity to ITSM priority (High → P1, Medium → P2, etc.)
3. Extracts incident details: title, description, entities, alerts, tactics
4. Creates a ticket in ServiceNow (or JIRA) with all context
5. Adds the ticket URL as a comment on the Sentinel incident
6. Sets up bi-directional sync: closing the ticket closes the incident and vice versa

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Microsoft Sentinel                            │
│  Any incident created → Trigger fires                           │
└──────────────┬───────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────┐
│  1. Extract Incident     │
│  - Title, description    │
│  - Severity, status      │
│  - Entities, alerts      │
│  - MITRE tactics         │
│  - Incident URL          │
└──────────┬───────────────┘
               │
               ▼
┌──────────────────────────┐
│  2. Map Severity →       │
│     ITSM Priority        │
│  High → P1 (Critical)    │
│  Medium → P2 (High)      │
│  Low → P3 (Medium)       │
│  Info → P4 (Low)         │
└──────────┬───────────────┘
               │
               ▼
┌──────────────────────────┐     ┌───────────────────────────┐
│  3. Create ITSM Ticket   │────▶│  ServiceNow / JIRA        │
│  - Mapped fields         │     │  REST API                  │
│  - Sentinel backlink     │     └───────────────────────────┘
│  - Entity summary        │
└──────────┬───────────────┘
               │
               ▼
┌──────────────────────────┐
│  4. Update Incident      │
│  - Add ticket URL        │
│  - Add ticket number tag │
└──────────┬───────────────┘
               │
               ▼
┌──────────────────────────┐
│  5. Bi-Directional Sync  │
│  - Incident closed →     │
│    close ticket           │
│  - Ticket closed →       │
│    close incident         │
└──────────────────────────┘
```

## Prerequisites

### API Connections

| Connection          | Purpose                                    | Auth Method              |
|---------------------|--------------------------------------------| -------------------------|
| `azuresentinel`     | Read incidents, add comments, update       | Managed Identity         |
| `service-now`       | Create/update/close ServiceNow incidents   | Service Account (OAuth)  |

> **JIRA alternative:** Replace the ServiceNow connector with the Atlassian JIRA connector (`jira`). The workflow logic is identical — only the API endpoints and field mappings differ. See the JIRA-specific section below.

### Required Permissions

| Permission                              | Type        | Justification                       |
|-----------------------------------------|-------------|-------------------------------------|
| `Microsoft Sentinel Responder`          | Azure RBAC  | Update incidents, run playbooks     |
| ServiceNow: `itil` role                | SNOW role   | Create and update incidents         |
| ServiceNow: `sn_si.analyst` role       | SNOW role   | Security incident module (if used)  |

### ServiceNow Configuration

1. **OAuth Application:** Register an OAuth app in ServiceNow → System OAuth → Application Registry
2. **API User:** Create a dedicated integration user with `itil` + `sn_si.analyst` roles
3. **Inbound REST API:** Ensure the Table API (`/api/now/table/incident`) is accessible from Azure IP ranges
4. **Correlation ID field:** Add a custom field `u_sentinel_incident_id` to the ServiceNow incident table for bi-directional lookup

### Key Vault Secrets

| Secret Name                    | Description                           |
|--------------------------------|---------------------------------------|
| `ServiceNow-Instance-URL`     | e.g., `https://contoso.service-now.com` |
| `ServiceNow-Client-Id`        | OAuth client ID                       |
| `ServiceNow-Client-Secret`    | OAuth client secret                   |
| `ServiceNow-Username`         | Integration user                      |
| `ServiceNow-Password`         | Integration user password             |

## Logic Apps Design

### Trigger

**Type:** `Microsoft Sentinel incident`
**Trigger name:** `Microsoft_Sentinel_incident`

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
    "path": "/incident-creation"
  }
}
```

This playbook triggers on ALL incidents. Use Sentinel automation rules to scope it to specific analytics rules or severity levels if needed.

### Step 1: Extract Incident Details

**Action:** `Compose` — build a structured summary from the incident

```json
{
  "Compose_Incident_Summary": {
    "type": "Compose",
    "inputs": {
      "incident_number": "@triggerBody()?['object']?['properties']?['incidentNumber']",
      "title": "@triggerBody()?['object']?['properties']?['title']",
      "description": "@triggerBody()?['object']?['properties']?['description']",
      "severity": "@triggerBody()?['object']?['properties']?['severity']",
      "status": "@triggerBody()?['object']?['properties']?['status']",
      "created_time": "@triggerBody()?['object']?['properties']?['createdTimeUtc']",
      "alert_count": "@triggerBody()?['object']?['properties']?['additionalData']?['alertsCount']",
      "tactics": "@join(triggerBody()?['object']?['properties']?['additionalData']?['tactics'], ', ')",
      "incident_url": "@triggerBody()?['object']?['properties']?['incidentUrl']",
      "incident_arm_id": "@triggerBody()?['object']?['id']"
    }
  }
}
```

Extract entities for the ticket description:
```json
{
  "Entities_-_Get_All": {
    "type": "ApiConnection",
    "inputs": {
      "host": {
        "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" }
      },
      "method": "post",
      "path": "/entities"
    }
  }
}
```

### Step 2: Map Severity to ITSM Priority

**Action:** `Switch`

```json
{
  "Map_Priority": {
    "type": "Switch",
    "expression": "@triggerBody()?['object']?['properties']?['severity']",
    "cases": {
      "High": {
        "actions": {
          "Set_P1": {
            "type": "SetVariable",
            "inputs": { "name": "snow_priority", "value": "1" }
          }
        }
      },
      "Medium": {
        "actions": {
          "Set_P2": {
            "type": "SetVariable",
            "inputs": { "name": "snow_priority", "value": "2" }
          }
        }
      },
      "Low": {
        "actions": {
          "Set_P3": {
            "type": "SetVariable",
            "inputs": { "name": "snow_priority", "value": "3" }
          }
        }
      }
    },
    "default": {
      "actions": {
        "Set_P4": {
          "type": "SetVariable",
          "inputs": { "name": "snow_priority", "value": "4" }
        }
      }
    }
  }
}
```

### Step 3: Create ServiceNow Ticket

**Action:** `HTTP` — ServiceNow Table API

```json
{
  "Create_SNOW_Incident": {
    "type": "Http",
    "inputs": {
      "method": "POST",
      "uri": "@{body('Get_SNOW_URL')?['value']}/api/now/table/incident",
      "headers": {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer @{body('Get_SNOW_Token')?['access_token']}"
      },
      "body": {
        "short_description": "[Sentinel-@{outputs('Compose_Incident_Summary')?['incident_number']}] @{outputs('Compose_Incident_Summary')?['title']}",
        "description": "Microsoft Sentinel Security Incident\n\n**Incident Number:** @{outputs('Compose_Incident_Summary')?['incident_number']}\n**Severity:** @{outputs('Compose_Incident_Summary')?['severity']}\n**Created:** @{outputs('Compose_Incident_Summary')?['created_time']}\n**Alerts:** @{outputs('Compose_Incident_Summary')?['alert_count']}\n**MITRE Tactics:** @{outputs('Compose_Incident_Summary')?['tactics']}\n\n**Description:**\n@{outputs('Compose_Incident_Summary')?['description']}\n\n**Entities:**\n@{body('Format_Entity_Summary')}\n\n**Sentinel Link:** @{outputs('Compose_Incident_Summary')?['incident_url']}",
        "priority": "@{variables('snow_priority')}",
        "category": "Security",
        "subcategory": "Security Incident",
        "assignment_group": "@{parameters('snow_assignment_group')}",
        "u_sentinel_incident_id": "@{outputs('Compose_Incident_Summary')?['incident_arm_id']}",
        "impact": "@{if(equals(outputs('Compose_Incident_Summary')?['severity'], 'High'), '1', if(equals(outputs('Compose_Incident_Summary')?['severity'], 'Medium'), '2', '3'))}",
        "urgency": "@{variables('snow_priority')}"
      }
    },
    "retryPolicy": {
      "type": "exponential",
      "count": 3,
      "interval": "PT20S",
      "minimumInterval": "PT10S",
      "maximumInterval": "PT5M"
    }
  }
}
```

#### JIRA Alternative

If using JIRA instead of ServiceNow:

```json
{
  "Create_JIRA_Issue": {
    "type": "Http",
    "inputs": {
      "method": "POST",
      "uri": "@{parameters('jira_base_url')}/rest/api/3/issue",
      "headers": {
        "Content-Type": "application/json",
        "Authorization": "Basic @{base64(concat(parameters('jira_email'), ':', body('Get_JIRA_Token')?['value']))}"
      },
      "body": {
        "fields": {
          "project": { "key": "@{parameters('jira_project_key')}" },
          "summary": "[Sentinel-@{outputs('Compose_Incident_Summary')?['incident_number']}] @{outputs('Compose_Incident_Summary')?['title']}",
          "description": {
            "type": "doc",
            "version": 1,
            "content": [
              {
                "type": "paragraph",
                "content": [{ "type": "text", "text": "@{outputs('Compose_Incident_Summary')?['description']}" }]
              }
            ]
          },
          "issuetype": { "name": "Bug" },
          "priority": { "name": "@{if(equals(variables('snow_priority'), '1'), 'Highest', if(equals(variables('snow_priority'), '2'), 'High', if(equals(variables('snow_priority'), '3'), 'Medium', 'Low')))}" },
          "labels": ["sentinel", "security-incident"]
        }
      }
    }
  }
}
```

### Step 4: Update Sentinel Incident

**Action:** `Microsoft Sentinel - Add comment` + tag with ticket number

```json
{
  "Add_ticket_comment": {
    "type": "ApiConnection",
    "inputs": {
      "host": {
        "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" }
      },
      "method": "post",
      "path": "/comment",
      "body": {
        "incidentArmId": "@triggerBody()?['object']?['id']",
        "message": "🎫 ITSM Ticket Created\n\n**Ticket Number:** @{body('Create_SNOW_Incident')?['result']?['number']}\n**Priority:** P@{variables('snow_priority')}\n**Assignment Group:** @{parameters('snow_assignment_group')}\n**Ticket URL:** @{body('Get_SNOW_URL')?['value']}/nav_to.do?uri=incident.do?sys_id=@{body('Create_SNOW_Incident')?['result']?['sys_id']}"
      }
    }
  }
}
```

Add the ticket number as an incident tag:
```json
{
  "Tag_incident": {
    "type": "ApiConnection",
    "inputs": {
      "body": {
        "incidentArmId": "@triggerBody()?['object']?['id']",
        "tagsToAdd": ["@{body('Create_SNOW_Incident')?['result']?['number']}", "itsm-synced"]
      }
    }
  }
}
```

### Step 5: Bi-Directional Sync

Bi-directional sync requires a second Logic App (or an additional trigger on this one) that watches for Sentinel incident status changes:

**Sentinel → ServiceNow (incident closed):**
```json
{
  "type": "ApiConnectionWebhook",
  "inputs": {
    "path": "/incident-update"
  }
}
```

When the Sentinel incident is closed, update the ServiceNow ticket:
```json
{
  "Close_SNOW_Ticket": {
    "type": "Http",
    "inputs": {
      "method": "PATCH",
      "uri": "@{body('Get_SNOW_URL')?['value']}/api/now/table/incident/@{variables('snow_sys_id')}",
      "body": {
        "state": "7",
        "close_code": "Resolved",
        "close_notes": "Closed via Sentinel incident closure. Classification: @{triggerBody()?['object']?['properties']?['classification']}"
      }
    }
  }
}
```

**ServiceNow → Sentinel (ticket closed):**

Configure a ServiceNow Business Rule or Flow to send a webhook to an Azure Function or Logic App HTTP trigger when a ticket with `u_sentinel_incident_id` is resolved. The receiving Logic App then closes the Sentinel incident:

```json
{
  "Close_Sentinel_Incident": {
    "type": "ApiConnection",
    "inputs": {
      "body": {
        "incidentArmId": "@{triggerBody()?['sentinel_incident_id']}",
        "status": "Closed",
        "classification": "TruePositive",
        "classificationReason": "SuspiciousActivity"
      }
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
      "Add_error_comment": {
        "type": "ApiConnection",
        "inputs": {
          "body": {
            "message": "⚠️ ITSM ticket creation failed: @{result('Scope_Ticket_Creation')?['error']?['message']}. Manual ticket creation required."
          }
        }
      }
    },
    "runAfter": {
      "Scope_Ticket_Creation": ["Failed", "TimedOut"]
    }
  }
}
```

## Bicep Template Reference

```bicep
@description('ITSM Ticket Creation SOAR Playbook')
param location string = resourceGroup().location
param workspaceName string
param workspaceResourceGroup string
param snowAssignmentGroup string = 'SOC-Tier1'

var playbookName = 'la-ticket-create'
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
        snow_assignment_group: {
          defaultValue: snowAssignmentGroup
          type: 'String'
        }
      }
      triggers: {
        Microsoft_Sentinel_incident: {
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
            path: '/incident-creation'
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

resource sentinelResponderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(playbook.id, 'sentinel-responder')
  scope: resourceId(workspaceResourceGroup, 'Microsoft.OperationalInsights/workspaces', workspaceName)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3e150fc0-dc56-4d40-8ad3-0a932e68a9a4')
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
  --name la-ticket-create \
  --state Disabled

# 2. Wait for in-flight runs
az logic workflow run list \
  --resource-group rg-soc-automation \
  --workflow-name la-ticket-create \
  --filter "status eq 'Running'" \
  --query "[].name"

# 3. Remove role assignments
az role assignment delete \
  --assignee <logic-app-principal-id> \
  --role "Microsoft Sentinel Responder" \
  --scope /subscriptions/<sub>/resourceGroups/rg-soc/providers/Microsoft.OperationalInsights/workspaces/law-soc

# 4. Delete Logic App and connections
az logic workflow delete \
  --resource-group rg-soc-automation \
  --name la-ticket-create --yes

az resource delete --ids <sentinel-connection-resource-id>

# 5. Remove ServiceNow Business Rule webhook (if bi-directional sync was configured)
```

### Reverse Ticket Actions

If the playbook created tickets incorrectly:

1. **Close/cancel created tickets:**
   ```bash
   # ServiceNow — close ticket via API
   curl -X PATCH "https://contoso.service-now.com/api/now/table/incident/{sys_id}" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"state": "8", "close_code": "Cancelled", "close_notes": "Created in error by automation"}'
   ```

2. **Remove ticket references from Sentinel:** Edit the incident comments in the Sentinel portal (comments cannot be deleted via API, but can be annotated with "superseded" notes).

3. **Bulk cleanup:** Query ServiceNow for all incidents with `u_sentinel_incident_id` populated and cancel those created during the error window.

## Testing Checklist

> For Carver (Detection/Validation Engineer) to verify before production deployment.

- [ ] **Trigger test:** Create a test Sentinel incident → ServiceNow ticket created within 60 seconds
- [ ] **Severity mapping:** Create incidents with High/Medium/Low/Informational severity → tickets have P1/P2/P3/P4 priority respectively
- [ ] **Ticket content:** Verify ticket contains incident title, description, entity summary, MITRE tactics, and Sentinel link
- [ ] **Sentinel backlink:** Verify ticket URL appears as an incident comment in Sentinel
- [ ] **Incident tagging:** Verify incident has ticket number tag and `itsm-synced` tag
- [ ] **Assignment group:** Verify ticket is assigned to the correct ServiceNow group
- [ ] **Bi-directional sync (Sentinel → SNOW):** Close Sentinel incident → ServiceNow ticket moves to Resolved
- [ ] **Bi-directional sync (SNOW → Sentinel):** Resolve ServiceNow ticket → Sentinel incident closes with correct classification
- [ ] **Duplicate prevention:** Run playbook twice on same incident → second run detects existing ticket and skips creation
- [ ] **Error handling:** Simulate ServiceNow API failure → Sentinel incident gets error comment, no ticket created
- [ ] **JIRA variant (if applicable):** Repeat ticket creation test with JIRA connector → issue created with correct fields

## Related Skills

- [Auto-Triage](./auto-triage.md) — auto-close decisions happen before ticket creation to reduce noise
- [Teams Notification](./teams-notification.md) — SOC channel notifications complement ticket creation
