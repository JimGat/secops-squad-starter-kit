---
title: "Sentinel Incident Teams Notification (Adaptive Card)"
category: soar
difficulty: beginner
trigger_type: sentinel-incident
products:
  - Microsoft Sentinel
  - Microsoft Teams
api_connections:
  - azuresentinel
  - teams
author: Herc
version: 1.0.0
---

# Sentinel Incident Teams Notification (Adaptive Card)

## Overview

This playbook sends a rich, actionable notification to a Microsoft Teams channel whenever a new Sentinel incident is created. The notification is an Adaptive Card with severity-coded colors, entity summaries, direct links to the Sentinel incident, and action buttons for quick triage (Assign to Me, Escalate, Close as False Positive).

**Business justification:** SOC analysts shouldn't have to live in the Sentinel portal to know something happened. This playbook pushes critical context to where the team already is — Teams. It eliminates the "I didn't see it" problem and cuts initial response time by giving analysts one-click actions directly from the notification.

**What it does:**
1. Triggers on any new Sentinel incident
2. Extracts incident metadata: title, description, severity, status, entities, tactics
3. Formats a severity-color-coded Adaptive Card
4. Sends the card to the appropriate Teams channel based on severity routing
5. Posts a follow-up thread message with detailed entity information
6. Falls back to email notification if Teams delivery fails

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  Microsoft Sentinel                                   │
│  New Incident Created → Trigger fires                 │
└──────────────┬────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────┐
│  1. Parse Incident       │
│  - Title, Description    │
│  - Severity, Status      │
│  - Entities, Tactics     │
│  - Incident URL          │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  2. Route by Severity    │
│  High/Critical → #soc-p1 │
│  Medium → #soc-alerts    │
│  Low/Info → #soc-info    │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐     ┌──────────────────────┐
│  3. Send Adaptive Card   │────▶│  Microsoft Teams     │
│  - Color-coded header    │     │  Channel message     │
│  - Entity summary        │     └──────────────────────┘
│  - Action buttons        │
│  - Incident deep link    │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  4. Post Entity Thread   │
│  - IP addresses          │
│  - Accounts              │
│  - Hosts                 │
│  - URLs                  │
│  - File hashes           │
└──────────────────────────┘
           │
           ▼  (on failure)
┌──────────────────────────┐
│  5. Fallback: Email      │
│  Send to SOC DL          │
└──────────────────────────┘
```

## Prerequisites

### API Connections

| Connection      | Purpose                          | Auth Method        |
|-----------------|----------------------------------|--------------------|
| `azuresentinel` | Read incident details/entities   | Managed Identity   |
| `teams`         | Post messages to channels        | Managed Identity   |

### Required Permissions

| Permission                    | Type        | Justification                     |
|-------------------------------|-------------|-----------------------------------|
| `Microsoft Sentinel Reader`   | Azure RBAC  | Read incident details             |
| `ChannelMessage.Send`         | Application | Post messages to Teams channels   |
| `Mail.Send`                   | Application | Fallback email notification       |

> **Alternative:** Instead of `ChannelMessage.Send` (Graph API), you can use an **Incoming Webhook** connector in Teams. This requires no Graph permissions but offers less control over card formatting and no action button support.

### Managed Identity Setup

```bash
# Enable system-assigned managed identity
az logic workflow identity assign \
  --resource-group rg-soc-automation \
  --name la-teams-notification \
  --system-assigned

# Grant Sentinel Reader
az role assignment create \
  --assignee <logic-app-principal-id> \
  --role "Microsoft Sentinel Reader" \
  --scope /subscriptions/<sub>/resourceGroups/rg-soc/providers/Microsoft.OperationalInsights/workspaces/law-soc
```

### Teams Channel Setup

Create the following channels in your SOC team (or map to existing ones):

| Channel       | Purpose                                | Severity Filter        |
|---------------|----------------------------------------|------------------------|
| `#soc-p1`     | Critical/High severity incidents       | High, Critical         |
| `#soc-alerts` | Medium severity incidents              | Medium                 |
| `#soc-info`   | Low/Informational incidents            | Low, Informational     |

Store channel IDs as Logic App parameters or in a configuration table.

## Logic Apps Design

### Trigger

**Type:** `Microsoft Sentinel incident`

```json
{
  "triggers": {
    "Microsoft_Sentinel_incident": {
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
  }
}
```

### Step 1: Parse Incident Details

**Action:** `Compose` — Extract key fields

```json
{
  "Compose_Incident_Data": {
    "type": "Compose",
    "inputs": {
      "incidentId": "@triggerBody()?['object']?['properties']?['incidentNumber']",
      "title": "@triggerBody()?['object']?['properties']?['title']",
      "description": "@triggerBody()?['object']?['properties']?['description']",
      "severity": "@triggerBody()?['object']?['properties']?['severity']",
      "status": "@triggerBody()?['object']?['properties']?['status']?['value']",
      "createdTime": "@triggerBody()?['object']?['properties']?['createdTimeUtc']",
      "alertCount": "@length(triggerBody()?['object']?['properties']?['alerts'])",
      "tactics": "@join(triggerBody()?['object']?['properties']?['additionalData']?['tactics'], ', ')",
      "incidentUrl": "@triggerBody()?['object']?['properties']?['incidentUrl']",
      "ownerName": "@triggerBody()?['object']?['properties']?['owner']?['userPrincipalName']"
    }
  }
}
```

**Action:** `Entities - Get Accounts`, `Entities - Get IPs`, `Entities - Get Hosts`, `Entities - Get URLs`

Extract entity counts and first few entity values for the card summary.

### Step 2: Severity Routing

**Action:** `Switch` on severity

```json
{
  "Switch_Severity_Channel": {
    "type": "Switch",
    "expression": "@outputs('Compose_Incident_Data')?['severity']",
    "cases": {
      "High": {
        "case": "High",
        "actions": {
          "Set_Channel_High": {
            "type": "SetVariable",
            "inputs": {
              "name": "targetChannelId",
              "value": "@parameters('channelId_P1')"
            }
          }
        }
      },
      "Medium": {
        "case": "Medium",
        "actions": {
          "Set_Channel_Medium": {
            "type": "SetVariable",
            "inputs": {
              "name": "targetChannelId",
              "value": "@parameters('channelId_Alerts')"
            }
          }
        }
      }
    },
    "default": {
      "actions": {
        "Set_Channel_Default": {
          "type": "SetVariable",
          "inputs": {
            "name": "targetChannelId",
            "value": "@parameters('channelId_Info')"
          }
        }
      }
    }
  }
}
```

### Step 3: Build and Send Adaptive Card

**Action:** `HTTP` — POST to Graph API (Teams channel message)

```
POST https://graph.microsoft.com/v1.0/teams/{teamId}/channels/{channelId}/messages
Content-Type: application/json

{
  "body": {
    "contentType": "html",
    "content": "<attachment id=\"adaptiveCard\"></attachment>"
  },
  "attachments": [
    {
      "id": "adaptiveCard",
      "contentType": "application/vnd.microsoft.card.adaptive",
      "content": "<ADAPTIVE_CARD_JSON>"
    }
  ]
}
```

### Complete Adaptive Card Template

```json
{
  "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
  "type": "AdaptiveCard",
  "version": "1.4",
  "body": [
    {
      "type": "Container",
      "style": "${if(severity == 'High', 'attention', if(severity == 'Medium', 'warning', 'good'))}",
      "bleed": true,
      "items": [
        {
          "type": "ColumnSet",
          "columns": [
            {
              "type": "Column",
              "width": "auto",
              "items": [
                {
                  "type": "Image",
                  "url": "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Logos/Azure_Sentinel.svg",
                  "size": "Small",
                  "altText": "Microsoft Sentinel"
                }
              ]
            },
            {
              "type": "Column",
              "width": "stretch",
              "items": [
                {
                  "type": "TextBlock",
                  "text": "Microsoft Sentinel Incident",
                  "weight": "Lighter",
                  "size": "Small",
                  "color": "${if(severity == 'High', 'attention', if(severity == 'Medium', 'warning', 'good'))}"
                },
                {
                  "type": "TextBlock",
                  "text": "#${incidentId}: ${title}",
                  "weight": "Bolder",
                  "size": "Medium",
                  "wrap": true
                }
              ]
            }
          ]
        }
      ]
    },
    {
      "type": "FactSet",
      "facts": [
        {
          "title": "Severity",
          "value": "${severity} ${if(severity == 'High', '🔴', if(severity == 'Medium', '🟠', if(severity == 'Low', '🟡', '🔵')))}"
        },
        {
          "title": "Status",
          "value": "${status}"
        },
        {
          "title": "Created",
          "value": "{{DATE(${createdTime}, SHORT)}} {{TIME(${createdTime})}}"
        },
        {
          "title": "Alerts",
          "value": "${alertCount} alert(s)"
        },
        {
          "title": "MITRE Tactics",
          "value": "${tactics}"
        },
        {
          "title": "Owner",
          "value": "${if(ownerName != '', ownerName, 'Unassigned')}"
        }
      ]
    },
    {
      "type": "TextBlock",
      "text": "${description}",
      "wrap": true,
      "maxLines": 3,
      "spacing": "Medium"
    },
    {
      "type": "Container",
      "spacing": "Medium",
      "items": [
        {
          "type": "TextBlock",
          "text": "Entities",
          "weight": "Bolder",
          "size": "Small"
        },
        {
          "type": "ColumnSet",
          "columns": [
            {
              "type": "Column",
              "width": "auto",
              "items": [
                {
                  "type": "TextBlock",
                  "text": "👤 Accounts: ${accountCount}"
                }
              ]
            },
            {
              "type": "Column",
              "width": "auto",
              "items": [
                {
                  "type": "TextBlock",
                  "text": "🌐 IPs: ${ipCount}"
                }
              ]
            },
            {
              "type": "Column",
              "width": "auto",
              "items": [
                {
                  "type": "TextBlock",
                  "text": "💻 Hosts: ${hostCount}"
                }
              ]
            },
            {
              "type": "Column",
              "width": "auto",
              "items": [
                {
                  "type": "TextBlock",
                  "text": "🔗 URLs: ${urlCount}"
                }
              ]
            }
          ]
        }
      ]
    }
  ],
  "actions": [
    {
      "type": "Action.OpenUrl",
      "title": "🔍 Open in Sentinel",
      "url": "${incidentUrl}"
    },
    {
      "type": "Action.OpenUrl",
      "title": "📋 Assign to Me",
      "url": "${incidentUrl}#assign"
    },
    {
      "type": "Action.OpenUrl",
      "title": "⬆️ Escalate",
      "url": "${incidentUrl}#escalate"
    }
  ]
}
```

#### Injecting Values into the Adaptive Card

In the Logic App, use `Compose` to build the card with dynamic values. Replace the template variables (`${...}`) with Logic Apps expressions:

```json
{
  "Compose_Adaptive_Card": {
    "type": "Compose",
    "inputs": {
      "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
      "type": "AdaptiveCard",
      "version": "1.4",
      "body": [
        {
          "type": "Container",
          "style": "@{if(equals(outputs('Compose_Incident_Data')?['severity'], 'High'), 'attention', if(equals(outputs('Compose_Incident_Data')?['severity'], 'Medium'), 'warning', 'good'))}",
          "bleed": true,
          "items": [
            {
              "type": "TextBlock",
              "text": "#@{outputs('Compose_Incident_Data')?['incidentId']}: @{outputs('Compose_Incident_Data')?['title']}",
              "weight": "Bolder",
              "size": "Medium",
              "wrap": true
            }
          ]
        }
      ]
    }
  }
}
```

> **Severity color mapping:**
> - `High` → Container style `attention` (red)
> - `Medium` → Container style `warning` (yellow/orange)
> - `Low` / `Informational` → Container style `good` (green)

### Step 4: Post Entity Thread

After the main card is sent, post a reply in the same thread with full entity details. This keeps the channel clean while providing depth when analysts drill in.

**Action:** `HTTP` — Reply to channel message

```
POST https://graph.microsoft.com/v1.0/teams/{teamId}/channels/{channelId}/messages/{parentMessageId}/replies
Content-Type: application/json

{
  "body": {
    "contentType": "html",
    "content": "<h3>Entity Details</h3><table><tr><th>Type</th><th>Value</th></tr>@{body('Format_Entity_Table')}</table>"
  }
}
```

Format the entity table by iterating over each entity type:

```html
<h3>📋 Entity Details</h3>

<b>Accounts:</b>
<ul>
  <li>user@contoso.com (Azure AD)</li>
</ul>

<b>IP Addresses:</b>
<ul>
  <li>198.51.100.23 (Location: US, ISP: Example ISP)</li>
</ul>

<b>Hosts:</b>
<ul>
  <li>WORKSTATION-01 (OS: Windows 11)</li>
</ul>

<b>URLs:</b>
<ul>
  <li>https://suspicious-domain[.]com/login</li>
</ul>

<b>File Hashes:</b>
<ul>
  <li>SHA256: a1b2c3d4... (filename: malware.exe)</li>
</ul>
```

### Step 5: Fallback to Email

If the Teams message fails (HTTP 4xx/5xx), fall back to email notification.

**Action:** `Send an email (V2)` — Office 365 connector (or HTTP to Graph API)

```json
{
  "Send_Fallback_Email": {
    "type": "ApiConnection",
    "inputs": {
      "host": {
        "connection": { "name": "@parameters('$connections')['office365']['connectionId']" }
      },
      "method": "post",
      "path": "/v2/Mail",
      "body": {
        "To": "@parameters('socDistributionList')",
        "Subject": "[@{outputs('Compose_Incident_Data')?['severity']}] Sentinel Incident #@{outputs('Compose_Incident_Data')?['incidentId']}: @{outputs('Compose_Incident_Data')?['title']}",
        "Body": "<h2>Sentinel Incident Notification</h2><p>Teams notification failed. Incident details below.</p><p><b>Severity:</b> @{outputs('Compose_Incident_Data')?['severity']}</p><p><b>Description:</b> @{outputs('Compose_Incident_Data')?['description']}</p><p><a href='@{outputs('Compose_Incident_Data')?['incidentUrl']}'>Open in Sentinel</a></p>",
        "Importance": "@{if(equals(outputs('Compose_Incident_Data')?['severity'], 'High'), 'High', 'Normal')}"
      }
    },
    "runAfter": {
      "Send_Teams_Message": ["Failed"]
    }
  }
}
```

### Error Handling

```json
{
  "retryPolicy": {
    "type": "exponential",
    "count": 3,
    "interval": "PT10S",
    "minimumInterval": "PT5S",
    "maximumInterval": "PT2M"
  }
}
```

The error handling flow:
1. Teams message send → retry 3 times with exponential backoff
2. If all retries fail → send email fallback
3. If email also fails → log to Logic App run history (no silent failures)

Since this is a notification-only playbook, there is no incident state modification. Failures are non-critical but should be monitored via Logic App diagnostics.

### Webhook Alternative

If you prefer Incoming Webhooks over Graph API (simpler setup, no Graph permissions):

```json
{
  "Send_Webhook": {
    "type": "Http",
    "inputs": {
      "method": "POST",
      "uri": "@parameters('teamsWebhookUrl')",
      "headers": {
        "Content-Type": "application/json"
      },
      "body": {
        "type": "message",
        "attachments": [
          {
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": null,
            "content": "@outputs('Compose_Adaptive_Card')"
          }
        ]
      }
    }
  }
}
```

> **Webhook limitations:**
> - No action buttons that call back to Logic Apps (OpenUrl only)
> - No threading (cannot post replies to create entity detail threads)
> - Webhook URLs can expire and must be rotated
> - Less reliable than Graph API for high-volume scenarios

## Bicep Template Reference

```bicep
@description('Sentinel Incident Teams Notification Playbook')
param location string = resourceGroup().location
param workspaceName string
param workspaceResourceGroup string
param teamsTeamId string
param channelIdP1 string
param channelIdAlerts string
param channelIdInfo string
param socDistributionList string = 'soc-team@contoso.com'

var playbookName = 'la-teams-notification'
var sentinelConnectionName = 'azuresentinel-${playbookName}'
var teamsConnectionName = 'teams-${playbookName}'

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

resource teamsConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: teamsConnectionName
  location: location
  kind: 'V1'
  properties: {
    displayName: teamsConnectionName
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'teams')
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
        teamsTeamId: {
          defaultValue: teamsTeamId
          type: 'String'
        }
        channelId_P1: {
          defaultValue: channelIdP1
          type: 'String'
        }
        channelId_Alerts: {
          defaultValue: channelIdAlerts
          type: 'String'
        }
        channelId_Info: {
          defaultValue: channelIdInfo
          type: 'String'
        }
        socDistributionList: {
          defaultValue: socDistributionList
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
              authentication: { type: 'ManagedServiceIdentity' }
            }
          }
          teams: {
            connectionId: teamsConnection.id
            connectionName: teamsConnectionName
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'teams')
            connectionProperties: {
              authentication: { type: 'ManagedServiceIdentity' }
            }
          }
        }
      }
    }
  }
}

// --- Role Assignments ---

resource sentinelReaderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(playbook.id, 'sentinel-reader')
  scope: resourceId(workspaceResourceGroup, 'Microsoft.OperationalInsights/workspaces', workspaceName)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '8d289c81-5878-46d4-8554-54e1e3d8b5cb') // Sentinel Reader
    principalId: playbook.identity.principalId
    principalType: 'ServicePrincipal'
  }
}
```

## Rollback / Destroy

This is a stateless notification playbook — it does not modify incidents or external systems. Rollback is straightforward.

### Remove the Automation

```bash
# 1. Disable the playbook
az logic workflow update \
  --resource-group rg-soc-automation \
  --name la-teams-notification \
  --state Disabled

# 2. Wait for in-flight runs (usually completes in seconds)
az logic workflow run list \
  --resource-group rg-soc-automation \
  --workflow-name la-teams-notification \
  --filter "status eq 'Running'" \
  --query "[].name"

# 3. Remove role assignments
az role assignment delete \
  --assignee <logic-app-principal-id> \
  --role "Microsoft Sentinel Reader" \
  --scope /subscriptions/<sub>/resourceGroups/rg-soc/providers/Microsoft.OperationalInsights/workspaces/law-soc

# 4. Delete Logic App and connections
az logic workflow delete \
  --resource-group rg-soc-automation \
  --name la-teams-notification --yes

az resource delete --ids <sentinel-connection-resource-id>
az resource delete --ids <teams-connection-resource-id>

# 5. (Optional) Remove Incoming Webhook from Teams channel if using webhook method
# This is done in Teams → Channel → Connectors → Remove webhook
```

### Cleanup Notes

- **No data to restore:** This playbook only sends messages. Deleting it stops future notifications.
- **Teams messages persist:** Previously sent notifications remain in the Teams channel. Delete them manually if needed.
- **Automation rules:** If you linked this playbook via a Sentinel Automation Rule, delete or disable that rule in Sentinel → Settings → Automation.

## Testing Checklist

> For Carver to verify before production deployment.

- [ ] **Trigger test:** Create a test incident in Sentinel → playbook triggers within 60 seconds
- [ ] **High severity routing:** Create a High severity incident → card posts to `#soc-p1` channel
- [ ] **Medium severity routing:** Create a Medium severity incident → card posts to `#soc-alerts` channel
- [ ] **Low severity routing:** Create a Low severity incident → card posts to `#soc-info` channel
- [ ] **Adaptive Card rendering:** Verify the card renders correctly in Teams desktop, web, and mobile clients
- [ ] **Severity colors:** Confirm High = red/attention, Medium = yellow/warning, Low = green/good
- [ ] **Incident link:** Click "Open in Sentinel" → navigates to the correct incident in the Sentinel portal
- [ ] **Entity summary:** Verify account, IP, host, and URL counts display correctly
- [ ] **Entity thread:** Verify a reply message is posted with detailed entity information
- [ ] **MITRE tactics:** Verify tactics display in the FactSet when present
- [ ] **Empty fields:** Create an incident with no description or no tactics → card handles gracefully (no blank fields or errors)
- [ ] **Long description:** Create an incident with a 500+ character description → card truncates at 3 lines with no overflow
- [ ] **Email fallback:** Temporarily use an invalid channel ID → Teams fails → email is sent to SOC DL
- [ ] **Rate limiting:** Create 10 incidents in rapid succession → all 10 notifications arrive (no drops)
- [ ] **Webhook path (if applicable):** Test with Incoming Webhook URL → card renders correctly
- [ ] **No duplicate notifications:** Incident update (not creation) does NOT trigger a second notification

## Tuning Guide

### Common Customizations

| Parameter                   | Default              | Tuning Notes                                         |
|-----------------------------|----------------------|------------------------------------------------------|
| Channel routing             | 3 channels by severity | Simplify to 1 channel if team is small             |
| Severity filter             | All severities       | Skip `Informational` to reduce noise                 |
| Entity detail thread        | Enabled              | Disable for high-volume environments (reduces API calls) |
| Email fallback              | Enabled              | Disable if you don't have an Office 365 connection   |
| Adaptive Card version       | 1.4                  | Downgrade to 1.2 if targeting older Teams clients    |
| Description max lines       | 3                    | Increase for detailed incident descriptions          |

### Severity Filter

To skip low-priority incidents, add a condition before the card is built:

```json
{
  "Condition_Severity_Filter": {
    "type": "If",
    "expression": {
      "not": {
        "equals": [
          "@outputs('Compose_Incident_Data')?['severity']",
          "Informational"
        ]
      }
    },
    "actions": { "...build and send card..." },
    "else": {
      "actions": {
        "Terminate_Skipped": {
          "type": "Terminate",
          "inputs": { "runStatus": "Succeeded" }
        }
      }
    }
  }
}
```

### Custom Branding

Replace the Sentinel logo URL in the Adaptive Card with your organization's security team logo. Update the header text from "Microsoft Sentinel Incident" to your SOC's branding (e.g., "Contoso SOC Alert").

### Deduplication

If your analytics rules can fire multiple alerts for the same incident (updates), add a dedup check:

1. Store sent incident IDs in a Storage Table or Logic App variable
2. Before sending, check if the incident ID was already notified
3. Skip if already sent, or send an "Updated" card variant

### Adding Custom Actions

The Adaptive Card supports `Action.OpenUrl` only (Teams limitation for bot-less cards). To add interactive actions (Assign, Close, etc.), you need one of:

1. **Power Automate flow URLs:** Create companion flows that accept HTTP triggers with incident ID parameters
2. **Azure Function endpoints:** Create Functions that call Sentinel API to update incidents
3. **Teams Bot:** Register a bot that handles Action.Submit callbacks (most complex but most powerful)

For a quick win, use `Action.OpenUrl` that links directly to the Sentinel incident page where the analyst can take action in the portal.

### High-Volume Environments

If your SOC generates 500+ incidents/day:

1. **Batch notifications:** Accumulate incidents for 5 minutes, then send a single summary card
2. **Severity gating:** Only send individual cards for High/Critical; batch everything else
3. **Quiet hours:** Suppress Low/Info notifications during off-hours (use a `Condition` with `utcNow()` time checks)
4. **Rate limiting:** Graph API allows 2 messages/second per channel. Add delays if needed.
