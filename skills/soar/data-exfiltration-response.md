---
title: "Data Exfiltration Response — DLP Alert Enrichment & Blocking"
category: soar
difficulty: advanced
trigger_type: sentinel-incident
products:
  - Microsoft Sentinel
  - Microsoft Purview
  - Entra ID
  - Microsoft Teams
api_connections:
  - azuresentinel
  - azuread
  - teams
author: Herc
version: 1.0.0
last_updated: 2026-04-28
mitre_attack:
  - T1567  # Exfiltration Over Web Service
  - T1048  # Exfiltration Over Alternative Protocol
---

# Data Exfiltration Response — DLP Alert Enrichment & Blocking

## Overview

This playbook automates the response to data exfiltration alerts from Microsoft Purview DLP policies. When a DLP policy match triggers a Sentinel incident, this playbook enriches the alert with user context, evaluates severity based on sensitivity labels and data volume, notifies the user's manager, and blocks further sharing for high-severity matches.

**Business justification:** DLP alerts are high-volume — a large enterprise generates 200+ DLP matches daily. Most are low-severity (accidental sharing of internal documents). Without automation, SOC analysts spend 5-10 minutes per alert on context gathering alone — pulling user profiles, checking sensitivity labels, and finding the right manager to notify. This playbook automates the entire enrichment and routing workflow, ensuring high-severity exfiltration attempts get blocked in under 60 seconds while low-severity matches are routed for awareness without SOC intervention.

**What it does:**
1. Extracts DLP alert details from the Sentinel incident (policy name, matched content, sensitivity label)
2. Enriches with user context from Entra ID (title, department, manager, risk level)
3. Evaluates severity based on sensitivity label + data volume + user risk level
4. High severity: blocks sharing, notifies manager, escalates incident
5. Medium severity: notifies manager, adds monitoring tag
6. Low severity: auto-documents and closes with awareness notification
7. Updates the Sentinel incident with full enrichment and actions taken

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Microsoft Sentinel                            │
│  Purview DLP Alert → Incident created → Trigger fires           │
└──────────────┬───────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────┐
│  1. Parse DLP Alert      │
│  Extract: user, policy,  │
│  sensitivity label,      │
│  matched content type,   │
│  sharing target          │
└──────────┬───────────────┘
               │
               ▼
┌──────────────────────────┐     ┌───────────────────────────┐
│  2. Enrich User Context  │────▶│  Microsoft Entra ID       │
│  - Profile + manager     │     │  Graph API                │
│  - Risk level            │     └───────────────────────────┘
│  - Group memberships     │
│  - Recent MFA changes    │
└──────────┬───────────────┘
               │
               ▼
┌──────────────────────────┐
│  3. Severity Evaluation  │
│  Label = Confidential +  │
│  External share +        │
│  High user risk          │
│  → Score → Route         │
├──────────────────────────┤
│  High → Block + Notify   │
│  Med  → Notify manager   │
│  Low  → Auto-close       │
└──────┬──────┬──────┬─────┘
       │      │      │
       ▼      ▼      ▼
┌──────┐ ┌────────┐ ┌──────────┐
│Block │ │Notify  │ │Auto-close│
│Share │ │Manager │ │+ log     │
│+Alert│ │+Monitor│ │          │
└──────┘ └────────┘ └──────────┘
               │
               ▼
┌──────────────────────────┐
│  4. Update Incident      │
│  - Enrichment comment    │
│  - Severity adjustment   │
│  - Tags + classification │
└──────────────────────────┘
```

## Prerequisites

### API Connections

| Connection          | Purpose                                    | Auth Method           |
|---------------------|--------------------------------------------|-----------------------|
| `azuresentinel`     | Read/update incidents, add comments        | Managed Identity      |
| `azuread`           | User profile, manager, risk level lookup   | Managed Identity      |
| `teams`             | Notify manager and SOC channel             | Managed Identity      |

### Required Permissions

| Permission                              | Type        | Justification                       |
|-----------------------------------------|-------------|-------------------------------------|
| `Microsoft Sentinel Responder`          | Azure RBAC  | Update incidents, run playbooks     |
| `User.Read.All`                         | Application | Read user profiles and managers     |
| `IdentityRiskyUser.Read.All`            | Application | Read user risk levels               |
| `GroupMember.Read.All`                   | Application | Check VIP / executive group membership |
| `ChannelMessage.Send`                   | Application | Post notifications to Teams         |

### Managed Identity Setup

```bash
# Enable system-assigned managed identity
az logic workflow identity assign \
  --resource-group rg-soc-automation \
  --name la-data-exfil-response \
  --system-assigned

# Grant Sentinel Responder
az role assignment create \
  --assignee <logic-app-principal-id> \
  --role "Microsoft Sentinel Responder" \
  --scope /subscriptions/<sub>/resourceGroups/rg-soc/providers/Microsoft.OperationalInsights/workspaces/law-soc

# Grant Graph API permissions
az ad app permission add \
  --id <app-id> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions \
    User.Read.All=Role \
    IdentityRiskyUser.Read.All=Role \
    GroupMember.Read.All=Role
```

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

**Incident filter:** Check that the incident originates from a DLP-related analytics rule or the title contains DLP/exfiltration patterns.

### Step 1: Parse DLP Alert Details

**Action:** `Entities - Get Accounts`, `Parse JSON`

Extract from the incident alert evidence:
- **User principal name** — the user who triggered the DLP policy
- **DLP policy name** — which policy was matched
- **Sensitivity label** — label on the matched content (General, Confidential, Highly Confidential)
- **Sharing target** — external domain or recipient
- **Matched content count** — number of sensitive items detected
- **Service** — SharePoint, OneDrive, Exchange, Teams, Endpoint

```json
{
  "Entities_-_Get_Accounts": {
    "type": "ApiConnection",
    "inputs": {
      "host": {
        "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" }
      },
      "method": "post",
      "path": "/entities/account"
    }
  }
}
```

### Step 2: Enrich User Context

#### 2a. User Profile and Manager

**Action:** `HTTP` — Microsoft Graph API

```json
{
  "Get_User_Profile": {
    "type": "Http",
    "inputs": {
      "method": "GET",
      "uri": "https://graph.microsoft.com/v1.0/users/@{variables('user_upn')}?$select=displayName,jobTitle,department,officeLocation,manager&$expand=manager($select=displayName,mail)",
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://graph.microsoft.com"
      }
    }
  }
}
```

#### 2b. User Risk Level

**Action:** `HTTP` — Entra ID Identity Protection

```json
{
  "Get_User_Risk": {
    "type": "Http",
    "inputs": {
      "method": "GET",
      "uri": "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/@{variables('user_object_id')}",
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://graph.microsoft.com"
      }
    }
  }
}
```

#### 2c. VIP Group Check

**Action:** `HTTP` — check membership in executive/VIP groups

```json
{
  "Check_VIP_Group": {
    "type": "Http",
    "inputs": {
      "method": "POST",
      "uri": "https://graph.microsoft.com/v1.0/users/@{variables('user_upn')}/checkMemberGroups",
      "body": {
        "groupIds": ["@{parameters('vip_group_id')}", "@{parameters('executive_group_id')}"]
      },
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://graph.microsoft.com"
      }
    }
  }
}
```

### Step 3: Severity Evaluation

**Action:** `Compose` + `Switch`

Calculate a severity score based on multiple signals:

```json
{
  "Compose_Severity_Score": {
    "type": "Compose",
    "inputs": {
      "score": "@add(
        if(equals(variables('sensitivity_label'), 'Highly Confidential'), 40, if(equals(variables('sensitivity_label'), 'Confidential'), 25, 10)),
        if(contains(variables('sharing_target'), '@external'), 25, 0),
        if(or(equals(body('Get_User_Risk')?['riskLevel'], 'high'), equals(body('Get_User_Risk')?['riskLevel'], 'medium')), 20, 0),
        if(greater(variables('matched_item_count'), 10), 15, if(greater(variables('matched_item_count'), 3), 10, 0)),
        if(greater(length(body('Check_VIP_Group')?['value']), 0), 10, 0)
      )"
    }
  }
}
```

**Decision tree:**

| Score   | Severity | Action                                              |
|---------|----------|-----------------------------------------------------|
| ≥ 70    | High     | Block sharing, notify manager + SOC, escalate       |
| 40 – 69 | Medium  | Notify manager, add monitoring tag, keep active      |
| < 40    | Low      | Auto-document, notify user, close as informational  |

### Step 4: Remediate (High Severity)

#### 4a. Block Sharing (via Purview Compliance API)

**Action:** `HTTP` — revoke external sharing

For SharePoint/OneDrive files:
```
POST https://graph.microsoft.com/v1.0/drives/{driveId}/items/{itemId}/permissions/{permId}
DELETE method — removes the sharing link
```

For Exchange:
```
POST https://graph.microsoft.com/v1.0/security/collaboration/contentSearches
— search and quarantine the email
```

#### 4b. Notify Manager

**Action:** `Microsoft Teams - Send message`

```json
{
  "Notify_Manager": {
    "type": "ApiConnection",
    "inputs": {
      "host": {
        "connection": { "name": "@parameters('$connections')['teams']['connectionId']" }
      },
      "method": "post",
      "path": "/v1.0/users/@{body('Get_User_Profile')?['manager']?['mail']}/chats",
      "body": {
        "contentType": "html",
        "content": "<h3>⚠️ Data Loss Prevention Alert</h3><p><b>Employee:</b> @{body('Get_User_Profile')?['displayName']} (@{variables('user_upn')})<br/><b>Department:</b> @{body('Get_User_Profile')?['department']}<br/><b>DLP Policy:</b> @{variables('dlp_policy_name')}<br/><b>Sensitivity Label:</b> @{variables('sensitivity_label')}<br/><b>Sharing Target:</b> @{variables('sharing_target')}<br/><b>Items Matched:</b> @{variables('matched_item_count')}<br/><b>Action Taken:</b> @{if(greaterOrEquals(variables('severity_score'), 70), 'Sharing blocked automatically', 'Monitoring — no block applied')}<br/><br/>Please review this activity with your team member. If this was authorized business activity, contact the SOC to clear the alert.</p>"
      }
    }
  }
}
```

### Step 5: Update Incident

```json
{
  "Update_incident": {
    "type": "ApiConnection",
    "inputs": {
      "host": {
        "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" }
      },
      "method": "put",
      "path": "/incidents",
      "body": {
        "incidentArmId": "@triggerBody()?['object']?['id']",
        "severity": "@if(greaterOrEquals(variables('severity_score'), 70), 'High', if(greaterOrEquals(variables('severity_score'), 40), 'Medium', 'Low'))",
        "status": "@if(less(variables('severity_score'), 40), 'Closed', 'Active')",
        "classification": "@if(less(variables('severity_score'), 40), 'BenignPositive', '')",
        "tagsToAdd": ["dlp", "auto-triaged", "@{variables('sensitivity_label')}"],
        "description": "DLP auto-triage: severity @{variables('severity_score')}/100. User: @{variables('user_upn')}. Policy: @{variables('dlp_policy_name')}."
      }
    }
  }
}
```

**Enrichment comment:**
```
## DLP Incident Enrichment Report
**Severity Score:** @{variables('severity_score')}/100

### User Context
- **User:** @{body('Get_User_Profile')?['displayName']} (@{variables('user_upn')})
- **Title:** @{body('Get_User_Profile')?['jobTitle']}
- **Department:** @{body('Get_User_Profile')?['department']}
- **Manager:** @{body('Get_User_Profile')?['manager']?['displayName']}
- **Risk Level:** @{body('Get_User_Risk')?['riskLevel']}
- **VIP Member:** @{if(greater(length(body('Check_VIP_Group')?['value']), 0), 'Yes', 'No')}

### DLP Details
- **Policy:** @{variables('dlp_policy_name')}
- **Sensitivity Label:** @{variables('sensitivity_label')}
- **Sharing Target:** @{variables('sharing_target')}
- **Items Matched:** @{variables('matched_item_count')}
- **Service:** @{variables('dlp_service')}

### Actions Taken
- ☑ User profile enriched from Entra ID
- ☑ User risk level checked
- ☑ Manager notified: @{body('Get_User_Profile')?['manager']?['displayName']}
- @{if(greaterOrEquals(variables('severity_score'), 70), '☑ Sharing blocked', '☐ Sharing not blocked (below threshold)')}
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
            "message": "⚠️ DLP response playbook error: @{result('Scope_DLP_Response')?['error']?['message']}. Manual review required."
          }
        }
      }
    },
    "runAfter": {
      "Scope_DLP_Response": ["Failed", "TimedOut"]
    }
  }
}
```

## Bicep Template Reference

```bicep
@description('Data Exfiltration Response SOAR Playbook')
param location string = resourceGroup().location
param workspaceName string
param workspaceResourceGroup string
param vipGroupId string = ''
param executiveGroupId string = ''

var playbookName = 'la-data-exfil-response'
var sentinelConnectionName = 'azuresentinel-${playbookName}'
var azureadConnectionName = 'azuread-${playbookName}'
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

resource azureadConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: azureadConnectionName
  location: location
  kind: 'V1'
  properties: {
    displayName: azureadConnectionName
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuread')
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
        vip_group_id: {
          defaultValue: vipGroupId
          type: 'String'
        }
        executive_group_id: {
          defaultValue: executiveGroupId
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
          azuread: {
            connectionId: azureadConnection.id
            connectionName: azureadConnectionName
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuread')
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
          }
          teams: {
            connectionId: teamsConnection.id
            connectionName: teamsConnectionName
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'teams')
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
  --name la-data-exfil-response \
  --state Disabled

# 2. Wait for in-flight runs
az logic workflow run list \
  --resource-group rg-soc-automation \
  --workflow-name la-data-exfil-response \
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
  --name la-data-exfil-response --yes

az resource delete --ids <sentinel-connection-resource-id>
az resource delete --ids <azuread-connection-resource-id>
az resource delete --ids <teams-connection-resource-id>
```

### Reverse Remediation Actions

If the playbook blocked sharing on a false positive:

1. **Unblock sharing:** Re-add the sharing permission on the affected file/site:
   ```bash
   # For SharePoint/OneDrive — re-share via Graph API
   POST https://graph.microsoft.com/v1.0/drives/{driveId}/items/{itemId}/invite
   {
     "recipients": [{"email": "external-user@partner.com"}],
     "requireSignIn": true,
     "roles": ["read"]
   }
   ```

2. **Clear DLP override:** If a DLP policy override was applied, remove it via the Purview Compliance Center → Data Loss Prevention → Policy → remove the override entry.

3. **Notify manager of false positive:** Send a follow-up Teams message clarifying the alert was a false positive.

4. **Update incident:** Add comment noting the false positive and reversal actions.

## Testing Checklist

> For Carver (Detection/Validation Engineer) to verify before production deployment.

- [ ] **Trigger test:** Create a test DLP incident in Sentinel → playbook triggers within 60 seconds
- [ ] **User enrichment:** Verify user profile, manager, department, and job title are correctly pulled from Entra ID
- [ ] **Risk level check:** Test with a user flagged as high-risk in Identity Protection → risk level appears in enrichment
- [ ] **VIP detection:** Test with a user in the VIP group → VIP flag reflected in severity score
- [ ] **High severity path:** Sensitivity label = "Highly Confidential" + external target → sharing blocked, manager notified, incident escalated
- [ ] **Medium severity path:** Sensitivity label = "Confidential" + internal target → manager notified, no block, incident stays active
- [ ] **Low severity path:** Sensitivity label = "General" + internal → auto-closed with informational classification
- [ ] **Manager notification:** Verify Teams message sent to correct manager with accurate details
- [ ] **Incident enrichment:** Confirm structured comment with user context, DLP details, and actions taken
- [ ] **Error handling:** Simulate Graph API failure → playbook adds error comment, does NOT auto-close
- [ ] **Rollback:** After test, successfully restore blocked sharing permissions and update incident

## Related Skills

- [Compromised Account](./compromised-account.md) — if exfiltration is paired with compromised credentials
- [Teams Notification](./teams-notification.md) — reusable notification patterns for manager alerts
- [Sentinel Enrichment — User](./sentinel-enrichment-user.md) — standalone user enrichment that this playbook builds on
