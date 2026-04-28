---
title: "Sentinel Enrichment — User Account Context"
category: soar
difficulty: intermediate
trigger_type: sentinel-entity
products:
  - Microsoft Sentinel
  - Entra ID
api_connections:
  - azuresentinel
  - azuread
author: Herc
version: 1.0.0
last_updated: 2026-04-28
mitre_attack:
  - T1078  # Valid Accounts
  - T1110  # Brute Force
  - T1136  # Create Account
  - T1098  # Account Manipulation
---

# Sentinel Enrichment — User Account Context

## Overview

This playbook enriches user/account entities attached to Sentinel incidents with identity context from Microsoft Entra ID. It pulls the user's profile, manager chain, department, risk level, group memberships, recent MFA changes, and sign-in activity — then writes a structured enrichment comment to the incident.

**Business justification:** User context is critical for incident triage. Is this a VIP executive or a service account? Is the user already flagged as risky? Did they recently change MFA methods? Analysts spend 3-5 minutes per user manually querying Entra ID, Identity Protection, and audit logs. This playbook delivers instant, consistent enrichment that helps analysts make faster, better-informed triage decisions.

**What it does:**
1. Receives a user/account entity from a Sentinel incident
2. Pulls full Entra ID profile (title, department, office, manager)
3. Checks Identity Protection risk level and risk detections
4. Retrieves group memberships (especially privileged role groups)
5. Checks for recent MFA registration changes (last 7 days)
6. Pulls last interactive sign-in details
7. Updates the incident with a structured enrichment comment

**This is a read-only enrichment playbook — no remediation actions are taken.**

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Microsoft Sentinel                            │
│  Incident with account entity → Entity trigger fires            │
└──────────────┬───────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────┐
│  1. Extract Account      │
│  UPN or AAD Object ID    │
└──────────┬───────────────┘
               │
               ├──────────────────────────────────┐
               ▼                                  ▼
┌──────────────────────────┐     ┌──────────────────────────┐
│  2a. User Profile        │     │  2b. Risk Assessment     │
│  - Display name          │     │  - Risk level            │
│  - Title / Department    │     │  - Risk state            │
│  - Manager               │     │  - Risk detections       │
│  - Account enabled?      │     │  - Last risk update      │
│  - Created date          │     └──────────┬───────────────┘
└──────────┬───────────────┘                │
               │                             │
               ├─────────────────────────────┘
               ▼
┌──────────────────────────┐
│  3. Group Memberships    │
│  - Directory roles       │
│  - Security groups       │
│  - Privileged access?    │
└──────────┬───────────────┘
               │
               ▼
┌──────────────────────────┐
│  4. Recent MFA Changes   │
│  - MFA method registered │
│  - MFA method deleted    │
│  - Last 7 days           │
└──────────┬───────────────┘
               │
               ▼
┌──────────────────────────┐
│  5. Last Sign-In         │
│  - Last interactive      │
│  - IP / location         │
│  - Device / browser      │
└──────────┬───────────────┘
               │
               ▼
┌──────────────────────────┐
│  6. Update Incident      │
│  - Structured comment    │
│  - Tags                  │
└──────────────────────────┘
```

## Prerequisites

### API Connections

| Connection          | Purpose                                    | Auth Method           |
|---------------------|--------------------------------------------|-----------------------|
| `azuresentinel`     | Read entities, update incidents            | Managed Identity      |
| `azuread`           | User profile, risk, groups, audit logs     | Managed Identity      |

### Required Permissions

| Permission                              | Type        | Justification                       |
|-----------------------------------------|-------------|-------------------------------------|
| `Microsoft Sentinel Responder`          | Azure RBAC  | Update incidents, add comments      |
| `User.Read.All`                         | Application | Read user profiles and managers     |
| `IdentityRiskyUser.Read.All`            | Application | Read user risk levels               |
| `IdentityRiskEvent.Read.All`            | Application | Read risk detection events          |
| `GroupMember.Read.All`                   | Application | Read group memberships              |
| `AuditLog.Read.All`                     | Application | Read MFA registration audit logs    |
| `Directory.Read.All`                    | Application | Read directory role assignments     |
| `SignInLog.Read.All`                    | Delegated   | Read sign-in activity (if needed)   |

### Managed Identity Setup

```bash
# Enable system-assigned managed identity
az logic workflow identity assign \
  --resource-group rg-soc-automation \
  --name la-enrich-user \
  --system-assigned

# Grant Sentinel Responder on the workspace
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
    IdentityRiskEvent.Read.All=Role \
    GroupMember.Read.All=Role \
    AuditLog.Read.All=Role \
    Directory.Read.All=Role
```

## Logic Apps Design

### Trigger

**Type:** `Microsoft Sentinel entity` (account)
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

The entity trigger receives the account in `triggerBody()?['Entity']?['properties']`. Extract the UPN from `upnSuffix` + `accountName` or use `aadUserId` for direct lookup.

### Step 1: Extract Account Identifier

**Action:** `Initialize variable` + `Compose`

```json
{
  "Initialize_UPN": {
    "type": "InitializeVariable",
    "inputs": {
      "variables": [{
        "name": "user_upn",
        "type": "string",
        "value": "@{triggerBody()?['Entity']?['properties']?['accountName']}@{triggerBody()?['Entity']?['properties']?['upnSuffix']}"
      }]
    }
  },
  "Initialize_AAD_ID": {
    "type": "InitializeVariable",
    "inputs": {
      "variables": [{
        "name": "aad_user_id",
        "type": "string",
        "value": "@{coalesce(triggerBody()?['Entity']?['properties']?['aadUserId'], '')}"
      }]
    }
  }
}
```

Use `aad_user_id` if available (more reliable), fall back to `user_upn`.

### Step 2a: User Profile and Manager

**Action:** `HTTP` — Microsoft Graph API

```json
{
  "Get_User_Profile": {
    "type": "Http",
    "inputs": {
      "method": "GET",
      "uri": "https://graph.microsoft.com/v1.0/users/@{if(not(empty(variables('aad_user_id'))), variables('aad_user_id'), variables('user_upn'))}?$select=displayName,userPrincipalName,jobTitle,department,officeLocation,accountEnabled,createdDateTime,lastPasswordChangeDateTime&$expand=manager($select=displayName,mail,jobTitle)",
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://graph.microsoft.com"
      }
    },
    "retryPolicy": {
      "type": "exponential",
      "count": 3,
      "interval": "PT20S"
    }
  }
}
```

### Step 2b: Risk Assessment

**Action:** `HTTP` — Identity Protection

```json
{
  "Get_User_Risk": {
    "type": "Http",
    "inputs": {
      "method": "GET",
      "uri": "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$filter=userPrincipalName eq '@{variables('user_upn')}'",
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://graph.microsoft.com"
      }
    }
  }
}
```

Also fetch recent risk detections:
```json
{
  "Get_Risk_Detections": {
    "type": "Http",
    "inputs": {
      "method": "GET",
      "uri": "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$filter=userPrincipalName eq '@{variables('user_upn')}' and detectedDateTime ge @{addDays(utcNow(), -30)}&$top=10&$orderby=detectedDateTime desc",
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://graph.microsoft.com"
      }
    }
  }
}
```

### Step 3: Group Memberships

**Action:** `HTTP` — get transitive memberships, flag privileged roles

```json
{
  "Get_Group_Memberships": {
    "type": "Http",
    "inputs": {
      "method": "GET",
      "uri": "https://graph.microsoft.com/v1.0/users/@{variables('user_upn')}/transitiveMemberOf?$select=displayName,id,@odata.type&$top=100",
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://graph.microsoft.com"
      }
    }
  }
}
```

Flag if user is a member of privileged directory roles:
- Global Administrator
- Privileged Authentication Administrator
- Exchange Administrator
- Security Administrator
- User Administrator

```json
{
  "Check_Privileged_Roles": {
    "type": "Compose",
    "inputs": {
      "is_privileged": "@contains(string(body('Get_Group_Memberships')?['value']), 'Global Administrator')",
      "roles": "@intersection(
        createArray('Global Administrator', 'Privileged Authentication Administrator', 'Security Administrator', 'Exchange Administrator', 'User Administrator'),
        @body('Filter_Directory_Roles')
      )"
    }
  }
}
```

### Step 4: Recent MFA Changes

**Action:** `HTTP` — query Entra ID audit logs for MFA registration events

```json
{
  "Get_MFA_Changes": {
    "type": "Http",
    "inputs": {
      "method": "GET",
      "uri": "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=targetResources/any(t:t/userPrincipalName eq '@{variables('user_upn')}') and activityDisplayName eq 'User registered security info' and activityDateTime ge @{addDays(utcNow(), -7)}&$top=10&$orderby=activityDateTime desc",
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://graph.microsoft.com"
      }
    }
  }
}
```

Also check for MFA method deletions:
```json
{
  "Get_MFA_Deletions": {
    "type": "Http",
    "inputs": {
      "method": "GET",
      "uri": "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=targetResources/any(t:t/userPrincipalName eq '@{variables('user_upn')}') and activityDisplayName eq 'User deleted security info' and activityDateTime ge @{addDays(utcNow(), -7)}&$top=10",
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://graph.microsoft.com"
      }
    }
  }
}
```

> **Red flag:** An MFA method deletion followed by a new MFA registration within minutes is a strong indicator of MFA fatigue or account takeover.

### Step 5: Last Sign-In Details

**Action:** `HTTP` — query sign-in logs

```json
{
  "Get_Last_SignIn": {
    "type": "Http",
    "inputs": {
      "method": "GET",
      "uri": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=userPrincipalName eq '@{variables('user_upn')}'&$top=1&$orderby=createdDateTime desc",
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://graph.microsoft.com"
      }
    }
  }
}
```

Extract: IP address, location, device, browser, conditional access status.

### Step 6: Update Incident Comment

**Action:** `Microsoft Sentinel - Add comment`

```
## User Enrichment Report: @{body('Get_User_Profile')?['displayName']}

### Identity
- **UPN:** @{variables('user_upn')}
- **Title:** @{body('Get_User_Profile')?['jobTitle']}
- **Department:** @{body('Get_User_Profile')?['department']}
- **Office:** @{body('Get_User_Profile')?['officeLocation']}
- **Manager:** @{body('Get_User_Profile')?['manager']?['displayName']} (@{body('Get_User_Profile')?['manager']?['mail']})
- **Account enabled:** @{body('Get_User_Profile')?['accountEnabled']}
- **Created:** @{body('Get_User_Profile')?['createdDateTime']}
- **Last password change:** @{body('Get_User_Profile')?['lastPasswordChangeDateTime']}

### Risk Assessment
- **Risk level:** @{coalesce(body('Get_User_Risk')?['value']?[0]?['riskLevel'], 'none')} @{if(or(equals(body('Get_User_Risk')?['value']?[0]?['riskLevel'], 'high'), equals(body('Get_User_Risk')?['value']?[0]?['riskLevel'], 'medium')), '⚠️', '✅')}
- **Risk state:** @{coalesce(body('Get_User_Risk')?['value']?[0]?['riskState'], 'none')}
- **Recent risk detections (30d):** @{length(body('Get_Risk_Detections')?['value'])}

### Privileged Access
- **Privileged role member:** @{if(variables('is_privileged'), '⚠️ YES', '✅ No')}
- **Directory roles:** @{body('Format_Roles_List')}
- **Total group memberships:** @{length(body('Get_Group_Memberships')?['value'])}

### MFA Activity (Last 7 Days)
- **MFA methods registered:** @{length(body('Get_MFA_Changes')?['value'])} @{if(greater(length(body('Get_MFA_Changes')?['value']), 0), '⚠️ Recent MFA change', '')}
- **MFA methods deleted:** @{length(body('Get_MFA_Deletions')?['value'])} @{if(greater(length(body('Get_MFA_Deletions')?['value']), 0), '🚨 MFA method removed!', '')}

### Last Sign-In
- **Time:** @{body('Get_Last_SignIn')?['value']?[0]?['createdDateTime']}
- **IP:** @{body('Get_Last_SignIn')?['value']?[0]?['ipAddress']}
- **Location:** @{body('Get_Last_SignIn')?['value']?[0]?['location']?['city']}, @{body('Get_Last_SignIn')?['value']?[0]?['location']?['countryOrRegion']}
- **Device:** @{body('Get_Last_SignIn')?['value']?[0]?['deviceDetail']?['displayName']}
- **Browser:** @{body('Get_Last_SignIn')?['value']?[0]?['deviceDetail']?['browser']}
```

Add tags based on findings:
```json
{
  "Update_incident_tags": {
    "type": "ApiConnection",
    "inputs": {
      "body": {
        "incidentArmId": "@triggerBody()?['IncidentArmId']",
        "tagsToAdd": "@union(
          createArray('user-enriched'),
          if(variables('is_privileged'), createArray('privileged-user'), createArray()),
          if(or(equals(body('Get_User_Risk')?['value']?[0]?['riskLevel'], 'high'), equals(body('Get_User_Risk')?['value']?[0]?['riskLevel'], 'medium')), createArray('risky-user'), createArray()),
          if(greater(length(body('Get_MFA_Deletions')?['value']), 0), createArray('mfa-change'), createArray())
        )"
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
            "message": "⚠️ User enrichment playbook error for @{variables('user_upn')}: @{result('Scope_Enrichment')?['error']?['message']}. Partial results may be available."
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

## Bicep Template Reference

```bicep
@description('Sentinel User Enrichment SOAR Playbook')
param location string = resourceGroup().location
param workspaceName string
param workspaceResourceGroup string

var playbookName = 'la-enrich-user'
var sentinelConnectionName = 'azuresentinel-${playbookName}'
var azureadConnectionName = 'azuread-${playbookName}'

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
  --name la-enrich-user \
  --state Disabled

# 2. Wait for in-flight runs
az logic workflow run list \
  --resource-group rg-soc-automation \
  --workflow-name la-enrich-user \
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
  --name la-enrich-user --yes

az resource delete --ids <sentinel-connection-resource-id>
az resource delete --ids <azuread-connection-resource-id>
```

### Reverse Actions

This is a **read-only enrichment playbook** — no remediation actions are taken. No reversal is needed beyond removing the automation itself. Incident comments added by this playbook are informational and do not need to be removed.

## Testing Checklist

> For Carver (Detection/Validation Engineer) to verify before production deployment.

- [ ] **Trigger test:** Run playbook on a test incident with account entity → playbook triggers and processes the user
- [ ] **User profile:** Verify displayName, title, department, manager are correctly pulled from Entra ID
- [ ] **Service account handling:** Submit a service account entity → playbook handles missing manager/department gracefully
- [ ] **Risk level:** Test with a user flagged as high-risk → risk level and state appear in enrichment
- [ ] **Risk detections:** Test with a user who has recent risk events → detections listed with types and dates
- [ ] **Group memberships:** Verify group list includes directory roles and security groups
- [ ] **Privileged role detection:** Test with a Global Admin → `privileged-user` tag added to incident
- [ ] **MFA registration check:** Register a new MFA method on test user → audit event detected within 7-day window
- [ ] **MFA deletion detection:** Delete an MFA method → playbook flags the deletion with 🚨 indicator
- [ ] **Last sign-in:** Verify last sign-in IP, location, device, and browser are populated
- [ ] **Incident tags:** Confirm correct tags applied (`user-enriched`, `privileged-user`, `risky-user`, `mfa-change` as applicable)
- [ ] **Error handling:** Simulate Graph API failure → playbook adds error comment, doesn't crash
- [ ] **Non-existent user:** Submit an entity for a deleted/non-existent user → playbook handles 404 gracefully

## Related Skills

- [Sentinel Enrichment — IP](./sentinel-enrichment-ip.md) — companion enrichment for IP address entities
- [Compromised Account](./compromised-account.md) — uses user enrichment data to decide remediation actions
- [Data Exfiltration Response](./data-exfiltration-response.md) — enriches user context for DLP alerts
