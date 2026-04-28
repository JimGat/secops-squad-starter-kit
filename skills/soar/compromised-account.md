---
title: "Compromised Account Auto-Response"
category: soar
difficulty: advanced
trigger_type: sentinel-incident
products:
  - Microsoft Sentinel
  - Entra ID
  - Entra ID Protection
  - Microsoft Graph
  - Microsoft Teams
api_connections:
  - azuresentinel
  - azuread
  - teams
author: Herc
version: 1.0.0
mitre_attack:
  - T1078    # Valid Accounts
  - T1078.004 # Cloud Accounts
  - T1110    # Brute Force
  - T1110.003 # Password Spraying
---

# Compromised Account Auto-Response

## Overview

This playbook automates the containment and remediation of compromised user accounts. It is triggered by a Sentinel incident linked to identity-based analytics rules or Entra ID Protection risk events (high-risk user/sign-in detections).

**Business justification:** A compromised account is an attacker's golden ticket — lateral movement, data exfiltration, and persistence all start here. The first 5 minutes after detection are critical. Manual response (find user → check risk → revoke sessions → reset password → notify manager) takes 20+ minutes per incident. This playbook executes the full containment sequence in under 30 seconds, stopping the attacker before they pivot.

**What it does:**
1. Extracts the compromised account entity from the Sentinel incident
2. Pulls the user's profile, risk level, recent sign-in activity, and manager from Graph API
3. Applies a tiered response based on risk level:
   - **High risk:** Block sign-ins + revoke all sessions + force password reset + require MFA re-registration
   - **Medium risk:** Revoke sessions + require MFA challenge on next sign-in
   - **Low risk:** Notify user and manager, add monitoring tag
4. Updates the Sentinel incident with enrichment findings and actions taken
5. Sends a Teams notification to the SOC channel and the user's manager

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Sentinel Incident Created                                       │
│  OR Entra ID Protection Risk Event (via Analytics Rule)          │
└──────────────┬───────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────┐
│  1. Extract Account      │
│  Get UPN from incident   │
│  entities                │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐     ┌─────────────────────────┐
│  2. Enrich User Profile  │────▶│  Microsoft Graph API    │
│  - User details          │     │  - /users/{id}          │
│  - Risk detections       │     │  - /riskyUsers/{id}     │
│  - Recent sign-ins       │     │  - /auditLogs/signIns   │
│  - Manager info          │     │  - /users/{id}/manager  │
└──────────┬───────────────┘     └─────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────┐
│  3. Risk-Based Response                  │
├──────────┬──────────────┬────────────────┤
│  HIGH    │  MEDIUM      │  LOW           │
│          │              │                │
│ Block    │ Revoke       │ Notify user    │
│ sign-ins │ sessions     │ & manager      │
│          │              │                │
│ Revoke   │ Require MFA  │ Add monitoring │
│ sessions │ challenge    │ tag            │
│          │              │                │
│ Force    │ Notify       │                │
│ password │ manager      │                │
│ reset    │              │                │
│          │              │                │
│ Require  │              │                │
│ MFA re-  │              │                │
│ register │              │                │
└──────────┴──────────────┴────────────────┘
               │
               ▼
┌──────────────────────────┐
│  4. Update & Notify      │
│  - Sentinel comment      │
│  - Teams SOC channel     │
│  - Manager notification  │
│  - User email (recovery) │
└──────────────────────────┘
```

## Prerequisites

### API Connections

| Connection          | Purpose                                    | Auth Method         |
|---------------------|--------------------------------------------|---------------------|
| `azuresentinel`     | Read/update incidents                      | Managed Identity    |
| `azuread`           | User management, risk remediation          | Managed Identity    |
| `teams`             | SOC and manager notifications              | Managed Identity    |

### Required Permissions

| Permission                        | Type        | Justification                              |
|-----------------------------------|-------------|--------------------------------------------|
| `Microsoft Sentinel Responder`    | Azure RBAC  | Update incidents, run playbooks            |
| `User.ReadWrite.All`              | Application | Read user profile, block/unblock sign-in   |
| `Directory.ReadWrite.All`         | Application | Force password reset, manage auth methods  |
| `UserAuthenticationMethod.ReadWrite.All` | Application | Reset MFA methods                    |
| `SecurityEvents.ReadWrite.All`    | Application | Read risk detections, dismiss risks        |
| `IdentityRiskyUser.ReadWrite.All` | Application | Confirm/dismiss user risk                  |
| `AuditLog.Read.All`              | Application | Read sign-in logs for enrichment           |
| `ChannelMessage.Send`            | Application | Post to Teams SOC channel                  |
| `Mail.Send`                      | Application | Send recovery instructions to user         |

### Managed Identity Setup

```bash
# Enable system-assigned managed identity
az logic workflow identity assign \
  --resource-group rg-soc-automation \
  --name la-compromised-account \
  --system-assigned

# Grant Sentinel Responder
az role assignment create \
  --assignee <logic-app-principal-id> \
  --role "Microsoft Sentinel Responder" \
  --scope /subscriptions/<sub>/resourceGroups/rg-soc/providers/Microsoft.OperationalInsights/workspaces/law-soc

# Grant Graph API permissions (requires Global Admin consent)
az ad app permission add \
  --id <app-id> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions \
    User.ReadWrite.All=Role \
    Directory.ReadWrite.All=Role \
    UserAuthenticationMethod.ReadWrite.All=Role \
    SecurityEvents.ReadWrite.All=Role \
    IdentityRiskyUser.ReadWrite.All=Role \
    AuditLog.Read.All=Role \
    ChannelMessage.Send=Role \
    Mail.Send=Role
```

> ⚠️ **Warning:** `Directory.ReadWrite.All` is a high-privilege permission. Apply conditional access policies to the managed identity and ensure the Logic App resource group has strict RBAC. Consider using `User.ReadWrite.All` + `UserAuthenticationMethod.ReadWrite.All` as a narrower alternative if your Entra ID configuration allows it.

## Logic Apps Design

### Trigger

**Type:** `Microsoft Sentinel incident`

The incident should originate from analytics rules such as:
- "Entra ID Protection - User risk level changed to High"
- "Multiple failed sign-in attempts followed by success"
- "Sign-in from unfamiliar location after password spray"
- "Impossible travel detection"

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

### Step 1: Extract Account Entity

**Action:** `Entities - Get Accounts`

```json
{
  "Entities_-_Get_Accounts": {
    "type": "ApiConnection",
    "inputs": {
      "host": {
        "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" }
      },
      "method": "post",
      "path": "/entities/account",
      "body": "@triggerBody()?['object']?['properties']?['relatedEntities']"
    }
  }
}
```

Extract the User Principal Name (UPN) or Azure AD Object ID from the first account entity:
```
variables('userUPN') = body('Entities_-_Get_Accounts')?['Accounts']?[0]?['Name']
  + '@'
  + body('Entities_-_Get_Accounts')?['Accounts']?[0]?['UPNSuffix']
```

**Guard clause:** If no account entity is found, add a comment to the incident ("No account entity found — manual triage required") and terminate.

### Step 2: Enrich User Profile

#### 2a. Get User Details

**Action:** `HTTP` — Microsoft Graph

```
GET https://graph.microsoft.com/v1.0/users/{userUPN}
  ?$select=id,displayName,mail,jobTitle,department,accountEnabled,
           createdDateTime,lastPasswordChangeDateTime,
           onPremisesSyncEnabled
```

#### 2b. Get User Risk Level

**Action:** `HTTP` — Microsoft Graph (Entra ID Protection)

```
GET https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/{userId}
  ?$select=riskLevel,riskState,riskDetail,riskLastUpdatedDateTime
```

Map risk level to response tier:
- `high` → Full containment
- `medium` → Session revocation + MFA challenge
- `low` / `none` → Notify only
- If the risky user endpoint returns 404 (user not in risky users list), fall back to the incident severity.

#### 2c. Get Recent Sign-In Activity

**Action:** `HTTP` — Microsoft Graph

```
GET https://graph.microsoft.com/v1.0/auditLogs/signIns
  ?$filter=userId eq '{userId}' and createdDateTime ge {last24hours}
  &$top=20
  &$orderby=createdDateTime desc
  &$select=createdDateTime,ipAddress,location,status,
           clientAppUsed,deviceDetail,riskLevelDuringSignIn,
           conditionalAccessStatus
```

Parse for anomalies:
- Sign-ins from unusual countries
- Multiple failed attempts before a success
- Legacy auth protocol usage (IMAP, POP3, SMTP)
- Sign-ins from TOR exit nodes or known VPN providers

#### 2d. Get Manager

**Action:** `HTTP` — Microsoft Graph

```
GET https://graph.microsoft.com/v1.0/users/{userId}/manager
  ?$select=id,displayName,mail
```

Store the manager's email for notification in step 4.

### Step 3: Risk-Based Response

**Action:** `Switch` on risk level

```json
{
  "Switch_Risk_Level": {
    "type": "Switch",
    "expression": "@variables('riskLevel')",
    "cases": {
      "High": {
        "case": "high",
        "actions": {
          "Block_Sign_Ins": { "..." : "..." },
          "Revoke_Sessions": { "..." : "..." },
          "Force_Password_Reset": { "..." : "..." },
          "Require_MFA_Reregistration": { "..." : "..." }
        }
      },
      "Medium": {
        "case": "medium",
        "actions": {
          "Revoke_Sessions": { "..." : "..." },
          "Set_MFA_Challenge": { "..." : "..." }
        }
      }
    },
    "default": {
      "actions": {
        "Notify_Only": { "..." : "..." }
      }
    }
  }
}
```

#### 3a. Block Sign-Ins (High Risk)

**Action:** `HTTP` — PATCH user

```
PATCH https://graph.microsoft.com/v1.0/users/{userId}
Content-Type: application/json

{
  "accountEnabled": false
}
```

#### 3b. Revoke All Sessions (High + Medium Risk)

**Action:** `HTTP` — POST revoke sessions

```
POST https://graph.microsoft.com/v1.0/users/{userId}/revokeSignInSessions
```

This invalidates all refresh tokens and session cookies. The user must re-authenticate on all devices.

#### 3c. Force Password Reset (High Risk)

**Action:** `HTTP` — PATCH user with `passwordProfile`

```
PATCH https://graph.microsoft.com/v1.0/users/{userId}
Content-Type: application/json

{
  "passwordProfile": {
    "forceChangePasswordNextSignIn": true,
    "forceChangePasswordNextSignInWithMfa": true
  }
}
```

> **Note:** This does NOT set a temporary password. The user must use Self-Service Password Reset (SSPR). Verify SSPR is enabled in your tenant before deploying this playbook.

#### 3d. Require MFA Re-Registration (High Risk)

**Action:** `HTTP` — Delete registered authentication methods (forces re-registration)

Only do this if the account may have had its MFA methods tampered with (e.g., attacker registered a new phone number):

```
GET https://graph.microsoft.com/v1.0/users/{userId}/authentication/methods
```

Then for each suspicious method:
```
DELETE https://graph.microsoft.com/v1.0/users/{userId}/authentication/phoneMethods/{id}
```

> ⚠️ **Caution:** Only remove methods that were recently added (check `createdDateTime`). Do not remove all MFA methods — leave at least one trusted method or the user will be locked out of SSPR.

#### 3e. Confirm User Risk (Entra ID Protection)

After containment, mark the user risk as confirmed compromised:

```
POST https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/confirmCompromised
Content-Type: application/json

{
  "userIds": ["{userId}"]
}
```

### Step 4: Update Incident & Notify

#### 4a. Update Sentinel Incident

**Action:** `Microsoft Sentinel - Update incident`

```json
{
  "Update_incident": {
    "type": "ApiConnection",
    "inputs": {
      "body": {
        "incidentArmId": "@triggerBody()?['object']?['id']",
        "severity": "@if(equals(variables('riskLevel'), 'high'), 'High', if(equals(variables('riskLevel'), 'medium'), 'Medium', 'Low'))",
        "status": "Active",
        "tagsToAdd": [
          "compromised-account",
          "auto-contained",
          "@{variables('riskLevel')}-risk"
        ],
        "ownerAction": "Assign",
        "owner": {
          "objectId": "<tier2-analyst-group-id>"
        }
      }
    }
  }
}
```

**Action:** `Microsoft Sentinel - Add comment`

```
## Automated Compromise Response Report
**User:** @{variables('userDisplayName')} (@{variables('userUPN')})
**Risk Level:** @{variables('riskLevel')}
**Department:** @{variables('userDepartment')}
**Manager:** @{variables('managerDisplayName')}

### Recent Sign-In Activity (Last 24h)
@{body('Format_SignIn_Summary')}

### Actions Taken
@{if(equals(variables('riskLevel'), 'high'),
  '- ☑ Account sign-in blocked\n- ☑ All sessions revoked\n- ☑ Password reset forced (SSPR required)\n- ☑ User risk confirmed in Entra ID Protection\n- ☑ Manager notified\n- ☑ SOC channel notified',
  if(equals(variables('riskLevel'), 'medium'),
    '- ☑ All sessions revoked\n- ☑ MFA challenge required on next sign-in\n- ☑ Manager notified\n- ☑ SOC channel notified',
    '- ☑ User and manager notified\n- ☑ Monitoring tag applied')
)}

### Recovery Steps
User must: @{if(equals(variables('riskLevel'), 'high'),
  '1. Contact IT helpdesk to verify identity\n2. Reset password via SSPR\n3. Re-register MFA methods\n4. IT helpdesk re-enables sign-in',
  '1. Complete MFA challenge on next sign-in\n2. Review recent account activity'
)}
```

#### 4b. Teams SOC Notification

**Action:** `Microsoft Teams - Post message` (or HTTP to Graph API)

Send an adaptive card to the SOC channel (see the [teams-notification skill](./teams-notification.md) for full adaptive card patterns). Include:
- User display name and UPN
- Risk level badge (color-coded)
- Actions taken
- Link to Sentinel incident

#### 4c. Manager Email Notification

**Action:** `HTTP` — Send mail via Graph API

```
POST https://graph.microsoft.com/v1.0/users/{logic-app-service-account}/sendMail
Content-Type: application/json

{
  "message": {
    "subject": "Security Alert: @{variables('userDisplayName')}'s account has been flagged",
    "body": {
      "contentType": "HTML",
      "content": "<h2>Account Security Alert</h2><p>@{variables('userDisplayName')}'s account was flagged as @{variables('riskLevel')} risk...</p>"
    },
    "toRecipients": [
      { "emailAddress": { "address": "@{variables('managerEmail')}" } }
    ]
  }
}
```

### Error Handling

Wrap the entire response sequence in a **Scope** with error handling:

```json
{
  "Scope_Containment": {
    "type": "Scope",
    "actions": { "...all containment actions..." }
  },
  "Scope_Error_Handler": {
    "type": "Scope",
    "actions": {
      "Escalate_On_Failure": {
        "type": "ApiConnection",
        "inputs": {
          "body": {
            "message": "🚨 CRITICAL: Compromised account playbook FAILED for @{variables('userUPN')}. Manual containment required IMMEDIATELY. Error: @{result('Scope_Containment')?['error']?['message']}"
          }
        }
      }
    },
    "runAfter": {
      "Scope_Containment": ["Failed", "TimedOut"]
    }
  }
}
```

**Critical failure behavior:** If the containment scope fails, this is a P1 situation. The error handler must:
1. Post an URGENT message to the SOC Teams channel
2. Send an email to the on-call distribution list
3. Keep the incident Active at High severity
4. Tag with `containment-failed`

### Retry Patterns

All Graph API calls should use exponential retry:

```json
{
  "retryPolicy": {
    "type": "exponential",
    "count": 3,
    "interval": "PT10S",
    "minimumInterval": "PT5S",
    "maximumInterval": "PT5M"
  }
}
```

For the `Block_Sign_Ins` and `Revoke_Sessions` actions specifically, use **aggressive retry** (these are the most critical):

```json
{
  "retryPolicy": {
    "type": "fixed",
    "count": 5,
    "interval": "PT5S"
  }
}
```

## Bicep Template Reference

```bicep
@description('Compromised Account Auto-Response Playbook')
param location string = resourceGroup().location
param workspaceName string
param workspaceResourceGroup string
param socTeamChannelId string
param tier2GroupObjectId string

var playbookName = 'la-compromised-account'
var sentinelConnectionName = 'azuresentinel-${playbookName}'
var azureAdConnectionName = 'azuread-${playbookName}'
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

resource azureAdConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: azureAdConnectionName
  location: location
  kind: 'V1'
  properties: {
    displayName: azureAdConnectionName
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
        socTeamChannelId: {
          defaultValue: socTeamChannelId
          type: 'String'
        }
        tier2GroupObjectId: {
          defaultValue: tier2GroupObjectId
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
          azuread: {
            connectionId: azureAdConnection.id
            connectionName: azureAdConnectionName
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuread')
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
  --name la-compromised-account \
  --state Disabled

# 2. Wait for in-flight runs to complete
az logic workflow run list \
  --resource-group rg-soc-automation \
  --workflow-name la-compromised-account \
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
  --name la-compromised-account --yes

az resource delete --ids <sentinel-connection-resource-id>
az resource delete --ids <azuread-connection-resource-id>
az resource delete --ids <teams-connection-resource-id>
```

### Reverse Containment Actions

If the playbook acted on a false positive, perform these steps in order:

#### 1. Re-Enable Sign-In

```
PATCH https://graph.microsoft.com/v1.0/users/{userId}
{
  "accountEnabled": true
}
```

Or via CLI:
```bash
az ad user update --id {userUPN} --account-enabled true
```

#### 2. Dismiss User Risk

```
POST https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/dismiss
{
  "userIds": ["{userId}"]
}
```

#### 3. User Self-Recovery

The user must:
1. Reset their password via SSPR (the forced reset flag is already set)
2. Re-register MFA methods at https://aka.ms/mfasetup
3. Sign in on all devices (sessions were revoked)

#### 4. Verify Recovery

```bash
# Check user can sign in
az ad user show --id {userUPN} --query "accountEnabled"

# Check risk state is remediated
# (via Graph API or Entra ID Protection portal)
```

## Testing Checklist

> For Carver to verify before production deployment.

- [ ] **Trigger test:** Create a test incident with account entity → playbook triggers and extracts UPN correctly
- [ ] **User enrichment:** Verify Graph API calls return user profile, risk level, sign-in history, and manager
- [ ] **High risk path:** Set test user risk to `high` → account blocked, sessions revoked, password reset forced, manager notified
- [ ] **Medium risk path:** Set test user risk to `medium` → sessions revoked, MFA challenge set, account NOT blocked
- [ ] **Low risk path:** Set test user risk to `low` → only notifications sent, no containment actions
- [ ] **No account entity:** Create incident without account entity → playbook adds comment and terminates gracefully
- [ ] **Block sign-in:** Confirm `accountEnabled` is `false` after high-risk response
- [ ] **Session revocation:** Confirm user is forced to re-authenticate on all devices (test with an active session)
- [ ] **Password reset:** Confirm `forceChangePasswordNextSignIn` is `true` and user can reset via SSPR
- [ ] **Manager notification:** Verify manager receives email with correct user details and recovery instructions
- [ ] **SOC Teams notification:** Verify adaptive card posts to SOC channel with correct risk level and actions
- [ ] **Error handling:** Simulate Graph API failure → error handler fires, URGENT message sent to SOC channel
- [ ] **Idempotency:** Run playbook twice on same incident → second run detects user is already blocked, skips redundant actions
- [ ] **Rollback test:** Re-enable account, dismiss risk, verify user can sign in and access resources normally
- [ ] **Break-glass exclusion:** Verify break-glass/emergency accounts are excluded from automated blocking
- [ ] **On-prem sync:** If user is synced from on-prem AD, verify playbook handles the `onPremisesSyncEnabled=true` case (cannot reset password via Graph for synced users)

## Tuning Guide

### Common Customizations

| Parameter                    | Default          | Tuning Notes                                              |
|------------------------------|------------------|-----------------------------------------------------------|
| High-risk action             | Block + revoke + reset | Some orgs prefer revoke-only for high risk; add a parameter to control |
| Medium-risk action           | Revoke + MFA     | Upgrade to block if you see lateral movement from medium-risk accounts |
| Low-risk action              | Notify only      | Add session revocation for low risk if your org is targeted frequently |
| Manager notification         | Always           | Disable for automated service accounts                    |
| Break-glass exclusion list   | Empty            | **MUST** add your emergency access accounts here          |
| Risk level source            | Entra ID Protection | Fall back to incident severity if Identity Protection is not licensed |
| MFA method cleanup           | Disabled         | Enable only if attacker is registering new MFA methods    |
| Sign-in history window       | 24 hours         | Extend to 72h for slow-and-low attacks                    |

### Break-Glass Account Exclusion

**This is mandatory.** Add a condition at the start of the playbook:

```json
{
  "Condition_Break_Glass": {
    "type": "If",
    "expression": {
      "not": {
        "contains": [
          "@parameters('breakGlassAccounts')",
          "@variables('userUPN')"
        ]
      }
    },
    "actions": { "...continue playbook..." },
    "else": {
      "actions": {
        "Add_Comment_Break_Glass": {
          "inputs": {
            "body": { "message": "⚠️ Break-glass account detected. Skipping automated response. Manual investigation required." }
          }
        },
        "Terminate_Break_Glass": {
          "type": "Terminate",
          "inputs": { "runStatus": "Succeeded" }
        }
      }
    }
  }
}
```

### VIP / Executive Handling

Add a `Condition` to check if the user is in a VIP group:

```
GET https://graph.microsoft.com/v1.0/groups/{vip-group-id}/members/$count
  ?$filter=id eq '{userId}'
```

If VIP: escalate to Tier 3 immediately regardless of risk level, and send notification to CISO distribution list.

### On-Premises Synced Accounts

If `onPremisesSyncEnabled` is `true`, the playbook cannot:
- Reset the password via Graph API (must be done on-prem AD)
- Some user properties are read-only

Add a condition to detect synced users and:
1. Still revoke cloud sessions and block sign-in (these work for synced users)
2. Send an alert to the on-prem AD team to reset the password on-prem
3. Add incident comment noting on-prem password reset is required
