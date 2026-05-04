// ============================================================================
// Compromised Account Response Playbook — Logic App (Consumption)
// Sentinel-triggered playbook that revokes sessions, forces MFA,
// conditionally disables accounts, and notifies the SOC via Teams.
// ============================================================================

// ── Phase 2 Integration ────────────────────────────────────────────────────
// Post-deployment: Configure Entra ID permissions and Sentinel automation rule.
// See skills/powershell/sentinel-api-wrapper.md § Automation Rules.
// See skills/powershell/defender-api-wrapper.md § Identity Protection for
// risky user remediation and session revocation APIs.
// See skills/powershell/rate-limiting.md § Microsoft Graph API for
// Entra ID throttling (10,000 req/10min per app per tenant).
//
// .secops/ context: Check identity/tenants.yaml for multi-tenant user lookups.
// Verify identity/rbac-conventions.yaml for account disable policy alignment.
// Check compliance/requirements.yaml for data residency before user actions.
//
// Post-deployment script:
//   ./scripts/Configure-SoarPlaybooks.ps1 -Playbook CompromisedAccount
//   Configures: Entra ID consent, Graph permissions, automation rule.
// ────────────────────────────────────────────────────────────────────────────

targetScope = 'resourceGroup'

// ── Parameters ──────────────────────────────────────────────────────────────

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Name of the Log Analytics workspace backing Microsoft Sentinel.')
param workspaceName string

@description('Resource group containing the Log Analytics workspace.')
param workspaceResourceGroup string = resourceGroup().name

@description('Minimum incident severity that triggers account disable. Allowed: High, Medium, Low, Informational.')
@allowed([ 'High', 'Medium', 'Low', 'Informational' ])
param riskThreshold string = 'High'

@description('Microsoft Teams channel ID for SOC notifications.')
param teamsChannelId string

@description('Teams team ID that owns the notification channel.')
param teamsTeamId string

@description('Name prefix for all resources.')
param namePrefix string = 'soar-compromised'

@description('Tags applied to every resource.')
param tags object = {
  solution: 'secops-squad'
  playbook: 'compromised-account'
  deployedBy: 'bicep'
}

// ── Variables ───────────────────────────────────────────────────────────────

var logicAppName = '${namePrefix}-${uniqueString(resourceGroup().id)}'
var sentinelConnectionName = '${namePrefix}-azuresentinel'
var entraConnectionName = '${namePrefix}-azuread'
var teamsConnectionName = '${namePrefix}-teams'

// ── Existing Resources ─────────────────────────────────────────────────────

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
  scope: resourceGroup(workspaceResourceGroup)
}

// ── Logic App ───────────────────────────────────────────────────────────────

resource logicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: logicAppName
  location: location
  tags: tags
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
        riskThreshold: {
          defaultValue: riskThreshold
          type: 'String'
        }
        teamsChannelId: {
          defaultValue: teamsChannelId
          type: 'String'
        }
        teamsTeamId: {
          defaultValue: teamsTeamId
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
      actions: {
        Get_incident: {
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            method: 'get'
            path: '/Incidents/subscriptions/@{encodeURIComponent(subscription().subscriptionId)}/resourceGroups/@{encodeURIComponent(resourceGroup().name)}/workspaces/@{encodeURIComponent(\'${workspaceName}\')}/incidents/@{encodeURIComponent(triggerBody()?[\'object\']?[\'properties\']?[\'incidentNumber\'])}'
          }
          runAfter: {}
        }
        Extract_user_entities: {
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/entities/subscriptions/@{encodeURIComponent(subscription().subscriptionId)}/resourceGroups/@{encodeURIComponent(resourceGroup().name)}/workspaces/@{encodeURIComponent(\'${workspaceName}\')}'
            body: '@triggerBody()?[\'object\']?[\'properties\']?[\'relatedEntities\']'
          }
          runAfter: {
            Get_incident: [ 'Succeeded' ]
          }
        }
        Filter_account_entities: {
          type: 'Query'
          inputs: {
            from: '@body(\'Extract_user_entities\')?[\'entities\']'
            where: '@equals(item()?[\'kind\'], \'Account\')'
          }
          runAfter: {
            Extract_user_entities: [ 'Succeeded' ]
          }
        }
        For_each_user: {
          type: 'Foreach'
          foreach: '@body(\'Filter_account_entities\')'
          actions: {
            Revoke_sessions: {
              type: 'ApiConnection'
              inputs: {
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azuread\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/v1.0/users/@{encodeURIComponent(items(\'For_each_user\')?[\'properties\']?[\'aadUserId\'])}/revokeSignInSessions'
              }
              runAfter: {}
            }
            Force_MFA_reregistration: {
              type: 'ApiConnection'
              inputs: {
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azuread\'][\'connectionId\']'
                  }
                }
                method: 'delete'
                path: '/v1.0/users/@{encodeURIComponent(items(\'For_each_user\')?[\'properties\']?[\'aadUserId\'])}/authentication/methods'
              }
              runAfter: {
                Revoke_sessions: [ 'Succeeded' ]
              }
            }
            Check_severity_for_disable: {
              type: 'If'
              expression: {
                or: [
                  {
                    equals: [
                      '@triggerBody()?[\'object\']?[\'properties\']?[\'severity\']'
                      'High'
                    ]
                  }
                  {
                    equals: [
                      '@triggerBody()?[\'object\']?[\'properties\']?[\'severity\']'
                      '@parameters(\'riskThreshold\')'
                    ]
                  }
                ]
              }
              actions: {
                Disable_account: {
                  type: 'ApiConnection'
                  inputs: {
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azuread\'][\'connectionId\']'
                      }
                    }
                    method: 'patch'
                    path: '/v1.0/users/@{encodeURIComponent(items(\'For_each_user\')?[\'properties\']?[\'aadUserId\'])}'
                    body: {
                      accountEnabled: false
                    }
                  }
                  runAfter: {}
                }
              }
              else: {
                actions: {}
              }
              runAfter: {
                Force_MFA_reregistration: [ 'Succeeded' ]
              }
            }
          }
          runAfter: {
            Filter_account_entities: [ 'Succeeded' ]
          }
        }
        Post_to_Teams: {
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'teams\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/v3/teams/@{encodeURIComponent(parameters(\'teamsTeamId\'))}/channels/@{encodeURIComponent(parameters(\'teamsChannelId\'))}/messages'
            body: {
              contentType: 'html'
              content: '<h3>🔑 Compromised Account Response</h3><p><strong>Incident:</strong> @{triggerBody()?[\'object\']?[\'properties\']?[\'title\']}</p><p><strong>Severity:</strong> @{triggerBody()?[\'object\']?[\'properties\']?[\'severity\']}</p><p><strong>Accounts affected:</strong> @{length(body(\'Filter_account_entities\'))}</p><p><strong>Actions taken:</strong> Sessions revoked, MFA reset enforced@{if(or(equals(triggerBody()?[\'object\']?[\'properties\']?[\'severity\'], \'High\'), equals(triggerBody()?[\'object\']?[\'properties\']?[\'severity\'], parameters(\'riskThreshold\'))), \', account disabled\', \'\')}</p>'
            }
          }
          runAfter: {
            For_each_user: [ 'Succeeded' ]
          }
        }
        Update_incident: {
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            method: 'put'
            path: '/Incidents/subscriptions/@{encodeURIComponent(subscription().subscriptionId)}/resourceGroups/@{encodeURIComponent(resourceGroup().name)}/workspaces/@{encodeURIComponent(\'${workspaceName}\')}'
            body: {
              incidentArmId: '@triggerBody()?[\'object\']?[\'id\']'
              status: 'Active'
              classification: 'TruePositive'
              classificationReason: 'SuspiciousActivity'
              tagsToAdd: [
                { Tag: 'automated-compromise-response' }
                { Tag: 'sessions-revoked' }
              ]
              severity: '@triggerBody()?[\'object\']?[\'properties\']?[\'severity\']'
            }
          }
          runAfter: {
            Post_to_Teams: [ 'Succeeded' ]
          }
        }
      }
      outputs: {}
    }
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: sentinelConnection.id
            connectionName: sentinelConnectionName
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
          }
          azuread: {
            connectionId: entraConnection.id
            connectionName: entraConnectionName
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuread')
          }
          teams: {
            connectionId: teamsConnection.id
            connectionName: teamsConnectionName
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'teams')
          }
        }
      }
    }
  }
}

// ── API Connections ─────────────────────────────────────────────────────────

resource sentinelConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: sentinelConnectionName
  location: location
  tags: tags
  properties: {
    displayName: sentinelConnectionName
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
    }
    parameterValueType: 'Alternative'
  }
  kind: 'V1'
}

resource entraConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: entraConnectionName
  location: location
  tags: tags
  properties: {
    displayName: entraConnectionName
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuread')
    }
  }
  kind: 'V1'
}

resource teamsConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: teamsConnectionName
  location: location
  tags: tags
  properties: {
    displayName: teamsConnectionName
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'teams')
    }
  }
  kind: 'V1'
}

// ── Role Assignments ────────────────────────────────────────────────────────

var sentinelResponderRoleId = 'ab8e14d6-4a74-4a29-9ba8-549422addade'

resource sentinelResponderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(logicApp.id, sentinelResponderRoleId, resourceGroup().id)
  scope: resourceGroup()
  properties: {
    principalId: logicApp.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', sentinelResponderRoleId)
    principalType: 'ServicePrincipal'
  }
}

// ── Outputs ─────────────────────────────────────────────────────────────────

@description('Resource ID of the deployed Logic App.')
output logicAppId string = logicApp.id

@description('Name of the deployed Logic App.')
output logicAppName string = logicApp.name

@description('Principal ID of the Logic App managed identity.')
output principalId string = logicApp.identity.principalId
