// ============================================================================
// Phishing Response Playbook — Logic App (Consumption)
// Deploys a Sentinel-triggered playbook that automates phishing triage,
// email purge, and SOC notification via Teams.
// ============================================================================

targetScope = 'resourceGroup'

// ── Parameters ──────────────────────────────────────────────────────────────

@description('Azure region for all resources. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Name of the Log Analytics workspace backing Microsoft Sentinel.')
param workspaceName string

@description('Resource group containing the Log Analytics workspace (if different).')
param workspaceResourceGroup string = resourceGroup().name

@description('Microsoft Teams channel ID for SOC notifications.')
param teamsChannelId string

@description('Teams team ID that owns the notification channel.')
param teamsTeamId string

@description('Email address of the Exchange / mail admin for escalation.')
param emailAdmin string

@description('Name prefix for all resources created by this template.')
param namePrefix string = 'soar-phishing'

@description('Tags to apply to every resource.')
param tags object = {
  solution: 'secops-squad'
  playbook: 'phishing-response'
  deployedBy: 'bicep'
}

// ── Variables ───────────────────────────────────────────────────────────────

var logicAppName = '${namePrefix}-${uniqueString(resourceGroup().id)}'
var sentinelConnectionName = '${namePrefix}-azuresentinel'
var teamsConnectionName = '${namePrefix}-teams'
var office365ConnectionName = '${namePrefix}-office365'
var entraConnectionName = '${namePrefix}-azuread'

// ── Existing Resources ─────────────────────────────────────────────────────

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
  scope: resourceGroup(workspaceResourceGroup)
}

// ── Managed Identity ────────────────────────────────────────────────────────

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
        teamsChannelId: {
          defaultValue: teamsChannelId
          type: 'String'
        }
        teamsTeamId: {
          defaultValue: teamsTeamId
          type: 'String'
        }
        emailAdmin: {
          defaultValue: emailAdmin
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
        Get_incident_details: {
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
        Get_entities: {
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
            Get_incident_details: [ 'Succeeded' ]
          }
        }
        Filter_mailbox_entities: {
          type: 'Query'
          inputs: {
            from: '@body(\'Get_entities\')?[\'entities\']'
            where: '@or(equals(item()?[\'kind\'], \'Mailbox\'), equals(item()?[\'kind\'], \'MailMessage\'))'
          }
          runAfter: {
            Get_entities: [ 'Succeeded' ]
          }
        }
        Check_mailbox_rules: {
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'office365\'][\'connectionId\']'
              }
            }
            method: 'get'
            path: '/codeless/v1.0/me/mailFolders/inbox/messageRules'
          }
          runAfter: {
            Filter_mailbox_entities: [ 'Succeeded' ]
          }
        }
        Purge_phishing_emails: {
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'office365\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/codeless/v1.0/security/collaboration/purge'
            body: {
              actionType: 'softDelete'
              description: 'Automated phishing email purge by secops-squad playbook'
              incidentId: '@triggerBody()?[\'object\']?[\'properties\']?[\'incidentNumber\']'
            }
          }
          runAfter: {
            Check_mailbox_rules: [ 'Succeeded' ]
          }
        }
        Check_user_identity: {
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuread\'][\'connectionId\']'
              }
            }
            method: 'get'
            path: '/v1.0/users/@{body(\'Filter_mailbox_entities\')?[0]?[\'properties\']?[\'mailboxAddress\']}'
          }
          runAfter: {
            Filter_mailbox_entities: [ 'Succeeded' ]
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
              content: '<h3>🎣 Phishing Incident Response</h3><p><strong>Incident:</strong> @{triggerBody()?[\'object\']?[\'properties\']?[\'title\']}</p><p><strong>Severity:</strong> @{triggerBody()?[\'object\']?[\'properties\']?[\'severity\']}</p><p><strong>Status:</strong> Emails purged, mailbox rules checked</p><p><strong>Entities:</strong> @{length(body(\'Get_entities\')?[\'entities\'])} extracted</p><p>Admin: @{parameters(\'emailAdmin\')}</p>'
            }
          }
          runAfter: {
            Purge_phishing_emails: [ 'Succeeded' ]
            Check_user_identity: [ 'Succeeded' ]
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
                { Tag: 'automated-phishing-response' }
                { Tag: 'emails-purged' }
              ]
              severity: '@triggerBody()?[\'object\']?[\'properties\']?[\'severity\']'
            }
          }
          runAfter: {
            Post_to_Teams: [ 'Succeeded' ]
          }
        }
        Add_incident_comment: {
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/Incidents/Comment/subscriptions/@{encodeURIComponent(subscription().subscriptionId)}/resourceGroups/@{encodeURIComponent(resourceGroup().name)}/workspaces/@{encodeURIComponent(\'${workspaceName}\')}'
            body: {
              incidentArmId: '@triggerBody()?[\'object\']?[\'id\']'
              message: 'Automated phishing response completed. Emails purged, mailbox rules inspected, Teams notified. Playbook: ${logicAppName}'
            }
          }
          runAfter: {
            Update_incident: [ 'Succeeded' ]
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
          teams: {
            connectionId: teamsConnection.id
            connectionName: teamsConnectionName
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'teams')
          }
          office365: {
            connectionId: office365Connection.id
            connectionName: office365ConnectionName
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'office365')
          }
          azuread: {
            connectionId: entraConnection.id
            connectionName: entraConnectionName
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuread')
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

resource office365Connection 'Microsoft.Web/connections@2016-06-01' = {
  name: office365ConnectionName
  location: location
  tags: tags
  properties: {
    displayName: office365ConnectionName
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'office365')
    }
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

// ── Role Assignments ────────────────────────────────────────────────────────
// Microsoft Sentinel Responder: ab8e14d6-4a74-4a29-9ba8-549422addade

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

// Sentinel Reader: 8d289c81-5878-46d4-8554-54e1e3d8b5cb
var sentinelReaderRoleId = '8d289c81-5878-46d4-8554-54e1e3d8b5cb'

resource sentinelReaderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(logicApp.id, sentinelReaderRoleId, resourceGroup().id)
  scope: resourceGroup()
  properties: {
    principalId: logicApp.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', sentinelReaderRoleId)
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

@description('Sentinel API connection resource ID.')
output sentinelConnectionId string = sentinelConnection.id
