// ============================================================================
// Teams SOC Notification Playbook — Logic App (Consumption)
// Sentinel-triggered playbook that routes incident notifications to
// severity-mapped Teams channels with rich Adaptive Cards.
// ============================================================================

targetScope = 'resourceGroup'

// ── Parameters ──────────────────────────────────────────────────────────────

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Name of the Log Analytics workspace backing Microsoft Sentinel.')
param workspaceName string

@description('Resource group containing the Log Analytics workspace.')
param workspaceResourceGroup string = resourceGroup().name

@description('Teams team ID that owns the notification channels.')
param teamsTeamId string

@description('Teams channel ID for Critical severity incidents.')
param criticalChannelId string

@description('Teams channel ID for High severity incidents.')
param highChannelId string

@description('Teams channel ID for Medium severity incidents.')
param mediumChannelId string

@description('Teams channel ID for Low/Informational severity incidents.')
param lowChannelId string

@description('Whether to post rich Adaptive Cards (true) or plain HTML (false).')
param useAdaptiveCard bool = true

@description('Name prefix for all resources.')
param namePrefix string = 'soar-teams-notify'

@description('Tags applied to every resource.')
param tags object = {
  solution: 'secops-squad'
  playbook: 'teams-notification'
  deployedBy: 'bicep'
}

// ── Variables ───────────────────────────────────────────────────────────────

var logicAppName = '${namePrefix}-${uniqueString(resourceGroup().id)}'
var sentinelConnectionName = '${namePrefix}-azuresentinel'
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
        teamsTeamId: {
          defaultValue: teamsTeamId
          type: 'String'
        }
        criticalChannelId: {
          defaultValue: criticalChannelId
          type: 'String'
        }
        highChannelId: {
          defaultValue: highChannelId
          type: 'String'
        }
        mediumChannelId: {
          defaultValue: mediumChannelId
          type: 'String'
        }
        lowChannelId: {
          defaultValue: lowChannelId
          type: 'String'
        }
        useAdaptiveCard: {
          defaultValue: useAdaptiveCard
          type: 'Bool'
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
            Get_incident: [ 'Succeeded' ]
          }
        }
        Map_severity_to_channel: {
          type: 'Compose'
          inputs: '@if(equals(triggerBody()?[\'object\']?[\'properties\']?[\'severity\'], \'High\'), parameters(\'highChannelId\'), if(equals(triggerBody()?[\'object\']?[\'properties\']?[\'severity\'], \'Medium\'), parameters(\'mediumChannelId\'), if(or(equals(triggerBody()?[\'object\']?[\'properties\']?[\'severity\'], \'Low\'), equals(triggerBody()?[\'object\']?[\'properties\']?[\'severity\'], \'Informational\')), parameters(\'lowChannelId\'), parameters(\'criticalChannelId\'))))'
          runAfter: {
            Get_entities: [ 'Succeeded' ]
          }
        }
        Build_entity_summary: {
          type: 'Compose'
          inputs: '@join(createArray(concat(\'Accounts: \', string(length(filter(body(\'Get_entities\')?[\'entities\'], item(), equals(item()?[\'kind\'], \'Account\'))))), concat(\'Hosts: \', string(length(filter(body(\'Get_entities\')?[\'entities\'], item(), equals(item()?[\'kind\'], \'Host\'))))), concat(\'IPs: \', string(length(filter(body(\'Get_entities\')?[\'entities\'], item(), equals(item()?[\'kind\'], \'Ip\')))))), \' | \')'
          runAfter: {
            Map_severity_to_channel: [ 'Succeeded' ]
          }
        }
        Check_adaptive_card_mode: {
          type: 'If'
          expression: {
            and: [
              {
                equals: [
                  '@parameters(\'useAdaptiveCard\')'
                  true
                ]
              }
            ]
          }
          actions: {
            Post_adaptive_card: {
              type: 'ApiConnection'
              inputs: {
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'teams\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/v1.0/teams/@{encodeURIComponent(parameters(\'teamsTeamId\'))}/channels/@{encodeURIComponent(outputs(\'Map_severity_to_channel\'))}/messages'
                body: {
                  messageType: 'message'
                  attachments: [
                    {
                      contentType: 'application/vnd.microsoft.card.adaptive'
                      content: {
                        '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json'
                        type: 'AdaptiveCard'
                        version: '1.4'
                        msteams: {
                          width: 'Full'
                        }
                        body: [
                          {
                            type: 'ColumnSet'
                            columns: [
                              {
                                type: 'Column'
                                width: 'auto'
                                items: [
                                  {
                                    type: 'TextBlock'
                                    text: '🚨'
                                    size: 'Large'
                                  }
                                ]
                              }
                              {
                                type: 'Column'
                                width: 'stretch'
                                items: [
                                  {
                                    type: 'TextBlock'
                                    text: 'Sentinel Incident'
                                    weight: 'Bolder'
                                    size: 'Medium'
                                  }
                                  {
                                    type: 'TextBlock'
                                    text: '@{triggerBody()?[\'object\']?[\'properties\']?[\'title\']}'
                                    wrap: true
                                    size: 'Large'
                                    weight: 'Bolder'
                                    color: '@{if(equals(triggerBody()?[\'object\']?[\'properties\']?[\'severity\'], \'High\'), \'Attention\', if(equals(triggerBody()?[\'object\']?[\'properties\']?[\'severity\'], \'Medium\'), \'Warning\', \'Default\'))}'
                                  }
                                ]
                              }
                            ]
                          }
                          {
                            type: 'FactSet'
                            facts: [
                              {
                                title: 'Severity'
                                value: '@{triggerBody()?[\'object\']?[\'properties\']?[\'severity\']}'
                              }
                              {
                                title: 'Status'
                                value: '@{triggerBody()?[\'object\']?[\'properties\']?[\'status\']}'
                              }
                              {
                                title: 'Incident #'
                                value: '@{triggerBody()?[\'object\']?[\'properties\']?[\'incidentNumber\']}'
                              }
                              {
                                title: 'Created'
                                value: '@{triggerBody()?[\'object\']?[\'properties\']?[\'createdTimeUtc\']}'
                              }
                              {
                                title: 'Entities'
                                value: '@{outputs(\'Build_entity_summary\')}'
                              }
                              {
                                title: 'Alert Count'
                                value: '@{length(triggerBody()?[\'object\']?[\'properties\']?[\'alerts\'])}'
                              }
                            ]
                          }
                          {
                            type: 'TextBlock'
                            text: '@{take(triggerBody()?[\'object\']?[\'properties\']?[\'description\'], 500)}'
                            wrap: true
                            maxLines: 4
                          }
                        ]
                        actions: [
                          {
                            type: 'Action.OpenUrl'
                            title: '🔍 View in Sentinel'
                            url: '@{triggerBody()?[\'object\']?[\'properties\']?[\'incidentUrl\']}'
                          }
                          {
                            type: 'Action.OpenUrl'
                            title: '📋 Investigation'
                            url: 'https://portal.azure.com/#blade/Microsoft_Azure_Security_Insights/IncidentBlade/incidentId/@{triggerBody()?[\'object\']?[\'properties\']?[\'incidentNumber\']}'
                          }
                        ]
                      }
                    }
                  ]
                }
              }
              runAfter: {}
            }
          }
          else: {
            actions: {
              Post_html_message: {
                type: 'ApiConnection'
                inputs: {
                  host: {
                    connection: {
                      name: '@parameters(\'$connections\')[\'teams\'][\'connectionId\']'
                    }
                  }
                  method: 'post'
                  path: '/v3/teams/@{encodeURIComponent(parameters(\'teamsTeamId\'))}/channels/@{encodeURIComponent(outputs(\'Map_severity_to_channel\'))}/messages'
                  body: {
                    contentType: 'html'
                    content: '<h3>🚨 Sentinel Incident: @{triggerBody()?[\'object\']?[\'properties\']?[\'title\']}</h3><table><tr><td><b>Severity:</b></td><td>@{triggerBody()?[\'object\']?[\'properties\']?[\'severity\']}</td></tr><tr><td><b>Incident #:</b></td><td>@{triggerBody()?[\'object\']?[\'properties\']?[\'incidentNumber\']}</td></tr><tr><td><b>Entities:</b></td><td>@{outputs(\'Build_entity_summary\')}</td></tr></table><p>@{take(triggerBody()?[\'object\']?[\'properties\']?[\'description\'], 500)}</p>'
                  }
                }
                runAfter: {}
              }
            }
          }
          runAfter: {
            Build_entity_summary: [ 'Succeeded' ]
          }
        }
        Add_comment_to_incident: {
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
              message: 'Teams notification sent to @{if(equals(triggerBody()?[\'object\']?[\'properties\']?[\'severity\'], \'High\'), \'high-severity\', if(equals(triggerBody()?[\'object\']?[\'properties\']?[\'severity\'], \'Medium\'), \'medium-severity\', if(or(equals(triggerBody()?[\'object\']?[\'properties\']?[\'severity\'], \'Low\'), equals(triggerBody()?[\'object\']?[\'properties\']?[\'severity\'], \'Informational\')), \'low-severity\', \'critical-severity\')))} channel. Playbook: ${logicAppName}'
            }
          }
          runAfter: {
            Check_adaptive_card_mode: [ 'Succeeded' ]
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

// ── Role Assignments ────────────────────────────────────────────────────────

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
