// ============================================================================
// IP Address Enrichment Playbook — Logic App (Consumption)
// Sentinel entity-triggered playbook that enriches IP addresses with GeoIP,
// watchlist lookups, and optional VirusTotal integration.
// ============================================================================

// ── Phase 2 Integration ────────────────────────────────────────────────────
// Post-deployment: Configure TI watchlist and optional VirusTotal integration.
// See skills/powershell/sentinel-api-wrapper.md § Threat Intelligence and
// § Watchlists for managing TI indicators and watchlist lifecycle.
// See skills/powershell/rate-limiting.md § External APIs for VirusTotal
// rate limits (4 req/min on free tier, 500 req/day on free tier).
//
// .secops/ context: Read workspaces/*.yaml for workspace-scoped TI indicators.
// Check data-sources/data-source-map.yaml for TI connector configuration.
//
// Post-deployment script:
//   ./scripts/Configure-SoarPlaybooks.ps1 -Playbook IpEnrichment
//   Configures: Sentinel connection auth, TI watchlist creation, VT key vault.
// ────────────────────────────────────────────────────────────────────────────

targetScope = 'resourceGroup'

// ── Parameters ──────────────────────────────────────────────────────────────

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Name of the Log Analytics workspace backing Microsoft Sentinel.')
param workspaceName string

@description('Resource group containing the Log Analytics workspace.')
param workspaceResourceGroup string = resourceGroup().name

@secure()
@description('VirusTotal API key for IP reputation lookups. Leave empty to skip VT enrichment.')
param virusTotalApiKey string = ''

@description('Name of the Sentinel watchlist containing known-malicious IPs.')
param tiWatchlistAlias string = 'IPWatchlist'

@description('Name prefix for all resources.')
param namePrefix string = 'soar-ip-enrich'

@description('Tags applied to every resource.')
param tags object = {
  solution: 'secops-squad'
  playbook: 'ip-enrichment'
  deployedBy: 'bicep'
}

// ── Variables ───────────────────────────────────────────────────────────────

var logicAppName = '${namePrefix}-${uniqueString(resourceGroup().id)}'
var sentinelConnectionName = '${namePrefix}-azuresentinel'
var hasVirusTotal = !empty(virusTotalApiKey)

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
        virusTotalApiKey: {
          defaultValue: ''
          type: 'SecureString'
        }
        tiWatchlistAlias: {
          defaultValue: tiWatchlistAlias
          type: 'String'
        }
      }
      triggers: {
        Microsoft_Sentinel_entity_IP: {
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
            path: '/entity/@{encodeURIComponent(\'IP\')}'
          }
        }
      }
      actions: {
        Initialize_enrichment_results: {
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'enrichmentResults'
                type: 'object'
                value: {
                  ip: '@triggerBody()?[\'Entity\']?[\'properties\']?[\'address\']'
                  geoip: {}
                  watchlistMatch: false
                  virusTotal: {}
                  verdict: 'unknown'
                }
              }
            ]
          }
          runAfter: {}
        }
        GeoIP_lookup: {
          type: 'Http'
          inputs: {
            method: 'GET'
            uri: 'https://ipapi.co/@{triggerBody()?[\'Entity\']?[\'properties\']?[\'address\']}/json/'
            headers: {
              'User-Agent': 'secops-squad-playbook/1.0'
            }
          }
          runAfter: {
            Initialize_enrichment_results: [ 'Succeeded' ]
          }
        }
        Set_GeoIP_result: {
          type: 'SetVariable'
          inputs: {
            name: 'enrichmentResults'
            value: '@setProperty(variables(\'enrichmentResults\'), \'geoip\', body(\'GeoIP_lookup\'))'
          }
          runAfter: {
            GeoIP_lookup: [ 'Succeeded', 'Failed' ]
          }
        }
        Check_TI_watchlist: {
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/Watchlists/subscriptions/@{encodeURIComponent(subscription().subscriptionId)}/resourceGroups/@{encodeURIComponent(resourceGroup().name)}/workspaces/@{encodeURIComponent(\'${workspaceName}\')}'
            body: {
              watchlistAlias: '@parameters(\'tiWatchlistAlias\')'
              searchKey: '@triggerBody()?[\'Entity\']?[\'properties\']?[\'address\']'
            }
          }
          runAfter: {
            Initialize_enrichment_results: [ 'Succeeded' ]
          }
        }
        Set_watchlist_result: {
          type: 'SetVariable'
          inputs: {
            name: 'enrichmentResults'
            value: '@setProperty(variables(\'enrichmentResults\'), \'watchlistMatch\', greater(length(body(\'Check_TI_watchlist\')?[\'value\']), 0))'
          }
          runAfter: {
            Check_TI_watchlist: [ 'Succeeded', 'Failed' ]
          }
        }
        Check_VirusTotal_enabled: {
          type: 'If'
          expression: {
            and: [
              {
                not: {
                  equals: [
                    '@parameters(\'virusTotalApiKey\')'
                    ''
                  ]
                }
              }
            ]
          }
          actions: {
            VirusTotal_IP_lookup: {
              type: 'Http'
              inputs: {
                method: 'GET'
                uri: 'https://www.virustotal.com/api/v3/ip_addresses/@{triggerBody()?[\'Entity\']?[\'properties\']?[\'address\']}'
                headers: {
                  'x-apikey': '@parameters(\'virusTotalApiKey\')'
                }
              }
              runAfter: {}
            }
            Set_VT_result: {
              type: 'SetVariable'
              inputs: {
                name: 'enrichmentResults'
                value: '@setProperty(variables(\'enrichmentResults\'), \'virusTotal\', body(\'VirusTotal_IP_lookup\')?[\'data\']?[\'attributes\']?[\'last_analysis_stats\'])'
              }
              runAfter: {
                VirusTotal_IP_lookup: [ 'Succeeded', 'Failed' ]
              }
            }
          }
          else: {
            actions: {}
          }
          runAfter: {
            Set_GeoIP_result: [ 'Succeeded' ]
            Set_watchlist_result: [ 'Succeeded' ]
          }
        }
        Determine_verdict: {
          type: 'SetVariable'
          inputs: {
            name: 'enrichmentResults'
            value: '@setProperty(variables(\'enrichmentResults\'), \'verdict\', if(equals(variables(\'enrichmentResults\')?[\'watchlistMatch\'], true), \'malicious-watchlist\', if(greater(variables(\'enrichmentResults\')?[\'virusTotal\']?[\'malicious\'], 5), \'malicious-vt\', if(greater(variables(\'enrichmentResults\')?[\'virusTotal\']?[\'suspicious\'], 3), \'suspicious\', \'benign\'))))'
          }
          runAfter: {
            Check_VirusTotal_enabled: [ 'Succeeded' ]
          }
        }
        Add_enrichment_comment: {
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
              incidentArmId: '@triggerBody()?[\'IncidentArmID\']'
              message: '🌐 **IP Enrichment: @{triggerBody()?[\'Entity\']?[\'properties\']?[\'address\']}**\n\n**Verdict:** @{variables(\'enrichmentResults\')?[\'verdict\']}\n\n**GeoIP:** @{body(\'GeoIP_lookup\')?[\'country_name\']} / @{body(\'GeoIP_lookup\')?[\'city\']} / ASN: @{body(\'GeoIP_lookup\')?[\'asn\']} (@{body(\'GeoIP_lookup\')?[\'org\']})\n\n**Watchlist match:** @{variables(\'enrichmentResults\')?[\'watchlistMatch\']}\n\n**VirusTotal:** @{if(empty(variables(\'enrichmentResults\')?[\'virusTotal\']), \'Skipped (no API key)\', concat(\'Malicious: \', string(variables(\'enrichmentResults\')?[\'virusTotal\']?[\'malicious\']), \' / Suspicious: \', string(variables(\'enrichmentResults\')?[\'virusTotal\']?[\'suspicious\'])))}\n\nPlaybook: ${logicAppName}'
            }
          }
          runAfter: {
            Determine_verdict: [ 'Succeeded' ]
          }
        }
        Conditionally_add_TI_indicator: {
          type: 'If'
          expression: {
            or: [
              {
                equals: [
                  '@variables(\'enrichmentResults\')?[\'verdict\']'
                  'malicious-watchlist'
                ]
              }
              {
                equals: [
                  '@variables(\'enrichmentResults\')?[\'verdict\']'
                  'malicious-vt'
                ]
              }
            ]
          }
          actions: {
            Create_TI_indicator: {
              type: 'ApiConnection'
              inputs: {
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
                  }
                }
                method: 'post'
                path: '/ThreatIntelligence/subscriptions/@{encodeURIComponent(subscription().subscriptionId)}/resourceGroups/@{encodeURIComponent(resourceGroup().name)}/workspaces/@{encodeURIComponent(\'${workspaceName}\')}/indicators'
                body: {
                  displayName: 'Malicious IP: @{triggerBody()?[\'Entity\']?[\'properties\']?[\'address\']}'
                  description: 'Auto-enriched by secops-squad IP enrichment playbook. Verdict: @{variables(\'enrichmentResults\')?[\'verdict\']}'
                  pattern: '[ipv4-addr:value = \'@{triggerBody()?[\'Entity\']?[\'properties\']?[\'address\']}\']'
                  patternType: 'ipv4-addr'
                  threatTypes: [ 'malicious-activity' ]
                  confidence: 85
                  validFrom: '@utcNow()'
                  validUntil: '@addDays(utcNow(), 30)'
                }
              }
              runAfter: {}
            }
          }
          else: {
            actions: {}
          }
          runAfter: {
            Add_enrichment_comment: [ 'Succeeded' ]
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
        }
      }
      virusTotalApiKey: {
        value: virusTotalApiKey
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

@description('Whether VirusTotal integration is enabled.')
output virusTotalEnabled bool = hasVirusTotal
