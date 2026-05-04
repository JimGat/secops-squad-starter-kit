// ============================================================================
// ADX Cluster — Azure Data Explorer Cluster for Security Data Lake
// Provisions a Kusto cluster with managed identity, diagnostics, network
// security, auto-scale, streaming ingestion, and optional CMK encryption.
// ============================================================================

// ── Phase 2 Integration ────────────────────────────────────────────────────
// Post-deployment: Verify cluster health and configure MCP access.
// See skills/powershell/data-tiering-commands.md § Cluster Health for
// cluster state validation and diagnostic verification.
// See skills/msft-security/sentinel-mcp-server.md for registering the
// cluster URI with MCP Server for agent-based KQL execution.
// See skills/powershell/rate-limiting.md § Azure Data Explorer for
// ADX query throttling (concurrent query limits per cluster SKU).
//
// .secops/ context: Read workspaces/*.yaml for diagnostic workspace targets.
// Check compliance/requirements.yaml for CMK and network isolation mandates.
// ────────────────────────────────────────────────────────────────────────────

targetScope = 'resourceGroup'

// ── Parameters ──────────────────────────────────────────────────────────────

@description('Azure region for all resources. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Name of the ADX cluster. Must be globally unique, 4-22 lowercase alphanumeric characters.')
@minLength(4)
@maxLength(22)
param clusterName string

@description('SKU name for the cluster compute tier.')
@allowed([
  'Dev(No SLA)_Standard_E2a_v4'
  'Standard_E8as_v5+1TB_PS'
  'Standard_E16as_v5+2TB_PS'
  'Standard_E8s_v5+1TB_PS'
  'Standard_E16s_v5+2TB_PS'
  'Standard_E2d_v5'
  'Standard_E4d_v5'
  'Standard_E8d_v5'
  'Standard_E16d_v5'
  'Standard_L8as_v3'
  'Standard_L16as_v3'
  'Standard_L32as_v3'
])
param skuName string = 'Standard_E8as_v5+1TB_PS'

@description('SKU tier for the cluster.')
@allowed([ 'Basic', 'Standard' ])
param skuTier string = 'Standard'

@description('Number of cluster instances (ignored for Dev SKU).')
@minValue(2)
@maxValue(100)
param instanceCount int = 2

@description('Enable auto-scale for the cluster.')
param enableAutoScale bool = true

@description('Minimum instance count for auto-scale.')
@minValue(2)
@maxValue(100)
param autoScaleMin int = 2

@description('Maximum instance count for auto-scale.')
@minValue(2)
@maxValue(100)
param autoScaleMax int = 10

@description('Enable streaming ingestion on the cluster.')
param enableStreamingIngestion bool = true

@description('Enable disk encryption using customer-managed keys.')
param enableCmkEncryption bool = false

@description('Key Vault URI for customer-managed key (required if enableCmkEncryption is true).')
param cmkKeyVaultUri string = ''

@description('Key name in Key Vault for CMK encryption.')
param cmkKeyName string = ''

@description('Key version in Key Vault for CMK encryption. Empty = latest.')
param cmkKeyVersion string = ''

@description('User-assigned managed identity resource ID for CMK access (required if enableCmkEncryption is true).')
param cmkUserAssignedIdentityId string = ''

@description('Enable VNet integration for the cluster.')
param enableVnet bool = false

@description('Subnet resource ID for VNet integration (required if enableVnet is true).')
param subnetId string = ''

@description('Engine subnet resource ID for VNet integration (required if enableVnet is true).')
param engineSubnetId string = ''

@description('Enable private endpoints for the cluster.')
param enablePrivateEndpoint bool = false

@description('Subnet resource ID for the private endpoint (required if enablePrivateEndpoint is true).')
param privateEndpointSubnetId string = ''

@description('Private DNS zone resource ID for private endpoint (required if enablePrivateEndpoint is true).')
param privateDnsZoneId string = ''

@description('Enable system-assigned managed identity.')
param enableSystemIdentity bool = true

@description('Optional user-assigned managed identity resource IDs.')
param userAssignedIdentityIds array = []

@description('Trusted external tenant IDs for cross-tenant queries.')
param trustedExternalTenants array = []

@description('Resource ID of the Log Analytics workspace for diagnostic settings.')
param logAnalyticsWorkspaceId string = ''

@description('Enable diagnostic settings to Log Analytics.')
param enableDiagnostics bool = true

@description('Environment tag value.')
@allowed([ 'dev', 'staging', 'production' ])
param environment string = 'production'

@description('Project tag value for resource identification.')
param project string = 'secops-squad'

@description('Cost center tag value for billing attribution.')
param costCenter string = ''

@description('Tags applied to every deployed resource.')
param tags object = {}

// ── Variables ───────────────────────────────────────────────────────────────

var isDevSku = startsWith(skuName, 'Dev')
var effectiveInstanceCount = isDevSku ? 1 : instanceCount

var identityType = enableSystemIdentity && !empty(userAssignedIdentityIds)
  ? 'SystemAssigned,UserAssigned'
  : enableSystemIdentity
    ? 'SystemAssigned'
    : !empty(userAssignedIdentityIds)
      ? 'UserAssigned'
      : 'None'

var userAssignedIdentities = reduce(userAssignedIdentityIds, {}, (acc, id) => union(acc, { '${id}': {} }))

var baseTags = {
  solution: 'secops-squad'
  component: 'adx-cluster'
  deployedBy: 'bicep'
  environment: environment
  project: project
}
var costTag = !empty(costCenter) ? { costCenter: costCenter } : {}
var mergedTags = union(baseTags, costTag, tags)

var trustedTenantObjects = [for tenant in trustedExternalTenants: { value: tenant }]

// ── Cluster Resource ────────────────────────────────────────────────────────

resource cluster 'Microsoft.Kusto/clusters@2023-08-15' = {
  name: clusterName
  location: location
  tags: mergedTags
  sku: {
    name: skuName
    tier: skuTier
    capacity: effectiveInstanceCount
  }
  identity: {
    type: identityType
    userAssignedIdentities: !empty(userAssignedIdentityIds) ? userAssignedIdentities : null
  }
  properties: {
    enableStreamingIngest: enableStreamingIngestion
    enableAutoStop: isDevSku
    enableDiskEncryption: true
    enablePurge: false
    trustedExternalTenants: !empty(trustedExternalTenants) ? trustedTenantObjects : []
    optimizedAutoscale: enableAutoScale && !isDevSku ? {
      isEnabled: true
      minimum: autoScaleMin
      maximum: autoScaleMax
      version: 1
    } : null
    virtualNetworkConfiguration: enableVnet ? {
      subnetId: subnetId
      enginePublicIpId: engineSubnetId
      dataManagementPublicIpId: ''
    } : null
    keyVaultProperties: enableCmkEncryption ? {
      keyVaultUri: cmkKeyVaultUri
      keyName: cmkKeyName
      keyVersion: cmkKeyVersion
      userIdentity: cmkUserAssignedIdentityId
    } : null
  }
}

// ── Private Endpoint ────────────────────────────────────────────────────────

resource privateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = if (enablePrivateEndpoint) {
  name: '${clusterName}-pe'
  location: location
  tags: mergedTags
  properties: {
    subnet: {
      id: privateEndpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${clusterName}-pe-connection'
        properties: {
          privateLinkServiceId: cluster.id
          groupIds: [ 'cluster' ]
        }
      }
    ]
  }
}

resource privateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = if (enablePrivateEndpoint && !empty(privateDnsZoneId)) {
  parent: privateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'privatelink-kusto'
        properties: {
          privateDnsZoneId: privateDnsZoneId
        }
      }
    ]
  }
}

// ── Diagnostic Settings ─────────────────────────────────────────────────────

resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enableDiagnostics && !empty(logAnalyticsWorkspaceId)) {
  name: '${clusterName}-diag'
  scope: cluster
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      { categoryGroup: 'allLogs', enabled: true }
    ]
    metrics: [
      { category: 'AllMetrics', enabled: true }
    ]
  }
}

// ── Outputs ─────────────────────────────────────────────────────────────────

@description('Resource ID of the ADX cluster.')
output clusterId string = cluster.id

@description('URI for connecting to the ADX cluster.')
output clusterUri string = cluster.properties.uri

@description('Data ingestion URI for the ADX cluster.')
output dataIngestionUri string = cluster.properties.dataIngestionUri

@description('Principal ID of the system-assigned managed identity.')
output principalId string = enableSystemIdentity ? cluster.identity.principalId : ''

@description('Name of the deployed ADX cluster.')
output clusterName string = cluster.name
