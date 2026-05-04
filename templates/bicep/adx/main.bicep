// ============================================================================
// ADX Security Data Lake — Main Orchestrator
// Deploys a complete Azure Data Explorer security data lake with configurable
// tiers (dev/standard/production), database, tables, and ingestion pipeline.
// Usage: az deployment group create -g <rg> -f main.bicep -p clusterName=<name>
// ============================================================================

// ── Phase 2 Integration ────────────────────────────────────────────────────
// Post-deployment: Configure data tiering, ingestion validation, and MCP access.
// See skills/powershell/data-tiering-commands.md for table tier management,
// retention policy auditing, and summary rule creation post-deployment.
// See skills/powershell/sentinel-api-wrapper.md § Data Connectors for
// configuring Sentinel→ADX cross-resource queries (adx() proxy function).
// See skills/msft-security/sentinel-mcp-server.md for MCP-based agent access
// to ADX tables via the Azure MCP Server.
// See skills/powershell/rate-limiting.md § Azure Resource Manager for ARM
// API throttling during bulk resource deployments (1200 writes/hr/subscription).
//
// .secops/ integration: Templates read workspace config from .secops/workspaces/
// to resolve Log Analytics workspace IDs for diagnostic settings.
// Check data-sources/data-source-map.yaml for ADX table→data source mapping.
// Verify compliance/requirements.yaml for data residency and retention rules.
//
// Post-deployment script:
//   ./scripts/Configure-AdxSecurityLake.ps1 -ClusterName <name> -Tier <tier>
//   This configures: table tiers, ingestion validation, Sentinel cross-query,
//   MCP registration, and data source mapping in .secops/.
// ────────────────────────────────────────────────────────────────────────────

targetScope = 'resourceGroup'

// ── Core Parameters ─────────────────────────────────────────────────────────

@description('Azure region for all resources. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Name of the ADX cluster. Must be globally unique, 4-22 lowercase alphanumeric characters.')
@minLength(4)
@maxLength(22)
param clusterName string

@description('Deployment tier controlling SKU, cache, and security defaults.')
@allowed([ 'dev', 'standard', 'production' ])
param deploymentTier string = 'standard'

@description('Name of the primary security database.')
param databaseName string = 'SecurityLake'

// ── Module Toggle Parameters ────────────────────────────────────────────────

@description('Deploy the security database.')
param deployDatabase bool = true

@description('Deploy the pre-built security tables.')
param deployTables bool = true

@description('Deploy the ingestion pipeline.')
param deployIngestion bool = true

// ── Network Parameters ──────────────────────────────────────────────────────

@description('Enable VNet integration (forced true for production tier).')
param enableVnet bool = false

@description('Subnet resource ID for VNet integration.')
param subnetId string = ''

@description('Engine subnet resource ID for VNet integration.')
param engineSubnetId string = ''

@description('Enable private endpoints (forced true for production tier).')
param enablePrivateEndpoint bool = false

@description('Subnet resource ID for the private endpoint.')
param privateEndpointSubnetId string = ''

@description('Private DNS zone resource ID for private endpoint.')
param privateDnsZoneId string = ''

// ── Encryption Parameters ───────────────────────────────────────────────────

@description('Enable CMK encryption (forced true for production tier).')
param enableCmkEncryption bool = false

@description('Key Vault URI for customer-managed key.')
param cmkKeyVaultUri string = ''

@description('Key name in Key Vault.')
param cmkKeyName string = ''

@description('Key version (empty = latest).')
param cmkKeyVersion string = ''

@description('User-assigned managed identity resource ID for CMK access.')
param cmkUserAssignedIdentityId string = ''

// ── Identity Parameters ─────────────────────────────────────────────────────

@description('Optional user-assigned managed identity resource IDs.')
param userAssignedIdentityIds array = []

@description('Trusted external tenant IDs for cross-tenant queries.')
param trustedExternalTenants array = []

// ── Diagnostics Parameters ──────────────────────────────────────────────────

@description('Resource ID of the Log Analytics workspace for diagnostic settings.')
param logAnalyticsWorkspaceId string = ''

// ── Database Parameters ─────────────────────────────────────────────────────

@description('Override hot cache period in days (tier default used if 0).')
param hotCacheDaysOverride int = 0

@description('Override soft delete period in days (tier default used if 0).')
param softDeleteDaysOverride int = 0

@description('Principal IDs for database Admin role.')
param dbAdminPrincipalIds array = []

@description('Principal IDs for database Viewer role.')
param dbViewerPrincipalIds array = []

@description('Principal IDs for database Ingestor role.')
param dbIngestorPrincipalIds array = []

// ── Table Toggles ───────────────────────────────────────────────────────────

@description('Deploy SecurityEvents table.')
param deploySecurityEvents bool = true

@description('Deploy NetworkTraffic table.')
param deployNetworkTraffic bool = true

@description('Deploy ThreatIntelligence table.')
param deployThreatIntelligence bool = true

@description('Deploy IdentityEvents table.')
param deployIdentityEvents bool = true

@description('Deploy CloudAudit table.')
param deployCloudAudit bool = true

// ── Ingestion Parameters ────────────────────────────────────────────────────

@description('Deploy Event Hub data connection.')
param deployEventHubConnection bool = false

@description('Resource ID of the Event Hub namespace.')
param eventHubNamespaceId string = ''

@description('Event Hub namespace name.')
param eventHubNamespaceName string = ''

@description('Event Hub name for security log ingestion.')
param eventHubName string = 'security-logs'

@description('Event Hub namespace resource group.')
param eventHubResourceGroup string = resourceGroup().name

@description('Deploy IoT Hub data connection.')
param deployIotHubConnection bool = false

@description('IoT Hub resource ID.')
param iotHubResourceId string = ''

@description('Deploy Event Grid data connection.')
param deployEventGridConnection bool = false

@description('Storage account resource ID for Event Grid.')
param storageAccountId string = ''

@description('Event Hub resource ID for Event Grid notifications.')
param eventGridEventHubId string = ''

// ── Tag Parameters ──────────────────────────────────────────────────────────

@description('Project tag value.')
param project string = 'secops-squad'

@description('Cost center tag value.')
param costCenter string = ''

@description('Additional tags.')
param tags object = {}

// ── Tier Configuration ──────────────────────────────────────────────────────

var tierConfig = {
  dev: {
    skuName: 'Dev(No SLA)_Standard_E2a_v4'
    skuTier: 'Basic'
    instanceCount: 2
    enableAutoScale: false
    autoScaleMin: 2
    autoScaleMax: 2
    hotCacheDays: 7
    softDeleteDays: 90
    enableStreamingIngestion: false
    enableVnet: false
    enablePrivateEndpoint: false
    enableCmkEncryption: false
  }
  standard: {
    skuName: 'Standard_E8as_v5+1TB_PS'
    skuTier: 'Standard'
    instanceCount: 2
    enableAutoScale: true
    autoScaleMin: 2
    autoScaleMax: 8
    hotCacheDays: 31
    softDeleteDays: 365
    enableStreamingIngestion: true
    enableVnet: enableVnet
    enablePrivateEndpoint: enablePrivateEndpoint
    enableCmkEncryption: enableCmkEncryption
  }
  production: {
    skuName: 'Standard_E16as_v5+2TB_PS'
    skuTier: 'Standard'
    instanceCount: 3
    enableAutoScale: true
    autoScaleMin: 3
    autoScaleMax: 16
    hotCacheDays: 90
    softDeleteDays: 730
    enableStreamingIngestion: true
    enableVnet: true
    enablePrivateEndpoint: true
    enableCmkEncryption: true
  }
}

var config = tierConfig[deploymentTier]
var effectiveHotCache = hotCacheDaysOverride > 0 ? hotCacheDaysOverride : config.hotCacheDays
var effectiveSoftDelete = softDeleteDaysOverride > 0 ? softDeleteDaysOverride : config.softDeleteDays

// ── Cluster Module ──────────────────────────────────────────────────────────

module adxCluster 'cluster.bicep' = {
  name: 'deploy-adx-cluster'
  params: {
    location: location
    clusterName: clusterName
    skuName: config.skuName
    skuTier: config.skuTier
    instanceCount: config.instanceCount
    enableAutoScale: config.enableAutoScale
    autoScaleMin: config.autoScaleMin
    autoScaleMax: config.autoScaleMax
    enableStreamingIngestion: config.enableStreamingIngestion
    enableCmkEncryption: config.enableCmkEncryption
    cmkKeyVaultUri: cmkKeyVaultUri
    cmkKeyName: cmkKeyName
    cmkKeyVersion: cmkKeyVersion
    cmkUserAssignedIdentityId: cmkUserAssignedIdentityId
    enableVnet: config.enableVnet
    subnetId: subnetId
    engineSubnetId: engineSubnetId
    enablePrivateEndpoint: config.enablePrivateEndpoint
    privateEndpointSubnetId: privateEndpointSubnetId
    privateDnsZoneId: privateDnsZoneId
    enableSystemIdentity: true
    userAssignedIdentityIds: userAssignedIdentityIds
    trustedExternalTenants: trustedExternalTenants
    logAnalyticsWorkspaceId: logAnalyticsWorkspaceId
    enableDiagnostics: !empty(logAnalyticsWorkspaceId)
    environment: deploymentTier == 'dev' ? 'dev' : deploymentTier == 'standard' ? 'staging' : 'production'
    project: project
    costCenter: costCenter
    tags: tags
  }
}

// ── Database Module ─────────────────────────────────────────────────────────

module adxDatabase 'database.bicep' = if (deployDatabase) {
  name: 'deploy-adx-database'
  params: {
    location: location
    clusterName: clusterName
    databaseName: databaseName
    hotCacheDays: effectiveHotCache
    softDeleteDays: effectiveSoftDelete
    adminPrincipalIds: dbAdminPrincipalIds
    viewerPrincipalIds: dbViewerPrincipalIds
    ingestorPrincipalIds: dbIngestorPrincipalIds
    environment: deploymentTier == 'dev' ? 'dev' : deploymentTier == 'standard' ? 'staging' : 'production'
    project: project
    costCenter: costCenter
    tags: tags
  }
  dependsOn: [ adxCluster ]
}

// ── Tables Module ───────────────────────────────────────────────────────────

module adxTables 'tables.bicep' = if (deployDatabase && deployTables) {
  name: 'deploy-adx-tables'
  params: {
    clusterName: clusterName
    databaseName: databaseName
    deploySecurityEvents: deploySecurityEvents
    deployNetworkTraffic: deployNetworkTraffic
    deployThreatIntelligence: deployThreatIntelligence
    deployIdentityEvents: deployIdentityEvents
    deployCloudAudit: deployCloudAudit
    retentionDays: effectiveSoftDelete
    hotCacheDays: effectiveHotCache
  }
  dependsOn: [ adxDatabase ]
}

// ── Ingestion Module ────────────────────────────────────────────────────────

module adxIngestion 'ingestion.bicep' = if (deployIngestion) {
  name: 'deploy-adx-ingestion'
  params: {
    location: location
    clusterName: clusterName
    databaseName: databaseName
    deployEventHubConnection: deployEventHubConnection
    eventHubNamespaceId: eventHubNamespaceId
    eventHubNamespaceName: eventHubNamespaceName
    eventHubName: eventHubName
    eventHubResourceGroup: eventHubResourceGroup
    deployIotHubConnection: deployIotHubConnection
    iotHubResourceId: iotHubResourceId
    deployEventGridConnection: deployEventGridConnection
    storageAccountId: storageAccountId
    eventGridEventHubId: eventGridEventHubId
    environment: deploymentTier == 'dev' ? 'dev' : deploymentTier == 'standard' ? 'staging' : 'production'
    project: project
    costCenter: costCenter
    tags: tags
  }
  dependsOn: [ adxDatabase ]
}

// ── Outputs ─────────────────────────────────────────────────────────────────

@description('URI for connecting to the ADX cluster.')
output clusterUri string = adxCluster.outputs.clusterUri

@description('Data ingestion URI for the ADX cluster.')
output dataIngestionUri string = adxCluster.outputs.dataIngestionUri

@description('Resource ID of the ADX cluster.')
output clusterId string = adxCluster.outputs.clusterId

@description('Name of the ADX cluster.')
output clusterName string = adxCluster.outputs.clusterName

@description('Name of the primary security database.')
output databaseName string = deployDatabase ? databaseName : ''

@description('Deployment tier used.')
output deploymentTier string = deploymentTier

@description('Hot cache period in days.')
output hotCacheDays int = effectiveHotCache

@description('Soft delete period in days.')
output softDeleteDays int = effectiveSoftDelete

@description('Principal ID of the cluster managed identity.')
output clusterPrincipalId string = adxCluster.outputs.principalId
