// ============================================================================
// ADX Ingestion — Data Ingestion Pipeline Configuration
// Configures Event Hub, IoT Hub, and Event Grid data connections
// for streaming security data into ADX with managed identity access.
// ============================================================================

targetScope = 'resourceGroup'

// ── Parameters ──────────────────────────────────────────────────────────────

@description('Azure region for all resources. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Name of the existing ADX cluster.')
param clusterName string

@description('Name of the existing ADX database.')
param databaseName string = 'SecurityLake'

// ── Event Hub Parameters ────────────────────────────────────────────────────

@description('Deploy Event Hub data connection for streaming ingestion.')
param deployEventHubConnection bool = true

@description('Resource ID of the Event Hub namespace.')
param eventHubNamespaceId string = ''

@description('Name of the Event Hub for security log ingestion.')
param eventHubName string = 'security-logs'

@description('Consumer group name for ADX ingestion from Event Hub.')
param eventHubConsumerGroup string = 'adx-ingestion'

@description('Target table name for Event Hub data connection.')
param eventHubTableName string = 'SecurityEvents_Raw'

@description('Ingestion mapping reference name for Event Hub data.')
param eventHubMappingName string = ''

@description('Data format for Event Hub messages.')
@allowed([ 'JSON', 'MULTIJSON', 'CSV', 'TSV', 'AVRO', 'APACHEAVRO', 'ORC', 'PARQUET', 'PSV', 'RAW', 'SCSV', 'SOHSV', 'TXT', 'W3CLOGFILE' ])
param eventHubDataFormat string = 'MULTIJSON'

@description('Event Hub namespace resource group (for role assignment scope).')
param eventHubResourceGroup string = resourceGroup().name

@description('Event Hub namespace name (extracted for role assignment).')
param eventHubNamespaceName string = ''

// ── IoT Hub Parameters ──────────────────────────────────────────────────────

@description('Deploy IoT Hub data connection.')
param deployIotHubConnection bool = false

@description('Resource ID of the IoT Hub.')
param iotHubResourceId string = ''

@description('Shared access policy name for IoT Hub.')
param iotHubSharedAccessPolicyName string = 'iothubowner'

@description('Consumer group name for ADX ingestion from IoT Hub.')
param iotHubConsumerGroup string = 'adx-ingestion'

@description('Target table name for IoT Hub data connection.')
param iotHubTableName string = 'NetworkTraffic_Raw'

@description('Ingestion mapping reference name for IoT Hub data.')
param iotHubMappingName string = ''

@description('Data format for IoT Hub messages.')
@allowed([ 'JSON', 'MULTIJSON', 'CSV', 'AVRO', 'APACHEAVRO', 'ORC', 'PARQUET' ])
param iotHubDataFormat string = 'MULTIJSON'

// ── Event Grid Parameters ───────────────────────────────────────────────────

@description('Deploy Event Grid data connection for blob-triggered ingestion.')
param deployEventGridConnection bool = false

@description('Resource ID of the storage account for Event Grid blob ingestion.')
param storageAccountId string = ''

@description('Resource ID of the Event Hub used by Event Grid for notification delivery.')
param eventGridEventHubId string = ''

@description('Consumer group for Event Grid notification Event Hub.')
param eventGridConsumerGroup string = '$Default'

@description('Target table name for Event Grid data connection.')
param eventGridTableName string = 'CloudAudit_Raw'

@description('Ingestion mapping reference name for Event Grid data.')
param eventGridMappingName string = ''

@description('Data format for Event Grid blob data.')
@allowed([ 'JSON', 'MULTIJSON', 'CSV', 'AVRO', 'APACHEAVRO', 'ORC', 'PARQUET', 'PSV', 'RAW' ])
param eventGridDataFormat string = 'MULTIJSON'

@description('Blob storage event type to react to.')
@allowed([ 'Microsoft.Storage.BlobCreated', 'Microsoft.Storage.BlobRenamed' ])
param eventGridBlobEventType string = 'Microsoft.Storage.BlobCreated'

// ── Managed Identity Parameters ─────────────────────────────────────────────

@description('Assign Event Hub Data Receiver role to the ADX cluster managed identity.')
param assignEventHubRole bool = true

// ── Tags ────────────────────────────────────────────────────────────────────

@description('Environment tag value.')
@allowed([ 'dev', 'staging', 'production' ])
param environment string = 'production'

@description('Project tag value.')
param project string = 'secops-squad'

@description('Cost center tag value.')
param costCenter string = ''

@description('Additional tags.')
param tags object = {}

// ── Variables ───────────────────────────────────────────────────────────────

var _baseTags = {
  solution: 'secops-squad'
  component: 'adx-ingestion'
  deployedBy: 'bicep'
  environment: environment
  project: project
}
var _costTag = !empty(costCenter) ? { costCenter: costCenter } : {}
#disable-next-line no-unused-vars
var mergedTags = union(_baseTags, _costTag, tags)

// Azure Event Hubs Data Receiver role
var eventHubDataReceiverRoleId = 'a638d3c7-ab3a-418d-83e6-5f17a39d4fde'

// ── Existing Resources ──────────────────────────────────────────────────────

resource cluster 'Microsoft.Kusto/clusters@2023-08-15' existing = {
  name: clusterName
}

resource database 'Microsoft.Kusto/clusters/databases@2023-08-15' existing = {
  parent: cluster
  name: databaseName
}

// ── Event Hub Consumer Group & Role Assignment ──────────────────────────────
// When Event Hub is in the SAME resource group, we create the consumer group
// and role assignment directly. For cross-RG Event Hubs, create the consumer
// group and role assignment separately (see README troubleshooting).

resource ehNamespace 'Microsoft.EventHub/namespaces@2024-01-01' existing = if (deployEventHubConnection && !empty(eventHubNamespaceName) && eventHubResourceGroup == resourceGroup().name) {
  name: eventHubNamespaceName
}

resource ehEntity 'Microsoft.EventHub/namespaces/eventhubs@2024-01-01' existing = if (deployEventHubConnection && !empty(eventHubNamespaceName) && eventHubResourceGroup == resourceGroup().name) {
  parent: ehNamespace
  name: eventHubName
}

resource consumerGroup 'Microsoft.EventHub/namespaces/eventhubs/consumergroups@2024-01-01' = if (deployEventHubConnection && !empty(eventHubNamespaceName) && eventHubResourceGroup == resourceGroup().name && eventHubConsumerGroup != '$Default') {
  parent: ehEntity
  name: eventHubConsumerGroup
  properties: {
    userMetadata: 'ADX ingestion consumer group for ${clusterName}/${databaseName}'
  }
}

resource eventHubRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (assignEventHubRole && deployEventHubConnection && !empty(eventHubNamespaceName) && eventHubResourceGroup == resourceGroup().name) {
  name: guid(cluster.id, eventHubDataReceiverRoleId, eventHubNamespaceId)
  scope: ehNamespace
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', eventHubDataReceiverRoleId)
    principalId: cluster.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ── Event Hub Data Connection ───────────────────────────────────────────────

resource eventHubConnection 'Microsoft.Kusto/clusters/databases/dataConnections@2023-08-15' = if (deployEventHubConnection && !empty(eventHubNamespaceId)) {
  parent: database
  name: 'eh-${eventHubName}'
  location: location
  kind: 'EventHub'
  properties: {
    eventHubResourceId: '${eventHubNamespaceId}/eventhubs/${eventHubName}'
    consumerGroup: eventHubConsumerGroup
    tableName: eventHubTableName
    mappingRuleName: !empty(eventHubMappingName) ? eventHubMappingName : null
    dataFormat: eventHubDataFormat
    managedIdentityResourceId: cluster.id
    databaseRouting: 'Single'
    compression: 'None'
  }
  dependsOn: [
    consumerGroup
    eventHubRoleAssignment
  ]
}

// ── IoT Hub Data Connection ─────────────────────────────────────────────────

resource iotHubConnection 'Microsoft.Kusto/clusters/databases/dataConnections@2023-08-15' = if (deployIotHubConnection && !empty(iotHubResourceId)) {
  parent: database
  name: 'iot-connection'
  location: location
  kind: 'IotHub'
  properties: {
    iotHubResourceId: iotHubResourceId
    sharedAccessPolicyName: iotHubSharedAccessPolicyName
    consumerGroup: iotHubConsumerGroup
    tableName: iotHubTableName
    mappingRuleName: !empty(iotHubMappingName) ? iotHubMappingName : null
    dataFormat: iotHubDataFormat
    databaseRouting: 'Single'
  }
}

// ── Event Grid Data Connection ──────────────────────────────────────────────

resource eventGridConnection 'Microsoft.Kusto/clusters/databases/dataConnections@2023-08-15' = if (deployEventGridConnection && !empty(storageAccountId) && !empty(eventGridEventHubId)) {
  parent: database
  name: 'eg-blob-ingestion'
  location: location
  kind: 'EventGrid'
  properties: {
    storageAccountResourceId: storageAccountId
    eventGridResourceId: ''
    eventHubResourceId: eventGridEventHubId
    consumerGroup: eventGridConsumerGroup
    tableName: eventGridTableName
    mappingRuleName: !empty(eventGridMappingName) ? eventGridMappingName : null
    dataFormat: eventGridDataFormat
    blobStorageEventType: eventGridBlobEventType
    ignoreFirstRecord: false
    managedIdentityResourceId: cluster.id
    databaseRouting: 'Single'
  }
}

// ── Outputs ─────────────────────────────────────────────────────────────────

@description('Event Hub data connection name (empty if not deployed).')
output eventHubConnectionName string = deployEventHubConnection && !empty(eventHubNamespaceId) ? eventHubConnection.name : ''

@description('IoT Hub data connection name (empty if not deployed).')
output iotHubConnectionName string = deployIotHubConnection && !empty(iotHubResourceId) ? iotHubConnection.name : ''

@description('Event Grid data connection name (empty if not deployed).')
output eventGridConnectionName string = deployEventGridConnection && !empty(storageAccountId) ? eventGridConnection.name : ''
