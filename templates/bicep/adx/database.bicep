// ============================================================================
// ADX Database — Security Database Configuration
// Creates a Kusto database with configurable retention, hot cache periods,
// and role assignments for security data lake operations.
// ============================================================================

targetScope = 'resourceGroup'

// ── Parameters ──────────────────────────────────────────────────────────────

@description('Name of the existing ADX cluster.')
param clusterName string

@description('Name of the database to create.')
param databaseName string = 'SecurityLake'

@description('Hot cache period in days. Data within this window is kept on SSD for fast queries.')
@minValue(1)
@maxValue(365)
param hotCacheDays int = 31

@description('Soft delete period in days. Data is retained for this duration before permanent deletion.')
@minValue(1)
@maxValue(3650)
param softDeleteDays int = 365

@description('Azure region. Defaults to resource group location.')
param location string = resourceGroup().location

@description('Principal IDs to assign the Admin role on this database.')
param adminPrincipalIds array = []

@description('Principal type for admin role assignments.')
@allowed([ 'App', 'Group', 'User' ])
param adminPrincipalType string = 'Group'

@description('Principal IDs to assign the Viewer role on this database.')
param viewerPrincipalIds array = []

@description('Principal type for viewer role assignments.')
@allowed([ 'App', 'Group', 'User' ])
param viewerPrincipalType string = 'Group'

@description('Principal IDs to assign the Ingestor role on this database.')
param ingestorPrincipalIds array = []

@description('Principal type for ingestor role assignments.')
@allowed([ 'App', 'Group', 'User' ])
param ingestorPrincipalType string = 'App'

@description('Environment tag value.')
@allowed([ 'dev', 'staging', 'production' ])
param environment string = 'production'

@description('Project tag value.')
param project string = 'secops-squad'

@description('Cost center tag value.')
param costCenter string = ''

@description('Additional tags applied to resources.')
param tags object = {}

// ── Variables ───────────────────────────────────────────────────────────────

var _baseTags = {
  solution: 'secops-squad'
  component: 'adx-database'
  deployedBy: 'bicep'
  environment: environment
  project: project
}
var _costTag = !empty(costCenter) ? { costCenter: costCenter } : {}
#disable-next-line no-unused-vars
var mergedTags = union(_baseTags, _costTag, tags)

// Build the principals array for database-level role assignments
var adminPrincipals = [for id in adminPrincipalIds: {
  name: 'admin-${id}'
  role: 'Admin'
  type: adminPrincipalType
  fqn: adminPrincipalType == 'App' ? 'aadapp=${id}' : adminPrincipalType == 'Group' ? 'aadgroup=${id}' : 'aaduser=${id}'
}]
var viewerPrincipals = [for id in viewerPrincipalIds: {
  name: 'viewer-${id}'
  role: 'Viewer'
  type: viewerPrincipalType
  fqn: viewerPrincipalType == 'App' ? 'aadapp=${id}' : viewerPrincipalType == 'Group' ? 'aadgroup=${id}' : 'aaduser=${id}'
}]
var ingestorPrincipals = [for id in ingestorPrincipalIds: {
  name: 'ingestor-${id}'
  role: 'Ingestor'
  type: ingestorPrincipalType
  fqn: ingestorPrincipalType == 'App' ? 'aadapp=${id}' : ingestorPrincipalType == 'Group' ? 'aadgroup=${id}' : 'aaduser=${id}'
}]
var allPrincipals = concat(adminPrincipals, viewerPrincipals, ingestorPrincipals)

// ── Existing Cluster ────────────────────────────────────────────────────────

resource cluster 'Microsoft.Kusto/clusters@2023-08-15' existing = {
  name: clusterName
}

// ── Database ────────────────────────────────────────────────────────────────

resource database 'Microsoft.Kusto/clusters/databases@2023-08-15' = {
  parent: cluster
  name: databaseName
  location: location
  kind: 'ReadWrite'
  properties: {
    hotCachePeriod: 'P${hotCacheDays}D'
    softDeletePeriod: 'P${softDeleteDays}D'
  }
}

// ── Database Principal Assignments ──────────────────────────────────────────

resource principalAssignments 'Microsoft.Kusto/clusters/databases/principalAssignments@2023-08-15' = [for principal in allPrincipals: {
  parent: database
  name: principal.name
  properties: {
    principalId: replace(replace(replace(principal.fqn, 'aadapp=', ''), 'aadgroup=', ''), 'aaduser=', '')
    role: principal.role
    principalType: principal.type
    tenantId: tenant().tenantId
  }
}]

// ── Outputs ─────────────────────────────────────────────────────────────────

@description('Resource ID of the created database.')
output databaseId string = database.id

@description('Name of the created database.')
output databaseName string = database.name

@description('Hot cache period configured on the database.')
output hotCachePeriod string = 'P${hotCacheDays}D'

@description('Soft delete period configured on the database.')
output softDeletePeriod string = 'P${softDeleteDays}D'
