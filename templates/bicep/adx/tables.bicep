// ============================================================================
// ADX Security Tables — Pre-built Table Schemas for Security Data Lake
// Creates security-focused tables via KQL script resources including:
// SecurityEvents, NetworkTraffic, ThreatIntelligence, IdentityEvents, CloudAudit
// Each table includes retention policies, update policies, and docstrings.
// ============================================================================

targetScope = 'resourceGroup'

// ── Parameters ──────────────────────────────────────────────────────────────

@description('Name of the existing ADX cluster.')
param clusterName string

@description('Name of the existing database to create tables in.')
param databaseName string = 'SecurityLake'

@description('Deploy the SecurityEvents table (Windows Security logs).')
param deploySecurityEvents bool = true

@description('Deploy the NetworkTraffic table (firewall/NSG flow logs).')
param deployNetworkTraffic bool = true

@description('Deploy the ThreatIntelligence table (IOC storage).')
param deployThreatIntelligence bool = true

@description('Deploy the IdentityEvents table (sign-in and audit logs).')
param deployIdentityEvents bool = true

@description('Deploy the CloudAudit table (Azure activity logs).')
param deployCloudAudit bool = true

@description('Default retention period in days for all tables. Reserved for future per-table override.')
@minValue(1)
@maxValue(3650)
#disable-next-line no-unused-params
param retentionDays int = 365

@description('Hot cache period in days for tables. Reserved for future per-table override.')
@minValue(1)
@maxValue(365)
#disable-next-line no-unused-params
param hotCacheDays int = 31

@description('Force script re-execution by changing this value (e.g., timestamp or version).')
param forceUpdateTag string = utcNow()

// ── Existing Resources ──────────────────────────────────────────────────────

resource cluster 'Microsoft.Kusto/clusters@2023-08-15' existing = {
  name: clusterName
}

resource database 'Microsoft.Kusto/clusters/databases@2023-08-15' existing = {
  parent: cluster
  name: databaseName
}

// ── SecurityEvents Table ────────────────────────────────────────────────────

resource securityEventsScript 'Microsoft.Kusto/clusters/databases/scripts@2023-08-15' = if (deploySecurityEvents) {
  parent: database
  name: 'createSecurityEvents'
  properties: {
    forceUpdateTag: forceUpdateTag
    continueOnErrors: false
    scriptContent: loadTextContent('scripts/security-events.kql')
  }
}

// ── NetworkTraffic Table ────────────────────────────────────────────────────

resource networkTrafficScript 'Microsoft.Kusto/clusters/databases/scripts@2023-08-15' = if (deployNetworkTraffic) {
  parent: database
  name: 'createNetworkTraffic'
  properties: {
    forceUpdateTag: forceUpdateTag
    continueOnErrors: false
    scriptContent: loadTextContent('scripts/network-traffic.kql')
  }
  dependsOn: [ securityEventsScript ]
}

// ── ThreatIntelligence Table ────────────────────────────────────────────────

resource threatIntelScript 'Microsoft.Kusto/clusters/databases/scripts@2023-08-15' = if (deployThreatIntelligence) {
  parent: database
  name: 'createThreatIntelligence'
  properties: {
    forceUpdateTag: forceUpdateTag
    continueOnErrors: false
    scriptContent: loadTextContent('scripts/threat-intelligence.kql')
  }
  dependsOn: [ networkTrafficScript ]
}

// ── IdentityEvents Table ────────────────────────────────────────────────────

resource identityEventsScript 'Microsoft.Kusto/clusters/databases/scripts@2023-08-15' = if (deployIdentityEvents) {
  parent: database
  name: 'createIdentityEvents'
  properties: {
    forceUpdateTag: forceUpdateTag
    continueOnErrors: false
    scriptContent: loadTextContent('scripts/identity-events.kql')
  }
  dependsOn: [ threatIntelScript ]
}

// ── CloudAudit Table ────────────────────────────────────────────────────────

resource cloudAuditScript 'Microsoft.Kusto/clusters/databases/scripts@2023-08-15' = if (deployCloudAudit) {
  parent: database
  name: 'createCloudAudit'
  properties: {
    forceUpdateTag: forceUpdateTag
    continueOnErrors: false
    scriptContent: loadTextContent('scripts/cloud-audit.kql')
  }
  dependsOn: [ identityEventsScript ]
}

// ── Outputs ─────────────────────────────────────────────────────────────────

@description('List of deployed table names.')
output deployedTables array = union(
  deploySecurityEvents ? [ 'SecurityEvents' ] : [],
  deployNetworkTraffic ? [ 'NetworkTraffic' ] : [],
  deployThreatIntelligence ? [ 'ThreatIntelligence' ] : [],
  deployIdentityEvents ? [ 'IdentityEvents' ] : [],
  deployCloudAudit ? [ 'CloudAudit' ] : []
)
