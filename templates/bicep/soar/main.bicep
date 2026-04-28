// ============================================================================
// SOAR Playbook Orchestrator — Main Deployment Template
// Deploys all 5 SOAR playbooks as Bicep modules with conditional deployment.
// Usage: az deployment group create -g <rg> -f main.bicep -p workspaceName=<ws>
// ============================================================================

targetScope = 'resourceGroup'

// ── Shared Parameters ───────────────────────────────────────────────────────

@description('Azure region for all resources. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Name of the Log Analytics workspace backing Microsoft Sentinel.')
param workspaceName string

@description('Resource group containing the Log Analytics workspace (if different from deployment RG).')
param workspaceResourceGroup string = resourceGroup().name

@description('Microsoft Teams team ID for SOC notifications.')
param teamsTeamId string

@description('Tags applied to every deployed resource.')
param tags object = {
  solution: 'secops-squad'
  deployedBy: 'bicep'
  component: 'soar-playbooks'
}

// ── Playbook Toggle Parameters ──────────────────────────────────────────────

@description('Deploy the Phishing Response playbook.')
param deployPhishing bool = true

@description('Deploy the Compromised Account Response playbook.')
param deployCompromisedAccount bool = true

@description('Deploy the Malware Containment playbook.')
param deployMalware bool = true

@description('Deploy the IP Enrichment playbook.')
param deployIpEnrichment bool = true

@description('Deploy the Teams SOC Notification playbook.')
param deployTeamsNotification bool = true

// ── Phishing Response Parameters ────────────────────────────────────────────

@description('Teams channel ID for phishing response notifications.')
param phishingTeamsChannelId string = ''

@description('Email address of the Exchange / mail admin for phishing escalation.')
param emailAdmin string = ''

// ── Compromised Account Parameters ──────────────────────────────────────────

@description('Teams channel ID for compromised account notifications.')
param compromisedTeamsChannelId string = ''

@description('Minimum incident severity that triggers account disable.')
@allowed([ 'High', 'Medium', 'Low', 'Informational' ])
param riskThreshold string = 'High'

// ── Malware Containment Parameters ──────────────────────────────────────────

@description('Teams channel ID for malware containment notifications.')
param malwareTeamsChannelId string = ''

@description('Minimum severity for automatic device isolation.')
@allowed([ 'High', 'Medium', 'Low' ])
param autoIsolateThreshold string = 'High'

// ── IP Enrichment Parameters ────────────────────────────────────────────────

@secure()
@description('VirusTotal API key (optional). Leave empty to skip VT enrichment.')
param virusTotalApiKey string = ''

@description('Sentinel watchlist alias for known-malicious IPs.')
param tiWatchlistAlias string = 'IPWatchlist'

// ── Teams Notification Parameters ───────────────────────────────────────────

@description('Teams channel ID for Critical severity incidents.')
param criticalChannelId string = ''

@description('Teams channel ID for High severity incidents.')
param highChannelId string = ''

@description('Teams channel ID for Medium severity incidents.')
param mediumChannelId string = ''

@description('Teams channel ID for Low/Informational severity incidents.')
param lowChannelId string = ''

@description('Use rich Adaptive Cards for Teams notifications.')
param useAdaptiveCard bool = true

// ── Module Deployments ──────────────────────────────────────────────────────

module phishingResponse 'phishing-response.bicep' = if (deployPhishing) {
  name: 'deploy-phishing-response'
  params: {
    location: location
    workspaceName: workspaceName
    workspaceResourceGroup: workspaceResourceGroup
    teamsChannelId: phishingTeamsChannelId
    teamsTeamId: teamsTeamId
    emailAdmin: emailAdmin
    tags: union(tags, { playbook: 'phishing-response' })
  }
}

module compromisedAccount 'compromised-account.bicep' = if (deployCompromisedAccount) {
  name: 'deploy-compromised-account'
  params: {
    location: location
    workspaceName: workspaceName
    workspaceResourceGroup: workspaceResourceGroup
    teamsChannelId: compromisedTeamsChannelId
    teamsTeamId: teamsTeamId
    riskThreshold: riskThreshold
    tags: union(tags, { playbook: 'compromised-account' })
  }
}

module malwareContainment 'malware-containment.bicep' = if (deployMalware) {
  name: 'deploy-malware-containment'
  params: {
    location: location
    workspaceName: workspaceName
    workspaceResourceGroup: workspaceResourceGroup
    teamsChannelId: malwareTeamsChannelId
    teamsTeamId: teamsTeamId
    autoIsolateThreshold: autoIsolateThreshold
    tags: union(tags, { playbook: 'malware-containment' })
  }
}

module ipEnrichment 'ip-enrichment.bicep' = if (deployIpEnrichment) {
  name: 'deploy-ip-enrichment'
  params: {
    location: location
    workspaceName: workspaceName
    workspaceResourceGroup: workspaceResourceGroup
    virusTotalApiKey: virusTotalApiKey
    tiWatchlistAlias: tiWatchlistAlias
    tags: union(tags, { playbook: 'ip-enrichment' })
  }
}

module teamsNotification 'teams-notification.bicep' = if (deployTeamsNotification) {
  name: 'deploy-teams-notification'
  params: {
    location: location
    workspaceName: workspaceName
    workspaceResourceGroup: workspaceResourceGroup
    teamsTeamId: teamsTeamId
    criticalChannelId: criticalChannelId
    highChannelId: highChannelId
    mediumChannelId: mediumChannelId
    lowChannelId: lowChannelId
    useAdaptiveCard: useAdaptiveCard
    tags: union(tags, { playbook: 'teams-notification' })
  }
}

// ── Outputs ─────────────────────────────────────────────────────────────────

@description('Resource ID of the Phishing Response Logic App (empty if not deployed).')
output phishingLogicAppId string = deployPhishing ? phishingResponse.outputs.logicAppId : ''

@description('Resource ID of the Compromised Account Logic App (empty if not deployed).')
output compromisedAccountLogicAppId string = deployCompromisedAccount ? compromisedAccount.outputs.logicAppId : ''

@description('Resource ID of the Malware Containment Logic App (empty if not deployed).')
output malwareLogicAppId string = deployMalware ? malwareContainment.outputs.logicAppId : ''

@description('Resource ID of the IP Enrichment Logic App (empty if not deployed).')
output ipEnrichmentLogicAppId string = deployIpEnrichment ? ipEnrichment.outputs.logicAppId : ''

@description('Resource ID of the Teams Notification Logic App (empty if not deployed).')
output teamsNotificationLogicAppId string = deployTeamsNotification ? teamsNotification.outputs.logicAppId : ''
