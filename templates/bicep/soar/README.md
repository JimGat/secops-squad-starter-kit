# SOAR Playbook Bicep Templates

Production-ready Bicep templates for deploying Microsoft Sentinel SOAR playbooks as Azure Logic Apps.

## Playbooks

| Template | Trigger | Description |
|---|---|---|
| `phishing-response.bicep` | Sentinel Incident | Phishing triage → email purge → mailbox rule check → Teams notification |
| `compromised-account.bicep` | Sentinel Incident | Session revocation → MFA reset → conditional account disable → Teams notification |
| `malware-containment.bicep` | Sentinel Incident | Device isolation (MDE) → investigation package → timeline → Teams notification |
| `ip-enrichment.bicep` | Sentinel Entity (IP) | GeoIP + watchlist + optional VirusTotal → enrichment comment → TI indicator |
| `teams-notification.bicep` | Sentinel Incident | Severity-mapped channel routing with rich Adaptive Cards |
| `main.bicep` | — | Orchestrator that deploys all 5 playbooks as modules |

## Prerequisites

1. **Azure subscription** with Contributor access to the target resource group
2. **Microsoft Sentinel** workspace (Log Analytics with Sentinel solution enabled)
3. **Azure CLI** with Bicep support (`az bicep install`)
4. **API permissions** (granted post-deployment):
   - Microsoft Sentinel Responder role (auto-assigned via managed identity)
   - Teams channel message send permissions
   - Exchange Online admin permissions (phishing playbook)
   - Entra ID User.ReadWrite.All (compromised account playbook)
   - Microsoft Defender for Endpoint Machine.Isolate (malware playbook)

## Deployment

### Deploy all playbooks

```bash
az deployment group create \
  --resource-group <your-rg> \
  --template-file main.bicep \
  --parameters \
    workspaceName=<sentinel-workspace> \
    teamsTeamId=<teams-team-guid> \
    phishingTeamsChannelId=<channel-id> \
    compromisedTeamsChannelId=<channel-id> \
    malwareTeamsChannelId=<channel-id> \
    criticalChannelId=<channel-id> \
    highChannelId=<channel-id> \
    mediumChannelId=<channel-id> \
    lowChannelId=<channel-id> \
    emailAdmin=secops@contoso.com
```

### Deploy a single playbook

```bash
# Example: phishing response only
az deployment group create \
  --resource-group <your-rg> \
  --template-file phishing-response.bicep \
  --parameters \
    workspaceName=<sentinel-workspace> \
    teamsChannelId=<channel-id> \
    teamsTeamId=<teams-team-guid> \
    emailAdmin=secops@contoso.com
```

### Deploy selected playbooks via orchestrator

```bash
# Only phishing + teams notification
az deployment group create \
  --resource-group <your-rg> \
  --template-file main.bicep \
  --parameters \
    workspaceName=<sentinel-workspace> \
    teamsTeamId=<teams-team-guid> \
    deployPhishing=true \
    deployCompromisedAccount=false \
    deployMalware=false \
    deployIpEnrichment=false \
    deployTeamsNotification=true \
    phishingTeamsChannelId=<channel-id> \
    emailAdmin=secops@contoso.com \
    criticalChannelId=<channel-id> \
    highChannelId=<channel-id> \
    mediumChannelId=<channel-id> \
    lowChannelId=<channel-id>
```

### Deploy with VirusTotal integration

```bash
az deployment group create \
  --resource-group <your-rg> \
  --template-file ip-enrichment.bicep \
  --parameters \
    workspaceName=<sentinel-workspace> \
    virusTotalApiKey=<your-vt-api-key>
```

## Post-Deployment Steps

### 1. Authorize API Connections

After deployment, each API connection must be authorized in the Azure Portal:

1. Navigate to **Resource Group** → filter by type **API Connection**
2. For each connection:
   - Click the connection → **Edit API connection** → **Authorize** → sign in
   - The **azuresentinel** connection uses managed identity (auto-authorized)
   - **teams**, **office365**, and **azuread** connections require interactive OAuth consent

### 2. Enable the Playbook in Sentinel

1. Go to **Microsoft Sentinel** → **Automation** → **Active playbooks**
2. Verify each Logic App appears and is **Enabled**
3. Click **Manage permissions** → grant the Logic App access to your Sentinel workspace

### 3. Create Automation Rules

Attach playbooks to specific analytics rules:

1. **Sentinel** → **Automation** → **Create** → **Automation rule**
2. Set trigger conditions (e.g., incident provider = "Microsoft Defender for Office 365")
3. Add action → **Run playbook** → select the deployed Logic App

### 4. Test the Playbook

1. Create a test incident in Sentinel (or use a test analytics rule)
2. Monitor the Logic App run history: **Logic App** → **Overview** → **Run history**
3. Verify Teams notifications appear in the configured channels

## Parameter Reference

### Shared Parameters (main.bicep)

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `workspaceName` | string | ✅ | — | Sentinel Log Analytics workspace name |
| `workspaceResourceGroup` | string | | current RG | Workspace resource group (if cross-RG) |
| `teamsTeamId` | string | ✅ | — | Teams team GUID |
| `location` | string | | RG location | Azure region |
| `tags` | object | | see template | Resource tags |
| `deployPhishing` | bool | | `true` | Toggle phishing playbook |
| `deployCompromisedAccount` | bool | | `true` | Toggle compromised account playbook |
| `deployMalware` | bool | | `true` | Toggle malware playbook |
| `deployIpEnrichment` | bool | | `true` | Toggle IP enrichment playbook |
| `deployTeamsNotification` | bool | | `true` | Toggle Teams notification playbook |

### Playbook-Specific Parameters

| Parameter | Playbook | Type | Description |
|---|---|---|---|
| `emailAdmin` | phishing | string | Exchange admin email for escalation |
| `riskThreshold` | compromised-account | string | Severity that triggers account disable |
| `autoIsolateThreshold` | malware | string | Severity that triggers device isolation |
| `virusTotalApiKey` | ip-enrichment | secureString | VT API key (optional) |
| `tiWatchlistAlias` | ip-enrichment | string | Sentinel watchlist alias |
| `criticalChannelId` | teams-notification | string | Teams channel for Critical incidents |
| `highChannelId` | teams-notification | string | Teams channel for High incidents |
| `mediumChannelId` | teams-notification | string | Teams channel for Medium incidents |
| `lowChannelId` | teams-notification | string | Teams channel for Low incidents |
| `useAdaptiveCard` | teams-notification | bool | Adaptive Cards vs plain HTML |

## Troubleshooting

### "API connection not authorized"

The API connections for Teams, Office 365, and Entra ID require interactive OAuth authorization after deployment. Navigate to the API connection resource in the portal and click **Authorize**.

### "Managed identity does not have required permissions"

The template auto-assigns **Sentinel Responder** and **Sentinel Reader** roles. If the role assignment fails (e.g., insufficient permissions), manually assign via:

```bash
# Get the Logic App principal ID from deployment outputs
PRINCIPAL_ID=$(az deployment group show -g <rg> -n deploy-phishing-response --query properties.outputs.principalId.value -o tsv)

# Assign Sentinel Responder
az role assignment create \
  --assignee-object-id $PRINCIPAL_ID \
  --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Responder" \
  --scope "/subscriptions/<sub-id>/resourceGroups/<rg>"
```

### "Logic App trigger not firing"

1. Verify the playbook is enabled in **Sentinel → Automation → Active playbooks**
2. Check that an **automation rule** is configured to trigger the playbook
3. Ensure the managed identity has **Microsoft Sentinel Responder** permissions

### "Teams message not posting"

1. Re-authorize the Teams API connection
2. Verify the Teams channel ID and team ID are correct
3. Check that the authorizing user has permission to post in the target channel

### "VirusTotal lookups failing"

The IP enrichment playbook gracefully degrades when VT is unavailable. Check:
1. API key is valid and has remaining quota
2. Network connectivity from Logic App to `www.virustotal.com`
3. Run history will show the VT step as "Skipped" if no API key was provided

## Architecture

```
main.bicep (orchestrator)
  ├── phishing-response.bicep      → Logic App + Sentinel/Teams/O365/EntraID connections
  ├── compromised-account.bicep    → Logic App + Sentinel/EntraID/Teams connections
  ├── malware-containment.bicep    → Logic App + Sentinel/MDE/Teams connections
  ├── ip-enrichment.bicep          → Logic App + Sentinel connection + HTTP actions
  └── teams-notification.bicep     → Logic App + Sentinel/Teams connections
```

Each playbook deploys:
- **Logic App** (Consumption tier) with system-assigned managed identity
- **API connections** for required services
- **Role assignments** for Sentinel Responder and/or Reader
- **Tags** for resource governance
