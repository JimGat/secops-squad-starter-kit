# Bicep Templates — secops-squad Infrastructure as Code

Bicep templates for deploying Microsoft Sentinel SOAR playbooks and Azure Data Explorer security data lake infrastructure. All templates integrate with the Phase 2 PowerShell wrapper skills for post-deployment configuration and the `.secops/` customer knowledge framework for environment-aware deployments.

## Template Inventory

### SOAR Playbook Templates (`soar/`)

| Template | Type | Trigger | Description |
|---|---|---|---|
| `main.bicep` | Orchestrator | — | Deploys all 5 SOAR playbooks with conditional toggles |
| `phishing-response.bicep` | Logic App | Sentinel Incident | Phishing triage → email purge → mailbox rule check → Teams notification |
| `compromised-account.bicep` | Logic App | Sentinel Incident | Session revocation → MFA reset → conditional account disable → Teams |
| `malware-containment.bicep` | Logic App | Sentinel Incident | MDE device isolation → investigation package → timeline → Teams |
| `ip-enrichment.bicep` | Logic App | Sentinel Entity (IP) | GeoIP + watchlist + optional VirusTotal → enrichment comment → TI indicator |
| `teams-notification.bicep` | Logic App | Sentinel Incident | Severity-mapped channel routing with rich Adaptive Cards |

### ADX Security Data Lake Templates (`adx/`)

| Template | Type | Description |
|---|---|---|
| `main.bicep` | Orchestrator | Deploys complete ADX security data lake (cluster + database + tables + ingestion) |
| `cluster.bicep` | ADX Cluster | Kusto cluster with managed identity, diagnostics, auto-scale, optional CMK/VNet |
| `database.bicep` | ADX Database | SecurityLake database with retention, hot cache, and role assignments |
| `tables.bicep` | KQL Scripts | 5 pre-built security tables (SecurityEvents, NetworkTraffic, ThreatIntelligence, IdentityEvents, CloudAudit) |
| `ingestion.bicep` | Data Connections | Event Hub, IoT Hub, and Event Grid data connections for streaming ingestion |

## Phase 2 PowerShell Wrapper Integration

These templates deploy Azure infrastructure. Post-deployment configuration — automation rules, API connection authorization, data tiering, MCP registration — is handled by PowerShell wrapper skills from Phase 2.

### Skill Cross-Reference

| Skill | Templates That Reference It | What It Configures |
|---|---|---|
| `skills/powershell/sentinel-api-wrapper.md` | All SOAR templates, ADX main/tables | Automation rules, incident config, watchlists, data connectors, cross-resource queries |
| `skills/powershell/defender-api-wrapper.md` | phishing-response, malware-containment, compromised-account | MDE machine actions, identity protection, Office 365 integration |
| `skills/powershell/data-tiering-commands.md` | All ADX templates | Table tiers, retention policies, cost analysis, ingestion validation |
| `skills/powershell/rate-limiting.md` | All templates | API throttling limits for ARM, Graph, MDE, Sentinel, Event Hub |
| `skills/msft-security/sentinel-mcp-server.md` | ADX main, ADX cluster | MCP Server registration for agent-based KQL execution |
| `skills/soar/workbook-automation.md` | SOAR main, ADX tables | SOC dashboard deployment, workbook lifecycle management |

### Post-Deployment Automation Flow

After `az deployment group create` completes, run the appropriate PowerShell script:

```bash
# SOAR playbooks — configure all deployed playbooks
./scripts/Configure-SoarPlaybooks.ps1 \
  -ResourceGroup <rg> \
  -WorkspaceName <sentinel-workspace>

# ADX security data lake — configure tiering and ingestion
./scripts/Configure-AdxSecurityLake.ps1 \
  -ClusterName <adx-cluster> \
  -Tier <dev|standard|production>
```

These scripts:
1. Read `.secops/workspaces/*.yaml` for workspace context
2. Configure Sentinel automation rules linking playbooks to analytics rules
3. Validate API connection authorization status
4. Set up data tiering policies aligned with compliance requirements
5. Register ADX cluster with MCP Server for agent access
6. Update `.secops/data-sources/data-source-map.yaml` with deployed resources

## Pre-Deployment Checklist

### 1. `.secops/` Environment Setup

Before deploying any template, ensure the `.secops/` directory is configured:

```bash
# Initialize .secops/ structure
secops-squad init --secops

# Validate environment configuration
secops-squad env validate
```

Required files:
- `.secops/environment.yaml` — Tenant ID, subscription, cloud type
- `.secops/workspaces/*.yaml` — Log Analytics workspace definitions
- `.secops/data-sources/data-source-map.yaml` — Data source inventory
- `.secops/compliance/requirements.yaml` — Retention and residency rules
- `.secops/identity/tenants.yaml` — Multi-tenant configuration (if applicable)
- `.secops/alerting/routing.yaml` — Severity-to-channel mappings (SOAR templates)

### 2. Azure Permissions

| Template Group | Required Role | Scope |
|---|---|---|
| SOAR playbooks | Contributor + User Access Administrator | Resource Group |
| ADX cluster | Contributor | Resource Group |
| ADX database | Kusto cluster admin | ADX Cluster |
| ADX ingestion | Contributor + Event Hubs Data Receiver | Resource Group + Event Hub |

### 3. Required Modules

```powershell
# Install required PowerShell modules
Install-Module -Name Az.Accounts -MinimumVersion 2.12.0
Install-Module -Name Az.SecurityInsights -MinimumVersion 3.1.0
Install-Module -Name Az.OperationalInsights -MinimumVersion 3.2.0
Install-Module -Name Az.Kusto -MinimumVersion 2.3.0
Install-Module -Name Az.Resources -MinimumVersion 6.0.0
```

### 4. Azure CLI with Bicep

```bash
# Install/update Bicep
az bicep install
az bicep upgrade

# Verify Bicep version (1.0+ recommended)
az bicep version
```

## Template Parameters Cross-Reference

### Shared Parameters (both SOAR and ADX)

| Parameter | Type | SOAR | ADX | Description |
|---|---|---|---|---|
| `location` | string | ✅ | ✅ | Azure region (defaults to RG location) |
| `tags` | object | ✅ | ✅ | Resource tags for governance |
| `workspaceName` | string | ✅ | — | Sentinel Log Analytics workspace name |
| `workspaceResourceGroup` | string | ✅ | — | Workspace RG (if cross-RG deployment) |

### SOAR-Specific Parameters

| Parameter | Template | Type | Required | Description |
|---|---|---|---|---|
| `teamsTeamId` | main, all playbooks | string | ✅ | Teams team GUID for notifications |
| `emailAdmin` | phishing-response | string | ✅ | Exchange admin email for escalation |
| `riskThreshold` | compromised-account | string | | Min severity for account disable (default: High) |
| `autoIsolateThreshold` | malware-containment | string | | Min severity for device isolation (default: High) |
| `virusTotalApiKey` | ip-enrichment | secureString | | VT API key (optional, empty = skip VT) |
| `tiWatchlistAlias` | ip-enrichment | string | | Sentinel watchlist alias (default: IPWatchlist) |
| `criticalChannelId` | teams-notification | string | | Teams channel for Critical incidents |
| `highChannelId` | teams-notification | string | | Teams channel for High incidents |
| `mediumChannelId` | teams-notification | string | | Teams channel for Medium incidents |
| `lowChannelId` | teams-notification | string | | Teams channel for Low incidents |
| `useAdaptiveCard` | teams-notification | bool | | Rich Adaptive Cards vs plain HTML (default: true) |
| `deployPhishing` | main | bool | | Toggle phishing playbook (default: true) |
| `deployCompromisedAccount` | main | bool | | Toggle compromised account (default: true) |
| `deployMalware` | main | bool | | Toggle malware playbook (default: true) |
| `deployIpEnrichment` | main | bool | | Toggle IP enrichment (default: true) |
| `deployTeamsNotification` | main | bool | | Toggle Teams notification (default: true) |

### ADX-Specific Parameters

| Parameter | Template | Type | Required | Description |
|---|---|---|---|---|
| `clusterName` | main, all modules | string | ✅ | ADX cluster name (4-22 lowercase alphanum) |
| `deploymentTier` | main | string | | Tier: dev, standard, production (default: standard) |
| `databaseName` | main, database, tables | string | | Database name (default: SecurityLake) |
| `hotCacheDaysOverride` | main | int | | Override tier default hot cache |
| `softDeleteDaysOverride` | main | int | | Override tier default retention |
| `deployEventHubConnection` | main, ingestion | bool | | Deploy Event Hub ingestion (default: false) |
| `eventHubNamespaceId` | main, ingestion | string | | Event Hub namespace resource ID |
| `enableVnet` | main, cluster | bool | | VNet integration (auto for production) |
| `enableCmkEncryption` | main, cluster | bool | | CMK encryption (auto for production) |

## Post-Deployment Automation Patterns

### Pattern 1: Full SOAR Deployment

```bash
# 1. Validate environment
secops-squad env validate

# 2. Deploy infrastructure
az deployment group create \
  --resource-group mySOCPlaybooks \
  --template-file templates/bicep/soar/main.bicep \
  --parameters workspaceName=mySentinelWorkspace teamsTeamId=<guid> \
    phishingTeamsChannelId=<id> emailAdmin=soc@contoso.com

# 3. Post-deployment configuration (Phase 2 wrappers)
./scripts/Configure-SoarPlaybooks.ps1 \
  -ResourceGroup mySOCPlaybooks \
  -WorkspaceName mySentinelWorkspace

# 4. Verify deployment
secops-squad env data-sources  # Shows deployed playbook connections
```

### Pattern 2: ADX Security Data Lake

```bash
# 1. Validate environment + compliance
secops-squad env validate
# Check: compliance/requirements.yaml for retention mandates

# 2. Deploy infrastructure
az deployment group create \
  --resource-group myADXCluster \
  --template-file templates/bicep/adx/main.bicep \
  --parameters clusterName=adxsec01 deploymentTier=standard

# 3. Post-deployment configuration (Phase 2 wrappers)
./scripts/Configure-AdxSecurityLake.ps1 \
  -ClusterName adxsec01 \
  -Tier standard

# 4. Configure Sentinel cross-resource query
# See skills/powershell/sentinel-api-wrapper.md § Data Connectors

# 5. Register with MCP Server for agent access
# See skills/msft-security/sentinel-mcp-server.md § ADX Integration
```

### Pattern 3: Incremental Playbook Addition

```bash
# Deploy single new playbook to existing SOAR infrastructure
az deployment group create \
  --resource-group mySOCPlaybooks \
  --template-file templates/bicep/soar/ip-enrichment.bicep \
  --parameters workspaceName=mySentinelWorkspace

# Configure only the new playbook
./scripts/Configure-SoarPlaybooks.ps1 \
  -ResourceGroup mySOCPlaybooks \
  -Playbook IpEnrichment
```

## Rate Limiting Considerations

All templates deploy resources that interact with rate-limited APIs. Review `skills/powershell/rate-limiting.md` before deployment:

| API | Limit | Impact on Templates |
|---|---|---|
| ARM (deployments) | 1,200 writes/hr/subscription | Limit concurrent template deployments |
| Microsoft Graph | 10,000 req/10min/app/tenant | Compromised account + phishing playbook actions |
| Defender for Endpoint | 100 calls/min (machine actions) | Malware containment isolation requests |
| Sentinel Incidents | 100 req/min/subscription | All SOAR playbooks (incident updates) |
| Event Hub Ingestion | 1 MB/s per partition | ADX ingestion throughput planning |
| VirusTotal (free tier) | 4 req/min, 500 req/day | IP enrichment playbook pacing |

## Architecture Overview

```
templates/bicep/
├── README.md                        ← This file
├── soar/
│   ├── main.bicep                   → Orchestrates all SOAR playbook modules
│   ├── phishing-response.bicep      → Logic App + Sentinel/Teams/O365/EntraID
│   ├── compromised-account.bicep    → Logic App + Sentinel/EntraID/Teams
│   ├── malware-containment.bicep    → Logic App + Sentinel/MDE/Teams
│   ├── ip-enrichment.bicep          → Logic App + Sentinel + HTTP enrichment
│   └── teams-notification.bicep     → Logic App + Sentinel/Teams routing
└── adx/
    ├── main.bicep                   → Orchestrates complete ADX data lake
    ├── cluster.bicep                → Kusto cluster (identity, diagnostics, scale)
    ├── database.bicep               → SecurityLake DB (retention, roles)
    ├── tables.bicep                 → 5 security tables via KQL scripts
    │   └── scripts/*.kql            → Table creation + update policy KQL
    └── ingestion.bicep              → Event Hub/IoT/Event Grid connections

Post-deployment (Phase 2 PowerShell wrappers):
├── scripts/Configure-SoarPlaybooks.ps1    → Automation rules, API auth, permissions
├── scripts/Configure-AdxSecurityLake.ps1  → Data tiering, MCP, ingestion validation
└── .secops/                               → Customer environment context (read at deploy)
```

## Related Documentation

- **SOAR templates**: `templates/bicep/soar/README.md` — deployment examples, troubleshooting
- **ADX templates**: `templates/bicep/adx/README.md` — tier comparison, parameter reference
- **PowerShell wrappers**: `skills/powershell/README.md` — module architecture overview
- **Sentinel API**: `skills/powershell/sentinel-api-wrapper.md` — REST API wrappers
- **Defender API**: `skills/powershell/defender-api-wrapper.md` — MDE/XDR wrappers
- **Data tiering**: `skills/powershell/data-tiering-commands.md` — retention/tier management
- **Rate limiting**: `skills/powershell/rate-limiting.md` — API throttling reference
- **MCP integration**: `skills/msft-security/sentinel-mcp-server.md` — agent access patterns
- **Workbook automation**: `skills/soar/workbook-automation.md` — dashboard deployment
- **Environment config**: `.secops/README.md` — customer knowledge framework
