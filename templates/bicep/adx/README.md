# ADX Security Data Lake — Bicep Templates

> **When to use ADX vs Sentinel data lake:** Microsoft Sentinel now includes the **Sentinel data lake** tier for low-cost, long-term retention within Sentinel. Use ADX when you need multi-TB/day ingestion, full KQL on historical data, advanced time-series analytics, or cross-team data sharing. For most SOC retention needs, Sentinel data lake is the modern default.

Production-ready Bicep templates for deploying an Azure Data Explorer cluster optimized for security data lake workloads. Provisions the cluster, database, pre-built security tables, and ingestion pipelines.

## Architecture

```
main.bicep (orchestrator)
  ├── cluster.bicep     → ADX cluster with managed identity, diagnostics, auto-scale
  ├── database.bicep    → SecurityLake database with retention and role assignments
  ├── tables.bicep      → 5 security tables via KQL deployment scripts
  │   └── scripts/
  │       ├── security-events.kql       → Windows Security event logs
  │       ├── network-traffic.kql       → Firewall/NSG flow logs
  │       ├── threat-intelligence.kql   → IOC storage
  │       ├── identity-events.kql       → Entra ID sign-in/audit logs
  │       └── cloud-audit.kql           → Azure activity logs
  └── ingestion.bicep   → Event Hub, IoT Hub, Event Grid data connections
```

## Prerequisites

1. **Azure subscription** with Contributor access to the target resource group
2. **Resource providers** registered:
   - `Microsoft.Kusto`
   - `Microsoft.EventHub` (if using Event Hub ingestion)
   - `Microsoft.Storage` (if using Event Grid ingestion)
   - `Microsoft.Network` (if using VNet/private endpoints)
3. **Azure CLI** with Bicep support (`az bicep install`)
4. **Log Analytics workspace** (recommended for diagnostic settings)
5. **Event Hub namespace** (if deploying ingestion pipeline)

Register required resource providers:
```bash
az provider register --namespace Microsoft.Kusto
az provider register --namespace Microsoft.EventHub
az provider register --namespace Microsoft.Network
```

## Quick Start

### Deploy with tier presets

```bash
# Dev tier — smallest SKU, 7-day cache, no VNet (cheapest for testing)
az deployment group create \
  --resource-group <your-rg> \
  --template-file main.bicep \
  --parameters \
    clusterName=adxsecdev01 \
    deploymentTier=dev

# Standard tier — mid-range SKU, 31-day cache, auto-scale
az deployment group create \
  --resource-group <your-rg> \
  --template-file main.bicep \
  --parameters \
    clusterName=adxsecstd01 \
    deploymentTier=standard \
    logAnalyticsWorkspaceId=<workspace-resource-id>

# Production tier — premium SKU, 90-day cache, VNet + private endpoints + CMK
az deployment group create \
  --resource-group <your-rg> \
  --template-file main.bicep \
  --parameters \
    clusterName=adxsecprod01 \
    deploymentTier=production \
    logAnalyticsWorkspaceId=<workspace-resource-id> \
    subnetId=<subnet-resource-id> \
    engineSubnetId=<engine-subnet-resource-id> \
    privateEndpointSubnetId=<pe-subnet-resource-id> \
    privateDnsZoneId=<dns-zone-resource-id> \
    cmkKeyVaultUri=<keyvault-uri> \
    cmkKeyName=<key-name> \
    cmkUserAssignedIdentityId=<identity-resource-id>
```

### Deploy individual modules

```bash
# Cluster only
az deployment group create \
  --resource-group <your-rg> \
  --template-file cluster.bicep \
  --parameters clusterName=adxsec01

# Add database to existing cluster
az deployment group create \
  --resource-group <your-rg> \
  --template-file database.bicep \
  --parameters clusterName=adxsec01 databaseName=SecurityLake

# Add tables to existing database
az deployment group create \
  --resource-group <your-rg> \
  --template-file tables.bicep \
  --parameters clusterName=adxsec01 databaseName=SecurityLake
```

### Deploy with Event Hub ingestion

```bash
az deployment group create \
  --resource-group <your-rg> \
  --template-file main.bicep \
  --parameters \
    clusterName=adxsec01 \
    deploymentTier=standard \
    deployEventHubConnection=true \
    eventHubNamespaceId=<eh-namespace-resource-id> \
    eventHubNamespaceName=<eh-namespace-name> \
    eventHubName=security-logs
```

## Deployment Tier Comparison

| Setting | Dev | Standard | Production |
|---|---|---|---|
| **SKU** | Dev(No SLA)_Standard_E2a_v4 | Standard_E8as_v5+1TB_PS | Standard_E16as_v5+2TB_PS |
| **SKU Tier** | Basic | Standard | Standard |
| **Instances** | 1 (fixed) | 2 (auto-scale 2–8) | 3 (auto-scale 3–16) |
| **Hot Cache** | 7 days | 31 days | 90 days |
| **Soft Delete** | 90 days | 365 days | 730 days |
| **Streaming Ingestion** | ❌ | ✅ | ✅ |
| **VNet Integration** | ❌ | Optional | ✅ Required |
| **Private Endpoints** | ❌ | Optional | ✅ Required |
| **CMK Encryption** | ❌ | Optional | ✅ Required |
| **Auto-scale** | ❌ | ✅ | ✅ |
| **Est. Monthly Cost** | ~$200 | ~$2,000–$8,000 | ~$6,000–$30,000+ |

> **Cost Note:** Estimates are approximate and depend on region, data volume, and query load. Use the [Azure Pricing Calculator](https://azure.microsoft.com/pricing/calculator/) for accurate estimates. The Dev tier uses a no-SLA SKU unsuitable for production.

## Parameter Reference

### Core Parameters (main.bicep)

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `clusterName` | string | ✅ | — | ADX cluster name (4-22 lowercase alphanumeric) |
| `deploymentTier` | string | | `standard` | Deployment tier: `dev`, `standard`, `production` |
| `databaseName` | string | | `SecurityLake` | Primary database name |
| `location` | string | | RG location | Azure region |
| `logAnalyticsWorkspaceId` | string | | — | Log Analytics workspace for diagnostics |

### Module Toggles

| Parameter | Type | Default | Description |
|---|---|---|---|
| `deployDatabase` | bool | `true` | Deploy the SecurityLake database |
| `deployTables` | bool | `true` | Deploy pre-built security tables |
| `deployIngestion` | bool | `true` | Deploy ingestion pipeline |

### Table Toggles

| Parameter | Type | Default | Description |
|---|---|---|---|
| `deploySecurityEvents` | bool | `true` | Windows Security event logs |
| `deployNetworkTraffic` | bool | `true` | Firewall/NSG flow logs |
| `deployThreatIntelligence` | bool | `true` | Threat intel IOC storage |
| `deployIdentityEvents` | bool | `true` | Entra ID sign-in/audit logs |
| `deployCloudAudit` | bool | `true` | Azure activity logs |

### Network & Security Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `enableVnet` | bool | `false` | VNet integration (auto-enabled for production) |
| `subnetId` | string | — | VNet subnet resource ID |
| `engineSubnetId` | string | — | Engine VNet subnet resource ID |
| `enablePrivateEndpoint` | bool | `false` | Private endpoint (auto-enabled for production) |
| `privateEndpointSubnetId` | string | — | PE subnet resource ID |
| `privateDnsZoneId` | string | — | Private DNS zone resource ID |
| `enableCmkEncryption` | bool | `false` | CMK encryption (auto-enabled for production) |
| `cmkKeyVaultUri` | string | — | Key Vault URI for CMK |
| `cmkKeyName` | string | — | Key name for CMK |
| `cmkUserAssignedIdentityId` | string | — | User MI for CMK access |

### Database Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `hotCacheDaysOverride` | int | `0` (tier default) | Hot cache period override |
| `softDeleteDaysOverride` | int | `0` (tier default) | Soft delete period override |
| `dbAdminPrincipalIds` | array | `[]` | Admin role principal IDs |
| `dbViewerPrincipalIds` | array | `[]` | Viewer role principal IDs |
| `dbIngestorPrincipalIds` | array | `[]` | Ingestor role principal IDs |

### Ingestion Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `deployEventHubConnection` | bool | `false` | Deploy Event Hub ingestion |
| `eventHubNamespaceId` | string | — | Event Hub namespace resource ID |
| `eventHubNamespaceName` | string | — | Event Hub namespace name |
| `eventHubName` | string | `security-logs` | Event Hub name |
| `deployIotHubConnection` | bool | `false` | Deploy IoT Hub ingestion |
| `iotHubResourceId` | string | — | IoT Hub resource ID |
| `deployEventGridConnection` | bool | `false` | Deploy Event Grid ingestion |
| `storageAccountId` | string | — | Storage account resource ID |
| `eventGridEventHubId` | string | — | Event Hub for Event Grid notifications |

### Tag Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `project` | string | `secops-squad` | Project identifier |
| `costCenter` | string | — | Cost center for billing |
| `tags` | object | `{}` | Additional resource tags |

## Pre-Built Security Tables

| Table | Schema Source | Use Case |
|---|---|---|
| **SecurityEvents** | Windows Security Event Log | Failed logons, privilege escalation, process creation |
| **NetworkTraffic** | Firewall/NSG Flow Logs | Lateral movement, C2 detection, data exfiltration |
| **ThreatIntelligence** | STIX/TAXII/MDTI feeds | IOC matching, threat correlation, indicator lifecycle |
| **IdentityEvents** | Entra ID Sign-in/Audit | Impossible travel, MFA bypass, risky sign-ins |
| **CloudAudit** | Azure Activity Log | Unauthorized RBAC changes, resource manipulation |

Each table includes:
- **Structured schema** with typed columns matching Microsoft security log formats
- **JSON ingestion mapping** for Event Hub streaming
- **Raw staging table** (`*_Raw`) for update policy transformation
- **Update policy** that transforms raw JSON into the structured target table
- **Retention policy** aligned with the database soft delete period
- **Docstring annotations** for discoverability

## Post-Deployment Steps

### 1. Verify Cluster Health

```bash
# Check cluster state
az kusto cluster show -n <cluster-name> -g <rg> --query "state"

# Verify database exists
az kusto database show -n SecurityLake --cluster-name <cluster-name> -g <rg> --query "name"
```

### 2. Configure Data Connectors

If you deployed with ingestion enabled, verify the data connections:

```bash
az kusto data-connection list \
  --cluster-name <cluster-name> \
  --database-name SecurityLake \
  -g <rg> \
  --query "[].{name:name, kind:kind}"
```

### 3. Verify Table Creation

Connect to the cluster via the Azure Data Explorer Web UI or Kusto Explorer:

```kql
// List all tables
.show tables

// Verify table schemas
.show table SecurityEvents schema as json
.show table NetworkTraffic schema as json

// Check ingestion mappings
.show table SecurityEvents ingestion json mappings
```

### 4. Send Test Data

```kql
// Ingest a test record
.ingest inline into table SecurityEvents <|
2024-01-15T10:30:00Z,4625,"An account failed to log on","SERVER01","DOMAIN\\user","User","","user","DOMAIN","attacker","","S-1-5-21-xxx",10,"RemoteInteractive","192.168.1.100","445","WORKSTATION1","","","","","","","0xC000006D","0xC0000064","Unknown user name","","Microsoft-Windows-Security-Auditing","Security","Information",0,"Audit Failure","OpsManager","","tenant-123",2024-01-15T10:30:05Z
```

### 5. Configure Sentinel Cross-Resource Query (Optional)

To query ADX from Microsoft Sentinel:

```kql
// In Sentinel Log Analytics, use adx() proxy function
let adxData = adx("<cluster-uri>/SecurityLake").SecurityEvents
| where TimeGenerated > ago(1d);
adxData
| summarize count() by EventID
```

## Troubleshooting

### "Cluster provisioning failed"

- Verify the SKU is available in your region: `az kusto cluster list-skus --location <region>`
- Check subscription quota for the selected SKU family
- Dev SKU requires `capacity: 1`; standard SKUs require `capacity: 2+`

### "Database script execution failed"

- Scripts run sequentially with `dependsOn` chains — check which script failed in the deployment log
- Verify cluster is in `Running` state before deploying tables
- Use `forceUpdateTag` parameter to force re-execution of table creation scripts

### "Event Hub data connection failed"

- Ensure the ADX cluster managed identity has **Azure Event Hubs Data Receiver** role on the Event Hub namespace
- Verify the consumer group exists (template creates it automatically for non-`$Default` groups)
- Check that the Event Hub name matches exactly (case-sensitive)

### "Private endpoint DNS resolution failing"

- Verify the private DNS zone (`privatelink.{region}.kusto.windows.net`) is linked to the VNet
- Check that the DNS zone group was created on the private endpoint
- Test resolution: `nslookup <cluster-name>.{region}.kusto.windows.net`

### "CMK encryption configuration failed"

- The user-assigned managed identity must have **Key Vault Crypto Service Encryption User** role on the Key Vault
- Key Vault must have soft-delete and purge protection enabled
- The key must be RSA 2048-bit or larger

### "Auto-scale not working"

- Dev tier does not support auto-scale (uses single instance)
- Verify `autoScaleMin` ≤ current capacity ≤ `autoScaleMax`
- Auto-scale reacts to CPU, ingestion, and cache utilization — allow 15+ minutes for scaling events
