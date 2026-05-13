---
title: Data Connectors Setup
category: log-analytics
difficulty: intermediate
mitre_attack:
  - General  # Data source enablement — foundational for all detection
products:
  - Azure Monitor Log Analytics
  - Microsoft Sentinel
  - Azure Monitor Agent (AMA)
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Data Connectors Setup

## Overview

Data connectors are how telemetry enters your Sentinel/Log Analytics workspace. Without properly configured connectors, you have no data — and no detections. This skill covers the major connector patterns: built-in Azure connectors, CEF/Syslog via Azure Monitor Agent (AMA), REST API custom ingestion, and connector health monitoring.

Use this skill when:
- You are onboarding a new data source into Sentinel
- You need to set up CEF or Syslog forwarding from non-Azure devices (firewalls, proxies, appliances)
- You are building custom log ingestion via the Logs Ingestion API
- You need to monitor connector health and diagnose data gaps

## Prerequisites

| Requirement | Detail |
|---|---|
| **Workspace** | Log Analytics workspace with Sentinel enabled |
| **Permissions** | `Microsoft Sentinel Contributor` for built-in connectors; `Monitoring Contributor` for DCRs; `Log Analytics Contributor` for custom tables |
| **Network** | For CEF/Syslog: Linux VM as log forwarder with AMA installed. For REST API: service principal or managed identity with DCR permissions. |
| **Tools** | Azure CLI 2.50+, Azure Monitor Agent (AMA) |

## Core Patterns

### Pattern 1 — Built-in Connectors: Azure AD & Office 365

These are the easiest connectors — toggle them on and data flows. Azure AD sign-in and audit logs, plus Office 365 activity logs, are table stakes for any SOC.

```bash
# Enable Azure AD (Entra ID) connector — requires Azure AD P1/P2 license
# Configure diagnostic settings on Azure AD to route to workspace
az monitor diagnostic-settings create \
  --name "entra-to-sentinel" \
  --resource "/providers/Microsoft.aadiam" \
  --workspace "/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-central" \
  --logs '[
    {"category": "SignInLogs", "enabled": true},
    {"category": "AuditLogs", "enabled": true},
    {"category": "NonInteractiveUserSignInLogs", "enabled": true},
    {"category": "ServicePrincipalSignInLogs", "enabled": true},
    {"category": "ManagedIdentitySignInLogs", "enabled": true},
    {"category": "RiskyUsers", "enabled": true},
    {"category": "UserRiskEvents", "enabled": true}
  ]'
```

```kql
// Verify Azure AD data is flowing after connector setup
SignInLogs
| where TimeGenerated > ago(1h)
| summarize EventCount = count() by bin(TimeGenerated, 5m)
| order by TimeGenerated desc
| take 20
```

---

### Pattern 2 — CEF/Syslog via AMA (Azure Monitor Agent)

For non-Azure devices (firewalls, proxies, IDS/IPS), CEF over Syslog is the standard ingestion path. AMA replaces the legacy Log Analytics Agent (MMA) and uses Data Collection Rules (DCRs) for configuration.

**Architecture:** Device → Syslog → Linux forwarder VM (AMA) → DCR → Log Analytics workspace

```bash
# Step 1: Create the Linux forwarder VM (Ubuntu 22.04 recommended)
az vm create \
  --resource-group rg-sentinel \
  --name vm-syslog-forwarder \
  --image Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest \
  --size Standard_D2s_v5 \
  --admin-username azureuser \
  --generate-ssh-keys \
  --nsg nsg-syslog-forwarder

# Step 2: Open syslog port (514 TCP/UDP) in NSG
az network nsg rule create \
  --resource-group rg-sentinel \
  --nsg-name nsg-syslog-forwarder \
  --name AllowSyslog \
  --priority 200 \
  --direction Inbound \
  --access Allow \
  --protocol '*' \
  --destination-port-ranges 514

# Step 3: Install AMA on the forwarder VM
az vm extension set \
  --resource-group rg-sentinel \
  --vm-name vm-syslog-forwarder \
  --name AzureMonitorLinuxAgent \
  --publisher Microsoft.Azure.Monitor \
  --version 1.0 \
  --enable-auto-upgrade true
```

```bicep
// Bicep: Data Collection Rule for CEF log ingestion
resource dcrCef 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: 'dcr-cef-forwarder'
  location: resourceGroup().location
  properties: {
    dataSources: {
      syslog: [
        {
          name: 'syslogCEF'
          streams: ['Microsoft-CommonSecurityLog']
          facilityNames: [
            'local0'
            'local1'
            'local2'
            'local3'
          ]
          logLevels: [
            'Warning'
            'Error'
            'Critical'
            'Alert'
            'Emergency'
          ]
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          name: 'sentinelWorkspace'
          workspaceResourceId: '/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-central'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Microsoft-CommonSecurityLog']
        destinations: ['sentinelWorkspace']
      }
    ]
  }
}
```

```kql
// Verify CEF data ingestion after forwarder setup
CommonSecurityLog
| where TimeGenerated > ago(1h)
| summarize
    EventCount = count(),
    DistinctDevices = dcount(DeviceVendor)
    by DeviceVendor, DeviceProduct
| order by EventCount desc
```

---

### Pattern 3 — REST API Ingestion (Custom Logs v2 / Logs Ingestion API)

For custom data sources — internal APIs, SaaS platforms, or scripts — use the Logs Ingestion API with a Data Collection Rule (DCR) and Data Collection Endpoint (DCE).

```bash
# Step 1: Create a Data Collection Endpoint (DCE)
az monitor data-collection endpoint create \
  --name dce-custom-logs \
  --resource-group rg-sentinel \
  --location eastus2 \
  --public-network-access Enabled

# Step 2: Create a custom table in the workspace
az monitor log-analytics workspace table create \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --name CustomAppAudit_CL \
  --columns \
    TimeGenerated=datetime \
    UserId=string \
    Action=string \
    ResourcePath=string \
    SourceIP=string \
    ResultCode=int \
    Duration=real

# Step 3: Create a DCR for the custom table
az monitor data-collection rule create \
  --name dcr-custom-app-audit \
  --resource-group rg-sentinel \
  --location eastus2 \
  --data-collection-endpoint-id "/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.Insights/dataCollectionEndpoints/dce-custom-logs" \
  --rule-file dcr-custom-app-audit.json
```

```json
// dcr-custom-app-audit.json — DCR definition for custom log ingestion
{
  "properties": {
    "streamDeclarations": {
      "Custom-CustomAppAudit_CL": {
        "columns": [
          { "name": "TimeGenerated", "type": "datetime" },
          { "name": "UserId", "type": "string" },
          { "name": "Action", "type": "string" },
          { "name": "ResourcePath", "type": "string" },
          { "name": "SourceIP", "type": "string" },
          { "name": "ResultCode", "type": "int" },
          { "name": "Duration", "type": "real" }
        ]
      }
    },
    "destinations": {
      "logAnalytics": [
        {
          "workspaceResourceId": "/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-central",
          "name": "sentinelWorkspace"
        }
      ]
    },
    "dataFlows": [
      {
        "streams": ["Custom-CustomAppAudit_CL"],
        "destinations": ["sentinelWorkspace"],
        "outputStream": "Custom-CustomAppAudit_CL",
        "transformKql": "source"
      }
    ]
  }
}
```

```bash
# Step 4: Ingest data via REST API (using curl with managed identity or service principal)
DCE_ENDPOINT="https://dce-custom-logs-XXXX.eastus2-1.ingest.monitor.azure.com"
DCR_IMMUTABLE_ID="dcr-XXXXXXXXXXXXXXXXXXXXXXXX"
STREAM_NAME="Custom-CustomAppAudit_CL"

TOKEN=$(az account get-access-token --resource "https://monitor.azure.com" --query accessToken -o tsv)

curl -X POST "${DCE_ENDPOINT}/dataCollectionRules/${DCR_IMMUTABLE_ID}/streams/${STREAM_NAME}?api-version=2023-01-01" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '[
    {
      "TimeGenerated": "2026-04-28T12:00:00Z",
      "UserId": "user@contoso.com",
      "Action": "FileDownload",
      "ResourcePath": "/shared/documents/confidential.pdf",
      "SourceIP": "10.0.1.50",
      "ResultCode": 200,
      "Duration": 1.23
    }
  ]'
```

---

### Pattern 4 — AWS CloudTrail Connector

Sentinel's built-in AWS connector pulls CloudTrail management events into the `AWSCloudTrail` table. For S3 data events, use the S3 connector via SQS.

```bash
# Create an AWS connector via Sentinel data connector API
# Requires: AWS IAM Role ARN with CloudTrail read access and SQS access
az sentinel data-connector create \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --data-connector-id "aws-cloudtrail-connector" \
  --kind AmazonWebServicesCloudTrail \
  --aws-role-arn "arn:aws:iam::123456789012:role/SentinelCloudTrailRole"
```

```kql
// Verify AWS CloudTrail data ingestion
AWSCloudTrail
| where TimeGenerated > ago(1h)
| summarize
    EventCount = count(),
    DistinctUsers = dcount(UserIdentityArn)
    by EventSource, EventName
| order by EventCount desc
| take 20
```

---

### Pattern 5 — Connector Health Monitoring

The most dangerous state is silent connector failure — data stops flowing and no one notices until an incident goes undetected. Build proactive health checks.

```kql
// Data connector health: identify tables with no recent data
// Run this daily as a Sentinel analytics rule or workbook
let ExpectedTables = dynamic([
    "SignInLogs", "AuditLogs", "SecurityEvent", "Syslog",
    "CommonSecurityLog", "AzureActivity", "OfficeActivity",
    "SecurityAlert", "AWSCloudTrail"
]);
let LookbackPeriod = 24h;
let WarningThresholdHours = 4;
union withsource=TableName *
| where TimeGenerated > ago(LookbackPeriod)
| where TableName in (ExpectedTables)
| summarize
    LastEvent = max(TimeGenerated),
    EventCount = count()
    by TableName
| extend
    HoursSinceLastEvent = datetime_diff('hour', now(), LastEvent),
    Status = iff(datetime_diff('hour', now(), LastEvent) > WarningThresholdHours, "⚠️ STALE", "✅ OK")
| order by HoursSinceLastEvent desc
```

```kql
// Data volume trend per connector — detect sudden drops
Usage
| where TimeGenerated > ago(7d)
| where IsBillable == true
| summarize
    DailyGB = sum(Quantity) / 1024.0
    by bin(TimeGenerated, 1d), DataType
| order by DataType asc, TimeGenerated asc
| serialize
| extend PrevDayGB = prev(DailyGB, 1)
| extend DropPercent = round(iff(PrevDayGB > 0, (PrevDayGB - DailyGB) / PrevDayGB * 100.0, 0.0), 1)
| where DropPercent > 50  // Flag connectors with >50% volume drop
| project TimeGenerated, DataType, DailyGB, PrevDayGB, DropPercent
```

```kql
// Heartbeat monitoring for AMA-based forwarders
Heartbeat
| where TimeGenerated > ago(1h)
| summarize
    LastHeartbeat = max(TimeGenerated),
    HeartbeatCount = count()
    by Computer, OSType, Version
| extend
    MinutesSinceHeartbeat = datetime_diff('minute', now(), LastHeartbeat),
    AgentStatus = iff(datetime_diff('minute', now(), LastHeartbeat) > 15, "⚠️ OFFLINE", "✅ ONLINE")
| order by MinutesSinceHeartbeat desc
```

## Best Practices

1. **AMA over MMA** — Azure Monitor Agent replaces the legacy Log Analytics Agent. All new deployments should use AMA with Data Collection Rules.
2. **Monitor every connector** — Set up the health monitoring queries above as scheduled analytics rules. Silent failures are the #1 cause of missed detections.
3. **Use DCR transforms** — Filter and enrich data at ingestion time. Drop noisy fields before they hit the workspace to reduce cost.
4. **Test connectors in dev first** — Use a non-production workspace to validate data flow before routing production telemetry.
5. **Document connector dependencies** — Maintain a connector inventory with owner, data source, expected volume, and escalation path.

## Cost Implications

| Connector Type | Cost Consideration |
|---|---|
| Azure AD / Entra ID | Requires P1/P2 license for sign-in logs; non-interactive sign-ins can be high volume |
| Office 365 | Exchange, SharePoint, Teams logs — SharePoint can be extremely high volume |
| CEF/Syslog | Linux forwarder VM cost + ingestion; firewall logs often dominate workspace costs |
| Custom Logs v2 | Pay per GB ingested; consider Basic Logs or Sentinel data lake tier for high-volume, low-query tables |
| AWS CloudTrail | S3 data events can be very high volume; management events are usually manageable |

## Related Skills

- **[Custom Tables & DCR](custom-tables-dcr.md)** — Deep dive into Data Collection Rules and custom table creation.
- **[Cost Optimization](cost-optimization.md)** — Strategies to reduce ingestion costs from high-volume connectors.
- **[Diagnostic Settings](diagnostic-settings.md)** — Azure resource diagnostic log routing patterns.
- **[Workspace Architecture](workspace-architecture.md)** — Where connectors route data depends on your workspace topology.
- **[Threat Hunting Foundations](../kql/threat-hunting-foundations.md)** — Once data flows, use these KQL patterns to hunt through it.

## Environment Context

Before executing this skill, check the customer's `.secops/` knowledge framework:

1. **Data location:** Read `.secops/data-sources/data-source-map.yaml` — tables may be in Sentinel, ADX, or external sources
2. **Active migrations:** Read `.secops/data-sources/migrations.yaml` — data may be moving between locations
3. **Workspace config:** Read `.secops/workspaces/` — know the workspace ID, tier, retention, and naming conventions
4. **Compliance:** Read `.secops/compliance/requirements.yaml` — respect data residency and regulatory constraints

If `.secops/` doesn't exist, proceed with defaults but suggest `secops-squad init --secops`.

See `.copilot/skills/secops-environment-context.md` for the full discovery flow.
