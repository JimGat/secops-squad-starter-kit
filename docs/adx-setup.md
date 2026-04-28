# Azure Data Explorer (ADX) Setup & Integration Guide

**When to use ADX:** Long-term security data retention (beyond 30 days), time-series anomaly detection, and federated querying across multiple security data sources.

---

## Quick Comparison: ADX vs Log Analytics

| Feature | Log Analytics | ADX |
|---------|---|---|
| **Retention** | 30 days (hot), up to 2,555 days (archive) | Configurable (7–730+ days) |
| **Query Speed** | Fast (hot), slower (archive) | Very fast (all tiers) |
| **Ingestion Volume** | ~100GB/day per workspace | Multi-TB/day per cluster |
| **Cost Model** | Pay-per-GB ingested | Cluster + storage (predictable) |
| **Best For** | Operational alerts, Sentinel | Historical hunts, forensics, data lake |
| **Setup** | Minutes | 15–30 minutes (via Bicep) |

**Choose ADX if:**
- You need to hunt across 6+ months of data
- You're doing forensic analysis on incidents
- You want a security data lake for compliance
- You have high ingestion volumes (multi-TB/day)

**Choose Log Analytics if:**
- You only need recent alerts (30 days)
- You're new to Azure security and want simplicity
- You're using Sentinel as your primary tool

---

## Install via Bicep Templates

The fastest way to deploy ADX is with the pre-built Bicep templates in `templates/bicep/adx/`.

### Prerequisites

```bash
# Register required Azure resource providers
az provider register --namespace Microsoft.Kusto
az provider register --namespace Microsoft.EventHub
az provider register --namespace Microsoft.Storage
```

### Deploy (3 Tiers)

#### Dev Tier (Testing & Proof of Concept)
```bash
az deployment group create \
  --resource-group <your-rg> \
  --template-file templates/bicep/adx/main.bicep \
  --parameters \
    clusterName=adxsecdev01 \
    deploymentTier=dev
```

**Specs:** Dev SKU (no SLA), 7-day hot cache, ~$200/month

#### Standard Tier (Production Hunt Workloads)
```bash
az deployment group create \
  --resource-group <your-rg> \
  --template-file templates/bicep/adx/main.bicep \
  --parameters \
    clusterName=adxsecprod01 \
    deploymentTier=standard \
    logAnalyticsWorkspaceId=/subscriptions/.../resourceGroups/.../providers/Microsoft.OperationalInsights/workspaces/...
```

**Specs:** Standard_E8as_v5 (2 nodes, auto-scale 2–8), 31-day hot cache, ~$2k–$8k/month

#### Production Tier (Enterprise Data Lake)
```bash
az deployment group create \
  --resource-group <your-rg> \
  --template-file templates/bicep/adx/main.bicep \
  --parameters \
    clusterName=adxsecprod01 \
    deploymentTier=production \
    logAnalyticsWorkspaceId=... \
    subnetId=... \
    privateEndpointSubnetId=... \
    privateDnsZoneId=... \
    cmkKeyVaultUri=... \
    cmkKeyName=... \
    cmkUserAssignedIdentityId=...
```

**Specs:** Standard_E16as_v5 (3 nodes, auto-scale 3–16), 90-day hot cache, VNet + Private Endpoints + CMK, ~$6k–$30k+/month

For full parameter reference, see [ADX Bicep Templates README](../templates/bicep/adx/README.md).

---

## Post-Deployment: Verify Cluster Health

After deployment completes:

```bash
# Check cluster state
az kusto cluster show -n adxsecprod01 -g <rg> --query "state"

# Verify database exists
az kusto database show -n SecurityLake --cluster-name adxsecprod01 -g <rg>

# List tables
az kusto database show -n SecurityLake --cluster-name adxsecprod01 -g <rg> --query "properties"
```

Expected output: Cluster is `Running`, database `SecurityLake` exists with 5 pre-built tables:
- **SecurityEvents** — Windows event logs
- **NetworkTraffic** — Firewall/NSG flow logs
- **ThreatIntelligence** — IOC storage
- **IdentityEvents** — Entra ID audit logs
- **CloudAudit** — Azure activity logs

---

## Ingest Data into ADX

### Option 1: Stream Data from Sentinel (Event Hub)

If you deployed ADX with Event Hub ingestion, Sentinel can stream logs directly:

**In Sentinel → Logs → Run query:**
```kql
SecurityEvent
| where EventID == 4625  // Failed logons
| limit 1000
```

**Export to Event Hub:**
1. Click **Export** → **Export to Event Hub**
2. Select the Event Hub namespace created by Bicep
3. Select target table (e.g., `SecurityEvents`)
4. Data flows automatically

### Option 2: Batch Upload from Log Analytics

Archive older Log Analytics data to ADX:

```kql
// KQL query in Log Analytics
SecurityEvent
| where TimeGenerated < ago(30d)  // Data older than 30 days
| where EventID in (4625, 4624, 4648)  // Focus on auth events
| project TimeGenerated, ComputerName, EventID, Account
```

Copy results and ingest via:
```bash
curl -X POST "https://<cluster-name>.<region>.kusto.windows.net/v1/rest/mgmt" \
  -H "Authorization: Bearer <token>" \
  -d "{\"csl\": \".ingest inline into table SecurityEvents <| ...\"}"
```

### Option 3: Diagnostic Settings from Azure Resources

Stream Azure activity logs directly:

**Azure Portal → Diagnostics Settings → Add diagnostic setting:**
- Send to Event Hub (connected to ADX)
- Select CloudAudit table in ADX

---

## Query ADX from Sentinel

Once ADX is populated, query it from Sentinel using the `adx()` proxy function:

**In Sentinel Log Analytics:**
```kql
// Query ADX for 90-day login pattern baseline
let adxData = adx("<cluster-name>.<region>.kusto.windows.net/SecurityLake")
  .SecurityEvents
  | where TimeGenerated > ago(90d)
  | where EventID == 4624;  // Successful logons

// Correlate with recent Sentinel data
let recentAlerts = SecurityAlert
  | where TimeGenerated > ago(1d);

recentAlerts
| join kind=inner adxData on $left.SourceIpAddress == $right.IpAddress
| summarize AlertCount = count() by SourceIpAddress, AlertName
```

---

## Load ADX Skills in Your Persona

Add ADX skills to your active persona:

Edit `secops-squad.config.json`:
```json
{
  "persona": "threat-hunting",
  "skills": {
    "loaded": [
      "threat-hunting-foundations",
      "cluster-architecture",
      "security-data-modeling",
      "cross-cluster-queries",
      "migration-from-sentinel"
    ]
  }
}
```

Then verify:
```bash
secops-squad status
```

---

## Common ADX Use Cases

### 1. Multi-Month Threat Hunt
```kql
// Search for credential spray over 6 months
let threshold = 100;
SecurityEvents
| where TimeGenerated > ago(180d)
| where EventID == 4625  // Failed logon
| summarize FailedAttempts = count() by SourceIpAddress, TargetAccount
| where FailedAttempts > threshold
| sort by FailedAttempts desc
```

### 2. Forensic Timeline (Incident)
```kql
// Complete timeline for compromised user over 30 days
let user = "domain\\attacker";
let suspiciousTime = datetime("2026-04-15T08:00:00Z");

union
  SecurityEvents | where Account == user and TimeGenerated > suspiciousTime - 2d,
  IdentityEvents | where UserPrincipalName == user and TimeGenerated > suspiciousTime - 2d,
  NetworkTraffic | where SrcUser == user and TimeGenerated > suspiciousTime - 2d
| sort by TimeGenerated asc
| project TimeGenerated, EventType, Description, IpAddress
```

### 3. Anomaly Detection (ML)
```kql
// Baseline login times per user
let userBaseline = SecurityEvents
  | where EventID == 4624
  | where TimeGenerated > ago(90d)
  | extend Hour = toint(format_datetime(TimeGenerated, "HH"))
  | summarize TypicalHours = make_set(Hour) by TargetAccount;

// Recent logins
SecurityEvents
| where EventID == 4624
| where TimeGenerated > ago(7d)
| extend Hour = toint(format_datetime(TimeGenerated, "HH"))
| join userBaseline on TargetAccount
| where Hour !in (TypicalHours)
| project TimeGenerated, TargetAccount, SourceIpAddress, Hour, TypicalHours
```

---

## Troubleshooting

### Cluster provisioning fails
- Check quota: `az kusto cluster list-skus --location <region>`
- Verify subscription permissions (Contributor role)

### Data not appearing in tables
- Verify Event Hub connection: `az kusto data-connection list --cluster-name ... --database-name SecurityLake`
- Check managed identity has **Azure Event Hubs Data Receiver** role

### Private endpoint DNS resolution failing
- Verify private DNS zone is linked to VNet
- Test: `nslookup <cluster-name>.<region>.kusto.windows.net`

### Query timeout
- ADX queries are fast; timeouts usually mean query inefficiency
- Use `| take 1000` to limit results during development
- For large scans, use pre-aggregated tables

For more details, see [ADX Bicep Templates — Troubleshooting](../templates/bicep/adx/README.md#troubleshooting).

---

## Next Steps

1. **Deploy ADX** — Run the Bicep template for your tier
2. **Ingest sample data** — Test with Sentinel export or batch upload
3. **Load ADX skills** — Add `cluster-architecture`, `security-data-modeling`, `cross-cluster-queries` to your persona
4. **Run your first hunt** — Use the multi-month threat hunt pattern above
5. **Automate archival** — Set up scheduled exports from Log Analytics to ADX

---

**Questions?** See [Skills Catalog — ADX Skills](skills-catalog.md#azure-data-explorer-8-skills-phase-3) for deep dives into each skill.
