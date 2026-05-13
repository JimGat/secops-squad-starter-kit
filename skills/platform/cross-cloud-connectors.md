---
title: Cross-Cloud Security Data Connectors
category: platform
difficulty: advanced
mitre_attack:
  - General   # Data source enablement — foundational for all cross-cloud detection
  - T1078     # Valid Accounts — cross-cloud credential misuse
  - T1537     # Transfer Data to Cloud Account
products:
  - Microsoft Sentinel
  - AWS CloudTrail
  - AWS GuardDuty
  - GCP Cloud Audit Logs
  - GCP Security Command Center
author: Freamon
version: 1.0.0
last_updated: 2026-05-04
---

# Cross-Cloud Security Data Connectors

## Overview

Most enterprises run workloads across AWS + Azure or GCP + Azure. Sentinel must have visibility into every cloud to detect lateral movement, cross-cloud credential abuse, and data exfiltration. Without cross-cloud connectors, attackers exploit blind spots at cloud boundaries.

This skill covers AWS and GCP native connectors, multi-SIEM migration patterns (Splunk/QRadar/Elastic), connector infrastructure (CEF, REST API, CCP, DCR/DCE), ASIM normalization for cross-cloud correlation, and cost optimization for high-volume sources.

**Complements:** [data-connectors-setup.md](../log-analytics/data-connectors-setup.md), [custom-tables-dcr.md](../log-analytics/custom-tables-dcr.md), [cost-optimization.md](../log-analytics/cost-optimization.md).

## Environment Context

Before configuring cross-cloud connectors, check `.secops/`:

| File | Check |
|---|---|
| `data-sources/data-source-map.yaml` | Existing cross-cloud sources, `source_cloud` fields |
| `data-sources/migrations.yaml` | Active Splunk/QRadar → Sentinel migrations |
| `workspaces/*.yaml` | Target workspace IDs, regions |
| `compliance/requirements.yaml` | Data residency constraints for cross-cloud data |

---

## AWS Integration

### CloudTrail → Sentinel (Native Connector)

**Architecture:** CloudTrail → S3 → SQS notification → Sentinel AWS connector → `AWSCloudTrail` table

```bash
# AWS side: Create S3 bucket, enable CloudTrail, configure SQS
aws cloudtrail create-trail \
  --name sentinel-trail \
  --s3-bucket-name sentinel-cloudtrail-${AWS_ACCOUNT_ID} \
  --is-multi-region-trail --enable-log-file-validation
aws cloudtrail start-logging --name sentinel-trail

# SQS queue for S3 event notifications
aws sqs create-queue --queue-name sentinel-cloudtrail-notifications
# Then configure S3 event notification → SQS for s3:ObjectCreated:*
```

Create an IAM role granting Sentinel `sts:AssumeRole` with external ID, plus `s3:GetObject` and `sqs:ReceiveMessage/DeleteMessage`.

```powershell
# Enable connector in Sentinel
$connectorBody = @{
    kind = "AmazonWebServicesCloudTrail"
    properties = @{
        awsRoleArn = "arn:aws:iam::$AwsAccountId:role/SentinelCloudTrailRole"
        dataTypes  = @{ logs = @{ state = "Enabled" } }
    }
} | ConvertTo-Json -Depth 5
Invoke-SecOpsRestMethod -Method PUT `
    -Uri "$SentinelBaseUri/dataConnectors/aws-cloudtrail?api-version=2024-03-01" `
    -Body $connectorBody
```

### GuardDuty → Sentinel

**Architecture:** GuardDuty findings → EventBridge → Firehose → S3 → Sentinel

```bash
aws events put-rule --name sentinel-guardduty \
  --event-pattern '{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"]}'
aws events put-targets --rule sentinel-guardduty \
  --targets "Id=s3,Arn=arn:aws:firehose:us-east-1:${AWS_ACCOUNT_ID}:deliverystream/sentinel-guardduty"
```

### Security Hub & VPC Flow Logs

- **Security Hub:** Aggregate findings from GuardDuty/Inspector/Macie → EventBridge → S3 → Sentinel
- **VPC Flow Logs:** Enable to S3 with custom log format → S3 connector. High volume — use Sentinel data lake tier.
- **IAM Access Analyzer:** No native connector — use Azure Function to poll the API and push via DCE/DCR.

### KQL — AWS Field Normalization (ASIM)

```kql
// ASIM Authentication schema — AWS CloudTrail
let ASIMAuthAWS = AWSCloudTrail
| where EventName in ("ConsoleLogin", "AssumeRole", "GetSessionToken")
| extend
    EventType       = iff(EventName == "ConsoleLogin", "Logon", "Elevate"),
    EventResult     = iff(ErrorCode == "", "Success", "Failure"),
    EventProduct    = "CloudTrail",
    EventVendor     = "AWS",
    EventSchema     = "Authentication",
    ActorUsername    = UserIdentityPrincipalid,
    SrcIpAddr       = SourceIpAddress,
    TargetAppName   = RecipientAccountId,
    LogonMethod     = iff(AdditionalEventData has "MFAUsed",
                        extract('"MFAUsed":"([^"]+)"', 1, AdditionalEventData), "Unknown"),
    EventOriginalUid = AwsEventId
| project-reorder TimeGenerated, EventType, EventResult, ActorUsername, SrcIpAddr;

// ASIM NetworkSession schema — AWS VPC Flow Logs
let ASIMNetworkAWS = AWSVPCFlow_CL
| extend
    EventType       = "NetworkSession",
    EventProduct    = "VPC Flow Logs",
    EventVendor     = "AWS",
    EventResult     = iff(Action_s == "ACCEPT", "Success", "Failure"),
    SrcIpAddr       = SrcAddr_s,
    DstIpAddr       = DstAddr_s,
    SrcPortNumber   = toint(SrcPort_d),
    DstPortNumber   = toint(DstPort_d),
    NetworkProtocol = case(Protocol_d == 6, "TCP", Protocol_d == 17, "UDP", "Other"),
    SrcBytes        = tolong(Bytes_d),
    EventStartTime  = unixtime_seconds_todatetime(Start_d),
    EventEndTime    = unixtime_seconds_todatetime(End_d);
```

---

## GCP Integration

### Cloud Audit Logs → Sentinel (Native Connector)

**Architecture:** GCP Audit Logs → Pub/Sub topic → Sentinel GCP connector → `GCPAuditLogs` table

```bash
# Create Pub/Sub topic and log sink
gcloud pubsub topics create sentinel-audit-logs --project=$GCP_PROJECT
gcloud logging sinks create sentinel-sink \
  pubsub.googleapis.com/projects/$GCP_PROJECT/topics/sentinel-audit-logs \
  --log-filter='logName:"cloudaudit.googleapis.com"' --project=$GCP_PROJECT

# Grant sink service account publish permission
SINK_SA=$(gcloud logging sinks describe sentinel-sink --project=$GCP_PROJECT --format='value(writerIdentity)')
gcloud pubsub topics add-iam-policy-binding sentinel-audit-logs \
  --member=$SINK_SA --role=roles/pubsub.publisher --project=$GCP_PROJECT

# Create subscription for Sentinel pull
gcloud pubsub subscriptions create sentinel-pull \
  --topic=sentinel-audit-logs --ack-deadline=60 --project=$GCP_PROJECT
```

```powershell
# Enable GCP connector in Sentinel
$gcpConnector = @{
    kind = "GCP"
    properties = @{
        connectorDefinitionName = "GCPAuditLogsDefinition"
        auth = @{
            serviceAccountEmail        = "sentinel-gcp@$GcpProject.iam.gserviceaccount.com"
            projectNumber              = $GcpProjectNumber
            workloadIdentityProviderId = $WorkloadIdentityProvider
        }
        request  = @{ projectId = $GcpProject; subscriptionNames = @("sentinel-pull") }
        dcrConfig = @{
            dataCollectionEndpoint         = $DceEndpoint
            dataCollectionRuleImmutableId   = $DcrImmutableId
            streamName                     = "Custom-GCPAuditLogs_CL"
        }
    }
} | ConvertTo-Json -Depth 6
Invoke-SecOpsRestMethod -Method PUT `
    -Uri "$SentinelBaseUri/dataConnectors/gcp-audit?api-version=2024-03-01" -Body $gcpConnector
```

### Security Command Center & VPC Flow Logs

- **SCC:** Create notification config → Pub/Sub → DCE custom ingestion → `GCPSCCFindings_CL`
- **VPC Flow Logs:** Enable on subnet → log sink to Pub/Sub → DCE → `GCPVPCFlow_CL` (Sentinel data lake tier)
- **Chronicle → Sentinel migration:** Export YARA-L rules → translate to KQL analytics rules; map UDM → ASIM schemas; replicate reference lists → Watchlists

### KQL — GCP Field Normalization (ASIM)

```kql
// ASIM Authentication schema — GCP Audit Logs
let ASIMAuthGCP = GCPAuditLogs_CL
| where ServiceName_s == "iam.googleapis.com"
    or MethodName_s has_any ("SetIamPolicy", "CreateServiceAccountKey")
| extend
    EventType       = "Logon",
    EventResult     = iff(Severity_s == "ERROR", "Failure", "Success"),
    EventProduct    = "GCP Audit Logs",
    EventVendor     = "Google",
    EventSchema     = "Authentication",
    ActorUsername    = AuthenticationInfo_principalEmail_s,
    SrcIpAddr       = RequestMetadata_callerIp_s,
    TargetAppName   = ResourceName_s,
    EventOriginalUid = InsertId_s
| project-reorder TimeGenerated, EventType, EventResult, ActorUsername, SrcIpAddr;
```

---

## Multi-SIEM Integration

### Splunk → Sentinel

**Data forwarding:** Use Logstash relay or Azure Function bridge from Splunk HEC output.

**SPL → KQL translation patterns:**

| SPL | KQL Equivalent |
|---|---|
| `index=main sourcetype=syslog` | `Syslog` |
| `stats count by src_ip` | `summarize count() by SrcIP` |
| `eval risk=if(count>100,"high","low")` | `extend risk = iff(count_ > 100, "high", "low")` |
| `dedup src_ip` | `summarize arg_max(TimeGenerated, *) by SrcIP` |
| `rex field=msg "user=(?<user>\w+)"` | `extend user = extract("user=(\\w+)", 1, msg)` |
| `lookup threat_list ip AS src_ip` | `join kind=leftouter (ThreatIntelligence) on $left.SrcIP == $right.IP` |
| `transaction src_ip maxspan=5m` | `summarize makeset(EventType) by SrcIP, bin(TimeGenerated, 5m)` |

### QRadar → Sentinel

Forward via CEF/Syslog to Linux forwarder running AMA. Map concepts: Log Source → Data Connector, Custom Rule → Analytics Rule, Building Block → KQL Function, Reference Set → Watchlist, Offense → Incident, AQL → KQL.

### Elastic → Sentinel

Use the [Logstash output plugin for Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/connect-logstash-data-connection-rules) or Sigma rule translation:

```bash
# Convert Sigma rules to Sentinel KQL
pip install sigma-cli pySigma-backend-kusto
sigma convert -t kusto -p microsoft365defender rules/windows/ --output sentinel-rules/
```

---

## Data Connector Patterns

### CEF/Syslog via Azure Monitor Agent

```bash
# Create DCR for CEF collection with transformation filter
az monitor data-collection rule create --name "dcr-cef-crosscloud" \
  --resource-group rg-sentinel --location eastus \
  --data-flows '[{"streams":["Microsoft-CommonSecurityLog"],
    "destinations":["sentinel-workspace"],
    "transformKql":"source | where DeviceVendor != \"TestVendor\""}]' \
  --data-sources '{"syslog":[{"name":"cef-src","streams":["Microsoft-CommonSecurityLog"],
    "facilityNames":["local4"],"logLevels":["Warning","Error","Critical"]}]}'
```

### REST API Custom Connectors (Azure Functions)

```powershell
function Push-LogsToSentinel {
    param([object[]]$Logs, [string]$DceEndpoint, [string]$DcrImmutableId, [string]$StreamName)
    $token = Get-AzAccessToken -ResourceUrl "https://monitor.azure.com"
    $uri = "$DceEndpoint/dataCollectionRules/$DcrImmutableId/streams/${StreamName}?api-version=2023-01-01"
    # Batch in 10,000-record chunks (API limit)
    for ($i = 0; $i -lt $Logs.Count; $i += 10000) {
        $batch = $Logs[$i..([Math]::Min($i + 9999, $Logs.Count - 1))]
        Invoke-SecOpsRestMethod -Method POST -Uri $uri `
            -Body ($batch | ConvertTo-Json -Depth 10 -AsArray) `
            -Headers @{ Authorization = "Bearer $($token.Token)" }
    }
}
```

### Codeless Connector Platform (CCP)

Build connectors without code via ARM/Bicep — define `dataConnectorDefinitions` resource with `connectorUiConfig` (title, data types, permissions, instruction steps). Sentinel handles polling, ingestion, and health monitoring.

### Data Collection Rules — Transformation at Ingestion

```kql
// DCR transform: filter high-volume VPC flow logs at ingestion time
source
| where not(Action_s == "ACCEPT" and DstPort_d in (80, 443, 53))
| extend NormalizedProtocol = case(Protocol_d == 6, "TCP", Protocol_d == 17, "UDP", "Other"),
         GeoInfo = geo_info_from_ip_address(SrcAddr_s)
| project-away RawField1_s, RawField2_s, DebugInfo_s
```

### Data Collection Endpoints (DCE)

```powershell
# Create DCE and retrieve ingestion endpoint
az monitor data-collection endpoint create --name "dce-cross-cloud-prod" `
    --resource-group "rg-sentinel" --location "eastus" --public-network-access "Enabled"
$dce = az monitor data-collection endpoint show --name "dce-cross-cloud-prod" `
    --resource-group "rg-sentinel" | ConvertFrom-Json
Write-Output "Ingestion URI: $($dce.logsIngestion.endpoint)"
```

---

## ASIM — Cross-Cloud Unifying Parsers

### Unifying Authentication Parser

```kql
// Single parser queries Azure + AWS + GCP authentication events
let imAuthentication = () {
    union
        (SigninLogs
        | extend EventProduct="Entra ID", EventVendor="Microsoft", EventType="Logon",
            EventResult=iff(ResultType=="0","Success","Failure"),
            ActorUsername=UserPrincipalName, SrcIpAddr=IPAddress),
        (AWSCloudTrail
        | where EventName in ("ConsoleLogin","AssumeRole")
        | extend EventProduct="CloudTrail", EventVendor="AWS",
            EventType=iff(EventName=="ConsoleLogin","Logon","Elevate"),
            EventResult=iff(ErrorCode=="","Success","Failure"),
            ActorUsername=UserIdentityPrincipalid, SrcIpAddr=SourceIpAddress),
        (GCPAuditLogs_CL
        | where ServiceName_s == "iam.googleapis.com"
        | extend EventProduct="GCP Audit", EventVendor="Google", EventType="Logon",
            EventResult=iff(Severity_s=="ERROR","Failure","Success"),
            ActorUsername=AuthenticationInfo_principalEmail_s,
            SrcIpAddr=RequestMetadata_callerIp_s)
    | project TimeGenerated, EventProduct, EventVendor, EventType, EventResult,
        ActorUsername, SrcIpAddr
};
// Example: failed logins across all clouds
imAuthentication | where EventResult == "Failure"
| summarize Failures=count() by ActorUsername, SrcIpAddr, EventProduct, bin(TimeGenerated,1h)
| where Failures > 5
```

### Cross-Cloud Threat Hunting

```kql
// Detect same IP targeting multiple clouds
let SuspiciousIPs =
    union
        (AWSCloudTrail | where EventName=="ConsoleLogin" and ErrorCode!="" | project SrcIpAddr=SourceIpAddress, Cloud="AWS", TimeGenerated),
        (SigninLogs | where ResultType!="0" | project SrcIpAddr=IPAddress, Cloud="Azure", TimeGenerated),
        (GCPAuditLogs_CL | where Severity_s=="ERROR" | project SrcIpAddr=RequestMetadata_callerIp_s, Cloud="GCP", TimeGenerated)
    | where isnotempty(SrcIpAddr)
    | summarize CloudsTargeted=dcount(Cloud), CloudList=make_set(Cloud),
        TotalAttempts=count() by SrcIpAddr
    | where CloudsTargeted >= 2 and TotalAttempts > 10;
SuspiciousIPs | sort by TotalAttempts desc

// Cross-cloud privilege escalation chain
let AWSEsc = AWSCloudTrail
| where EventName in ("AttachUserPolicy","CreateAccessKey","AssumeRole")
| project TimeGenerated, Cloud="AWS", Actor=UserIdentityPrincipalid, Action=EventName;
let AzureEsc = AzureActivity
| where OperationNameValue has_any ("roleAssignments/write","elevateAccess/action")
| project TimeGenerated, Cloud="Azure", Actor=Caller, Action=OperationNameValue;
union AWSEsc, AzureEsc
| summarize Actions=make_list(pack("cloud",Cloud,"action",Action)),
    CloudsUsed=dcount(Cloud), ActionCount=count() by Actor, bin(TimeGenerated,1h)
| where CloudsUsed >= 2
```

---

## `.secops/` Integration

### Data Source Map Entries

```yaml
# Add to .secops/data-sources/data-source-map.yaml
AWSCloudTrail:
  location: "sentinel"
  workspace: "prod-sentinel"
  tier: "Basic"
  daily_gb: 15
  ingestion_method: "s3-to-sentinel"
  source_cloud: "aws"
AWSGuardDuty_CL:
  location: "sentinel"
  workspace: "prod-sentinel"
  tier: "Analytics"
  daily_gb: 0.5
  ingestion_method: "eventbridge-to-dce"
  source_cloud: "aws"
AWSVPCFlow_CL:
  location: "sentinel"
  workspace: "prod-sentinel"
  tier: "Sentinel data lake"
  daily_gb: 50
  ingestion_method: "s3-to-dce"
  source_cloud: "aws"
GCPAuditLogs_CL:
  location: "sentinel"
  workspace: "prod-sentinel"
  tier: "Analytics"
  daily_gb: 5
  ingestion_method: "pub-sub-to-sentinel"
  source_cloud: "gcp"
```

### Migration & Discovery Tracking

```yaml
# .secops/data-sources/migrations.yaml entry for SIEM migration
- id: "mig-splunk-001"
  status: "in-progress"
  description: "Splunk to Sentinel migration — security events"
  source: { location: "external", platform: "splunk" }
  target: { location: "sentinel", workspace: "prod-sentinel", tier: "Analytics" }
  started: "2026-03-01"
  estimated_completion: "2026-08-01"
  owner: "soc-platform-team"

# .secops/discovery-log.yaml — agent-discovered cross-cloud source
- timestamp: "2026-05-04T08:30:00Z"
  agent: "freamon"
  category: "data-source"
  finding: "Found AWSGuardDuty_CL custom table with 30-day data"
  source_cloud: "aws"
  confidence: "high"
  action_required: "Add to data-source-map.yaml with tier and volume"
```

---

## Cost Optimization

### Tier Selection

| Data Source | Tier | Rationale |
|---|---|---|
| CloudTrail | Basic | High volume, search-only sufficient |
| GuardDuty | Analytics | Low volume, need join/summarize |
| Security Hub | Analytics | Aggregated findings, full KQL needed |
| AWS VPC Flow Logs | Sentinel data lake | Very high volume, basic search |
| GCP Audit Logs | Analytics | Core security, full correlation |
| GCP VPC Flow Logs | Sentinel data lake | High volume |

### Summary Rules & Archive

```kql
// Summary rule: hourly VPC flow aggregation → reduces query cost
AWSVPCFlow_CL
| summarize TotalFlows=count(), TotalBytes=sum(Bytes_d), DeniedFlows=countif(Action_s=="REJECT"),
    UniqueSourceIPs=dcount(SrcAddr_s) by AccountId_s, AWSRegion_s, bin(TimeGenerated, 1h)
```

```powershell
# Archive policy for compliance retention (7 years)
Update-AzOperationalInsightsTable -ResourceGroupName "rg-sentinel" `
    -WorkspaceName "prod-sentinel" -TableName "AWSCloudTrail" `
    -RetentionInDays 90 -TotalRetentionInDays 2555
```

---

## PowerShell — Connector Health Monitoring

```powershell
function Get-CrossCloudConnectorHealth {
    [CmdletBinding()]
    param([int]$StaleThresholdMinutes = 60)

    $config = Get-SecOpsConfig -Path (Join-Path $PSScriptRoot "../../.secops/data-sources/data-source-map.yaml")
    $crossCloud = $config.sources.GetEnumerator() |
        Where-Object { $_.Value.source_cloud -and $_.Value.source_cloud -ne "azure" }

    foreach ($src in $crossCloud) {
        $query = "$($src.Key) | summarize LastEvent=max(TimeGenerated) | extend AgeMin=datetime_diff('minute',now(),LastEvent)"
        try {
            $r = Invoke-SecOpsLogAnalyticsQuery -WorkspaceId $WorkspaceId -Query $query
            New-SecOpsResult -Ok -Data @{
                Table = $src.Key; Cloud = $src.Value.source_cloud
                LastEvent = $r.LastEvent; AgeMinutes = $r.AgeMin
                Status = if ($r.AgeMin -gt $StaleThresholdMinutes) {"STALE"} else {"HEALTHY"}
            }
        } catch { New-SecOpsResult -Error "Failed to query $($src.Key): $_" }
    }
}

function Test-CrossCloudIngestionVolume {
    [CmdletBinding()]
    param([string]$WorkspaceId, [int]$VarianceThreshold = 30)

    $config = Get-SecOpsConfig -Path (Join-Path $PSScriptRoot "../../.secops/data-sources/data-source-map.yaml")
    foreach ($src in $config.sources.GetEnumerator()) {
        if (-not $src.Value.source_cloud -or $src.Value.source_cloud -eq "azure") { continue }
        $query = "Usage | where TimeGenerated > ago(1d) and DataType == `"$($src.Key)`" | summarize ActualGB=sum(Quantity)/1024.0"
        $r = Invoke-SecOpsLogAnalyticsQuery -WorkspaceId $WorkspaceId -Query $query
        $variance = if ($src.Value.daily_gb -gt 0) { [Math]::Abs(($r.ActualGB - $src.Value.daily_gb) / $src.Value.daily_gb * 100) } else { 0 }
        [PSCustomObject]@{ Table=$src.Key; Cloud=$src.Value.source_cloud; ExpectedGB=$src.Value.daily_gb
            ActualGB=[Math]::Round($r.ActualGB,2); VariancePct=[Math]::Round($variance,1)
            Status=if($variance -gt $VarianceThreshold){"DRIFT"}else{"OK"} }
    }
}
```

---

## References

- [Sentinel Data Connectors Reference](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference)
- [AWS S3 Connector](https://learn.microsoft.com/en-us/azure/sentinel/connect-aws)
- [GCP Connector](https://learn.microsoft.com/en-us/azure/sentinel/connect-google-cloud-platform)
- [ASIM Overview](https://learn.microsoft.com/en-us/azure/sentinel/normalization)
- [Codeless Connector Platform](https://learn.microsoft.com/en-us/azure/sentinel/create-codeless-connector)
- [Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [SPL to KQL Mapping](https://learn.microsoft.com/en-us/azure/sentinel/migrate-splunk-detection-rules)
