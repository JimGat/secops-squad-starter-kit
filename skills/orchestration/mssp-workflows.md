---
title: MSSP SecOps Workflows
category: orchestration
difficulty: advanced
mitre_attack:
  - T1078      # Valid Accounts
  - T1098      # Account Manipulation
  - T1199      # Trusted Relationship
  - T1087.004  # Cloud Account Discovery
products:
  - Azure Lighthouse
  - Microsoft Sentinel
  - Microsoft Defender XDR
  - Microsoft Defender for Cloud
  - Azure Monitor Log Analytics
author: Freamon
version: 1.0.0
last_updated: 2026-05-04
references:
  - skills/platform/multi-tenant-support.md
  - skills/orchestration/cross-skill-orchestration.md
---

# MSSP SecOps Workflows

## Overview

MSSPs manage 10–100+ customer tenants from a centralized SOC with distinct SLA commitments, detection requirements, and compliance obligations.

| Challenge | Single-Tenant SOC | MSSP SOC |
|---|---|---|
| **Tenant count** | 1 | 10–100+ |
| **SLA tracking** | Internal KPIs | Contractual per-customer SLAs |
| **Detection rules** | One ruleset | Per-customer tier (Gold/Silver/Bronze) |
| **Billing** | Cost center | Revenue driver — per-GB, per-SCU |
| **Analyst workflow** | Single context | Constant tenant switching |
| **Reporting** | Internal dashboards | Customer-facing branded reports |

This skill builds on [`multi-tenant-support.md`](../platform/multi-tenant-support.md) (Lighthouse, token management, tenant isolation) and [`cross-skill-orchestration.md`](cross-skill-orchestration.md) (workflow composition). It covers operational workflows unique to MSSP scenarios.

**Prerequisites:** Lighthouse delegations configured per `multi-tenant-support.md`. `.secops/environment.yaml` with `org_type: "mssp"`.

---

## Tenant Onboarding Workflow

### Customer Intake Checklist

```yaml
# .secops/onboarding/customer-intake-template.yaml
schema_version: "1.0"
customer:
  name: ""
  tenant_id: ""
  sla_tier: ""          # gold | silver | bronze
  contract_start: ""
workspace:
  subscription_id: ""
  resource_group: ""
  workspace_name: ""
  region: ""
  retention_days: 90
data_sources:
  - name: "SecurityEvent"
    expected_daily_gb: 0
lighthouse:
  delegated_subscriptions: []
  roles_required: ["Microsoft Sentinel Contributor", "Log Analytics Reader"]
compliance:
  frameworks: []        # SOC2, ISO27001, PCI-DSS
  data_residency: ""
```

### Automated Onboarding Function

```powershell
function New-MSSPCustomerOnboarding {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$IntakeFile, [switch]$DryRun)
    $intake = Get-Content $IntakeFile -Raw | ConvertFrom-Yaml
    $c = $intake.customer
    $required = @('name','tenant_id','sla_tier')
    $missing = $required | Where-Object { -not $c.$_ }
    if ($missing) { return @{ ok=$false; error="Missing: $($missing -join ', ')" } }
    if ($DryRun) { return @{ ok=$true; mode="dry-run"; customer=$c.name } }

    # Step 1: Lighthouse — uses Register-LighthouseDelegation from multi-tenant-support.md
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $mgmt = ($env.tenants | Where-Object { $_.type -eq "primary" }).id
    Register-LighthouseDelegation -CustomerSubscriptionId $intake.workspace.subscription_id `
        -ManagingTenantId $mgmt -TemplateFile "templates/lighthouse/mssp-delegation.json"

    # Step 2: Provision .secops/ configs for customer
    Initialize-CustomerSecOpsConfig -Intake $intake

    # Step 3: Validate data connectors
    $connectors = Test-CustomerDataConnectors -TenantId $c.tenant_id `
        -WorkspaceName $intake.workspace.workspace_name -ExpectedSources $intake.data_sources

    # Step 4: Deploy tier-appropriate detection rules
    Deploy-TierDetectionRules -TenantId $c.tenant_id `
        -WorkspaceName $intake.workspace.workspace_name -Tier $c.sla_tier

    Write-CrossTenantAudit -Operation "CustomerOnboarding" `
        -TargetTenantName $c.name -Details "SLA: $($c.sla_tier)"
    return @{ ok=$true; customer=$c.name; connectors=$connectors }
}
```

### Data Connector Validation & Tier Detection Deployment

`Initialize-CustomerSecOpsConfig` (called by onboarding) appends the new tenant to `environment.yaml`, creates a workspace YAML under `.secops/workspaces/<slug>-sentinel.yaml`, and adds data source entries to `data-source-map.yaml`.

```powershell
function Test-CustomerDataConnectors {
    [CmdletBinding()]
    param([string]$TenantId, [string]$WorkspaceName, [hashtable[]]$ExpectedSources)
    $results = foreach ($src in $ExpectedSources) {
        $q = "$($src.name) | where TimeGenerated > ago(1h) | count"
        $r = Invoke-TenantScopedApi -TenantId $TenantId `
            -Uri "https://api.loganalytics.io/v1/workspaces/$WorkspaceName/query" `
            -Method POST -Body @{ query=$q } -Resource "https://api.loganalytics.io"
        [PSCustomObject]@{ Source=$src.name; Flowing=($r.ok -and $r.data.tables[0].rows[0][0] -gt 0) }
    }
    return @{ ok=$true; sources=$results; all_flowing=($results | Where-Object {-not $_.Flowing}).Count -eq 0 }
}

function Deploy-TierDetectionRules {
    [CmdletBinding()]
    param([string]$TenantId, [string]$WorkspaceName, [ValidateSet("gold","silver","bronze")][string]$Tier)
    $rulePacks = @{
        bronze = @("brute-force-detection","malware-alerts","suspicious-signin")
        silver = @("brute-force-detection","malware-alerts","suspicious-signin",
                   "lateral-movement","data-exfiltration","privilege-escalation")
        gold   = @("brute-force-detection","malware-alerts","suspicious-signin","lateral-movement",
                   "data-exfiltration","privilege-escalation","insider-threat","advanced-hunting","custom-ti-matching")
    }
    foreach ($rule in $rulePacks[$Tier]) {
        $tpl = Get-Content "templates/detection-rules/$rule.json" -Raw | ConvertFrom-Json
        Invoke-TenantScopedApi -TenantId $TenantId `
            -Uri "https://management.azure.com/.../alertRules/$($tpl.name)?api-version=2023-11-01" `
            -Method PUT -Body $tpl
    }
}
```

---

## SOC Dashboard Aggregation

### Cross-Tenant Incident Summary

```kql
// Run via Invoke-CrossTenantQuery — union results from all managed workspaces
SecurityIncident
| where TimeGenerated > ago(24h)
| summarize
    TotalIncidents = count(),
    HighSeverity = countif(Severity == "High"),
    OpenIncidents = countif(Status in ("New", "Active")),
    AvgTimeToTriage = avg(datetime_diff('minute', FirstModifiedTime, CreatedTime)),
    AvgTimeToClose = avg(iff(Status == "Closed",
        datetime_diff('minute', ClosedTime, CreatedTime), long(null)))
```

### SLA Tracking Per Customer

```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| extend ResponseMin = datetime_diff('minute', FirstModifiedTime, CreatedTime)
| summarize
    Count = count(),
    P95ResponseMin = percentile(ResponseMin, 95)
    by Severity
| extend SLATarget = case(Severity == "High", 15, Severity == "Medium", 60, 240)
| extend SLAMet = iff(P95ResponseMin <= SLATarget, "✅", "❌")
```

### Tenant Health Scorecard

```kql
// Ingestion health — detect drops indicating connector issues
Usage
| where TimeGenerated > ago(7d)
| summarize DailyGB = sum(Quantity) / 1024 by bin(TimeGenerated, 1d), DataType
| summarize AvgGB = avg(DailyGB), MinGB = min(DailyGB) by DataType
| extend Health = iff(MinGB < AvgGB * 0.5, "⚠️ Drop", "✅ Stable")
```

```kql
// Alert fatigue ratio
SecurityAlert
| where TimeGenerated > ago(30d)
| summarize Total = count(), FP = countif(Status == "Dismissed")
| extend FatigueRatio = round(todouble(FP) / Total * 100, 1)
| extend Health = case(FatigueRatio > 70, "🔴 Critical", FatigueRatio > 40, "🟡 Warning", "🟢 Healthy")
```

### Dashboard Aggregation Function

```powershell
function Get-MSSPDashboard {
    [CmdletBinding()]
    param([int]$HoursBack = 24, [ValidateSet("summary","sla","health","all")][string]$View = "all")
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $managed = $env.tenants | Where-Object { $_.type -in @("lighthouse-delegated","managed") }
    $dashboard = @{}
    if ($View -in @("summary","all")) {
        $dashboard.summary = Invoke-CrossTenantQuery -Query @"
SecurityIncident | where TimeGenerated > ago($($HoursBack)h)
| summarize Total=count(), High=countif(Severity=='High'), Open=countif(Status in ('New','Active'))
"@
    }
    if ($View -in @("sla","all")) {
        $dashboard.sla = Invoke-CrossTenantQuery -Query @"
SecurityIncident | where TimeGenerated > ago(30d)
| extend ResponseMin=datetime_diff('minute', FirstModifiedTime, CreatedTime)
| summarize P95=percentile(ResponseMin, 95), Count=count() by Severity
"@
    }
    if ($View -in @("health","all")) {
        $dashboard.health = Invoke-CrossTenantQuery -Query "Usage | where TimeGenerated > ago(1d) | summarize TotalGB=sum(Quantity)/1024"
    }
    return @{ ok=$true; data=$dashboard; tenants=$managed.Count }
}
```

---

## Multi-Tenant Alerting

### Alert Routing by Tenant

```yaml
# .secops/alerting/routing.yaml — MSSP extension
mssp_routing:
  - customer: "Acme Corp"
    sla_tier: "gold"
    assigned_team: "soc-team-alpha"
    channels:
      high:   { type: "pagerduty", integration_key: "pd-acme-high" }
      medium: { type: "teams", webhook: "https://..." }
      low:    { type: "email", to: "soc-triage@secureops.com" }
  - customer: "Globex Industries"
    sla_tier: "silver"
    assigned_team: "soc-team-beta"
    channels:
      high:   { type: "teams", webhook: "https://..." }
      medium: { type: "email", to: "soc-triage@secureops.com" }
      low:    { type: "email", to: "soc-triage@secureops.com" }
```

### SLA Escalation Paths

| Severity | Gold (15/30/60 min) | Silver (30/60/240 min) | Bronze (60/240/480 min) |
|---|---|---|---|
| **High** | PagerDuty → L2 15m → Mgr 30m | Teams → L2 30m → Mgr 60m | Email → L2 60m |
| **Medium** | Teams → L2 30m | Email → L2 60m | Email → L2 240m |
| **Low** | Email 60m | Email 240m | Daily digest |

### Cross-Tenant Threat Correlation

```kql
// Same attacker IP across tenants — run per tenant, aggregate in managing tenant
SigninLogs
| where TimeGenerated > ago(24h) and ResultType != 0
| summarize FailedAttempts=count(), TargetAccounts=dcount(UserPrincipalName),
    FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by IPAddress
| where FailedAttempts > 10 or TargetAccounts > 3
```

```powershell
function Find-CrossTenantThreatActor {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$IoC, [string]$Type = "ip")
    $queries = @{
        ip     = "SigninLogs | where IPAddress == '$IoC' | summarize Hits=count(), Users=dcount(UserPrincipalName)"
        hash   = "DeviceFileEvents | where SHA256 == '$IoC' | summarize Hits=count(), Devices=dcount(DeviceName)"
        domain = "DnsEvents | where Name contains '$IoC' | summarize Hits=count(), Sources=dcount(ClientIP)"
    }
    $results = Invoke-CrossTenantQuery -Query $queries[$Type] -Timespan "P7D"
    $affected = $results.data | Where-Object { $_.Data[1] -gt 0 } | Select-Object -ExpandProperty Tenant -Unique
    return @{ ok=$true; ioc=$IoC; affected_tenants=$affected }
}
```

### Per-Tenant Alert Suppression

```powershell
function Set-MSSPAlertSuppression {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CustomerName, [Parameter(Mandatory)][string]$RuleName,
          [Parameter(Mandatory)][string]$Reason, [int]$DurationHours = 24)
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $tenant = $env.tenants | Where-Object { $_.name -eq $CustomerName }
    if (-not $tenant) { return @{ ok=$false; error="Customer not found" } }
    $suppression = @{
        customer=$CustomerName; rule=$RuleName; reason=$Reason
        expires=(Get-Date).AddHours($DurationHours).ToString("o")
        created_by=(Get-AzContext).Account.Id
    }
    $slug = ($CustomerName -replace '[^a-zA-Z0-9]','-').ToLower()
    $path = ".secops/alerting/suppressions/$slug.yaml"
    if (-not (Test-Path (Split-Path $path))) { New-Item -ItemType Directory -Path (Split-Path $path) -Force | Out-Null }
    $suppression | ConvertTo-Yaml | Add-Content $path -Encoding UTF8
    Write-CrossTenantAudit -Operation "AlertSuppression" -TargetTenantName $CustomerName -Details "Rule: $RuleName"
    return @{ ok=$true; suppression=$suppression }
}
```

---

## Customer Tenant Switching Workflows

### Quick-Switch with State Preservation

```powershell
# Extends Switch-SecOpsTenant from multi-tenant-support.md
function Switch-MSSPCustomer {
    [CmdletBinding()]
    param([Parameter(Mandatory,Position=0)][string]$CustomerName, [switch]$PreserveState)
    if ($PreserveState) {
        $ctx = Get-Content ".secops/tenant-context.yaml" -Raw -ErrorAction SilentlyContinue | ConvertFrom-Yaml
        if ($ctx.active_tenant) {
            $file = ".secops/analyst-state/$($ctx.active_tenant.name -replace ' ','-').yaml"
            @{ tenant=$ctx.active_tenant.name; saved_at=(Get-Date -Format "o")
               open_incidents=$Global:SecOpsOpenIncidents; active_query=$Global:SecOpsLastQuery
            } | ConvertTo-Yaml | Set-Content $file -Encoding UTF8
        }
    }
    $result = Switch-SecOpsTenant -TenantName $CustomerName
    $file = ".secops/analyst-state/$($CustomerName -replace ' ','-').yaml"
    if (Test-Path $file) {
        $saved = Get-Content $file -Raw | ConvertFrom-Yaml
        $Global:SecOpsOpenIncidents = $saved.open_incidents
        Write-Host "  Restored state from $($saved.saved_at)" -ForegroundColor DarkCyan
    }
    return $result
}
```

### Batch Operations Across Tenant Groups

```powershell
function Invoke-MSSPBatchOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$Operation,
        [ValidateSet("all","gold","silver","bronze")][string]$TierFilter = "all",
        [int]$ThrottleLimit = 5
    )
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $tenants = $env.tenants | Where-Object { $_.type -in @("lighthouse-delegated","managed") }
    if ($TierFilter -ne "all") {
        $tenants = $tenants | Where-Object { $_.lighthouse_delegation.sla_tier -eq $TierFilter }
    }
    # Uses Invoke-ParallelTenantOperation from multi-tenant-support.md
    Invoke-ParallelTenantOperation -Operation $Operation `
        -TenantFilter $tenants.name -ThrottleLimit $ThrottleLimit
}
```

---

## Reporting & Compliance

### Monthly Executive Report

```powershell
function Export-MSSPCustomerReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CustomerName, [string]$Period = "P30D",
          [ValidateSet("html","json","csv")][string]$Format = "html")
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $tenant = $env.tenants | Where-Object { $_.name -eq $CustomerName }
    if (-not $tenant) { return @{ ok=$false; error="Customer not found" } }
    $metrics = @{
        incidents = Invoke-CrossTenantQuery -Timespan $Period -TenantFilter $CustomerName -Query @"
SecurityIncident | summarize Total=count(), High=countif(Severity=='High'),
  MTTR_Hrs=avg(iff(Status=='Closed', datetime_diff('hour',ClosedTime,CreatedTime), real(null)))
"@
        ingestion = Invoke-CrossTenantQuery -Timespan $Period -TenantFilter $CustomerName -Query @"
Usage | where IsBillable == true | summarize TotalGB=round(sum(Quantity)/1024, 2)
"@
    }
    $outPath = "reports/$($CustomerName -replace ' ','-')-$(Get-Date -Format 'yyyyMM').$Format"
    @{ customer=$CustomerName; period=$Period; generated=(Get-Date -Format "o"); metrics=$metrics } |
        ConvertTo-Json -Depth 10 | Set-Content $outPath -Encoding UTF8
    Write-CrossTenantAudit -Operation "ExportReport" -TargetTenantName $CustomerName
    return @{ ok=$true; path=$outPath }
}
```

### Compliance Evidence Export

Generates per-framework evidence packages (SOC 2, ISO 27001, PCI-DSS) by running control-mapped KQL queries against customer workspaces and exporting structured JSON with control IDs, record counts, and raw data for auditor review. Uses `Invoke-CrossTenantQuery` with 90-day timespan. Output stored in `reports/compliance/<customer>-<framework>-<date>.json`.

### Portfolio Trend Analysis

```kql
// 90-day trend — run per tenant, union in managing tenant
SecurityIncident
| where TimeGenerated > ago(90d)
| summarize Weekly=count(), HighSev=countif(Severity == "High") by Week=startofweek(TimeGenerated)
| order by Week asc
| extend Trend = iff(Weekly > prev(Weekly), "📈", "📉")
```

---

## MSSP Billing Integration

### Ingestion Volume Tracking

```kql
Usage
| where TimeGenerated > ago(30d) and IsBillable == true
| summarize BillableGB = round(sum(Quantity) / 1024, 2) by DataType
| order by BillableGB desc
| extend MonthlyCost = round(BillableGB * 2.76, 2)  // analytics tier example
```

### Billing Summary & Feature Tier Enforcement

```powershell
function Get-MSSPBillingSummary {
    [CmdletBinding()]
    param([string]$Period = "P30D")
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $cfg = Get-Content ".secops/mssp-config.yaml" -Raw -ErrorAction SilentlyContinue | ConvertFrom-Yaml
    $managed = $env.tenants | Where-Object { $_.type -in @("lighthouse-delegated","managed") }
    $billing = foreach ($t in $managed) {
        $r = Invoke-CrossTenantQuery -Timespan $Period -TenantFilter $t.name -Query "Usage | where IsBillable | summarize GB=round(sum(Quantity)/1024,2)"
        $gb = if ($r.ok -and $r.data.Count -gt 0) { $r.data[0].Data[0] } else { 0 }
        $tier = $cfg.billing.tiers | Where-Object { $_.name -eq $t.lighthouse_delegation.sla_tier }
        [PSCustomObject]@{ Customer=$t.name; Tier=$t.lighthouse_delegation.sla_tier
            BillableGB=$gb; TotalCharge=[math]::Round($gb * ($tier.cost_per_gb ?? 2.76), 2) }
    }
    return @{ ok=$true; billing=$billing; total=($billing | Measure-Object TotalCharge -Sum).Sum }
}

function Assert-MSSPFeatureTier {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CustomerName, [Parameter(Mandatory)][string]$Feature)
    $cfg = Get-Content ".secops/mssp-config.yaml" -Raw | ConvertFrom-Yaml
    $customer = $cfg.customers | Where-Object { $_.name -eq $CustomerName }
    $tierFeatures = @{
        bronze = @("basic-monitoring","incident-response","monthly-report")
        silver = @("basic-monitoring","incident-response","monthly-report","threat-hunting","custom-detections")
        gold   = @("basic-monitoring","incident-response","monthly-report","threat-hunting","custom-detections",
                   "dedicated-analyst","real-time-dashboard","compliance-reporting","24x7-coverage")
    }
    $allowed = $tierFeatures[$customer.sla_tier]
    if ($Feature -notin $allowed) { return @{ ok=$false; error="'$Feature' requires upgrade from $($customer.sla_tier)" } }
    return @{ ok=$true; feature=$Feature; tier=$customer.sla_tier }
}
```

---

## `.secops/` MSSP Extensions

### `mssp-config.yaml` Schema

```yaml
# .secops/mssp-config.yaml
schema_version: "1.0"
soc_teams:
  - name: "soc-team-alpha"
    lead: "lead1@secureops.com"
    analysts: ["analyst1@secureops.com", "analyst2@secureops.com"]
    shift: "day"        # day | night | 24x7
customers:
  - name: "Acme Corp"
    sla_tier: "gold"
    assigned_team: "soc-team-alpha"
    notification_channels:
      primary: { type: "pagerduty", key: "pd-acme" }
      servicenow: { instance: "acme.service-now.com", assignment_group: "SOC" }
    compliance_frameworks: ["SOC2", "ISO27001"]
  - name: "Globex Industries"
    sla_tier: "silver"
    assigned_team: "soc-team-beta"
    notification_channels:
      primary: { type: "teams", webhook: "https://..." }
    compliance_frameworks: ["PCI-DSS"]
billing:
  tiers:
    - name: "gold"
      cost_per_gb: 4.50
      scu_allocation: 6
      base_monthly_fee: 15000
    - name: "silver"
      cost_per_gb: 3.25
      scu_allocation: 3
      base_monthly_fee: 8000
    - name: "bronze"
      cost_per_gb: 2.00
      scu_allocation: 1
      base_monthly_fee: 3000
sla_definitions:
  gold:   { high_response_min: 15, medium_response_min: 30, low_response_min: 60, availability: "24x7" }
  silver: { high_response_min: 30, medium_response_min: 60, low_response_min: 240, availability: "8x5" }
  bronze: { high_response_min: 60, medium_response_min: 240, low_response_min: 480, availability: "8x5" }
analyst_rotation:
  schedule:
    - shift: "day"
      days: ["Monday","Tuesday","Wednesday","Thursday","Friday"]
      assignments:
        - { customer: "Acme Corp", analyst: "analyst1@secureops.com" }
        - { customer: "Globex Industries", analyst: "analyst3@secureops.com" }
```

### Centralized vs Distributed Config

| Pattern | When | Tradeoffs |
|---|---|---|
| **Centralized** — single `mssp-config.yaml` | < 20 customers | Simple; doesn't scale |
| **Distributed** — per-customer folder | 20+ customers | Scales; harder to audit |
| **Hybrid** — central SLA + per-customer overlay | 50+ customers | Best of both; merge logic |

Distributed layout:

```
.secops/customers/
├── acme-corp/
│   ├── config.yaml        # Customer overrides
│   └── suppressions.yaml  # Alert suppressions
├── globex-industries/
│   └── config.yaml
└── _defaults/
    └── config.yaml        # Inherited by all
```

---

## Quick Reference

| Task | Function | Source |
|---|---|---|
| Onboard customer | `New-MSSPCustomerOnboarding` | This skill |
| SOC dashboard | `Get-MSSPDashboard` | This skill |
| Batch tenant ops | `Invoke-MSSPBatchOperation` | This skill |
| Customer report | `Export-MSSPCustomerReport` | This skill |
| Switch customer | `Switch-MSSPCustomer` | This skill |
| Cross-tenant query | `Invoke-CrossTenantQuery` | `multi-tenant-support.md` |
| Parallel ops | `Invoke-ParallelTenantOperation` | `multi-tenant-support.md` |
| Lighthouse setup | `Register-LighthouseDelegation` | `multi-tenant-support.md` |
| Compliance export | `Export-ComplianceEvidence` | This skill |
| Billing summary | `Get-MSSPBillingSummary` | This skill |
| Threat correlation | `Find-CrossTenantThreatActor` | This skill |
| Alert suppression | `Set-MSSPAlertSuppression` | This skill |
| Feature tier check | `Assert-MSSPFeatureTier` | This skill |
