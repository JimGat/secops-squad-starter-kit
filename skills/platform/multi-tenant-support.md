---
title: Multi-Tenant SecOps Operations
category: platform
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
  - Microsoft Entra ID
  - Azure Monitor Log Analytics
author: Sydnor
version: 1.0.0
last_updated: 2026-05-04
---

# Multi-Tenant SecOps Operations

## Overview

Most SecOps frameworks assume a single Azure tenant. Real-world scenarios differ:

| Scenario | Tenants | Access Model | Key Challenge |
|---|---|---|---|
| **MSSP** | 10–100+ | Lighthouse | Scale, isolation, per-customer SLAs |
| **Enterprise + subs** | 2–10 | B2B + Lighthouse | Unified visibility |
| **B2B ISV** | 50–500+ | Multi-tenant app reg | Token management, throttling |
| **Government split** | 2–4 | Separate credentials | Air-gapped endpoints |

**Principles:** (1) Every API call carries explicit tenant context. (2) Least privilege per tenant via scoped Lighthouse roles. (3) Data never crosses tenant boundaries unless aggregated in the managing tenant. (4) Separate token per tenant. (5) All cross-tenant operations are audited.

## Environment Context

Before multi-tenant operations, agents MUST check `.secops/`:

- **`environment.yaml`** — `org_type`, `tenants[]`, `lighthouse.delegations[]`
- **`workspaces/`** — Per-tenant workspace definitions
- **`data-sources/data-source-map.yaml`** — Tenant-scoped table routing
- **`identity/tenants.yaml`** — Cross-tenant RBAC
- **`compliance/requirements.yaml`** — Per-tenant data residency

If `.secops/` does not exist, run `secops-squad init --secops` first.

---

## Azure Lighthouse

Lighthouse enables delegated resource management — MSSP analysts manage customer Sentinel workspaces without switching directories or sharing credentials.

```
┌──────────────────────┐       ┌──────────────────────┐
│ Managing Tenant      │       │ Customer Tenant      │
│ SOC Analysts ────────┼───────┼─► Delegated Subs     │
│ Automation ──────────┼───────┼─► Scoped RBAC        │
│ ✅ Single sign-on    │       │ ✅ Customer control   │
└──────────────────────┘       └──────────────────────┘
```

### Onboarding via ARM Template

```powershell
function Register-LighthouseDelegation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CustomerSubscriptionId,
        [Parameter(Mandatory)][string]$ManagingTenantId,
        [Parameter(Mandatory)][string]$TemplateFile,
        [string]$Location = "eastus2"
    )
    $ctx = Get-AzContext
    if (-not $ctx) { throw "Run Connect-AzAccount -Tenant <customer-tenant> first." }
    Set-AzContext -SubscriptionId $CustomerSubscriptionId -ErrorAction Stop
    $name = "lighthouse-$(Get-Date -Format 'yyyyMMddHHmmss')"
    $result = New-AzSubscriptionDeployment -Name $name -Location $Location `
        -TemplateFile $TemplateFile -managedByTenantId $ManagingTenantId -ErrorAction Stop
    return @{ ok = $true; data = @{ deployment = $name; state = $result.ProvisioningState } }
}
```

### RBAC Roles for Lighthouse

| Role | ID | Use Case |
|---|---|---|
| Sentinel Reader | `8d289c81-...` | L1 — view incidents, queries |
| Sentinel Responder | `3e150fc0-...` | L2 — update incidents, playbooks |
| Sentinel Contributor | `51d6186e-...` | Engineers — create rules |
| Log Analytics Reader | `73c42c96-...` | Query-only access |

**Critical:** Lighthouse does NOT support `Owner` or `User Access Administrator`. Customers always retain ultimate control.

### Cross-Workspace Sentinel Incidents

```powershell
function Get-CrossTenantSentinelIncidents {
    [CmdletBinding()]
    param([ValidateSet("New","Active","Closed")][string]$Status = "Active")
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $delegations = $env.lighthouse.delegations
    if (-not $delegations) { return @{ ok = $true; data = @() } }
    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($d in $delegations) {
        try {
            foreach ($ws in (Get-AzOperationalInsightsWorkspace)) {
                Get-AzSentinelIncident -ResourceGroupName $ws.ResourceGroupName `
                    -WorkspaceName $ws.Name |
                    Where-Object { $_.Status -eq $Status } |
                    ForEach-Object { $all.Add([PSCustomObject]@{
                        Tenant=$d.customer_name; Workspace=$ws.Name
                        Title=$_.Title; Severity=$_.Severity; Created=$_.CreatedTimeUtc
                    })}
            }
        } catch { Write-Warning "Query failed for $($d.customer_name): $_" }
    }
    return @{ ok = $true; data = $all.ToArray() }
}
```

---

## `.secops/` Multi-Tenant Schema

### Extended `environment.yaml`

```yaml
schema_version: "1.0"
organization:
  name: "SecureOps MSSP"
  cloud: "azure-commercial"
  primary_region: "eastus2"
  org_type: "mssp"       # Triggers multi-tenant agent behavior

tenants:
  - id: "aaaa1111-bbbb-cccc-dddd-eeeeeeee0001"
    name: "SecureOps Management"
    type: "primary"

  - id: "aaaa1111-bbbb-cccc-dddd-eeeeeeee0002"
    name: "Acme Corp"
    type: "lighthouse-delegated"
    lighthouse_delegation:
      onboarded_date: "2025-11-15"
      delegated_subscriptions: ["sub-acme-prod-001"]
      delegated_roles: ["Microsoft Sentinel Contributor", "Log Analytics Reader"]
      sla_tier: "premium"

  - id: "aaaa1111-bbbb-cccc-dddd-eeeeeeee0003"
    name: "Globex Industries"
    type: "managed"
    managed_access:
      admin_consent_granted: true
      credentials_vault: "keyvault://secureops-vault/globex-sp"

lighthouse:
  delegations:
    - customer_tenant: "aaaa1111-bbbb-cccc-dddd-eeeeeeee0002"
      customer_name: "Acme Corp"
      delegated_roles: ["Microsoft Sentinel Contributor", "Log Analytics Reader"]
```

### Per-Tenant Workspace Mappings

Files under `.secops/workspaces/` include `tenant_id` linking to the tenant array:

```yaml
# .secops/workspaces/acme-sentinel.yaml
schema_version: "1.0"
workspace:
  name: "acme-sentinel-prod"
  resource_id: "/subscriptions/sub-acme-prod-001/resourceGroups/rg-soc/..."
  tenant_id: "aaaa1111-bbbb-cccc-dddd-eeeeeeee0002"
  log_analytics_workspace_id: "ws-acme-prod-001"
  retention_days: 90
```

### Tenant-Scoped Data Sources

Extend `data-source-map.yaml` with `tenant_id` per entry to route queries correctly:

```yaml
tables:
  - name: "SecurityEvent"
    tenant_id: "aaaa1111-bbbb-cccc-dddd-eeeeeeee0002"
    workspace: "acme-sentinel-prod"
    tier: "analytics"
  - name: "SecurityEvent"
    tenant_id: "aaaa1111-bbbb-cccc-dddd-eeeeeeee0003"
    workspace: "globex-sentinel-prod"
    tier: "analytics"
```

### Tenant Context File

Agents track active tenant in `.secops/tenant-context.yaml` (agent-managed, gitignored):

```yaml
schema_version: "1.0"
active_tenant:
  id: "aaaa1111-bbbb-cccc-dddd-eeeeeeee0002"
  name: "Acme Corp"
  switched_at: "2026-05-04T13:41:00Z"
default_tenant:
  id: "aaaa1111-bbbb-cccc-dddd-eeeeeeee0001"
  name: "SecureOps Management"
```

### Cross-Tenant Discovery Log Entries

Discovery log entries include tenant attribution for MSSP traceability:

```yaml
- timestamp: "2026-05-04T13:42:00Z"
  agent: "freamon"
  tenant_id: "aaaa1111-bbbb-cccc-dddd-eeeeeeee0002"
  tenant_name: "Acme Corp"
  category: "data-source"
  finding: "SigninLogs confirmed active in acme-sentinel-prod"
  confidence: "confirmed"
```

---

## API Wrapper Patterns

### Token Acquisition Per Tenant

```powershell
$script:TokenCache = @{}

function Get-TenantScopedToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$Resource,
        [string]$ClientId = $env:SECOPS_CLIENT_ID,
        [string]$ClientSecret = $env:SECOPS_CLIENT_SECRET
    )
    $key = "$TenantId|$Resource"
    if ($script:TokenCache.ContainsKey($key)) {
        $c = $script:TokenCache[$key]
        if ($c.ExpiresOn -gt (Get-Date).AddMinutes(5)) { return @{ ok=$true; data=$c } }
    }
    try {
        $r = Invoke-RestMethod -Method Post `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -Body @{ grant_type="client_credentials"; client_id=$ClientId
                     client_secret=$ClientSecret; scope="$Resource/.default" }
        $entry = @{ AccessToken=$r.access_token; ExpiresOn=(Get-Date).AddSeconds($r.expires_in); TenantId=$TenantId }
        $script:TokenCache[$key] = $entry
        return @{ ok = $true; data = $entry }
    } catch { return @{ ok = $false; error = "Token failed: $_"; tenant = $TenantId } }
}
```

### Tenant-Scoped API Wrapper

```powershell
function Invoke-TenantScopedApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = "GET", [object]$Body,
        [string]$Resource = "https://management.azure.com"
    )
    $token = Get-TenantScopedToken -TenantId $TenantId -Resource $Resource
    if (-not $token.ok) { return @{ ok=$false; error=$token.error } }
    $headers = @{ Authorization="Bearer $($token.data.AccessToken)"; "Content-Type"="application/json" }
    try {
        $p = @{ Uri=$Uri; Method=$Method; Headers=$headers }
        if ($Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10) }
        return @{ ok=$true; data=(Invoke-RestMethod @p); tenant=$TenantId }
    } catch { return @{ ok=$false; error=$_.Exception.Message; tenant=$TenantId } }
}
```

### Cross-Tenant Query (Union Across Workspaces)

```powershell
function Invoke-CrossTenantQuery {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Query, [string]$Timespan = "P1D", [string[]]$TenantFilter)
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $results = [System.Collections.Generic.List[object]]::new()
    $errors  = [System.Collections.Generic.List[object]]::new()
    foreach ($f in (Get-ChildItem ".secops/workspaces/*.yaml")) {
        $ws = (Get-Content $f.FullName -Raw | ConvertFrom-Yaml).workspace
        $t = $env.tenants | Where-Object { $_.id -eq $ws.tenant_id }
        if ($TenantFilter -and $t.name -notin $TenantFilter) { continue }
        $r = Invoke-TenantScopedApi -TenantId $ws.tenant_id `
            -Uri "https://api.loganalytics.io/v1/workspaces/$($ws.name)/query" `
            -Method POST -Body @{ query=$Query; timespan=$Timespan } -Resource "https://api.loganalytics.io"
        if ($r.ok) { foreach ($row in $r.data.tables[0].rows) {
            $results.Add([PSCustomObject]@{ Tenant=$t.name; Workspace=$ws.name; Data=$row })
        }} else { $errors.Add(@{ tenant=$t.name; error=$r.error }) }
    }
    return @{ ok=$true; data=$results.ToArray(); errors=$errors.ToArray() }
}
```

### Tenant Isolation Safeguard

```powershell
function Assert-TenantIsolation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ExpectedTenantId, [Parameter(Mandatory)][string]$ResourceId)
    $ctx = Get-AzContext
    if ($ctx.Tenant.Id -ne $ExpectedTenantId) {
        throw "ISOLATION VIOLATION: context tenant ($($ctx.Tenant.Id)) != expected ($ExpectedTenantId)"
    }
    if ($ResourceId -match "/subscriptions/([^/]+)/") {
        $sub = Get-AzSubscription -SubscriptionId $Matches[1] -ErrorAction SilentlyContinue
        if ($sub.TenantId -ne $ExpectedTenantId) { throw "ISOLATION VIOLATION: wrong subscription tenant" }
    }
    return @{ ok = $true; tenant = $ExpectedTenantId }
}
```

---

## Cross-Tenant Workflows

### Incident Aggregation (SOC Dashboard)

```powershell
function Get-MSSPIncidentDashboard {
    [CmdletBinding()]
    param([int]$HoursBack = 24)
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $managed = $env.tenants | Where-Object { $_.type -in @("lighthouse-delegated","managed") }
    $dash = [System.Collections.Generic.List[object]]::new()
    foreach ($t in $managed) {
        $q = "SecurityIncident | where TimeGenerated > ago(${HoursBack}h) " +
             "| summarize Total=count(), High=countif(Severity=='High'), Open=countif(Status in ('New','Active'))"
        $r = Invoke-CrossTenantQuery -Query $q -TenantFilter $t.name
        if ($r.ok -and $r.data.Count -gt 0) {
            $dash.Add([PSCustomObject]@{
                Tenant=$t.name; SLA=$t.lighthouse_delegation.sla_tier
                Total=$r.data[0].Data[0]; High=$r.data[0].Data[1]; Open=$r.data[0].Data[2]
            })
        }
    }
    return @{ ok=$true; data=$dash.ToArray(); period="${HoursBack}h" }
}
```

### Unified Threat Hunting

```powershell
function Start-CrossTenantHunt {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$HuntQuery, [string]$Timespan = "P7D")
    $results = Invoke-CrossTenantQuery -Query $HuntQuery -Timespan $Timespan
    $correlations = $results.data | Group-Object { $_.Data[0] } |
        Where-Object { $_.Count -gt 1 } | ForEach-Object {
            [PSCustomObject]@{
                Indicator=$_.Name; Tenants=($_.Group.Tenant | Select-Object -Unique) -join ", "
                Hits=$_.Count
            }
        }
    return @{ ok=$true; results=$results.data; correlations=$correlations; errors=$results.errors }
}
```

### Compliance Posture Rollup

```powershell
function Get-CrossTenantCompliancePosture {
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $managed = $env.tenants | Where-Object { $_.type -in @("lighthouse-delegated","managed") }
    $posture = [System.Collections.Generic.List[object]]::new()
    foreach ($t in $managed) {
        $tok = Get-TenantScopedToken -TenantId $t.id -Resource "https://management.azure.com"
        if (-not $tok.ok) { continue }
        try {
            $s = Invoke-RestMethod -Headers @{ Authorization="Bearer $($tok.data.AccessToken)" } `
                -Uri "https://management.azure.com/providers/Microsoft.Security/secureScores/ascScore?api-version=2020-01-01"
            $posture.Add([PSCustomObject]@{
                Tenant=$t.name; Score=[math]::Round(($s.properties.score.current/$s.properties.score.max)*100,1)
            })
        } catch { Write-Warning "Score unavailable for $($t.name)" }
    }
    return @{ ok=$true; per_tenant=$posture.ToArray() }
}
```

### Alert Routing Per Tenant

Route alerts through SLA-tier-aware escalation paths defined in `.secops/alerting/routing.yaml`. Premium tenants get PagerDuty for High severity (15-min SLA); standard tenants get Teams (60-min SLA). Medium/Low alerts route to email with longer SLAs.

---

## PowerShell Patterns

### `Switch-SecOpsTenant`

```powershell
function Switch-SecOpsTenant {
    [CmdletBinding()]
    param([Parameter(Mandatory,Position=0)][string]$TenantName, [switch]$Force)
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $t = $env.tenants | Where-Object { $_.name -eq $TenantName }
    if (-not $t) { throw "Tenant '$TenantName' not found. Available: $(($env.tenants.name) -join ', ')" }
    $ctx = Get-AzContext
    if ($ctx.Tenant.Id -ne $t.id -or $Force) {
        Write-Host "Switching to $($t.name)..." -ForegroundColor Cyan
        Connect-AzAccount -TenantId $t.id -ErrorAction Stop | Out-Null
    }
    $primary = $env.tenants | Where-Object { $_.type -eq "primary" }
    @{ schema_version="1.0"
       active_tenant=@{ id=$t.id; name=$t.name; switched_at=(Get-Date -Format "o") }
       default_tenant=@{ id=$primary.id; name=$primary.name }
    } | ConvertTo-Yaml | Set-Content ".secops/tenant-context.yaml" -Encoding UTF8
    Write-Host "Active tenant: $($t.name)" -ForegroundColor Green
    return @{ ok=$true; tenant=$t.name; tenantId=$t.id }
}
```

### Parallel Tenant Operations with Throttling

```powershell
function Invoke-ParallelTenantOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$Operation,
        [string[]]$TenantFilter, [int]$ThrottleLimit = 5, [int]$MaxRetries = 3
    )
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $tenants = $env.tenants | Where-Object { $_.type -in @("primary","lighthouse-delegated","managed") }
    if ($TenantFilter) { $tenants = $tenants | Where-Object { $TenantFilter -contains $_.name } }
    $results = $tenants | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $t = $_; $op = $using:Operation
        for ($i = 1; $i -le $using:MaxRetries; $i++) {
            try { $d = & $op -Tenant $t; [PSCustomObject]@{ Tenant=$t.name; Status="OK"; Data=$d }; break }
            catch { if ($i -eq $using:MaxRetries) { [PSCustomObject]@{ Tenant=$t.name; Status="FAIL"; Error=$_.Exception.Message } }
                    else { Start-Sleep (10 * $i) } }
        }
    }
    return @{ ok=($results | Where-Object Status -eq "FAIL").Count -eq 0; results=$results }
}
```

### Token Cache Management

```powershell
function Get-TokenCacheStatus {
    if (-not $script:TokenCache) { return @() }
    $now = Get-Date
    $script:TokenCache.Keys | ForEach-Object {
        $e = $script:TokenCache[$_]; $rem = ($e.ExpiresOn - $now).TotalMinutes
        [PSCustomObject]@{ Tenant=$e.TenantId; ExpiresIn=("{0:N0}m" -f $rem)
            Status = if($rem -gt 5){"Valid"}elseif($rem -gt 0){"Expiring"}else{"Expired"} }
    }
}

function Clear-TenantTokenCache ([string]$TenantId) {
    if ($TenantId) { $script:TokenCache.Keys | Where-Object { $_ -like "$TenantId|*" } | ForEach-Object { $script:TokenCache.Remove($_) } }
    else { $script:TokenCache.Clear() }
}
```

---

## Security Considerations

### Least Privilege Per Tenant

| Principle | Implementation |
|---|---|
| Minimal roles | Sentinel Responder (not Contributor) unless rule creation needed |
| Scoped delegation | Specific subscriptions — never entire tenant |
| Time-boxed access | PIM with JIT activation for elevated roles |
| Separate SPs | One service principal per customer for audit clarity |
| No persistent admin | Lighthouse avoids credential storage; rotate managed secrets |

### Audit Logging

```powershell
function Write-CrossTenantAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][string]$TargetTenantName,
        [string]$Outcome = "Success", [string]$Details
    )
    $entry = [PSCustomObject]@{
        Timestamp=(Get-Date -Format "o"); Operator=(Get-AzContext).Account.Id
        Operation=$Operation; Target=$TargetTenantName; Outcome=$Outcome; Details=$Details
    }
    $dir = ".secops/audit"
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $entry | ConvertTo-Json -Compress | Add-Content "$dir/cross-tenant-operations.log" -Encoding UTF8
    return $entry
}
```

### Data Residency Enforcement

```powershell
function Assert-DataResidency {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$TargetRegion)
    $c = Get-Content ".secops/compliance/requirements.yaml" -Raw | ConvertFrom-Yaml
    if ($c.data_residency.prohibited_regions -contains $TargetRegion) {
        return @{ ok=$false; error="Region '$TargetRegion' prohibited by policy" }
    }
    $allowed = $c.data_residency.allowed_regions
    if ($allowed -and $allowed.Count -gt 0 -and $allowed -notcontains $TargetRegion) {
        return @{ ok=$false; error="Region '$TargetRegion' not in allowed list" }
    }
    return @{ ok=$true; region=$TargetRegion }
}
```

### Tenant Isolation Verification

Periodically verify no cross-tenant data leakage by attempting to access each tenant's subscriptions with another tenant's token. All attempts should return 403:

```powershell
function Test-TenantIsolation {
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $checks = [System.Collections.Generic.List[object]]::new()
    foreach ($t in ($env.tenants | Where-Object { $_.type -ne "primary" })) {
        $tok = Get-TenantScopedToken -TenantId $t.id -Resource "https://management.azure.com"
        if (-not $tok.ok) { continue }
        $h = @{ Authorization = "Bearer $($tok.data.AccessToken)" }
        foreach ($sub in ($env.subscriptions | Where-Object { $_.tenant -ne $t.id })) {
            try {
                Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$($sub.id)?api-version=2022-12-01" -Headers $h -ErrorAction Stop
                $checks.Add([PSCustomObject]@{ Status="VIOLATION"; From=$t.name; Sub=$sub.name })
            } catch { $checks.Add([PSCustomObject]@{ Status="PASS"; From=$t.name; Sub=$sub.name }) }
        }
    }
    $v = @($checks | Where-Object Status -eq "VIOLATION")
    return @{ ok=($v.Count -eq 0); checks=$checks.ToArray(); violations=$v.Count }
}
```

---

## Quick Reference

| Task | Function |
|---|---|
| Switch tenant | `Switch-SecOpsTenant` |
| Query all tenants | `Invoke-CrossTenantQuery` |
| Aggregate incidents | `Get-MSSPIncidentDashboard` |
| Hunt across tenants | `Start-CrossTenantHunt` |
| Compliance rollup | `Get-CrossTenantCompliancePosture` |
| Route alerts | `Route-TenantAlert` |
| Onboard customer | `Register-LighthouseDelegation` |
| Verify isolation | `Test-TenantIsolation` |
| Check tokens | `Get-TokenCacheStatus` |
| Parallel ops | `Invoke-ParallelTenantOperation` |
