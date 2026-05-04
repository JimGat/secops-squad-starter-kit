---
title: Attack Simulation Training API
category: msft-security
difficulty: advanced
mitre_attack:
  - T1566   # Phishing
  - T1566.001 # Spearphishing Attachment
  - T1566.002 # Spearphishing Link
  - T1078   # Valid Accounts (credential harvest)
  - T1204   # User Execution
  - T1204.001 # Malicious Link
  - T1204.002 # Malicious File
  - T1528   # Steal Application Access Token (OAuth consent grant)
products:
  - Microsoft 365 Defender
  - Microsoft Defender for Office 365
  - Microsoft Graph Security API
  - Microsoft Sentinel
author: Kima
version: 1.0.0
last_updated: 2026-05-04
---

# Attack Simulation Training API

## Overview

Attack Simulation Training (AST) in Microsoft 365 Defender validates your organization's security posture by running controlled phishing, credential harvest, and social engineering campaigns against real users. This provides three critical capabilities:

1. **Defense Validation** — Confirm email filters, browser protections, and endpoint controls catch simulated threats before real attackers exploit gaps
2. **SOC Analyst Training** — Generate realistic alert volume so analysts practice triage, escalation, and incident response in production tooling
3. **Compliance Testing** — Demonstrate security awareness training effectiveness for ISO 27001, NIST 800-53 (AT-2), and regulatory audits

Use this skill when:
- Automating phishing simulation campaigns via Graph API
- Building scheduled simulation programs with reporting dashboards
- Correlating simulation events with Sentinel detections to find detection gaps
- Managing payloads and training assignments programmatically
- Generating compliance reports on user susceptibility trends

## Environment Context

Before using Attack Simulation Training APIs, check `.secops/`:

1. **`.secops/environment.yaml`** — Tenant ID, cloud type (AST unavailable in GCC High/DoD)
2. **`.secops/identity/tenants.yaml`** — Service principal permissions for simulation management
3. **`.secops/compliance/requirements.yaml`** — Regulatory frameworks requiring phishing simulation evidence
4. **`.secops/alerting/routing.yaml`** — Ensure simulation alerts don't trigger production incident workflows

## Section 1: Graph API Endpoints

### Base URL and Authentication

All Attack Simulation Training operations use the Microsoft Graph Security API:

```
Base URL: https://graph.microsoft.com/v1.0/security/attackSimulation
Beta URL: https://graph.microsoft.com/beta/security/attackSimulation
```

**Required Permissions (Application):**
| Permission | Type | Description |
|---|---|---|
| `AttackSimulation.Read.All` | Application | Read simulation data, reports |
| `AttackSimulation.ReadWrite.All` | Application | Create/manage simulations and payloads |
| `User.Read.All` | Application | Resolve target users/groups |

**Required Permissions (Delegated):**
| Permission | Type | Description |
|---|---|---|
| `AttackSimulation.Read` | Delegated | Read own simulation data |
| `AttackSimulation.ReadWrite` | Delegated | Manage simulations (requires Attack Simulation Admin role) |

### Core Endpoints Reference

```
# Simulations
GET    /security/attackSimulation/simulations
POST   /security/attackSimulation/simulations
GET    /security/attackSimulation/simulations/{id}
DELETE /security/attackSimulation/simulations/{id}

# Payloads (tenant-scoped custom payloads)
GET    /security/attackSimulation/payloads
GET    /security/attackSimulation/payloads/{id}
POST   /security/attackSimulation/payloads
PATCH  /security/attackSimulation/payloads/{id}
DELETE /security/attackSimulation/payloads/{id}

# Simulation Automations (scheduled campaigns)
GET    /security/attackSimulation/simulationAutomations
POST   /security/attackSimulation/simulationAutomations
GET    /security/attackSimulation/simulationAutomations/{id}
PATCH  /security/attackSimulation/simulationAutomations/{id}
DELETE /security/attackSimulation/simulationAutomations/{id}

# Reports
GET    /security/attackSimulation/simulations/{id}/report/overview
GET    /security/attackSimulation/simulations/{id}/report/simulationUsers
```

### Simulation Types

| Type | API Value | Description |
|---|---|---|
| Credential Harvest | `credentialHarvest` | Fake login page captures entered credentials |
| Attachment | `malwareAttachment` | Simulated malicious attachment (Word, Excel, PDF) |
| Drive-by URL | `driveByUrl` | Link to simulated exploit kit landing page |
| Link in Attachment | `linkInAttachment` | Phishing link embedded inside an attachment |
| OAuth Consent Grant | `oAuthConsentGrant` | Simulated malicious OAuth app consent prompt |

## Section 2: Payload Management

### List Available Payloads

```powershell
function Get-SecOpsSimulationPayloads {
    [CmdletBinding()]
    param(
        [ValidateSet('credentialHarvest','malwareAttachment','driveByUrl',
                     'linkInAttachment','oAuthConsentGrant')]
        [string]$Technique,
        [ValidateSet('global','tenant')]
        [string]$Source = 'global'
    )

    $token = Get-SecOpsGraphToken -Scope 'https://graph.microsoft.com/.default'
    $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

    $filter = @()
    if ($Technique) { $filter += "technique eq '$Technique'" }
    if ($Source)    { $filter += "source eq '$Source'" }

    $uri = 'https://graph.microsoft.com/v1.0/security/attackSimulation/payloads'
    if ($filter.Count -gt 0) {
        $uri += '?$filter=' + ($filter -join ' and ')
    }

    $allPayloads = @()
    do {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        $allPayloads += $response.value
        $uri = $response.'@odata.nextLink'
    } while ($uri)

    return @{ ok = $true; data = $allPayloads; count = $allPayloads.Count }
}
```

### Create Custom Payload

```powershell
function New-SecOpsPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][ValidateSet('credentialHarvest','malwareAttachment',
                     'driveByUrl','linkInAttachment','oAuthConsentGrant')]
        [string]$Technique,
        [Parameter(Mandatory)][string]$ContentHtml,
        [string]$Description,
        [string]$Brand = 'Microsoft',
        [string]$Theme = 'accountActivation'
    )

    $token = Get-SecOpsGraphToken -Scope 'https://graph.microsoft.com/.default'
    $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

    $body = @{
        displayName = $DisplayName
        description = $Description
        technique   = $Technique
        brand       = $Brand
        theme       = $Theme
        content     = @{ html = $ContentHtml }
        status      = 'draft'
    } | ConvertTo-Json -Depth 5

    try {
        $result = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/security/attackSimulation/payloads' `
            -Headers $headers -Method Post -Body $body
        return @{ ok = $true; data = $result }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message; status = $_.Exception.Response.StatusCode.value__ }
    }
}
```

## Section 3: Campaign Management

### Create and Launch a Simulation

```powershell
function New-SecOpsAttackSimulation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$PayloadId,
        [Parameter(Mandatory)][string[]]$TargetUserIds,
        [ValidateSet('credentialHarvest','malwareAttachment','driveByUrl',
                     'linkInAttachment','oAuthConsentGrant')]
        [string]$AttackTechnique = 'credentialHarvest',
        [datetime]$LaunchDateTime = (Get-Date).AddHours(1),
        [int]$DurationDays = 7,
        [string]$TrainingAssignmentId
    )

    $token = Get-SecOpsGraphToken -Scope 'https://graph.microsoft.com/.default'
    $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

    $includedTargets = $TargetUserIds | ForEach-Object {
        @{ targetType = 'user'; id = $_ }
    }

    $body = @{
        displayName          = $DisplayName
        attackTechnique      = $AttackTechnique
        status               = 'scheduled'
        launchDateTime       = $LaunchDateTime.ToUniversalTime().ToString('o')
        completionDateTime   = $LaunchDateTime.AddDays($DurationDays).ToUniversalTime().ToString('o')
        payload              = @{ id = $PayloadId }
        includedAccountTarget = @{
            '@odata.type' = '#microsoft.graph.addressBookAccountTargetContent'
            type          = 'addressBook'
            accountTargetContent = $includedTargets
        }
    }

    if ($TrainingAssignmentId) {
        $body['trainingSetting'] = @{
            settingType        = 'custom'
            trainingAssignment = @{ id = $TrainingAssignmentId }
        }
    }

    $bodyJson = $body | ConvertTo-Json -Depth 10

    try {
        $result = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/security/attackSimulation/simulations' `
            -Headers $headers -Method Post -Body $bodyJson
        return @{ ok = $true; data = $result; simulationId = $result.id }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message; status = $_.Exception.Response.StatusCode.value__ }
    }
}
```

### Schedule Recurring Campaigns

```powershell
function New-SecOpsSimulationAutomation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$PayloadId,
        [Parameter(Mandatory)][string[]]$TargetGroupIds,
        [ValidateSet('weekly','biweekly','monthly')]
        [string]$Frequency = 'monthly',
        [datetime]$StartDate = (Get-Date).AddDays(1)
    )

    $token = Get-SecOpsGraphToken -Scope 'https://graph.microsoft.com/.default'
    $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

    $groupTargets = $TargetGroupIds | ForEach-Object {
        @{ targetType = 'group'; id = $_ }
    }

    $body = @{
        displayName     = $DisplayName
        status          = 'enabled'
        attackTechnique = 'credentialHarvest'
        payload         = @{ id = $PayloadId }
        includedAccountTarget = @{
            '@odata.type' = '#microsoft.graph.addressBookAccountTargetContent'
            type          = 'addressBook'
            accountTargetContent = $groupTargets
        }
        schedule = @{
            recurrence = @{
                pattern = @{
                    type     = switch ($Frequency) {
                        'weekly'   { 'weekly' }
                        'biweekly' { 'weekly' }
                        'monthly'  { 'absoluteMonthly' }
                    }
                    interval = switch ($Frequency) {
                        'weekly'   { 1 }
                        'biweekly' { 2 }
                        'monthly'  { 1 }
                    }
                }
                range = @{
                    type      = 'noEnd'
                    startDate = $StartDate.ToString('yyyy-MM-dd')
                }
            }
        }
    } | ConvertTo-Json -Depth 10

    try {
        $result = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/security/attackSimulation/simulationAutomations' `
            -Headers $headers -Method Post -Body $body
        return @{ ok = $true; data = $result; automationId = $result.id }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message; status = $_.Exception.Response.StatusCode.value__ }
    }
}
```

## Section 4: Reporting

### Get Simulation Report

```powershell
function Get-SecOpsSimulationReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SimulationId,
        [switch]$IncludeUserDetails
    )

    $token = Get-SecOpsGraphToken -Scope 'https://graph.microsoft.com/.default'
    $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

    $baseUri = "https://graph.microsoft.com/v1.0/security/attackSimulation/simulations/$SimulationId/report"

    # Overview metrics
    try {
        $overview = Invoke-RestMethod -Uri "$baseUri/overview" -Headers $headers -Method Get
    } catch {
        return @{ ok = $false; error = "Failed to retrieve overview: $($_.Exception.Message)" }
    }

    $report = @{
        simulationId     = $SimulationId
        totalUsers       = $overview.resolvedTargetsCount
        compromisedCount = $overview.compromisedUsersCount
        reportedCount    = $overview.reportedPhishCount
        completionRate   = if ($overview.resolvedTargetsCount -gt 0) {
            [math]::Round(($overview.compromisedUsersCount / $overview.resolvedTargetsCount) * 100, 2)
        } else { 0 }
        trainingComplete = $overview.trainingCompletionCount
    }

    # Per-user breakdown
    if ($IncludeUserDetails) {
        $users = @()
        $uri = "$baseUri/simulationUsers"
        do {
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
            $users += $response.value
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        $report['users'] = $users
    }

    return @{ ok = $true; data = $report }
}
```

### Aggregate Campaign Metrics

```powershell
function Get-SecOpsSimulationTrends {
    [CmdletBinding()]
    param(
        [int]$DaysBack = 90,
        [ValidateSet('credentialHarvest','malwareAttachment','driveByUrl',
                     'linkInAttachment','oAuthConsentGrant')]
        [string]$Technique
    )

    $token = Get-SecOpsGraphToken -Scope 'https://graph.microsoft.com/.default'
    $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

    $cutoff = (Get-Date).AddDays(-$DaysBack).ToString('o')
    $filter = "launchDateTime ge $cutoff and status eq 'succeeded'"
    if ($Technique) { $filter += " and attackTechnique eq '$Technique'" }

    $uri = "https://graph.microsoft.com/v1.0/security/attackSimulation/simulations?`$filter=$filter&`$orderby=launchDateTime desc"

    $simulations = @()
    do {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        $simulations += $response.value
        $uri = $response.'@odata.nextLink'
    } while ($uri)

    $trends = $simulations | ForEach-Object {
        @{
            id              = $_.id
            name            = $_.displayName
            technique       = $_.attackTechnique
            launched        = $_.launchDateTime
            compromiseRate  = $_.report.overview.compromisedRate
            reportRate      = $_.report.overview.reportedPhishRate
        }
    }

    return @{ ok = $true; data = $trends; count = $trends.Count }
}
```

## Section 5: Sentinel Integration

### Correlate Simulations with Sentinel Detections

When a simulation runs, Defender for Office 365 generates real alerts. Correlating these with Sentinel validates your detection pipeline end-to-end.

```kql
// Find Sentinel alerts triggered during a simulation window
let SimulationStart = datetime(2026-05-01T00:00:00Z);
let SimulationEnd = datetime(2026-05-08T00:00:00Z);
SecurityAlert
| where TimeGenerated between (SimulationStart .. SimulationEnd)
| where ProviderName in ("Office 365 Advanced Threat Protection", "OATP")
| where AlertType has_any ("Phish", "MalwareEmail", "UrlClick")
| summarize AlertCount = count(), Techniques = make_set(AlertType)
    by AlertSeverity, ProviderName
| order by AlertCount desc
```

### Validate Detection Rules Fire on Simulated Attacks

```kql
// Cross-reference simulation target users with alert entities
let SimulationTargets = dynamic(["user1@contoso.com", "user2@contoso.com"]);
let SimulationWindow = 7d;
SecurityAlert
| where TimeGenerated > ago(SimulationWindow)
| mv-expand Entity = parse_json(Entities)
| where Entity.Type == "account"
| extend TargetUPN = strcat(Entity.Name, "@", Entity.UPNSuffix)
| where TargetUPN in (SimulationTargets)
| project TimeGenerated, AlertName, AlertSeverity, TargetUPN, ProviderName
| summarize
    DetectedAlerts = count(),
    AlertTypes = make_set(AlertName)
    by TargetUPN
```

### Detection Gap Report

```kql
// Identify simulation techniques with no corresponding Sentinel detections
let SimulationTechniques = datatable(technique:string, mitre_id:string) [
    "credentialHarvest", "T1566.001",
    "malwareAttachment", "T1566.002",
    "driveByUrl", "T1204.001",
    "oAuthConsentGrant", "T1528"
];
let DetectedTechniques = SecurityAlert
| where TimeGenerated > ago(30d)
| where ProviderName has "Office 365"
| extend Tactics = parse_json(Tactics)
| mv-expand Tactic = Tactics
| summarize by tostring(Tactic);
SimulationTechniques
| where mitre_id !in (DetectedTechniques)
| project technique, mitre_id, Status = "DETECTION GAP"
```

### Simulation Sentinel Workbook Query

```powershell
# PowerShell: Query Sentinel for simulation correlation data
function Get-SecOpsSimulationDetectionGaps {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceId,
        [Parameter(Mandatory)][string]$SimulationId
    )

    $sim = Get-SecOpsSimulationReport -SimulationId $SimulationId -IncludeUserDetails
    if (-not $sim.ok) { return $sim }

    $targetUpns = $sim.data.users | ForEach-Object { $_.email }

    $kql = @"
SecurityAlert
| where TimeGenerated > ago(14d)
| mv-expand Entity = parse_json(Entities)
| where Entity.Type == "account"
| extend TargetUPN = strcat(Entity.Name, "@", Entity.UPNSuffix)
| where TargetUPN in (dynamic($($targetUpns | ConvertTo-Json -Compress)))
| summarize DetectedCount = count() by TargetUPN
"@

    $token = Get-SecOpsGraphToken -Scope 'https://api.loganalytics.io/.default'
    $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
    $body = @{ query = $kql } | ConvertTo-Json

    try {
        $queryResult = Invoke-RestMethod `
            -Uri "https://api.loganalytics.io/v1/workspaces/$WorkspaceId/query" `
            -Headers $headers -Method Post -Body $body
        $detectedUpns = $queryResult.tables[0].rows | ForEach-Object { $_[0] }
    } catch {
        return @{ ok = $false; error = "Log Analytics query failed: $($_.Exception.Message)" }
    }

    $gaps = $targetUpns | Where-Object { $_ -notin $detectedUpns }

    return @{
        ok   = $true
        data = @{
            totalTargets = $targetUpns.Count
            detected     = $detectedUpns.Count
            gaps         = $gaps
            gapRate      = [math]::Round(($gaps.Count / $targetUpns.Count) * 100, 2)
        }
    }
}
```

## Section 6: .secops/ Integration

### Simulation Configuration

Add to `.secops/environment.yaml`:

```yaml
# .secops/environment.yaml — Attack Simulation Training
attack_simulation:
  enabled: true
  cloud_type: commercial    # AST not available in GCC High/DoD
  default_technique: credentialHarvest
  max_concurrent_simulations: 3
  notification_recipients:
    - soc-leads@contoso.com
  excluded_users:            # Never target these accounts
    - breakglass@contoso.com
    - svc-sentinel@contoso.com
  training_defaults:
    auto_assign: true
    due_days: 14
    reminder_days: [7, 3, 1]
```

### Campaign Schedule Configuration

```yaml
# .secops/simulation-campaigns.yaml
schema_version: "1.0"
campaigns:
  - name: monthly-credential-harvest
    technique: credentialHarvest
    frequency: monthly
    target_groups:
      - all-employees
    payload_rotation: true
    payload_pool:
      - Microsoft 365 Password Expiry
      - SharePoint Document Share
      - Teams Meeting Invitation
    baseline_metrics:
      compromise_rate_target: 5.0    # percent
      report_rate_target: 30.0       # percent
      training_completion_target: 95.0

  - name: quarterly-oauth-consent
    technique: oAuthConsentGrant
    frequency: quarterly
    target_groups:
      - developers
      - it-admins
    baseline_metrics:
      compromise_rate_target: 3.0
```

### Baseline Metrics Tracking

```yaml
# .secops/simulation-baselines.yaml
schema_version: "1.0"
baselines:
  - date: "2026-01-15"
    technique: credentialHarvest
    metrics:
      compromise_rate: 12.4
      report_rate: 18.2
      training_completion: 87.0
  - date: "2026-02-15"
    technique: credentialHarvest
    metrics:
      compromise_rate: 8.1
      report_rate: 24.5
      training_completion: 92.3
  - date: "2026-03-15"
    technique: credentialHarvest
    metrics:
      compromise_rate: 5.7
      report_rate: 31.0
      training_completion: 96.1
```

## Rate Limits and Throttling

| Endpoint | Limit | Window |
|---|---|---|
| Simulation CRUD | 100 requests | 20 seconds |
| Payload operations | 50 requests | 20 seconds |
| Report queries | 200 requests | 20 seconds |

Use exponential backoff on `429 Too Many Requests`:

```powershell
$retryAfter = $_.Exception.Response.Headers['Retry-After']
Start-Sleep -Seconds ([int]$retryAfter + 1)
```

## Cross-References

- **[defender-api-permissions.md](defender-api-permissions.md)** — App registration and permission setup
- **[defender-xdr-configuration.md](defender-xdr-configuration.md)** — XDR unified incident view for simulation alerts
- **[sentinel-api-reference.md](sentinel-api-reference.md)** — Log Analytics query API for detection correlation
- **[microsoft-graph-security.md](microsoft-graph-security.md)** — Graph Security API authentication patterns
- **[copilot-security-workflows.md](../copilot-security-workflows.md)** — AI-assisted analysis of simulation results
