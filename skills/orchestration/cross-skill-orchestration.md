---
title: Cross-Skill Workflow Orchestration
category: orchestration
difficulty: advanced
mitre_attack:
  - T1059.001  # PowerShell
  - T1078      # Valid Accounts
  - T1566      # Phishing
  - T1048      # Exfiltration Over Alternative Protocol
  - T1530      # Data from Cloud Storage
  - T1114      # Email Collection
products:
  - Microsoft Sentinel
  - Microsoft Defender XDR
  - Microsoft Purview
  - Microsoft Purview eDiscovery
  - Microsoft Copilot for Security
  - Microsoft Defender for Cloud Apps
  - Azure Monitor Log Analytics
  - Azure Data Explorer
author: Sydnor
version: 1.0.0
last_updated: 2026-05-04
---

# Cross-Skill Workflow Orchestration

## Overview

Real SecOps requires chaining skills into end-to-end workflows. An incident investigation touches Sentinel, Defender, KQL, and Copilot. A compliance export spans eDiscovery, Purview, and workbook automation. This skill teaches agents how to compose multi-step workflows using five orchestration patterns with full error handling and `.secops/` integration.

**Skills referenced (not duplicated):**

| Domain | Key Skills |
|---|---|
| **PowerShell** | `sentinel-api-wrapper.md`, `defender-api-wrapper.md`, `error-handling.md`, `rate-limiting.md`, `data-tiering-commands.md` |
| **KQL** | `query-builder.md`, `cross-workspace-queries.md`, `incident-investigation.md` |
| **Detection** | `advanced-hunting-api.md`, `mitre-attack-mapping.md` |
| **MSFT Security** | `copilot-for-security.md`, `ediscovery-api-wrapper.md`, `purview-api-wrapper.md`, `defender-cloud-apps.md` |
| **SOAR** | `compliance-framework-mappings.md`, `workbook-automation.md` |
| **Log Analytics** | `workspace-architecture.md`, `cost-optimization.md` |

## Environment Context

Before any orchestration, load `.secops/` context (see `.copilot/skills/secops-environment-context.md`):

```powershell
$envConfig     = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
$dataSourceMap = Get-Content ".secops/data-sources/data-source-map.yaml" -Raw | ConvertFrom-Yaml
$routing       = Get-Content ".secops/alerting/routing.yaml" -Raw | ConvertFrom-Yaml
$compliance    = Get-Content ".secops/compliance/requirements.yaml" -Raw | ConvertFrom-Yaml
$workspaces    = Get-ChildItem ".secops/workspaces/*.yaml" |
    ForEach-Object { Get-Content $_.FullName -Raw | ConvertFrom-Yaml }
```

---

## Orchestration Patterns

### Pattern 1: Sequential Pipeline

Each step's output feeds the next. Halts on failure.

```powershell
function Invoke-SequentialPipeline {
    param([hashtable[]]$Steps, [object]$InitialInput)
    $results = @(); $current = $InitialInput
    foreach ($step in $Steps) {
        Write-Host "[Pipeline] $($step.Name)" -ForegroundColor Cyan
        try {
            $out = & $step.Action $current
            if ($out -is [hashtable] -and $out.ContainsKey('ok') -and -not $out.ok) {
                return @{ ok = $false; error = "Failed at '$($step.Name)': $($out.error)"; results = $results }
            }
            $results += @{ Step = $step.Name; Status = "Success"; Output = $out }
            $current = $out
        } catch {
            return @{ ok = $false; error = "Exception at '$($step.Name)': $_"; results = $results }
        }
    }
    return @{ ok = $true; results = $results; output = $current }
}
```

### Pattern 2: Fan-Out/Fan-In

One trigger → parallel actions → aggregated results. Uses runspaces for concurrency.

```powershell
function Invoke-FanOutFanIn {
    param([hashtable[]]$Actions, [object]$TriggerInput, [int]$MaxConcurrency = 5, [int]$TimeoutSec = 300)
    $pool = [runspacefactory]::CreateRunspacePool(1, $MaxConcurrency); $pool.Open()
    $jobs = foreach ($a in $Actions) {
        $ps = [powershell]::Create().AddScript({ param($Block, $In) & $Block $In }).AddArgument($a.Action).AddArgument($TriggerInput)
        $ps.RunspacePool = $pool
        @{ Name = $a.Name; PS = $ps; Handle = $ps.BeginInvoke() }
    }
    $results = @(); $deadline = (Get-Date).AddSeconds($TimeoutSec)
    foreach ($j in $jobs) {
        $remaining = [math]::Max(1, ($deadline - (Get-Date)).TotalMilliseconds)
        try {
            if ($j.Handle.AsyncWaitHandle.WaitOne([int]$remaining)) {
                $results += @{ Name = $j.Name; Status = "Success"; Output = $j.PS.EndInvoke($j.Handle) }
            } else { $results += @{ Name = $j.Name; Status = "Timeout" } }
        } catch { $results += @{ Name = $j.Name; Status = "Error"; Error = $_.Exception.Message } }
        finally { $j.PS.Dispose() }
    }
    $pool.Close(); $pool.Dispose()
    return @{ ok = ($results | Where-Object { $_.Status -ne "Success" }).Count -eq 0; results = $results }
}
```

### Pattern 3: Conditional Branching

Route execution based on findings — different paths for different outcomes.

```powershell
function Invoke-ConditionalBranch {
    param([object]$Input, [hashtable[]]$Branches)
    foreach ($b in $Branches) {
        if (& $b.Condition $Input) {
            Write-Host "[Branch] Matched: $($b.Name)" -ForegroundColor Green
            return @{ ok = $true; branch = $b.Name; output = (& $b.Action $Input) }
        }
    }
    return @{ ok = $false; error = "No branch matched" }
}
```

### Pattern 4: Loop/Iteration with Circuit Breaker

Process each entity with automatic halt after N consecutive failures.

```powershell
function Invoke-EntityLoop {
    param([object[]]$Entities, [scriptblock]$ProcessEntity, [int]$MaxFailures = 3, [int]$DelayMs = 500)
    $results = @(); $consecutiveFails = 0
    foreach ($entity in $Entities) {
        if ($consecutiveFails -ge $MaxFailures) {
            Write-Warning "[Loop] Circuit breaker — $MaxFailures consecutive failures"
            $results += @{ Entity = $entity; Status = "Skipped" }; continue
        }
        try {
            $out = & $ProcessEntity $entity
            if ($out.ok) { $consecutiveFails = 0; $results += @{ Entity = $entity; Status = "Success"; Output = $out } }
            else { $consecutiveFails++; $results += @{ Entity = $entity; Status = "Failed"; Error = $out.error } }
        } catch { $consecutiveFails++; $results += @{ Entity = $entity; Status = "Error"; Error = $_.Exception.Message } }
        if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
    }
    $ok = ($results | Where-Object { $_.Status -eq "Success" }).Count
    return @{ ok = $ok -gt 0; total = $results.Count; succeeded = $ok; failed = $results.Count - $ok; results = $results }
}
```

### Pattern 5: Checkpoint/Resume

Saves state to JSON after each step. Re-run resumes from last checkpoint.

```powershell
function Invoke-CheckpointWorkflow {
    param([string]$WorkflowId, [hashtable[]]$Steps, [string]$CheckpointDir = ".secops/checkpoints", [object]$InitialInput)
    $path = Join-Path $CheckpointDir "$WorkflowId.json"
    $cp = if (Test-Path $path) { Get-Content $path -Raw | ConvertFrom-Json -AsHashtable }
    else {
        if (-not (Test-Path $CheckpointDir)) { New-Item -ItemType Directory -Path $CheckpointDir -Force | Out-Null }
        @{ workflowId = $WorkflowId; startedAt = (Get-Date -Format "o"); completedSteps = @(); lastInput = $InitialInput }
    }
    $current = $cp.lastInput; $startIdx = $cp.completedSteps.Count
    for ($i = $startIdx; $i -lt $Steps.Count; $i++) {
        $step = $Steps[$i]; Write-Host "[Checkpoint] Step $($i+1)/$($Steps.Count): $($step.Name)" -ForegroundColor Cyan
        try {
            $out = & $step.Action $current
            if ($out -is [hashtable] -and $out.ContainsKey('ok') -and -not $out.ok) {
                $cp.lastError = $out.error; $cp | ConvertTo-Json -Depth 10 | Set-Content $path -Encoding UTF8
                return @{ ok = $false; error = $out.error; checkpoint = $path }
            }
            $cp.completedSteps += $step.Name; $cp.lastInput = $out
            $cp | ConvertTo-Json -Depth 10 | Set-Content $path -Encoding UTF8; $current = $out
        } catch {
            $cp.lastError = $_.Exception.Message; $cp | ConvertTo-Json -Depth 10 | Set-Content $path -Encoding UTF8
            return @{ ok = $false; error = $_.Exception.Message; checkpoint = $path }
        }
    }
    $cp.completedAt = (Get-Date -Format "o"); $cp.status = "completed"
    $cp | ConvertTo-Json -Depth 10 | Set-Content $path -Encoding UTF8
    return @{ ok = $true; output = $current; checkpoint = $path }
}
```

---

## Pre-Built Workflow Templates

### Workflow 1: Incident Investigation Pipeline

**Pattern:** Sequential + Fan-Out + Loop | **Skills:** `sentinel-api-wrapper.md`, `advanced-hunting-api.md`, `defender-api-wrapper.md`, `copilot-for-security.md`

```powershell
function Start-IncidentInvestigation {
    param([string]$IncidentId, [string]$WorkspaceId)
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $sub = $env.azure.primary_subscription; $rg = $env.azure.resource_group
    $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
    $gToken = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
    $h = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }
    $gh = @{ Authorization = "Bearer $gToken"; "Content-Type" = "application/json" }
    $baseUri = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceId/providers/Microsoft.SecurityInsights"

    Invoke-SequentialPipeline -InitialInput @{} -Steps @(
        @{ Name = "GetIncident"; Action = {
            $resp = Invoke-RestMethod -Uri "$baseUri/incidents/${IncidentId}?api-version=2024-03-01" -Headers $h
            @{ ok = $true; data = $resp }
        }},
        @{ Name = "ExtractEntities"; Action = { param($in)
            $ents = Invoke-RestMethod -Uri "$baseUri/incidents/${IncidentId}/entities?api-version=2024-03-01" -Headers $h -Method Post
            $grouped = @{
                ips   = $ents.entities | Where-Object { $_.kind -eq "Ip" }
                users = $ents.entities | Where-Object { $_.kind -eq "Account" }
                hosts = $ents.entities | Where-Object { $_.kind -eq "Host" }
            }
            @{ ok = $true; data = @{ incident = $in.data; entities = $grouped } }
        }},
        @{ Name = "EnrichEntities"; Action = { param($in)
            $all = @()
            $all += $in.data.entities.ips   | ForEach-Object { @{ type="ip";   value=$_.properties.address } }
            $all += $in.data.entities.users | ForEach-Object { @{ type="user"; value=$_.properties.accountName } }
            $all += $in.data.entities.hosts | ForEach-Object { @{ type="host"; value=$_.properties.hostName } }

            $enriched = Invoke-EntityLoop -Entities $all -MaxFailures 5 -ProcessEntity {
                param($e)
                $q = switch ($e.type) {
                    "ip"   { "DeviceNetworkEvents | where RemoteIP == '$($e.value)' | take 50" }
                    "user" { "IdentityLogonEvents | where AccountName == '$($e.value)' | take 50" }
                    "host" { "DeviceInfo | where DeviceName == '$($e.value)' | take 50" }
                }
                try {
                    $r = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" `
                        -Headers $gh -Method Post -Body (@{ Query = $q } | ConvertTo-Json)
                    @{ ok = $true; data = @{ entity = $e; results = $r.results } }
                } catch { @{ ok = $false; error = $_.Exception.Message } }
            }
            @{ ok = $true; data = @{ incident = $in.data.incident; enriched = $enriched.results } }
        }},
        @{ Name = "UpdateIncident"; Action = { param($in)
            $summary = "Enriched $($in.data.enriched.Count) entities via automated investigation."
            $body = @{ properties = @{ message = "## Automated Investigation`n$summary" } } | ConvertTo-Json -Depth 5
            Invoke-RestMethod -Uri "$baseUri/incidents/${IncidentId}/comments/$(New-Guid)?api-version=2024-03-01" `
                -Headers $h -Method Put -Body $body
            @{ ok = $true; data = "Incident updated" }
        }}
    )
}
```

### Workflow 2: Compliance Export

**Pattern:** Sequential + Checkpoint | **Skills:** `compliance-framework-mappings.md`, `ediscovery-api-wrapper.md`, `purview-api-wrapper.md`, `workbook-automation.md`

```powershell
function Start-ComplianceExport {
    param([string]$Framework, [string]$ControlId)
    $gToken = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
    $gh = @{ Authorization = "Bearer $gToken"; "Content-Type" = "application/json" }
    $caseName = "Compliance-$Framework-$ControlId-$(Get-Date -Format 'yyyyMMdd')"

    Invoke-CheckpointWorkflow -WorkflowId "compliance-$caseName" -Steps @(
        @{ Name = "LoadRequirements"; Action = {
            $c = Get-Content ".secops/compliance/requirements.yaml" -Raw | ConvertFrom-Yaml
            $fw = $c.frameworks | Where-Object { $_.name -eq $Framework }
            if (-not $fw) { return @{ ok = $false; error = "Framework '$Framework' not found" } }
            @{ ok = $true; data = @{ framework = $fw; controlId = $ControlId } }
        }},
        @{ Name = "IdentifyDataSources"; Action = { param($in)
            $dsm = Get-Content ".secops/data-sources/data-source-map.yaml" -Raw | ConvertFrom-Yaml
            $sources = $dsm.tables | Where-Object { $_.compliance_tags -contains $Framework }
            if (-not $sources) { $sources = $dsm.tables }
            @{ ok = $true; data = @{ framework = $in.data.framework; dataSources = $sources } }
        }},
        @{ Name = "CreateCase"; Action = { param($in)
            $body = @{ displayName = $caseName; description = "Export for $Framework" } | ConvertTo-Json
            $case = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases" `
                -Headers $gh -Method Post -Body $body
            @{ ok = $true; data = @{ caseId = $case.id; dataSources = $in.data.dataSources } }
        }},
        @{ Name = "ExecuteSearch"; Action = { param($in)
            $searchBody = @{
                displayName = "Search-$caseName"; contentQuery = "kind:document OR kind:email"
                dataSourceScopes = @{ includedSources = @("allTenantSources") }
            } | ConvertTo-Json -Depth 5
            $search = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$($in.data.caseId)/searches" `
                -Headers $gh -Method Post -Body $searchBody
            # Poll for completion — eDiscovery searches can take hours
            $deadline = (Get-Date).AddMinutes(120)
            while ((Get-Date) -lt $deadline) {
                Start-Sleep -Seconds 30
                $s = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$($in.data.caseId)/searches/$($search.id)" -Headers $gh
                if ($s.status -eq "completed") { return @{ ok = $true; data = @{ caseId = $in.data.caseId; searchId = $search.id } } }
            }
            @{ ok = $false; error = "Search timed out after 120 minutes" }
        }},
        @{ Name = "ApplyLabels"; Action = { param($in)
            $labels = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/informationProtection/sensitivityLabels" -Headers $gh
            $label = $labels.value | Where-Object { $_.name -match "Confidential" } | Select-Object -First 1
            @{ ok = $true; data = @{ caseId = $in.data.caseId; searchId = $in.data.searchId; label = $label.name } }
        }},
        @{ Name = "ExportEvidence"; Action = { param($in)
            $exportBody = @{ outputName = "export-$(Get-Date -Format 'yyyyMMdd-HHmmss')"; exportOptions = "originalFiles" } | ConvertTo-Json
            $export = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$($in.data.caseId)/searches/$($in.data.searchId)/microsoft.graph.security.exportResult" `
                -Headers $gh -Method Post -Body $exportBody
            @{ ok = $true; data = @{ caseId = $in.data.caseId; exportId = $export.id; status = "initiated" } }
        }}
    )
}
```

### Workflow 3: Threat Hunting Campaign

**Pattern:** Sequential + Conditional + Loop | **Skills:** `mitre-attack-mapping.md`, `query-builder.md`, `cross-workspace-queries.md`, `advanced-hunting-api.md`, `sentinel-api-wrapper.md`

```powershell
function Start-ThreatHuntingCampaign {
    param([string]$TechniqueId, [string]$Hypothesis, [int]$LookbackDays = 30)
    $dsm = Get-Content ".secops/data-sources/data-source-map.yaml" -Raw | ConvertFrom-Yaml
    $wsList = Get-ChildItem ".secops/workspaces/*.yaml" | ForEach-Object { Get-Content $_.FullName -Raw | ConvertFrom-Yaml }
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
    $gToken = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
    $armH = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }
    $gH = @{ Authorization = "Bearer $gToken"; "Content-Type" = "application/json" }
    $campaign = "Hunt-$TechniqueId-$(Get-Date -Format 'yyyyMMdd')"

    # Build KQL from technique (query-builder.md)
    $queries = @{
        "T1078" = @(
            @{ Name="SuspiciousSignIns"; Table="SigninLogs"; KQL=@"
SigninLogs | where TimeGenerated > ago(${LookbackDays}d)
| where ResultType == 0 and RiskLevelDuringSignIn in ("high","medium")
| summarize Attempts=count(), IPs=dcount(IPAddress) by UserPrincipalName
| where IPs > 3 or Attempts > 50
"@ }
        )
    }
    $base = $TechniqueId.Split(".")[0]
    $huntQ = if ($queries.ContainsKey($base)) { $queries[$base] }
    else { @(@{ Name="Generic"; Table="SecurityEvent"; KQL="SecurityEvent | where TimeGenerated > ago(${LookbackDays}d) | take 100" }) }

    # Execute across workspaces (cross-workspace-queries.md)
    $findings = [System.Collections.ArrayList]::new()
    foreach ($ws in $wsList) {
        foreach ($q in $huntQ) {
            $tableEntry = $dsm.tables | Where-Object { $_.name -eq $q.Table }
            if ($tableEntry -and $tableEntry.workspace -ne $ws.workspace.name) { continue }
            try {
                $r = Invoke-RestMethod -Uri "https://api.loganalytics.io/v1/workspaces/$($ws.workspace.id)/query" `
                    -Headers $armH -Method Post -Body (@{ query = $q.KQL } | ConvertTo-Json)
                if ($r.tables[0].rows.Count -gt 0) {
                    [void]$findings.Add(@{ workspace=$ws.workspace.name; query=$q.Name; rows=$r.tables[0].rows.Count })
                }
            } catch { Write-Warning "$($q.Name) in $($ws.workspace.name) failed: $_" }
        }
    }

    # Advanced Hunting in Defender XDR (advanced-hunting-api.md)
    try {
        $xdr = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" -Headers $gH `
            -Method Post -Body (@{ Query = "DeviceLogonEvents | where Timestamp > ago(${LookbackDays}d) | where LogonType == 'RemoteInteractive' | summarize C=count() by AccountName | where C > 20" } | ConvertTo-Json)
        if ($xdr.results.Count -gt 0) { [void]$findings.Add(@{ workspace="DefenderXDR"; query="AdvancedHunting"; rows=$xdr.results.Count }) }
    } catch { Write-Warning "Advanced Hunting failed: $_" }

    # Conditional: threats found → create incident; clean → log
    $result = Invoke-ConditionalBranch -Input @{ findings = $findings; campaign = $campaign } -Branches @(
        @{ Name="ThreatsFound"; Condition={ param($in) $in.findings.Count -gt 0 }; Action={ param($in)
            $body = @{ properties = @{
                title = "[Hunt] $campaign — $Hypothesis"; severity = "Medium"; status = "New"
                description = "Found $($in.findings.Count) result sets across workspaces."
            }} | ConvertTo-Json -Depth 5
            $ws0 = ($wsList | Select-Object -First 1).workspace
            $uri = "https://management.azure.com/subscriptions/$($env.azure.primary_subscription)/resourceGroups/$($env.azure.resource_group)/providers/Microsoft.OperationalInsights/workspaces/$($ws0.name)/providers/Microsoft.SecurityInsights/incidents/$(New-Guid)?api-version=2024-03-01"
            $inc = Invoke-RestMethod -Uri $uri -Headers $armH -Method Put -Body $body
            Write-OrchestrationDiscovery -Type "threat_hunt_finding" -Detail "Campaign $($in.campaign) found $($in.findings.Count) result sets" -Confidence "high" -ActionTaken "Created incident $($inc.name)"
            @{ ok = $true; action = "incident_created"; incidentId = $inc.name }
        }},
        @{ Name="Clean"; Condition={ param($in) $in.findings.Count -eq 0 }; Action={ param($in)
            Write-Host "[Hunt] No threats found" -ForegroundColor Green
            @{ ok = $true; action = "clean" }
        }}
    )
    @{ ok = $true; campaign = $campaign; findings = $findings.Count; outcome = $result.branch }
}
```

### Workflow 4: Data Tiering Migration

**Pattern:** Loop + Checkpoint | **Skills:** `data-tiering-commands.md`, `query-builder.md`, `cost-optimization.md`, `retention-archive.md`

```powershell
function Start-DataTieringMigration {
    param([string]$WorkspaceName, [string]$TargetTier, [switch]$DryRun)
    $env = Get-Content ".secops/environment.yaml" -Raw | ConvertFrom-Yaml
    $dsm = Get-Content ".secops/data-sources/data-source-map.yaml" -Raw | ConvertFrom-Yaml
    $sub = $env.azure.primary_subscription; $rg = $env.azure.resource_group
    $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
    $h = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

    $tables = $dsm.tables | Where-Object { $_.workspace -eq $WorkspaceName -and $_.tier -ne $TargetTier }
    if (-not $tables) { return @{ ok = $true; data = "No tables eligible" } }

    $results = Invoke-EntityLoop -Entities $tables -MaxFailures 3 -DelayMs 1000 -ProcessEntity {
        param($tbl)
        $tblUri = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/tables/$($tbl.name)?api-version=2023-09-01"
        # Check analytics rule dependencies before downgrading
        if ($TargetTier -in @("Basic","Auxiliary")) {
            $rulesUri = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01"
            try {
                $rules = Invoke-RestMethod -Uri $rulesUri -Headers $h
                $deps = $rules.value | Where-Object { $_.properties.query -match $tbl.name }
                if ($deps) { return @{ ok = $false; error = "$($tbl.name) has $($deps.Count) dependent analytics rules — blocked" } }
            } catch { Write-Warning "Could not check rule deps: $_" }
        }
        if ($DryRun) { return @{ ok = $true; action = "dry_run"; table = $tbl.name; from = $tbl.tier; to = $TargetTier } }
        try {
            Invoke-RestMethod -Uri $tblUri -Headers $h -Method Patch -Body (@{ properties = @{ plan = $TargetTier } } | ConvertTo-Json)
            @{ ok = $true; action = "changed"; table = $tbl.name; from = $tbl.tier; to = $TargetTier }
        } catch { @{ ok = $false; error = "Tier change failed: $_" } }
    }
    Write-OrchestrationDiscovery -Type "data_tiering_migration" -Confidence "high" `
        -Detail "Processed $($results.total) tables. Succeeded: $($results.succeeded), Failed: $($results.failed)" `
        -ActionTaken $(if ($DryRun) { "Dry run" } else { "Tier changes applied" })
    @{ ok = $true; dryRun = [bool]$DryRun; results = $results }
}
```

### Workflow 5: Shadow IT Assessment

**Pattern:** Sequential + Fan-Out + Conditional | **Skills:** `defender-cloud-apps.md`, `purview-api-wrapper.md`, `compliance-framework-mappings.md`, `workbook-automation.md`

```powershell
function Start-ShadowITAssessment {
    param([int]$RiskThreshold = 7, [int]$LookbackDays = 90)
    $gToken = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
    $gh = @{ Authorization = "Bearer $gToken"; "Content-Type" = "application/json" }
    $compliance = Get-Content ".secops/compliance/requirements.yaml" -Raw | ConvertFrom-Yaml

    Invoke-SequentialPipeline -Steps @(
        @{ Name = "DiscoverApps"; Action = {
            $streams = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/cloudAppDiscovery/uploadedStreams" -Headers $gh
            $apps = foreach ($s in $streams.value) {
                try {
                    $r = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/cloudAppDiscovery/uploadedStreams/$($s.id)/microsoft.graph.security.aggregatedAppsDetails(period=duration'P${LookbackDays}D')" -Headers $gh
                    $r.value
                } catch { Write-Warning "Stream $($s.displayName) failed: $_" }
            }
            @{ ok = $true; data = @{ apps = @($apps) } }
        }},
        @{ Name = "ScoreRisk"; Action = { param($in)
            $scored = $in.data.apps | ForEach-Object {
                $risk = 5
                if (-not $_.complianceRisks.isSOC2Compliant) { $risk += 2 }
                if (-not $_.securityRisks.hasEncryptionAtRest) { $risk += 2 }
                if ($_.userCount -gt 50) { $risk += 1 }
                $_ | Add-Member -NotePropertyName "riskScore" -NotePropertyValue ([math]::Min($risk, 10)) -PassThru
            }
            $high = @($scored | Where-Object { $_.riskScore -ge $RiskThreshold })
            @{ ok = $true; data = @{ all = $scored; highRisk = $high; total = $scored.Count; highCount = $high.Count } }
        }},
        @{ Name = "ComplianceCheck"; Action = { param($in)
            $recs = $in.data.highRisk | ForEach-Object {
                $violations = @()
                foreach ($fw in $compliance.frameworks) {
                    if ($fw.name -match "PCI" -and -not $_.complianceRisks.isPCIDSSCompliant) { $violations += "PCI-DSS" }
                    if ($fw.name -match "SOC" -and -not $_.complianceRisks.isSOC2Compliant) { $violations += "SOC2" }
                }
                @{ app = $_.displayName; riskScore = $_.riskScore; violations = $violations
                   recommendation = if ($violations.Count -gt 0) { "Block" } else { "Monitor" } }
            }
            Write-OrchestrationDiscovery -Type "shadow_it_assessment" -Confidence "high" `
                -Detail "Assessed $($in.data.total) apps. High risk: $($in.data.highCount)" -ActionTaken "Report generated"
            @{ ok = $true; data = @{ total = $in.data.total; highRisk = $in.data.highCount; recommendations = $recs } }
        }}
    )
}
```

---

## Error Handling Patterns

See `skills/powershell/error-handling.md` for foundational patterns and `skills/powershell/rate-limiting.md` for throttle management. Orchestration adds these cross-workflow patterns:

### Retry with Exponential Backoff

```powershell
function Invoke-WithRetry {
    param([scriptblock]$Action, [int]$MaxRetries = 3, [int]$BaseDelayMs = 1000, [int[]]$RetryOn = @(429,503,504))
    for ($i = 0; $i -le $MaxRetries; $i++) {
        try { return & $Action }
        catch {
            $code = $_.Exception.Response.StatusCode.value__
            if ($code -in $RetryOn -and $i -lt $MaxRetries) {
                $delay = $BaseDelayMs * [math]::Pow(2, $i)
                $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                if ($retryAfter) { $delay = [int]$retryAfter * 1000 }
                Write-Warning "[Retry] Attempt $($i+1)/$MaxRetries — ${delay}ms"
                Start-Sleep -Milliseconds $delay
            } else { throw }
        }
    }
}
```

### Dead Letter Queue

Persist failed items for later retry:

```powershell
function Add-ToDeadLetterQueue {
    param([string]$WorkflowId, [object]$FailedItem, [string]$Error, [string]$QueueDir = ".secops/dead-letter")
    if (-not (Test-Path $QueueDir)) { New-Item -ItemType Directory -Path $QueueDir -Force | Out-Null }
    $file = Join-Path $QueueDir "$WorkflowId.json"
    $queue = if (Test-Path $file) { Get-Content $file -Raw | ConvertFrom-Json -AsHashtable } else { @() }
    $queue += @{ failedAt = (Get-Date -Format "o"); item = $FailedItem; error = $Error; status = "pending" }
    $queue | ConvertTo-Json -Depth 10 | Set-Content $file -Encoding UTF8
}
```

### Discovery Logger

Append environment facts found during orchestration (see `.copilot/skills/secops-environment-context.md`):

```powershell
function Write-OrchestrationDiscovery {
    param([string]$Type, [string]$Detail, [ValidateSet("high","medium","low")][string]$Confidence = "medium", [string]$ActionTaken = "")
    $entry = "`n- timestamp: $(Get-Date -Format 'o')`n  agent: orchestration`n  type: $Type`n  detail: `"$Detail`"`n  confidence: $Confidence`n  action_taken: `"$ActionTaken`""
    Add-Content -Path ".secops/discovery-log.yaml" -Value $entry
}
```

---

## Agent Orchestration Patterns

### Workflow Decomposition — Who Handles What

| Workflow Step | Agent | Skill Domain |
|---|---|---|
| KQL query building | **Freamon** | `skills/kql/` |
| Sentinel API operations | **Kima** | `skills/msft-security/` |
| Advanced Hunting | **Freamon** | `skills/detection/` |
| eDiscovery / Purview | **Kima** | `skills/msft-security/` |
| SOAR playbook triggers | **Herc** | `skills/soar/` |
| PowerShell wrappers | **Sydnor** | `skills/powershell/` |
| Data tiering operations | **Freamon** | `skills/log-analytics/` |
| Dashboard creation | **Herc** | `skills/soar/workbook-automation.md` |
| Validation / testing | **Carver** | Quality gates |

### Handoff Protocol

1. **Structured output** — every step returns `@{ ok = $true; data = ... }` (see `error-handling.md`)
2. **Schema agreement** — both producer and consumer reference the same skill file for data contracts
3. **Error propagation** — coordinator decides: continue, retry, or abort
4. **Context preservation** — pass `.secops/` config references, never hardcoded values

### Result Aggregation

```powershell
function Merge-WorkflowResults {
    param([hashtable[]]$StepResults, [string]$WorkflowName)
    $ok = ($StepResults | Where-Object { $_.ok }).Count
    $fail = ($StepResults | Where-Object { -not $_.ok }).Count
    @{
        workflow = $WorkflowName; completedAt = (Get-Date -Format "o")
        totalSteps = $StepResults.Count; succeeded = $ok; failed = $fail
        overallStatus = if ($fail -eq 0) { "success" } elseif ($ok -gt 0) { "partial" } else { "failed" }
        steps = $StepResults
    }
}
```

---

## Quick Reference

| Pattern | Use When | Function |
|---|---|---|
| Sequential Pipeline | Steps depend on previous output | `Invoke-SequentialPipeline` |
| Fan-Out/Fan-In | Independent parallel actions | `Invoke-FanOutFanIn` |
| Conditional Branching | Different paths per finding | `Invoke-ConditionalBranch` |
| Loop/Iteration | Same steps per entity | `Invoke-EntityLoop` |
| Checkpoint/Resume | Long-running, interruptible | `Invoke-CheckpointWorkflow` |

| Workflow | Entry Function | Primary Pattern |
|---|---|---|
| Incident Investigation | `Start-IncidentInvestigation` | Sequential + Fan-Out + Loop |
| Compliance Export | `Start-ComplianceExport` | Sequential + Checkpoint |
| Threat Hunting Campaign | `Start-ThreatHuntingCampaign` | Sequential + Conditional + Loop |
| Data Tiering Migration | `Start-DataTieringMigration` | Loop + Checkpoint |
| Shadow IT Assessment | `Start-ShadowITAssessment` | Sequential + Fan-Out + Conditional |
