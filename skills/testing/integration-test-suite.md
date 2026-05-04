---
title: Integration Test Suite for SecOps Workflows
category: testing
difficulty: advanced
mitre_attack:
  - T1059.001  # PowerShell
  - T1078      # Valid Accounts
  - T1566      # Phishing
  - T1048      # Exfiltration Over Alternative Protocol
  - T1530      # Data from Cloud Storage
products:
  - Microsoft Sentinel
  - Microsoft Defender XDR
  - Microsoft Purview
  - Microsoft Purview eDiscovery
  - Microsoft Defender for Cloud Apps
  - Azure Monitor Log Analytics
  - Azure Data Explorer
author: Carver
version: 1.0.0
last_updated: 2026-05-04
---

# Integration Test Suite for SecOps Workflows

## Overview

Unit tests validate individual skills; integration tests validate the **handoffs between them**. Does the entity extractor's output feed the enrichment step? Does a rate-limit hit in step 3 propagate correctly to the checkpoint system? Does a missing `.secops/` config produce an actionable error?

This skill defines test architecture, mock factories, and end-to-end scenarios for all five workflows in `skills/orchestration/cross-skill-orchestration.md`.

**Why integration testing matters:**
- Orchestration bugs hide in seams between skills, not inside them
- `.secops/` context errors only surface when multiple skills share config
- Rate limiting across chained API calls requires cross-step coordination
- Partial failures must degrade gracefully, not cascade into full crashes

---

## Test Architecture

### Test Harness Design

Intercept all HTTP calls at `Invoke-RestMethod` boundary with deterministic mock responses.

```powershell
BeforeAll {
    $script:ApiCallLog = [System.Collections.ArrayList]::new()
    $script:MockResponses = @{}

    function Register-MockResponse {
        param([string]$UriPattern, [string]$Method = "Get", [object]$Response,
              [int]$StatusCode = 200, [int]$DelayMs = 0, [int]$FailCount = 0)
        $script:MockResponses["$Method|$UriPattern"] = @{
            Response = $Response; StatusCode = $StatusCode; DelayMs = $DelayMs
            FailCount = $FailCount; CallCount = 0
        }
    }

    function Invoke-RestMethod {
        param([string]$Uri, [hashtable]$Headers = @{}, [string]$Method = "Get", [string]$Body = "")
        [void]$script:ApiCallLog.Add(@{ Uri=$Uri; Method=$Method; Body=$Body; Timestamp=Get-Date })
        foreach ($key in $script:MockResponses.Keys) {
            $parts = $key -split '\|', 2
            if ($Method -ieq $parts[0] -and $Uri -match $parts[1]) {
                $mock = $script:MockResponses[$key]; $mock.CallCount++
                if ($mock.DelayMs -gt 0) { Start-Sleep -Milliseconds $mock.DelayMs }
                if ($mock.CallCount -le $mock.FailCount) {
                    throw [System.Net.Http.HttpRequestException]::new("Mock 429")
                }
                return $mock.Response
            }
        }
        throw "No mock registered for $Method $Uri"
    }

    function Get-AzAccessToken { param([string]$ResourceUrl); @{ Token = "mock-token-$(New-Guid)" } }
}
```

### Test Data Generators

```powershell
function New-MockSentinelIncident {
    param([string]$IncidentId = "inc-$(New-Guid)", [string]$Severity = "Medium", [string]$Status = "New")
    @{ id = $IncidentId; name = $IncidentId
       properties = @{ title = "Test Incident"; severity = $Severity; status = $Status
           incidentNumber = (Get-Random -Min 10000 -Max 99999); createdTimeUtc = (Get-Date -Format "o") } }
}

function New-MockIncidentEntities {
    param([int]$IpCount = 2, [int]$UserCount = 1, [int]$HostCount = 1)
    $entities = @()
    1..$IpCount   | ForEach-Object { $entities += @{ kind="Ip";      properties=@{ address="10.0.$_.$(Get-Random -Max 255)" } } }
    1..$UserCount | ForEach-Object { $entities += @{ kind="Account"; properties=@{ accountName="testuser$_" } } }
    1..$HostCount | ForEach-Object { $entities += @{ kind="Host";    properties=@{ hostName="WORKSTATION-$_" } } }
    @{ entities = $entities }
}

function New-MockDefenderAlert {
    param([string]$AlertId = "da-$(New-Guid)", [string]$Severity = "High")
    @{ id=$AlertId; severity=$Severity; category="SuspiciousActivity"; title="Suspicious PowerShell"
       status="new"; evidence=@(@{ type="process"; fileName="powershell.exe" }) }
}

function New-MockEdiscoveryCase {
    param([string]$CaseId = "case-$(New-Guid)", [string]$Status = "active")
    @{ id=$CaseId; displayName="Test-Compliance-Export"; status=$Status; createdDateTime=(Get-Date -Format "o") }
}

function New-MockEdiscoverySearch {
    param([string]$SearchId = "search-$(New-Guid)", [string]$Status = "completed")
    @{ id=$SearchId; status=$Status; displayName="Test-Search"; resultCount=42 }
}
```

#### Synthetic Telemetry (JSON payloads for Defender event shapes)

```json
{ "Timestamp":"2026-05-03T14:22:31Z", "DeviceName":"WORKSTATION-1", "ActionType":"ProcessCreated",
  "FileName":"powershell.exe", "ProcessCommandLine":"powershell.exe -enc SQBuAHYAbwBr",
  "InitiatingProcessFileName":"cmd.exe", "AccountName":"testuser1" }

{ "Timestamp":"2026-05-03T14:23:15Z", "DeviceName":"WORKSTATION-1", "ActionType":"ConnectionSuccess",
  "RemoteIP":"185.220.101.42", "RemotePort":443, "RemoteUrl":"suspicious-c2.example.com" }

{ "TimeGenerated":"2026-05-03T14:20:00Z", "UserPrincipalName":"testuser1@contoso.com",
  "IPAddress":"185.220.101.42", "ResultType":0, "RiskLevelDuringSignIn":"high" }
```

### Environment Isolation

```powershell
function New-TestSecopsConfig {
    param([ValidateSet("single-tenant","multi-tenant","gov-cloud")][string]$Scenario = "single-tenant")
    $base = @{ schema_version="1.0"; organization=@{ name="Contoso Corp (TEST)"; tenant_id="00000000-0000-0000-0000-000000000001" }
        azure=@{ primary_subscription="00000000-0000-0000-0000-000000000002"; resource_group="rg-secops-test"; cloud="AzureCloud" } }
    switch ($Scenario) {
        "multi-tenant" { $base.organization.managed_tenants = @(
            @{ name="Fabrikam (TEST)"; tenant_id="00000000-0000-0000-0000-000000000003" }
            @{ name="Woodgrove (TEST)"; tenant_id="00000000-0000-0000-0000-000000000004" }) }
        "gov-cloud" { $base.azure.cloud = "AzureUSGovernment"; $base.azure.endpoints = @{
            management="https://management.usgovcloudapi.net"; graph="https://graph.microsoft.us"
            logAnalytics="https://api.loganalytics.us" } }
    }
    $base
}

function New-TestDataSourceMap {
    param([string]$WorkspaceName = "test-workspace-001")
    @{ schema_version="1.0"; tables=@(
        @{ name="SecurityEvent"; workspace=$WorkspaceName; tier="Analytics"; retention_days=90; compliance_tags=@("SOC2","PCI-DSS") }
        @{ name="SigninLogs"; workspace=$WorkspaceName; tier="Analytics"; retention_days=365 }
        @{ name="DeviceNetworkEvents"; workspace=$WorkspaceName; tier="Analytics"; retention_days=30 }
        @{ name="AzureActivity"; workspace=$WorkspaceName; tier="Basic"; retention_days=90 }
        @{ name="ContainerLog"; workspace=$WorkspaceName; tier="Auxiliary"; retention_days=30 }
    )}
}
```

### API Fixture Sets

```powershell
$LogAnalyticsFixtures = @{
    QueryResult = @{ tables=@(@{ name="PrimaryResult"
        columns=@(@{name="UserPrincipalName";type="string"},@{name="Attempts";type="long"},@{name="IPs";type="long"})
        rows=@(@("testuser1@contoso.com",75,5),@("testuser2@contoso.com",120,8)) }) }
    EmptyResult = @{ tables=@(@{ name="PrimaryResult"; columns=@(); rows=@() }) }
}
$DefenderFixtures = @{
    HuntingResult = @{ results=@(@{ AccountName="testuser1"; C=25 }) }
    EmptyHunting  = @{ results=@() }
}
$PurviewFixtures = @{
    Labels = @{ value=@(@{id="label-1";name="Confidential"},@{id="label-2";name="Public"}) }
}
```

---

## Workflow Test Scenarios

### Scenario 1: Incident Investigation Pipeline

**Ref:** `cross-skill-orchestration.md` → Workflow 1 | **Pattern:** Sequential + Fan-Out + Loop

```powershell
Describe "Workflow 1 — Incident Investigation" {
    BeforeAll {
        . "$PSScriptRoot/../helpers/test-harness.ps1"
        $script:CurrentYamlFixture = New-TestSecopsConfig
        Register-MockResponse -UriPattern "incidents/inc-001\?" -Method "Get" -Response (New-MockSentinelIncident -IncidentId "inc-001" -Severity "High")
        Register-MockResponse -UriPattern "incidents/inc-001/entities" -Method "Post" -Response (New-MockIncidentEntities)
        Register-MockResponse -UriPattern "security/runHuntingQuery" -Method "Post" -Response @{ results=@(@{AccountName="testuser1";C=30}) }
        Register-MockResponse -UriPattern "incidents/inc-001/comments" -Method "Put" -Response @{ id="comment-001" }
    }

    It "produces expected output at each step" {
        $r = Start-IncidentInvestigation -IncidentId "inc-001" -WorkspaceId "test-ws"
        $r.ok | Should -Be $true
        $r.results | Should -HaveCount 4
        $r.results[0].Output.data.properties.severity | Should -Be "High"
        $r.results[1].Output.data.entities.ips.Count | Should -Be 2
    }

    It "error in one step doesn't crash the pipeline" {
        Register-MockResponse -UriPattern "incidents/inc-001/entities" -Method "Post" `
            -Response @{ ok=$false; error="503 Service Unavailable" }
        $r = Start-IncidentInvestigation -IncidentId "inc-001" -WorkspaceId "test-ws"
        $r.ok | Should -Be $false
        $r.error | Should -Match "ExtractEntities"
        $r.results.Count | Should -BeGreaterOrEqual 1
    }

    It "rate limiting is respected across chained calls" {
        Register-MockResponse -UriPattern "security/runHuntingQuery" -Method "Post" `
            -Response @{ results=@(@{C=5}) } -FailCount 2
        $r = Start-IncidentInvestigation -IncidentId "inc-001" -WorkspaceId "test-ws"
        $script:ApiCallLog | Where-Object { $_.Uri -match "runHuntingQuery" } | Should -Not -BeNullOrEmpty
    }
}
```

### Scenario 2: Compliance Export Workflow

**Ref:** `cross-skill-orchestration.md` → Workflow 2 | **Pattern:** Sequential + Checkpoint

```powershell
Describe "Workflow 2 — Compliance Export" {
    BeforeAll {
        . "$PSScriptRoot/../helpers/test-harness.ps1"
        Register-MockResponse -UriPattern "ediscoveryCases$" -Method "Post" -Response (New-MockEdiscoveryCase)
        Register-MockResponse -UriPattern "ediscoveryCases/.*/searches$" -Method "Post" -Response (New-MockEdiscoverySearch -Status "running")
        Register-MockResponse -UriPattern "ediscoveryCases/.*/searches/.*$" -Method "Get" -Response (New-MockEdiscoverySearch)
        Register-MockResponse -UriPattern "sensitivityLabels" -Method "Get" -Response $PurviewFixtures.Labels
        Register-MockResponse -UriPattern "exportResult" -Method "Post" -Response @{ id="export-001" }
    }

    It "framework mappings resolve correctly" {
        $script:CurrentYamlFixture = @{ frameworks=@(@{ name="PCI-DSS"; version="4.0" }) }
        $r = Start-ComplianceExport -Framework "PCI-DSS" -ControlId "1.2"
        $r.ok | Should -Be $true
    }

    It "eDiscovery lifecycle: create → search → export" {
        $script:ApiCallLog.Clear()
        Start-ComplianceExport -Framework "PCI-DSS" -ControlId "1.2"
        ($script:ApiCallLog | Where-Object { $_.Uri -match "ediscoveryCases$" -and $_.Method -eq "Post" }).Count | Should -Be 1
        ($script:ApiCallLog | Where-Object { $_.Uri -match "searches$" -and $_.Method -eq "Post" }).Count | Should -Be 1
        ($script:ApiCallLog | Where-Object { $_.Uri -match "exportResult" }).Count | Should -Be 1
    }

    It "unknown framework returns actionable error" {
        $script:CurrentYamlFixture = @{ frameworks=@(@{ name="SOC2" }) }
        $r = Start-ComplianceExport -Framework "HIPAA" -ControlId "1.1"
        $r.ok | Should -Be $false
        $r.error | Should -Match "HIPAA.*not found"
    }
}
```

### Scenario 3: Threat Hunting Campaign

**Ref:** `cross-skill-orchestration.md` → Workflow 3 | **Pattern:** Sequential + Conditional + Loop

```powershell
Describe "Workflow 3 — Threat Hunting Campaign" {
    BeforeAll {
        . "$PSScriptRoot/../helpers/test-harness.ps1"
        $script:CurrentYamlFixture = New-TestSecopsConfig
    }

    It "KQL builder produces valid queries for known technique" {
        Register-MockResponse -UriPattern "workspaces/.*/query" -Method "Post" -Response $LogAnalyticsFixtures.QueryResult
        Register-MockResponse -UriPattern "security/runHuntingQuery" -Method "Post" -Response $DefenderFixtures.HuntingResult
        Register-MockResponse -UriPattern "incidents/" -Method "Put" -Response @{ name="new-inc" }
        $r = Start-ThreatHuntingCampaign -TechniqueId "T1078" -Hypothesis "Compromised creds"
        ($script:ApiCallLog | Where-Object { $_.Body -match "SigninLogs" }).Count | Should -BeGreaterThan 0
    }

    It "cross-workspace queries route per data-source-map" {
        $script:CurrentYamlFixture = New-TestDataSourceMap -WorkspaceName "primary-ws"
        Register-MockResponse -UriPattern "workspaces/primary-ws/query" -Method "Post" -Response $LogAnalyticsFixtures.QueryResult
        Start-ThreatHuntingCampaign -TechniqueId "T1078" -Hypothesis "Test routing"
        ($script:ApiCallLog | Where-Object { $_.Uri -match "secondary-ws" }).Count | Should -Be 0
    }

    It "creates incident when threats found, logs clean when none" {
        Register-MockResponse -UriPattern "workspaces/.*/query" -Method "Post" -Response $LogAnalyticsFixtures.EmptyResult
        Register-MockResponse -UriPattern "security/runHuntingQuery" -Method "Post" -Response $DefenderFixtures.EmptyHunting
        $r = Start-ThreatHuntingCampaign -TechniqueId "T1078" -Hypothesis "Negative"
        $r.outcome | Should -Be "Clean"
    }
}
```

### Scenario 4: Data Tiering Migration

**Ref:** `cross-skill-orchestration.md` → Workflow 4 | **Pattern:** Loop + Checkpoint

```powershell
Describe "Workflow 4 — Data Tiering Migration" {
    BeforeAll {
        . "$PSScriptRoot/../helpers/test-harness.ps1"
        $script:CurrentYamlFixture = New-TestDataSourceMap
    }

    It "pre-flight blocks downgrade when analytics rules depend on table" {
        Register-MockResponse -UriPattern "alertRules\?" -Method "Get" -Response @{
            value=@(@{ properties=@{ query="SecurityEvent | where EventID == 4625" } }) }
        $r = Start-DataTieringMigration -WorkspaceName "test-workspace-001" -TargetTier "Basic"
        ($r.results.results | Where-Object { $_.Status -eq "Failed" -and $_.Error -match "dependent" }) | Should -Not -BeNullOrEmpty
    }

    It "dry-run makes no tier changes" {
        Register-MockResponse -UriPattern "alertRules\?" -Method "Get" -Response @{ value=@() }
        $script:ApiCallLog.Clear()
        Start-DataTieringMigration -WorkspaceName "test-workspace-001" -TargetTier "Basic" -DryRun
        ($script:ApiCallLog | Where-Object { $_.Method -eq "Patch" }).Count | Should -Be 0
    }

    It "discovery log updated after changes" {
        Register-MockResponse -UriPattern "alertRules\?" -Method "Get" -Response @{ value=@() }
        Register-MockResponse -UriPattern "tables/" -Method "Patch" -Response @{ properties=@{ plan="Basic" } }
        $r = Start-DataTieringMigration -WorkspaceName "test-workspace-001" -TargetTier "Basic"
        $r.ok | Should -Be $true
    }

    It "circuit breaker trips after consecutive failures" {
        Register-MockResponse -UriPattern "alertRules\?" -Method "Get" -Response @{ value=@() }
        Register-MockResponse -UriPattern "tables/" -Method "Patch" -Response $null -FailCount 10
        $r = Start-DataTieringMigration -WorkspaceName "test-workspace-001" -TargetTier "Basic"
        ($r.results.results | Where-Object { $_.Status -eq "Skipped" }).Count | Should -BeGreaterThan 0
    }
}
```

### Scenario 5: Shadow IT Assessment

**Ref:** `cross-skill-orchestration.md` → Workflow 5 | **Pattern:** Sequential + Fan-Out + Conditional

```powershell
Describe "Workflow 5 — Shadow IT Assessment" {
    BeforeAll {
        . "$PSScriptRoot/../helpers/test-harness.ps1"
        $mockApps = @{ value=@(
            @{ displayName="ShadowDrive"; userCount=75; complianceRisks=@{isSOC2Compliant=$false;isPCIDSSCompliant=$false}; securityRisks=@{hasEncryptionAtRest=$false} }
            @{ displayName="ApprovedApp"; userCount=200; complianceRisks=@{isSOC2Compliant=$true;isPCIDSSCompliant=$true}; securityRisks=@{hasEncryptionAtRest=$true} }
        )}
        Register-MockResponse -UriPattern "uploadedStreams$" -Method "Get" -Response @{ value=@(@{id="s1";displayName="Corp"}) }
        Register-MockResponse -UriPattern "aggregatedAppsDetails" -Method "Get" -Response $mockApps
    }

    It "MDCA API responses parsed correctly" {
        $script:CurrentYamlFixture = @{ frameworks=@(@{ name="SOC2" }) }
        $r = Start-ShadowITAssessment -RiskThreshold 7
        $r.ok | Should -Be $true
        $r.output.data.total | Should -Be 2
    }

    It "Purview classification flags non-compliant apps for blocking" {
        $script:CurrentYamlFixture = @{ frameworks=@(@{name="PCI-DSS"},@{name="SOC2"}) }
        $r = Start-ShadowITAssessment -RiskThreshold 7
        $blocked = $r.output.data.recommendations | Where-Object { $_.recommendation -eq "Block" }
        $blocked | Should -Not -BeNullOrEmpty
        $blocked[0].violations | Should -Contain "PCI-DSS"
    }
}
```

---

## Error Handling Tests

```powershell
Describe "Cross-Workflow Error Handling" {
    BeforeAll { . "$PSScriptRoot/../helpers/test-harness.ps1" }

    It "API timeout → retry with exponential backoff" {
        $attempt = 0
        $result = Invoke-WithRetry -Action {
            $attempt++; if ($attempt -le 2) { throw "429" }; @{ ok=$true }
        } -MaxRetries 3 -BaseDelayMs 50
        $result.ok | Should -Be $true
    }

    It "Partial failure → continue with remaining items" {
        $r = Invoke-EntityLoop -Entities @("good1","bad1","good2","bad2","good3") -MaxFailures 5 -ProcessEntity {
            param($e); if ($e -match "bad") { @{ok=$false;error="fail"} } else { @{ok=$true;data=$e} }
        }
        $r.succeeded | Should -Be 3; $r.failed | Should -Be 2; $r.ok | Should -Be $true
    }

    It "Auth token expiry → refresh and retry on 401" {
        Register-MockResponse -UriPattern "incidents/" -Method "Get" -Response (New-MockSentinelIncident) -FailCount 1
        $r = Invoke-WithRetry -Action { Invoke-RestMethod -Uri "https://mgmt.azure.com/incidents/1" } `
            -MaxRetries 2 -RetryOn @(401,429,503)
        $r | Should -Not -BeNullOrEmpty
    }

    It "Invalid .secops/ config → graceful error, no crash" {
        $script:CurrentYamlFixture = $null
        { Start-IncidentInvestigation -IncidentId "x" -WorkspaceId "y" } | Should -Not -Throw
    }
}
```

---

## Performance Tests

```powershell
Describe "Performance and Scale" {
    BeforeAll { . "$PSScriptRoot/../helpers/test-harness.ps1" }

    It "large result set pagination (1000+ incidents)" {
        $page = @{ value = (1..100 | ForEach-Object { New-MockSentinelIncident }); nextLink = "https://next" }
        Register-MockResponse -UriPattern "incidents\?" -Method "Get" -Response $page
        $resp = Invoke-RestMethod -Uri "https://mgmt.azure.com/incidents?api-version=2024-03-01"
        $resp.value.Count | Should -Be 100
    }

    It "fan-out respects MaxConcurrency" {
        $actions = 1..10 | ForEach-Object { @{ Name="A$_"; Action={ param($in) @{ok=$true} } } }
        $r = Invoke-FanOutFanIn -Actions $actions -TriggerInput @{} -MaxConcurrency 3 -TimeoutSec 30
        $r.results.Count | Should -Be 10
    }

    It "query timeout handled gracefully" {
        Register-MockResponse -UriPattern "query" -Method "Post" -Response @{} -DelayMs 5000
        $r = Invoke-FanOutFanIn -Actions @(@{ Name="Slow"; Action={ Invoke-RestMethod -Uri "https://api/query" -Method Post } }) `
            -TriggerInput @{} -MaxConcurrency 1 -TimeoutSec 2
        ($r.results | Where-Object { $_.Status -eq "Timeout" }) | Should -Not -BeNullOrEmpty
    }

    It "batch 500 entities without circuit breaker" {
        $r = Invoke-EntityLoop -Entities (1..500) -MaxFailures 10 -DelayMs 0 -ProcessEntity { param($e) @{ok=$true;data=$e} }
        $r.succeeded | Should -Be 500
    }
}
```

---

## `.secops/` Context Tests

```powershell
Describe ".secops/ Configuration Context" {
    It "missing environment.yaml → helpful error suggesting init" {
        $r = & { try { Get-Content ".secops/environment.yaml" -Raw -EA Stop } catch {
            @{ ok=$false; error="Missing .secops/environment.yaml — run 'secops-squad init --secops'" } } }
        $r.error | Should -Match "secops-squad init"
    }

    It "multiple workspaces → query routes to correct workspace" {
        $dsm = @{ tables=@(@{name="SecurityEvent";workspace="sentinel-prod"},@{name="SigninLogs";workspace="sentinel-identity"}) }
        ($dsm.tables | Where-Object { $_.name -eq "SigninLogs" }).workspace | Should -Be "sentinel-identity"
    }

    It "migration in progress → skips migrating tables" {
        $dsm = @{ tables=@(@{name="SecurityEvent";workspace="old-ws";migration_status="in_progress"}) }
        ($dsm.tables | Where-Object { $_.migration_status -eq "in_progress" }).Count | Should -Be 1
    }

    It "discovery log append produces valid YAML" {
        $entry = "- timestamp: $(Get-Date -Format 'o')`n  agent: test`n  type: workspace_discovered`n  confidence: high"
        $entry | Should -Match "^- timestamp:"
    }

    It "gov-cloud uses correct endpoints" {
        $c = New-TestSecopsConfig -Scenario "gov-cloud"
        $c.azure.endpoints.management | Should -Be "https://management.usgovcloudapi.net"
        $c.azure.endpoints.graph | Should -Be "https://graph.microsoft.us"
    }

    It "multi-tenant loads managed tenants for MSSP" {
        $c = New-TestSecopsConfig -Scenario "multi-tenant"
        $c.organization.managed_tenants.Count | Should -Be 2
    }
}
```

---

## PowerShell Test Harness — Pester Patterns

### Assert Helpers for `@{ ok; data/error }` Contract

```powershell
function Assert-SuccessResult {
    param([hashtable]$Result, [string]$Because = "")
    $Result.ok | Should -Be $true -Because "should indicate success. $Because"
    $Result.ContainsKey('data') | Should -Be $true -Because "success must have 'data'. $Because"
}

function Assert-ErrorResult {
    param([hashtable]$Result, [string]$ExpectedPattern = ".*", [string]$Because = "")
    $Result.ok | Should -Be $false -Because "should indicate failure. $Because"
    $Result.error | Should -Match $ExpectedPattern -Because $Because
}
```

### Mock Invoke-AzRestMethod Pattern

```powershell
Describe "Invoke-AzRestMethod Mock" {
    It "captures URI and method" {
        Mock Invoke-AzRestMethod { @{ StatusCode=200; Content=(@{value=@(@{id="test"})}|ConvertTo-Json -Depth 5) } }
        $r = Invoke-AzRestMethod -Path "/subscriptions/sub-1/resourceGroups/rg-1" -Method "GET"
        $r.StatusCode | Should -Be 200
        Should -Invoke Invoke-AzRestMethod -Times 1 -Exactly
    }
}
```

### Rate-Limit Mock Helper

```powershell
function Register-RateLimitedMock {
    param([string]$UriPattern, [string]$Method = "Get", [object]$SuccessResponse, [int]$FailForFirstN = 3)
    Register-MockResponse -UriPattern $UriPattern -Method $Method -Response $SuccessResponse -FailCount $FailForFirstN
}
```

### Synthetic KQL for Validator Testing

```kql
// Valid hunting query — should pass validator
SigninLogs | where TimeGenerated > ago(30d)
| where ResultType == 0 and RiskLevelDuringSignIn in ("high","medium")
| summarize Attempts=count(), IPs=dcount(IPAddress) by UserPrincipalName
| where IPs > 3

// Invalid query — should trigger validator error
SecurityEvent | where EventID = 4625 | summerize count() by Account
```

---

## Test Execution Checklist

| # | Check | Command | Owner |
|---|---|---|---|
| 1 | KQL syntax validation | `node --test lib/kql-validator/*.test.js` | Carver |
| 2 | Graph Security API tests | `node --test lib/graph-security/*.test.js` | Carver |
| 3 | Integration workflow tests | `Invoke-Pester -Path tests/integration/ -Output Detailed` | Carver |
| 4 | `.secops/` config tests | `Invoke-Pester -Path tests/secops-config/ -Output Detailed` | Carver |
| 5 | Bicep template validation | `az bicep build --file templates/bicep/soar/main.bicep` | Herc |
| 6 | KQL CI gate | `secops-squad kql validate skills/` | Carver |

## Quick Reference

| What | Pattern | Example |
|---|---|---|
| Mock API | `Register-MockResponse` | `Register-MockResponse -UriPattern "incidents/" -Response $data` |
| Test incident | `New-MockSentinelIncident` | `New-MockSentinelIncident -Severity "High"` |
| Test entities | `New-MockIncidentEntities` | `New-MockIncidentEntities -IpCount 3` |
| Test config | `New-TestSecopsConfig` | `New-TestSecopsConfig -Scenario "gov-cloud"` |
| Assert success | `Assert-SuccessResult` | `Assert-SuccessResult -Result $r` |
| Assert error | `Assert-ErrorResult` | `Assert-ErrorResult -Result $r -ExpectedPattern "not found"` |
| Rate limit mock | `Register-RateLimitedMock` | `Register-RateLimitedMock -UriPattern "api/" -FailForFirstN 2` |
| Run all | Pester | `Invoke-Pester -Path tests/integration/ -Output Detailed` |
