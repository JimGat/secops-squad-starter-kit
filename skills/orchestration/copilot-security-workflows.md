---
title: Copilot for Security Enriched Workflows
category: orchestration
difficulty: advanced
mitre_attack:
  - T1059   # Command and Scripting Interpreter (script analysis)
  - T1078   # Valid Accounts (identity investigation)
  - T1566   # Phishing (incident summarization)
  - T1190   # Exploit Public-Facing Application (vulnerability assessment)
  - T1071   # Application Layer Protocol (TI enrichment)
  - T1003   # OS Credential Dumping (credential theft triage)
  - T1486   # Data Encrypted for Impact (ransomware triage)
  - T1027   # Obfuscated Files or Information (script deobfuscation)
products:
  - Microsoft Copilot for Security
  - Microsoft Sentinel
  - Microsoft Defender XDR
  - Microsoft Defender for Endpoint
  - Microsoft Entra ID
  - Microsoft Purview
  - Azure Monitor Log Analytics
author: Kima
version: 1.0.0
last_updated: 2026-05-04
---

# Copilot for Security Enriched Workflows

## Overview

Microsoft Copilot for Security augments SOC workflows with AI-powered enrichment at key decision points. Rather than replacing analyst judgment, Copilot provides contextual summaries, threat intelligence, script analysis, and query generation that accelerate investigation and reduce mean-time-to-respond (MTTR).

This skill defines **how to weave Copilot for Security into orchestrated workflows** — feeding it structured inputs, processing AI-generated outputs, and handling graceful degradation when SCUs are exhausted or Copilot is unavailable (e.g., GCC High/DoD environments).

**Use this skill when:**
- Building automated triage pipelines that benefit from AI summarization
- Enriching alerts with threat intelligence context before analyst review
- Analyzing suspicious scripts or commands captured during incidents
- Generating hunting queries from natural language hypotheses
- Creating AI-assisted reports for executives or compliance teams

**Skills referenced (not duplicated):**

| Domain | Key Skills |
|---|---|
| **MSFT Security** | `copilot-for-security.md` (SCU planning, plugins, promptbooks, REST API) |
| **Orchestration** | `cross-skill-orchestration.md` (pipeline patterns, error handling) |
| **PowerShell** | `sentinel-api-wrapper.md`, `defender-api-wrapper.md`, `error-handling.md` |
| **KQL** | `query-builder.md`, `cross-workspace-queries.md` |
| **Platform** | `gov-cloud-support.md` (Copilot availability per cloud) |

## Environment Context

Before using Copilot for Security in workflows, check `.secops/`:

1. **`.secops/environment.yaml`** — Verify `copilot_for_security.provisioned: true` and SCU allocation
2. **`.secops/environment.yaml`** — Check `organization.cloud`; Copilot unavailable in GCC High/DoD/China (see `gov-cloud-support.md`)
3. **`.secops/identity/tenants.yaml`** — Copilot runs in home tenant; cross-tenant requires delegation
4. **`.secops/alerting/routing.yaml`** — Route AI-assisted findings through existing escalation paths

## Section 1: Enrichment Patterns

### Pattern 1: Incident Summarization

Feed a Sentinel incident to Copilot and receive an analyst-ready summary.

**Input:** Incident ID, alert details, entity list
**Output:** Natural language summary with severity assessment, affected entities, and recommended next steps

```powershell
function Invoke-SecOpsCopilotIncidentSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IncidentId,
        [Parameter(Mandatory)][string]$WorkspaceId,
        [Parameter(Mandatory)][string]$SessionId
    )

    # Fetch incident context from Sentinel
    $incident = Get-SecOpsSentinelIncident -WorkspaceId $WorkspaceId -IncidentId $IncidentId
    if (-not $incident.ok) { return $incident }

    $entities = Get-SecOpsSentinelEntities -WorkspaceId $WorkspaceId -IncidentId $IncidentId
    $alerts = Get-SecOpsSentinelAlerts -WorkspaceId $WorkspaceId -IncidentId $IncidentId

    $prompt = @"
Summarize this security incident for a SOC analyst:

Incident: $($incident.data.properties.title)
Severity: $($incident.data.properties.severity)
Status: $($incident.data.properties.status)
Created: $($incident.data.properties.createdTimeUtc)

Alerts ($($alerts.data.Count)):
$($alerts.data | ForEach-Object { "- $($_.properties.alertDisplayName) [$($_.properties.severity)]" } | Out-String)

Entities ($($entities.data.Count)):
$($entities.data | ForEach-Object { "- $($_.kind): $($_.properties.friendlyName)" } | Out-String)

Provide: 1) One-paragraph summary, 2) Key risk indicators, 3) Recommended next steps, 4) Confidence: high/medium/low
"@

    return Invoke-SecOpsCopilotPrompt -SessionId $SessionId -Prompt $prompt
}
```

### Pattern 2: Threat Intelligence Enrichment

Feed IOCs (IPs, domains, hashes) to Copilot for context-rich threat intelligence.

```powershell
function Invoke-SecOpsCopilotTIEnrichment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Indicators,
        [Parameter(Mandatory)][string]$SessionId
    )

    $iocList = $Indicators | ForEach-Object { "- $_" } | Out-String
    $prompt = @"
Analyze these indicators of compromise using Microsoft Threat Intelligence:

$iocList

For each indicator provide:
1. Known associations (threat actors, campaigns, malware families)
2. Risk rating (Critical/High/Medium/Low/Unknown)
3. First seen / last seen dates
4. Recommended blocking actions
5. Related indicators to hunt for
"@

    return Invoke-SecOpsCopilotPrompt -SessionId $SessionId -Prompt $prompt
}
```

### Pattern 3: Script Analysis & Deobfuscation

Feed captured scripts (PowerShell, VBScript, batch files) for AI-powered analysis.

```powershell
function Invoke-SecOpsCopilotScriptAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptContent,
        [ValidateSet('PowerShell','VBScript','Bash','Batch','Python','JavaScript')]
        [string]$ScriptType = 'PowerShell',
        [Parameter(Mandatory)][string]$SessionId
    )

    # Truncate to avoid excessive SCU consumption
    $maxLength = 4000
    $truncated = if ($ScriptContent.Length -gt $maxLength) {
        $ScriptContent.Substring(0, $maxLength) + "`n... [TRUNCATED at $maxLength chars]"
    } else { $ScriptContent }

    $prompt = @"
Analyze this suspicious $ScriptType script found during an incident investigation:

``````$($ScriptType.ToLower())
$truncated
``````

Provide:
1. Deobfuscated version (if obfuscated)
2. What the script does (step-by-step)
3. Malicious indicators and MITRE ATT&CK techniques
4. Network IOCs (IPs, domains, URLs)
5. File system IOCs (paths, registry keys)
6. Severity assessment and recommended response
"@

    return Invoke-SecOpsCopilotPrompt -SessionId $SessionId -Prompt $prompt
}
```

### Pattern 4: KQL Assistance

Describe intent in natural language and receive an optimized KQL query.

```powershell
function Invoke-SecOpsCopilotKQLAssist {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Intent,
        [string[]]$Tables,
        [string]$TimeRange = "7d",
        [Parameter(Mandatory)][string]$SessionId
    )

    $tableContext = if ($Tables) {
        "Available tables: $($Tables -join ', ')"
    } else { "Use standard Sentinel tables" }

    $prompt = @"
Generate an optimized KQL query for Microsoft Sentinel:

Intent: $Intent
Time range: $TimeRange
$tableContext

Requirements:
1. Use efficient patterns (project early, filter before join)
2. Include comments explaining each section
3. Handle missing/null values
4. Suggest a threshold if applicable
"@

    return Invoke-SecOpsCopilotPrompt -SessionId $SessionId -Prompt $prompt
}
```

### Pattern 5: Vulnerability Assessment

Feed CVE identifiers for contextual impact analysis.

```powershell
function Invoke-SecOpsCopilotVulnAssess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$CVEs,
        [string]$EnvironmentContext,
        [Parameter(Mandatory)][string]$SessionId
    )

    $cveList = $CVEs | ForEach-Object { "- $_" } | Out-String
    $envInfo = if ($EnvironmentContext) { "Environment: $EnvironmentContext" } else { "" }

    $prompt = @"
Assess the impact of these vulnerabilities:

$cveList
$envInfo

For each CVE provide:
1. CVSS score and attack vector
2. Affected products and versions
3. Known exploitation in the wild
4. Microsoft Defender detection coverage
5. Recommended remediation priority and steps
6. Compensating controls if patching is delayed
"@

    return Invoke-SecOpsCopilotPrompt -SessionId $SessionId -Prompt $prompt
}
```

## Section 2: Workflow Templates

### Workflow 1: AI-Assisted Incident Triage

Automate initial triage with AI enrichment at each decision point.

```
┌─────────────────────────────────────────────────────────────┐
│                 AI-Assisted Incident Triage                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  New Sentinel Incident                                       │
│       │                                                      │
│       ▼                                                      │
│  Extract entities (IPs, users, hosts, files)                 │
│       │                                                      │
│       ├──► Copilot: Summarize incident context               │
│       │         (incident summary + risk indicators)         │
│       │                                                      │
│       ├──► Copilot: Analyze related scripts/commands         │
│       │         (deobfuscation + MITRE mapping)              │
│       │                                                      │
│       ├──► Copilot: Assess threat severity                   │
│       │         (true positive confidence score)             │
│       │                                                      │
│       ▼                                                      │
│  Auto-classify based on AI outputs:                          │
│       │                                                      │
│       ├── True Positive (high confidence)                    │
│       │     └──► Route to IR team + auto-contain             │
│       │                                                      │
│       ├── False Positive (high confidence)                   │
│       │     └──► Auto-close with AI evidence summary         │
│       │                                                      │
│       └── Needs Review (low confidence)                      │
│             └──► Route to L2 analyst with AI context         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

```powershell
function Invoke-SecOpsAITriage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IncidentId,
        [Parameter(Mandatory)][string]$WorkspaceId
    )

    # Create a Copilot session for the entire triage workflow
    $session = New-SecOpsCopilotSession -Description "Triage: Incident $IncidentId"
    if (-not $session.ok) {
        Write-Warning "Copilot unavailable — falling back to manual triage"
        return @{ ok = $true; classification = "NeedsReview"; reason = "Copilot unavailable" }
    }

    # Step 1: Incident summary
    $summary = Invoke-SecOpsCopilotIncidentSummary `
        -IncidentId $IncidentId -WorkspaceId $WorkspaceId -SessionId $session.data.sessionId
    
    # Step 2: Script analysis (if process execution entities exist)
    $entities = Get-SecOpsSentinelEntities -WorkspaceId $WorkspaceId -IncidentId $IncidentId
    $processes = $entities.data | Where-Object { $_.kind -eq 'Process' }
    $scriptAnalysis = $null
    if ($processes) {
        $scriptAnalysis = Invoke-SecOpsCopilotScriptAnalysis `
            -ScriptContent ($processes[0].properties.commandLine) `
            -SessionId $session.data.sessionId
    }

    # Step 3: Severity assessment with accumulated context
    $assessPrompt = @"
Based on our investigation so far in this session, provide a final classification:
- TRUE_POSITIVE (confidence > 80%)
- FALSE_POSITIVE (confidence > 80%)
- NEEDS_REVIEW (confidence < 80%)

Output as JSON: {"classification": "...", "confidence": 0-100, "reasoning": "..."}
"@
    $assessment = Invoke-SecOpsCopilotPrompt -SessionId $session.data.sessionId -Prompt $assessPrompt

    # Step 4: Route based on classification
    $result = $assessment.data | ConvertFrom-Json -ErrorAction SilentlyContinue
    $classification = $result.classification ?? "NEEDS_REVIEW"

    switch ($classification) {
        "TRUE_POSITIVE" {
            Update-SecOpsSentinelIncident -WorkspaceId $WorkspaceId -IncidentId $IncidentId `
                -Status "Active" -Severity "High" `
                -Comment "AI Triage: True Positive (confidence: $($result.confidence)%). $($result.reasoning)"
        }
        "FALSE_POSITIVE" {
            Update-SecOpsSentinelIncident -WorkspaceId $WorkspaceId -IncidentId $IncidentId `
                -Status "Closed" -Classification "FalsePositive" `
                -Comment "AI Triage: False Positive (confidence: $($result.confidence)%). $($result.reasoning)"
        }
        default {
            Update-SecOpsSentinelIncident -WorkspaceId $WorkspaceId -IncidentId $IncidentId `
                -Status "Active" -Owner "L2-Queue" `
                -Comment "AI Triage: Needs human review. $($summary.data)`n$($result.reasoning)"
        }
    }

    return @{
        ok             = $true
        incidentId     = $IncidentId
        classification = $classification
        confidence     = $result.confidence
        aiSummary      = $summary.data
        scriptAnalysis = $scriptAnalysis?.data
        scuConsumed    = $session.data.scuUsed
    }
}
```

### Workflow 2: Threat Hunt with AI

Iterative hypothesis-driven hunting with AI-generated queries and analysis.

```
┌─────────────────────────────────────────────────────────────┐
│                   Threat Hunt with AI                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Hypothesis (natural language)                               │
│       │                                                      │
│       ▼                                                      │
│  Copilot: Generate hunting queries                           │
│       │   (KQL for Sentinel + Advanced Hunting for XDR)      │
│       │                                                      │
│       ▼                                                      │
│  Execute queries across workspaces                           │
│       │   (parallel execution via workspace config)          │
│       │                                                      │
│       ▼                                                      │
│  Copilot: Analyze findings                                   │
│       │   (pattern identification + risk assessment)         │
│       │                                                      │
│       ▼                                                      │
│  Copilot: Suggest follow-up queries                          │
│       │   (pivot based on findings)                          │
│       │                                                      │
│       ▼                                                      │
│  ┌──────────────────────────┐                                │
│  │ More leads?              │                                │
│  │  YES → Loop back         │                                │
│  │  NO  → Generate report   │                                │
│  └──────────────────────────┘                                │
│       │                                                      │
│       ▼                                                      │
│  Copilot: Generate hunt report                               │
│       (executive summary + findings + recommendations)       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

```powershell
function Invoke-SecOpsAIThreatHunt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Hypothesis,
        [string[]]$WorkspaceIds,
        [int]$MaxIterations = 3,
        [int]$SCUBudget = 10
    )

    $session = New-SecOpsCopilotSession -Description "Hunt: $($Hypothesis.Substring(0, [Math]::Min(50, $Hypothesis.Length)))"
    if (-not $session.ok) {
        return @{ ok = $false; error = "Copilot unavailable for AI-assisted hunting" }
    }

    $findings = @()
    $queriesExecuted = @()
    $scuUsed = 0

    for ($i = 1; $i -le $MaxIterations; $i++) {
        # Generate hunting queries
        $queryPrompt = if ($i -eq 1) {
            "Generate 2-3 KQL hunting queries for: $Hypothesis"
        } else {
            "Based on previous findings, suggest 1-2 follow-up hunting queries to investigate further."
        }

        $queryResult = Invoke-SecOpsCopilotPrompt -SessionId $session.data.sessionId -Prompt $queryPrompt
        $scuUsed += $queryResult.data.scuConsumed ?? 1

        # Check SCU budget
        if ($scuUsed -ge $SCUBudget) {
            Write-Warning "SCU budget ($SCUBudget) reached at iteration $i. Stopping hunt."
            break
        }

        # Execute generated queries across workspaces
        foreach ($wsId in $WorkspaceIds) {
            # Parse KQL blocks from Copilot response and execute
            $kqlBlocks = [regex]::Matches($queryResult.data, '```kql\s*([\s\S]*?)```')
            foreach ($kql in $kqlBlocks) {
                $result = Invoke-SecOpsSentinelQuery -WorkspaceId $wsId -Query $kql.Groups[1].Value -Timespan "P7D"
                if ($result.ok -and $result.data.Count -gt 0) {
                    $findings += @{
                        iteration = $i
                        workspace = $wsId
                        query     = $kql.Groups[1].Value
                        results   = $result.data.Count
                        sample    = $result.data | Select-Object -First 5
                    }
                }
                $queriesExecuted += $kql.Groups[1].Value
            }
        }

        # Analyze findings
        if ($findings.Count -gt 0) {
            $analysisPrompt = "Analyze these hunting results and identify patterns:`n" +
                ($findings | ForEach-Object { "Query returned $($_.results) results from workspace $($_.workspace)" } | Out-String)
            $analysis = Invoke-SecOpsCopilotPrompt -SessionId $session.data.sessionId -Prompt $analysisPrompt
            $scuUsed += $analysis.data.scuConsumed ?? 1
        } else {
            break  # No findings, stop hunting
        }
    }

    # Generate hunt report
    $reportPrompt = @"
Generate a threat hunt report with:
1. Executive Summary (2-3 sentences)
2. Hypothesis: $Hypothesis
3. Findings Summary ($($findings.Count) results across $($WorkspaceIds.Count) workspaces)
4. Risk Assessment
5. Recommendations
6. Queries Used ($($queriesExecuted.Count) queries)
"@
    $report = Invoke-SecOpsCopilotPrompt -SessionId $session.data.sessionId -Prompt $reportPrompt

    return @{
        ok             = $true
        hypothesis     = $Hypothesis
        iterations     = [Math]::Min($MaxIterations, $scuUsed)
        findings       = $findings
        report         = $report.data
        queriesUsed    = $queriesExecuted
        scuConsumed    = $scuUsed
    }
}
```

### Workflow 3: Automated Reporting

Weekly/monthly security reporting with AI-generated narratives.

```
┌─────────────────────────────────────────────────────────────┐
│                    Automated Reporting                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Scheduled trigger (weekly/monthly)                          │
│       │                                                      │
│       ▼                                                      │
│  Collect metrics via KQL:                                    │
│       ├── Incident counts by severity                        │
│       ├── MTTR / MTTA by category                            │
│       ├── Detection coverage changes                         │
│       ├── Alert volume trends                                │
│       └── Top triggered rules                                │
│       │                                                      │
│       ▼                                                      │
│  Copilot: Generate narrative                                 │
│       (convert raw metrics to analyst-friendly prose)         │
│       │                                                      │
│       ▼                                                      │
│  Copilot: Create executive summary                           │
│       (3-5 bullet points for leadership)                     │
│       │                                                      │
│       ▼                                                      │
│  Copilot: Identify trends & recommendations                  │
│       (week-over-week comparison, action items)              │
│       │                                                      │
│       ▼                                                      │
│  Deploy:                                                     │
│       ├── Sentinel Workbook (interactive)                    │
│       ├── Email report (HTML)                                │
│       └── Teams notification (summary)                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

```powershell
function Invoke-SecOpsWeeklyReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceId,
        [int]$LookbackDays = 7,
        [string]$ReportRecipient
    )

    $session = New-SecOpsCopilotSession -Description "Weekly Report $(Get-Date -Format 'yyyy-MM-dd')"

    # Collect metrics via KQL
    $incidentQuery = @"
SecurityIncident
| where TimeGenerated > ago($($LookbackDays)d)
| summarize
    TotalIncidents = count(),
    Critical = countif(Severity == "High"),
    Medium = countif(Severity == "Medium"),
    Low = countif(Severity == "Low"),
    AvgClosureHours = avg(datetime_diff('hour', ClosedTime, CreatedTime)),
    AutoClosed = countif(Classification == "FalsePositive")
"@

    $alertQuery = @"
SecurityAlert
| where TimeGenerated > ago($($LookbackDays)d)
| summarize AlertCount = count() by AlertName, AlertSeverity
| top 10 by AlertCount desc
"@

    $incidents = Invoke-SecOpsSentinelQuery -WorkspaceId $WorkspaceId -Query $incidentQuery
    $topAlerts = Invoke-SecOpsSentinelQuery -WorkspaceId $WorkspaceId -Query $alertQuery

    # Generate narrative
    if ($session.ok) {
        $narrativePrompt = @"
Generate a weekly SOC operations report narrative from these metrics:

Period: Last $LookbackDays days
$($incidents.data | ConvertTo-Json)

Top Alerts:
$($topAlerts.data | ConvertTo-Json)

Include: 1) Operational summary, 2) Key metrics with context, 3) Notable trends
"@
        $narrative = Invoke-SecOpsCopilotPrompt -SessionId $session.data.sessionId -Prompt $narrativePrompt

        $execPrompt = "Create a 5-bullet executive summary of the report we just generated. Focus on risk posture changes and required leadership decisions."
        $execSummary = Invoke-SecOpsCopilotPrompt -SessionId $session.data.sessionId -Prompt $execPrompt

        $trendPrompt = "Compare this week's data to typical baselines. Identify 3 trends and provide specific recommendations for each."
        $trends = Invoke-SecOpsCopilotPrompt -SessionId $session.data.sessionId -Prompt $trendPrompt
    }

    return @{
        ok             = $true
        period         = "$LookbackDays days ending $(Get-Date -Format 'yyyy-MM-dd')"
        metrics        = $incidents.data
        topAlerts      = $topAlerts.data
        narrative      = $narrative?.data
        execSummary    = $execSummary?.data
        trends         = $trends?.data
    }
}
```

## Section 3: SCU Cost Management

### Understanding SCU Consumption

| Operation | Approx SCU Cost | Notes |
|---|---|---|
| Simple prompt | 0.5-1 SCU | Short context, single question |
| Incident summary | 1-2 SCU | Medium context with entity extraction |
| Script analysis | 2-4 SCU | Large input, detailed output |
| Promptbook (4 steps) | 3-6 SCU | Cumulative per step |
| Hunt iteration | 1-3 SCU | Varies with findings volume |

### Budget Threshold Configuration

```yaml
# .secops/environment.yaml — SCU cost management
copilot_for_security:
  provisioned: true
  scu_count: 3
  region: eastus

  cost_management:
    monthly_budget_usd: 5000
    daily_scu_limit: 50           # Throttle after this daily consumption
    per_workflow_limit: 10         # Max SCU per single workflow execution
    alert_threshold_percent: 80   # Alert at 80% of monthly budget
    fallback_on_exhaustion: true   # Use non-AI path when SCUs exhausted
```

### SCU Tracking Function

```powershell
function Get-SecOpsCopilotSCUUsage {
    [CmdletBinding()]
    param(
        [string]$CapacityName,
        [int]$LookbackHours = 24
    )

    $ep = (Get-SecOpsCloudEndpoints -CloudType (Get-SecOpsCloudType)).endpoints

    $usage = Invoke-RestMethod -Uri "$($ep.CopilotAPI)/v1/usage" `
        -Headers @{ Authorization = "Bearer $token" } `
        -Method GET

    return @{
        ok         = $true
        scuUsed    = $usage.scuConsumed
        scuTotal   = $usage.scuProvisioned
        remaining  = $usage.scuProvisioned - $usage.scuConsumed
        pctUsed    = [math]::Round(($usage.scuConsumed / $usage.scuProvisioned) * 100, 1)
    }
}
```

### Fallback to Non-AI Path

When SCUs are exhausted or Copilot is unavailable:

```powershell
function Invoke-SecOpsCopilotPromptWithFallback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string]$SessionId,
        [scriptblock]$FallbackAction
    )

    # Check SCU budget
    $usage = Get-SecOpsCopilotSCUUsage
    if ($usage.ok -and $usage.pctUsed -ge 95) {
        Write-Warning "SCU budget nearly exhausted ($($usage.pctUsed)%). Using fallback path."
        if ($FallbackAction) { return & $FallbackAction }
        return @{ ok = $false; error = "SCU budget exhausted"; fallback = $true }
    }

    # Check cloud availability (GCC High/DoD/China → no Copilot)
    $cloud = Get-SecOpsCloudType
    if ($cloud -in @('gcc_high', 'dod', 'china')) {
        Write-Warning "Copilot for Security not available in $cloud. Using fallback path."
        if ($FallbackAction) { return & $FallbackAction }
        return @{ ok = $false; error = "Copilot unavailable in $cloud"; fallback = $true }
    }

    # Attempt Copilot prompt
    $result = Invoke-SecOpsCopilotPrompt -SessionId $SessionId -Prompt $Prompt
    if (-not $result.ok -and $FallbackAction) {
        Write-Warning "Copilot call failed: $($result.error). Using fallback."
        return & $FallbackAction
    }

    return $result
}
```

### Cost Optimization Patterns

| Pattern | Savings | Implementation |
|---|---|---|
| **Session reuse** | 20-30% | Reuse Copilot session across related prompts (accumulated context avoids re-explaining) |
| **Batch prompts** | 15-25% | Combine multiple small questions into one structured prompt |
| **Cache responses** | 30-50% | Cache TI enrichment results for recurring IOCs (24h TTL) |
| **Truncate input** | 10-20% | Limit script/log input to first 4KB; summarize large datasets before feeding |
| **Skip known FPs** | Variable | Don't send known false-positive patterns to Copilot; auto-close locally |

```powershell
# Response cache for TI enrichment (avoids re-querying same IOCs)
$script:CopilotTICache = @{}

function Get-SecOpsCachedTIEnrichment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Indicator,
        [Parameter(Mandatory)][string]$SessionId,
        [int]$CacheTTLHours = 24
    )

    $cacheKey = $Indicator.ToLower()
    $cached = $script:CopilotTICache[$cacheKey]

    if ($cached -and ((Get-Date) - $cached.timestamp).TotalHours -lt $CacheTTLHours) {
        return @{ ok = $true; data = $cached.data; source = "cache" }
    }

    $result = Invoke-SecOpsCopilotTIEnrichment -Indicators @($Indicator) -SessionId $SessionId
    if ($result.ok) {
        $script:CopilotTICache[$cacheKey] = @{ data = $result.data; timestamp = Get-Date }
    }

    return @{ ok = $result.ok; data = $result.data; source = "copilot" }
}
```

## Section 4: PowerShell Integration — Core Copilot API Functions

### Session Management

```powershell
function New-SecOpsCopilotSession {
    [CmdletBinding()]
    param(
        [string]$Description = "SecOps Agent Session"
    )

    $ep = (Get-SecOpsCloudEndpoints -CloudType (Get-SecOpsCloudType)).endpoints
    if (-not $ep.CopilotAPI) {
        return @{ ok = $false; error = "Copilot for Security not available in current cloud" }
    }

    $body = @{ description = $Description } | ConvertTo-Json
    try {
        $response = Invoke-RestMethod -Uri "$($ep.CopilotAPI)/v1/sessions" `
            -Headers @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' } `
            -Method POST -Body $body
        return @{ ok = $true; data = @{ sessionId = $response.sessionId; scuUsed = 0 } }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message; status = $_.Exception.Response.StatusCode.value__ }
    }
}
```

### Prompt Execution

```powershell
function Invoke-SecOpsCopilotPrompt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SessionId,
        [Parameter(Mandatory)][string]$Prompt,
        [string[]]$Plugins,
        [int]$TimeoutSeconds = 120
    )

    $ep = (Get-SecOpsCloudEndpoints -CloudType (Get-SecOpsCloudType)).endpoints

    $body = @{
        sessionId = $SessionId
        prompt    = $Prompt
    }
    if ($Plugins) { $body.plugins = $Plugins }
    $bodyJson = $body | ConvertTo-Json -Depth 5

    try {
        $response = Invoke-RestMethod -Uri "$($ep.CopilotAPI)/v1/sessions/$SessionId/prompts" `
            -Headers @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' } `
            -Method POST -Body $bodyJson -TimeoutSec $TimeoutSeconds

        return @{
            ok   = $true
            data = $response.content
            scuConsumed = $response.scuConsumed
            promptId    = $response.promptId
        }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message; status = $_.Exception.Response.StatusCode.value__ }
    }
}
```

## Section 5: `.secops/` Integration

### Full Copilot Workflow Configuration

```yaml
# .secops/environment.yaml — Copilot for Security workflow settings
copilot_for_security:
  provisioned: true
  capacity_name: "soc-copilot-capacity"
  scu_count: 3
  region: "eastus"

  # Plugin enablement
  plugins:
    microsoft_sentinel: { enabled: true, workspace_ref: "workspaces/production.yaml" }
    microsoft_defender_xdr: { enabled: true }
    microsoft_entra: { enabled: true }
    threat_intelligence: { enabled: true }
    natural_language_kql: { enabled: true }

  # Custom plugins
  custom_plugins:
    - name: "InternalThreatIntel"
      manifest_url: "https://ti-api.contoso.com/copilot-manifest.yaml"

  # Workflow-specific SCU budgets
  workflows:
    incident_triage:
      enabled: true
      max_scu_per_run: 5
      auto_close_fp: true
      confidence_threshold: 80
    threat_hunt:
      enabled: true
      max_scu_per_run: 10
      max_iterations: 3
    weekly_report:
      enabled: true
      max_scu_per_run: 8
      schedule: "0 8 * * MON"      # Monday 8 AM
      recipients:
        - "soc-leads@contoso.com"

  # Cost management
  cost_management:
    monthly_budget_usd: 5000
    daily_scu_limit: 50
    alert_threshold_percent: 80
    fallback_on_exhaustion: true

  # Availability note
  availability:
    commercial: true
    gcc: true
    gcc_high: false     # Planned; check gov-cloud-support.md for updates
    dod: false
    china: false
```

### Cloud Availability Guard

Agents must check cloud availability before attempting any Copilot workflow:

```powershell
function Test-SecOpsCopilotAvailable {
    <#
    .SYNOPSIS
        Pre-flight check for Copilot for Security availability.
    .DESCRIPTION
        Reads .secops/ config to determine if Copilot is available,
        provisioned, and within SCU budget.
    #>
    [CmdletBinding()]
    param()

    $config = Get-SecOpsConfig
    $cloud = $config.organization.cloud -replace 'azure-', ''

    # Cloud availability check
    $available = $cloud -in @('commercial', 'gcc')
    if (-not $available) {
        return @{
            ok        = $true
            available = $false
            reason    = "Copilot for Security not available in $cloud. See gov-cloud-support.md"
        }
    }

    # Provisioning check
    if (-not $config.copilot_for_security.provisioned) {
        return @{
            ok        = $true
            available = $false
            reason    = "Copilot for Security not provisioned. Set copilot_for_security.provisioned: true"
        }
    }

    return @{
        ok        = $true
        available = $true
        scuCount  = $config.copilot_for_security.scu_count
        region    = $config.copilot_for_security.region
    }
}
```

## Section 6: Error Handling & Graceful Degradation

### Copilot-Specific Error Codes

| HTTP Status | Error | Handling |
|---|---|---|
| `429` | SCU rate limit | Exponential backoff; if persistent, check daily limit |
| `403` | Permission denied | Verify Copilot Owner/Contributor RBAC |
| `404` | Session expired | Create new session; sessions timeout after 30 min idle |
| `500` | Service error | Retry once; if persistent, activate fallback path |
| `503` | Service unavailable | Copilot capacity at limit; queue and retry later |

### Fallback Decision Matrix

| Scenario | Primary Path | Fallback Path |
|---|---|---|
| Incident summary unavailable | Copilot summarization | Structured entity extraction (KQL-only) |
| TI enrichment unavailable | Copilot TI analysis | Direct MDTI API query |
| Script analysis unavailable | Copilot deobfuscation | Static regex pattern matching |
| KQL generation unavailable | Copilot NL2KQL | Template-based query builder (see `query-builder.md`) |
| Report generation unavailable | Copilot narrative | Metrics-only report with tabular data |

## References

- `copilot-for-security.md` — SCU capacity planning, plugin development, promptbooks, REST API details
- `cross-skill-orchestration.md` — Pipeline patterns and error handling for multi-skill workflows
- `gov-cloud-support.md` — Cloud-specific feature availability including Copilot
- `sentinel-api-wrapper.md` — Sentinel API functions used in workflow examples
- `defender-api-wrapper.md` — Defender API functions for entity enrichment
- `error-handling.md` — Structured result pattern (`{ok/error}`) used throughout
- [Copilot for Security API Documentation](https://learn.microsoft.com/en-us/security-copilot/api-overview)
- [Copilot for Security SCU Management](https://learn.microsoft.com/en-us/security-copilot/manage-usage)
