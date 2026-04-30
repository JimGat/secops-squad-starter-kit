---
title: Microsoft Copilot for Security Integration
category: msft-security
difficulty: advanced
mitre_attack:
  - T1059   # Command and Scripting Interpreter (script analysis)
  - T1078   # Valid Accounts (identity investigation)
  - T1566   # Phishing (incident summarization)
  - T1190   # Exploit Public-Facing Application (vuln context)
  - T1071   # Application Layer Protocol (TI enrichment)
  - T1003   # OS Credential Dumping (incident triage)
products:
  - Microsoft Copilot for Security
  - Microsoft Sentinel
  - Microsoft Defender XDR
  - Microsoft Defender for Endpoint
  - Microsoft Intune
  - Microsoft Entra ID
  - Microsoft Purview
author: Kima
version: 1.0.0
last_updated: 2026-04-30
---

# Microsoft Copilot for Security Integration

## Overview

Microsoft Copilot for Security is a generative AI-powered security product that augments SOC workflows with natural language investigation, incident summarization, threat intelligence enrichment, and guided response. It operates as a **standalone portal** (`securitycopilot.microsoft.com`) and as an **embedded experience** within Defender XDR, Sentinel, Intune, Entra, and Purview.

Use this skill when:
- Integrating Copilot for Security into agent-driven investigation workflows
- Building custom plugins or promptbooks for repeatable SOC processes
- Planning Security Compute Unit (SCU) capacity
- Calling Copilot APIs programmatically from PowerShell or automation

### Standalone vs. Embedded

| Mode | Access Point | Best For |
|---|---|---|
| **Standalone** | `securitycopilot.microsoft.com` | Free-form investigation, promptbook execution, custom plugin dev |
| **Embedded** | Defender XDR, Sentinel, Intune, Entra, Purview | Contextual analysis inline during existing workflows |

## Environment Context

Before using Copilot for Security, check `.secops/`:

1. **`.secops/environment.yaml`** — Verify SCU capacity allocation and region
2. **`.secops/identity/tenants.yaml`** — Copilot runs in home tenant; cross-tenant requires delegation
3. **`.secops/workspaces/*.yaml`** — Sentinel workspace context for Copilot's Sentinel plugin
4. **`.secops/identity/rbac-conventions.yaml`** — Copilot Owner vs Copilot Contributor roles

## Section 1: Security Compute Units (SCU)

SCUs are the capacity metric for Copilot for Security. Every prompt, plugin invocation, and promptbook execution consumes SCUs.

| Workload Profile | SCUs | Use Case |
|---|---|---|
| **Evaluation/POC** | 1 | Testing, familiarization |
| **Small SOC (1-5 analysts)** | 3 | Daily incident triage, ad-hoc investigation |
| **Medium SOC (5-15 analysts)** | 6-10 | Continuous triage, promptbook automation |
| **Large SOC / MSSP** | 10+ | High-volume automated workflows |

### Provisioning via Bicep

```bicep
resource copilotCapacity 'Microsoft.SecurityCopilot/capacities@2024-11-01' = {
  name: 'soc-copilot-capacity'
  location: 'eastus'
  properties: {
    numberOfUnits: 3
    crossGeoCompute: 'NotAllowed'
    geo: 'US'
  }
  sku: { name: 'SCU' }
}
```

### `.secops/` SCU Configuration

```yaml
# .secops/environment.yaml
copilot_for_security:
  provisioned: true
  capacity_name: soc-copilot-capacity
  scu_count: 3
  region: eastus
  cross_geo_compute: false
  monthly_budget_alert_usd: 5000
```

## Section 2: Built-in Plugins

| Plugin | Key Capabilities | Required License |
|---|---|---|
| **Microsoft Sentinel** | Incident summary, KQL hunting, watchlists | Sentinel |
| **Microsoft Defender XDR** | Incident triage, device timeline, alert correlation | M365 E5 / Defender P2 |
| **Defender for Endpoint** | Device posture, vulnerability context | MDE P2 |
| **Defender for Cloud** | Security recommendations, secure score | Defender for Cloud |
| **Microsoft Intune** | Device compliance, policy status | Intune P1 |
| **Microsoft Entra** | User risk, sign-in logs, CA evaluation | Entra ID P2 |
| **Microsoft Purview** | DLP alerts, sensitivity labels | Purview |
| **Threat Intelligence** | IoC enrichment, threat articles | MDTI |
| **Natural Language to KQL** | Convert questions to KQL queries | Sentinel |

```yaml
# .secops/environment.yaml — plugin configuration
copilot_for_security:
  plugins:
    microsoft_sentinel: { enabled: true, workspace_ref: "workspaces/production.yaml" }
    microsoft_defender_xdr: { enabled: true }
    microsoft_entra: { enabled: true }
    threat_intelligence: { enabled: true }
    microsoft_purview: { enabled: false }   # Not licensed
```

## Section 3: Custom Plugins

Custom plugins extend Copilot with proprietary data sources via OpenAPI specs.

### Plugin Manifest

```yaml
Descriptor:
  Name: ContosoThreatIntel
  DisplayName: Contoso Threat Intelligence
  Description: Enriches indicators with internal threat intelligence
  PluginType: API
  Authorization:
    Type: AADDelegated
    AadAuthority: https://login.microsoftonline.com/contoso.onmicrosoft.com
    ClientId: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    Scopes: api://contoso-ti-api/.default
OpenApi: https://ti-api.contoso.com/openapi.json
```

### OpenAPI Requirements

```yaml
openapi: 3.0.1
info: { title: Contoso Threat Intel API, version: "1.0" }
paths:
  /api/indicators/{indicator}:
    get:
      operationId: LookupIndicator
      summary: Look up an IoC in Contoso's threat intel database
      x-openai-isConsequential: false
      parameters:
        - name: indicator
          in: path
          required: true
          schema: { type: string }
```

### Authentication Options

| Auth Type | Use Case |
|---|---|
| `AADDelegated` | Internal APIs behind Entra ID |
| `OAuthAuthorizationCode` | Third-party integrations |
| `APIKey` | Simple external APIs |

## Section 4: Promptbooks

Promptbooks are multi-step prompt chains that execute sequentially, passing context between steps.

### Example Promptbook

```yaml
Name: Suspicious Sign-in Investigation
Tags: [incident-response, identity, T1078]
Parameters:
  - Name: UserPrincipalName
    Required: true
Steps:
  - Prompt: "Get risk detections and sign-in activity for <UserPrincipalName> from last 7 days."
  - Prompt: "Check user's device compliance status in Intune for policy violations."
  - Prompt: "Search Defender XDR for alerts involving <UserPrincipalName> in last 30 days."
  - Prompt: "Provide risk assessment: no action / password reset / revoke sessions / escalate."
```

### Built-in Promptbooks

| Promptbook | Plugins Used |
|---|---|
| Incident Investigation | Defender XDR, Sentinel |
| Vulnerability Impact Assessment | MDE, Defender for Cloud |
| Suspicious Script Analysis | NL2KQL, Defender XDR |
| Threat Actor Profile | Threat Intelligence |
| User Compromise Assessment | Entra, Intune, Defender XDR |

## Section 5: REST API Patterns

### Authentication

```powershell
$token = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -Method POST -Body @{
        client_id = $clientId; client_secret = $clientSecret
        scope = 'https://api.securitycopilot.microsoft.com/.default'
        grant_type = 'client_credentials'
    }).access_token
$headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
```

### Session Management and Prompt Evaluation

```powershell
# Create session
$session = Invoke-RestMethod -Uri 'https://api.securitycopilot.microsoft.com/sessions' `
    -Method POST -Headers $headers -Body (@{ title = "Incident #12345" } | ConvertTo-Json)

# Submit prompt (async — must poll for response)
$prompt = Invoke-RestMethod -Uri "https://api.securitycopilot.microsoft.com/sessions/$($session.sessionId)/prompts" `
    -Method POST -Headers $headers -Body (@{
        content = "Summarize Sentinel incident #12345 with all related alerts and entities"
        plugins = @("Microsoft Sentinel", "Microsoft Defender XDR")
    } | ConvertTo-Json)

# Poll for completion
do {
    Start-Sleep -Seconds 5
    $result = Invoke-RestMethod -Uri "https://api.securitycopilot.microsoft.com/sessions/$($session.sessionId)/prompts/$($prompt.promptId)" `
        -Method GET -Headers $headers
} while ($result.state -eq 'Running')
```

### Plugin and Promptbook Management

```powershell
# List/enable plugins
$plugins = Invoke-RestMethod -Uri 'https://api.securitycopilot.microsoft.com/plugins' -Method GET -Headers $headers
Invoke-RestMethod -Uri "https://api.securitycopilot.microsoft.com/plugins/$pluginId/enable" -Method POST -Headers $headers

# Execute promptbook
$execution = Invoke-RestMethod -Uri 'https://api.securitycopilot.microsoft.com/promptbooks/run' `
    -Method POST -Headers $headers -Body (@{
        promptbookId = $promptbookId
        parameters = @{ UserPrincipalName = "john.doe@contoso.com" }
    } | ConvertTo-Json)
```

## Section 6: Agent Integration Patterns

### Pattern 1: Incident Summarization

```powershell
function Get-CopilotIncidentSummary {
    param([string]$IncidentId, [string]$SessionId)
    $prompt = @{
        content = @"
Summarize Sentinel incident $IncidentId:
1. Severity and classification confidence
2. Related alerts with timestamps
3. Affected entities (users, devices, IPs)
4. MITRE ATT&CK techniques
5. Recommended immediate response actions
"@
        plugins = @("Microsoft Sentinel", "Microsoft Defender XDR")
    }
    Invoke-RestMethod -Uri "https://api.securitycopilot.microsoft.com/sessions/$SessionId/prompts" `
        -Method POST -Headers $script:headers -Body ($prompt | ConvertTo-Json)
}
```

### Pattern 2: Threat Intelligence Enrichment

```powershell
function Get-CopilotIoCEnrichment {
    param([string]$Indicator, [string]$SessionId)
    $prompt = @{
        content = "Enrich indicator $Indicator — reputation, first/last seen, threat actors, campaigns, MITRE techniques."
        plugins = @("Threat Intelligence", "Microsoft Defender XDR")
    }
    Invoke-RestMethod -Uri "https://api.securitycopilot.microsoft.com/sessions/$SessionId/prompts" `
        -Method POST -Headers $script:headers -Body ($prompt | ConvertTo-Json)
}
```

### Pattern 3: Script Analysis (T1059)

```powershell
function Invoke-CopilotScriptAnalysis {
    param([string]$EncodedScript, [string]$SessionId)
    $prompt = @{
        content = @"
Analyze this script: $EncodedScript
Provide: decoded version, step-by-step behavior, IoCs, MITRE mapping, risk assessment.
"@
    }
    Invoke-RestMethod -Uri "https://api.securitycopilot.microsoft.com/sessions/$SessionId/prompts" `
        -Method POST -Headers $script:headers -Body ($prompt | ConvertTo-Json)
}
```

### Pattern 4: Guided Investigation Workflow

```powershell
function Start-CopilotGuidedInvestigation {
    param([string]$IncidentId)
    $session = New-CopilotSession -Title "Investigation: Incident $IncidentId"
    $sid = $session.sessionId

    # Step 1: Summary
    Submit-CopilotPrompt -SessionId $sid -Content "Summarize Sentinel incident $IncidentId with full entity extraction."
    # Step 2: Entity enrichment (context carries from step 1)
    Submit-CopilotPrompt -SessionId $sid -Content "For each entity: check Entra risk, Intune compliance, MDE alerts, IP reputation."
    # Step 3: Timeline
    Submit-CopilotPrompt -SessionId $sid -Content "Build chronological attack timeline. Map to MITRE ATT&CK."
    # Step 4: Response recommendation
    Submit-CopilotPrompt -SessionId $sid -Content "Confidence level, containment actions, evidence preservation, stakeholder comms template."
}
```

## Section 7: Rate Limits and Best Practices

| Endpoint | Limit |
|---|---|
| Session creation | 10/min |
| Prompt submission | 20/min |
| Plugin management | 30/min |
| Promptbook execution | 10/min |

### SCU Best Practices

1. **Reuse sessions** — new sessions waste context-building SCU
2. **Be specific** — vague prompts invoke broader plugin chains, consuming more SCU
3. **Use promptbooks** — pre-defined chains are optimized
4. **Enable only needed plugins** — each enabled plugin increases evaluation cost
5. **Monitor via Azure Monitor** — alert when consumption exceeds thresholds

### Error Handling (Structured Result Pattern)

```powershell
function Invoke-CopilotWithRetry {
    param([scriptblock]$Action, [int]$MaxRetries = 3)
    for ($i = 0; $i -lt $MaxRetries; $i++) {
        try {
            $result = & $Action
            if ($result.state -eq 'Failed') {
                if ($result.error -match 'capacity') { Start-Sleep 60; continue }
                return @{ ok = $false; error = $result.error }
            }
            return @{ ok = $true; data = $result }
        } catch {
            if ($_.Exception.Response.StatusCode -eq 429) {
                Start-Sleep -Seconds ([int]($_.Exception.Response.Headers['Retry-After'] ?? 30))
                continue
            }
            return @{ ok = $false; error = $_.Exception.Message }
        }
    }
    return @{ ok = $false; error = "Max retries exhausted" }
}
```

## Section 8: MITRE ATT&CK Coverage

| Tactic | Copilot Capability | Primary Plugin |
|---|---|---|
| **Initial Access** (TA0001) | Phishing analysis, exploit context | Defender XDR, TI |
| **Execution** (TA0002) | Script deobfuscation, command analysis | NL2KQL, Defender XDR |
| **Persistence** (TA0003) | Scheduled task/registry detection | MDE, Sentinel |
| **Privilege Escalation** (TA0004) | Token/permission abuse | Entra, MDE |
| **Defense Evasion** (TA0005) | Encoded script analysis | Defender XDR |
| **Credential Access** (TA0006) | Credential dump analysis | Entra, MDI |
| **Lateral Movement** (TA0008) | RDP/SMB/WMI correlation | MDE, Defender XDR |
| **Exfiltration** (TA0010) | Data transfer anomaly analysis | Purview, MDCA |

## Related Skills

- **[Sentinel MCP Server](sentinel-mcp-server.md)** — MCP-based Sentinel operations complementing Copilot's NL2KQL
- **[Defender MCP Server](defender-mcp-server.md)** — Direct API operations for actions Copilot recommends
- **[Microsoft Graph Security](microsoft-graph-security.md)** — Graph API patterns used by Copilot plugins
- **[Defender XDR Configuration](defender-xdr-configuration.md)** — XDR settings affecting Copilot's embedded experience
- **[Entra ID Protection](entra-id-protection.md)** — Identity signals feeding Copilot's user risk assessments
