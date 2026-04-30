---
title: Azure Monitor Submodule
category: powershell
difficulty: intermediate
mitre_attack:
  - T1562.001  # Impair Defenses: Disable or Modify Tools
  - T1489      # Service Stop (alerting failure impact)
products:
  - Azure Monitor
  - Azure Action Groups
  - Azure Alert Rules
  - Azure Diagnostic Settings
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# Azure Monitor Submodule

## Overview

The Azure Monitor submodule wraps the `Microsoft.Insights` resource provider — Action Groups for notification routing, Alert Rules for detection, and Diagnostic Settings for log collection. It integrates with `.secops/alerting/routing.yaml` for environment-aware alert configuration.

Use this skill when:
- Creating or managing Action Groups (email, SMS, webhook, Logic App, Azure Function)
- Defining alert rules (metric alerts, log search alerts, activity log alerts)
- Configuring diagnostic settings on Azure resources
- Integrating alert routing with the `.secops/` framework

## Prerequisites

| Requirement | Detail |
|---|---|
| **Az.Monitor** | `Install-Module Az.Monitor` |
| **Permissions** | `Monitoring Contributor` for alert and action group management |
| **Permissions** | `Log Analytics Contributor` for log search alert rules |
| **Workspace** | Log Analytics workspace for log-based alerts |

## REST API Endpoints

| Endpoint | Purpose | API Version |
|---|---|---|
| `.../Microsoft.Insights/actionGroups` | Action group CRUD | `2023-01-01` |
| `.../Microsoft.Insights/scheduledQueryRules` | Log search alert rules | `2023-03-15-preview` |
| `.../Microsoft.Insights/metricAlerts` | Metric alert rules | `2018-03-01` |
| `.../Microsoft.Insights/activityLogAlerts` | Activity log alert rules | `2020-10-01` |
| `.../Microsoft.Insights/diagnosticSettings` | Diagnostic settings | `2021-05-01-preview` |

## Integration with .secops/alerting/routing.yaml

The Azure Monitor submodule reads `.secops/alerting/routing.yaml` to automatically configure alert destinations:

```powershell
function Get-SecOpsAlertRouting {
    <#
    .SYNOPSIS
        Reads alert routing configuration from .secops/alerting/routing.yaml.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $routingFile = Join-Path $script:SecOpsContext.SecOpsPath 'alerting' 'routing.yaml'
    if (-not (Test-Path $routingFile)) {
        Write-Warning "Alert routing config not found: $routingFile"
        return @{
            default_channel           = 'teams://soc-general'
            default_severity_threshold = 'Medium'
            routes                    = @()
        }
    }

    return Get-Content $routingFile -Raw | ConvertFrom-Yaml
}
```

## Key Functions

### New-SecOpsActionGroup — Create an Action Group

```powershell
function New-SecOpsActionGroup {
    <#
    .SYNOPSIS
        Creates an Azure Monitor action group for alert notifications.
    .DESCRIPTION
        Action groups define WHO gets notified and HOW when an alert fires.
        Supports email, SMS, webhook, Logic App, and Azure Function receivers.
    .EXAMPLE
        New-SecOpsActionGroup -Name 'SOC-Critical' -ShortName 'SOCCrit' `
            -EmailReceivers @(@{ Name = 'SOC Team'; Email = 'soc@contoso.com' }) `
            -WebhookReceivers @(@{ Name = 'PagerDuty'; Uri = 'https://events.pagerduty.com/...' })
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateLength(1, 12)]
        [string]$ShortName,

        [string]$ResourceGroupName,

        [hashtable[]]$EmailReceivers = @(),

        [hashtable[]]$SmsReceivers = @(),

        [hashtable[]]$WebhookReceivers = @(),

        [hashtable[]]$LogicAppReceivers = @(),

        [hashtable[]]$AzureFunctionReceivers = @()
    )

    if (-not $ResourceGroupName) {
        $env = $script:SecOpsContext.Environment
        $ResourceGroupName = $env.subscriptions |
            Where-Object { $_.purpose -match 'sentinel|soar' } |
            ForEach-Object { "rg-soc-alerting" } |
            Select-Object -First 1
        if (-not $ResourceGroupName) { $ResourceGroupName = 'rg-soc-alerting' }
    }

    if (-not $PSCmdlet.ShouldProcess($Name, 'Create Action Group')) { return }

    $body = @{
        location   = 'global'
        properties = @{
            groupShortName         = $ShortName
            enabled                = $true
            emailReceivers         = $EmailReceivers | ForEach-Object {
                @{ name = $_.Name; emailAddress = $_.Email; useCommonAlertSchema = $true }
            }
            smsReceivers           = $SmsReceivers | ForEach-Object {
                @{ name = $_.Name; countryCode = ($_.CountryCode ?? '1'); phoneNumber = $_.Phone }
            }
            webhookReceivers       = $WebhookReceivers | ForEach-Object {
                @{ name = $_.Name; serviceUri = $_.Uri; useCommonAlertSchema = $true }
            }
            logicAppReceivers      = $LogicAppReceivers | ForEach-Object {
                @{
                    name            = $_.Name
                    resourceId      = $_.ResourceId
                    callbackUrl     = $_.CallbackUrl
                    useCommonAlertSchema = $true
                }
            }
            azureFunctionReceivers = $AzureFunctionReceivers | ForEach-Object {
                @{
                    name                  = $_.Name
                    functionAppResourceId = $_.FunctionAppResourceId
                    functionName          = $_.FunctionName
                    httpTriggerUrl        = $_.HttpTriggerUrl
                    useCommonAlertSchema  = $true
                }
            }
        }
    }

    $subId = (Get-AzContext).Subscription.Id
    $uri = "https://management.azure.com/subscriptions/$subId" +
           "/resourceGroups/$ResourceGroupName" +
           "/providers/Microsoft.Insights/actionGroups/$Name" +
           "?api-version=2023-01-01"

    $token = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ 'Authorization' = "Bearer $token" }

    return Invoke-SecOpsRestMethod -Uri $uri -Method PUT -Body $body `
        -Headers $headers -OperationName 'New-SecOpsActionGroup'
}
```

### New-SecOpsAlertRule — Create a Log Search Alert Rule

```powershell
function New-SecOpsAlertRule {
    <#
    .SYNOPSIS
        Creates a scheduled log search alert rule in Azure Monitor.
    .DESCRIPTION
        Log search alert rules evaluate a KQL query on a schedule and fire
        when the result meets the threshold condition. Linked to action groups
        for notification delivery.
    .EXAMPLE
        New-SecOpsAlertRule -Name 'High-Severity Incidents' `
            -Description 'Fires when new high-severity Sentinel incidents are created' `
            -Query "SecurityIncident | where Severity == 'High' and Status == 'New'" `
            -Severity 1 -ActionGroupId '/subscriptions/.../actionGroups/SOC-Critical' `
            -EvaluationFrequency 'PT5M' -WindowSize 'PT5M'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Description = '',

        [Parameter(Mandatory)]
        [string]$Query,

        [ValidateRange(0, 4)]
        [int]$Severity = 2,

        [Parameter(Mandatory)]
        [string]$ActionGroupId,

        [string]$EvaluationFrequency = 'PT5M',

        [string]$WindowSize = 'PT5M',

        [int]$Threshold = 0,

        [string]$ResourceGroupName,

        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName

    if (-not $ResourceGroupName) { $ResourceGroupName = $ctx.ResourceGroup }

    if (-not $PSCmdlet.ShouldProcess($Name, 'Create Log Alert Rule')) { return }

    $workspaceResourceId = "/subscriptions/$($ctx.SubscriptionId)" +
                           "/resourceGroups/$($ctx.ResourceGroup)" +
                           "/providers/Microsoft.OperationalInsights/workspaces/$($ctx.WorkspaceName)"

    $body = @{
        location   = $ctx.Region
        properties = @{
            description          = $Description
            severity             = $Severity
            enabled              = $true
            evaluationFrequency  = $EvaluationFrequency
            windowSize           = $WindowSize
            scopes               = @($workspaceResourceId)
            criteria             = @{
                allOf = @(
                    @{
                        query           = $Query
                        timeAggregation = 'Count'
                        operator        = 'GreaterThan'
                        threshold       = $Threshold
                        failingPeriods  = @{
                            numberOfEvaluationPeriods = 1
                            minFailingPeriodsToAlert  = 1
                        }
                    }
                )
            }
            actions = @{
                actionGroups = @($ActionGroupId)
            }
        }
    }

    $uri = "https://management.azure.com/subscriptions/$($ctx.SubscriptionId)" +
           "/resourceGroups/$ResourceGroupName" +
           "/providers/Microsoft.Insights/scheduledQueryRules/$Name" +
           "?api-version=2023-03-15-preview"

    $token = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ 'Authorization' = "Bearer $token" }

    return Invoke-SecOpsRestMethod -Uri $uri -Method PUT -Body $body `
        -Headers $headers -OperationName 'New-SecOpsAlertRule'
}
```

### Set-SecOpsDiagnosticSetting — Configure Diagnostic Settings

```powershell
function Set-SecOpsDiagnosticSetting {
    <#
    .SYNOPSIS
        Creates or updates a diagnostic setting on an Azure resource.
    .DESCRIPTION
        Routes platform logs and metrics from any Azure resource to a
        Log Analytics workspace, Event Hub, or Storage Account.
    .EXAMPLE
        Set-SecOpsDiagnosticSetting -ResourceId '/subscriptions/.../keyVaults/prod-kv' `
            -Name 'SendToSentinel' -Categories @('AuditEvent', 'AzurePolicyEvaluationDetails')
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceId,

        [Parameter(Mandatory)]
        [string]$Name,

        [string[]]$Categories = @(),

        [switch]$AllLogs,

        [switch]$AllMetrics,

        [string]$WorkspaceName
    )

    $ctx = Get-SentinelContext -WorkspaceName $WorkspaceName
    $workspaceResourceId = "/subscriptions/$($ctx.SubscriptionId)" +
                           "/resourceGroups/$($ctx.ResourceGroup)" +
                           "/providers/Microsoft.OperationalInsights/workspaces/$($ctx.WorkspaceName)"

    if (-not $PSCmdlet.ShouldProcess("$ResourceId -> $($ctx.WorkspaceName)", 'Set Diagnostic Setting')) {
        return
    }

    $logs = if ($AllLogs) {
        @(@{ categoryGroup = 'allLogs'; enabled = $true })
    }
    else {
        $Categories | ForEach-Object { @{ category = $_; enabled = $true } }
    }

    $body = @{
        properties = @{
            workspaceId = $workspaceResourceId
            logs        = $logs
            metrics     = if ($AllMetrics) { @(@{ category = 'AllMetrics'; enabled = $true }) } else { @() }
        }
    }

    $uri = "$ResourceId/providers/Microsoft.Insights/diagnosticSettings/$Name" +
           "?api-version=2021-05-01-preview"

    $token = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $headers = @{ 'Authorization' = "Bearer $token" }

    return Invoke-SecOpsRestMethod -Uri $uri -Method PUT -Body $body `
        -Headers $headers -OperationName 'Set-SecOpsDiagnosticSetting'
}
```

## Alert Severity Mapping

| Azure Monitor Severity | Sentinel Severity | Typical Use |
|---|---|---|
| **Sev 0** (Critical) | Critical | Active attack, data exfiltration |
| **Sev 1** (Error) | High | Compromised account, malware execution |
| **Sev 2** (Warning) | Medium | Suspicious activity, policy violation |
| **Sev 3** (Informational) | Low | Anomaly, informational alert |
| **Sev 4** (Verbose) | Informational | Audit event, diagnostic info |

## Best Practices

1. **Use Common Alert Schema** — Set `useCommonAlertSchema = $true` on all receivers for consistent payloads
2. **Action group per severity tier** — Separate action groups for Critical vs Informational alerts
3. **Test action groups** — Use `Test-AzActionGroup` or the portal test button before production
4. **Diagnostic settings on all Key Vaults** — AuditEvent category is essential for SOC visibility
5. **Window size ≥ frequency** — Query window must be at least as long as evaluation frequency
6. **Reference .secops/ routing** — Read `routing.yaml` to align programmatic alerts with the routing framework

## Environment Context

Before using Azure Monitor functions, agents MUST consult:

- **`.secops/environment.yaml`** — Primary region and subscription for alert deployment
- **`.secops/alerting/routing.yaml`** — Existing routing rules to avoid duplicate or conflicting alerts
- **`.secops/alerting/escalation.yaml`** — Escalation tiers for action group configuration
- **`.secops/compliance/requirements.yaml`** — Data residency constraints for alert rule placement

## Related Skills

- `skills/soar/logic-apps-playbooks.md` — Logic Apps triggered by action groups
- `skills/log-analytics/diagnostic-settings.md` — Detailed diagnostic settings patterns
- `skills/powershell/sentinel-module.md` — Sentinel analytics rules complement log alerts
- `skills/powershell/error-handling.md` — Error handling for Azure Monitor REST calls
