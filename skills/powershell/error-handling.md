---
title: PowerShell Error Handling Patterns
category: powershell
difficulty: intermediate
mitre_attack:
  - T1562  # Impair Defenses (error handling gaps can mask security events)
  - T1059.001  # Command and Scripting Interpreter: PowerShell
products:
  - Azure PowerShell
  - Microsoft Graph API
  - Azure REST API
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# PowerShell Error Handling Patterns

## Overview

Security operations code runs in high-stakes environments — missed errors can mean missed alerts, failed incident response, or incomplete forensic collection. This skill covers structured error handling for REST API calls, retry logic with exponential backoff, HTTP 429 throttling detection, audit-grade logging, and common Microsoft Security API error codes with remediation steps.

Use this skill when:
- Wrapping Microsoft Security REST API calls in PowerShell functions
- Building unattended automation that must handle transient failures
- Implementing retry logic for API rate limiting
- Creating audit trails for compliance and forensic purposes
- Diagnosing common API error codes from Sentinel, Defender, or Graph

## Prerequisites

| Requirement | Detail |
|---|---|
| **PowerShell** | 7.4+ (for `Invoke-RestMethod` improvements) |
| **Knowledge** | HTTP status codes, REST API patterns, PowerShell error handling |
| **Context** | Understanding of Microsoft API throttling behavior |

## Structured Error Wrapping

### The SecOpsResult Pattern

All API-wrapping functions return a structured result object — never throw exceptions for API errors. This aligns with the team's structured result convention (see `decisions.md`).

```powershell
function New-SecOpsResult {
    <#
    .SYNOPSIS
        Creates a standardized result object for API operations.
    #>
    [CmdletBinding()]
    param(
        [switch]$Success,
        [object]$Data,
        [string]$Error,
        [int]$StatusCode,
        [string]$ErrorCode,
        [string]$RequestId
    )

    [PSCustomObject]@{
        PSTypeName = 'SecOps.Result'
        Ok         = [bool]$Success
        Data       = $Data
        Error      = $Error
        StatusCode = $StatusCode
        ErrorCode  = $ErrorCode
        RequestId  = $RequestId
        Timestamp  = [DateTimeOffset]::UtcNow
    }
}
```

### Wrapping REST Calls

```powershell
function Invoke-SecOpsRestMethod {
    <#
    .SYNOPSIS
        Wraps Invoke-RestMethod with structured error handling, retry, and logging.
    .DESCRIPTION
        Central REST wrapper used by all submodules. Handles:
        - Structured result objects (never throws for API errors)
        - Exponential backoff with jitter for transient failures
        - HTTP 429 Retry-After header respect
        - Request/response audit logging
        - Pagination via nextLink
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [object]$Body,

        [hashtable]$Headers = @{},

        [int]$MaxRetries = 3,

        [int]$RetryBaseDelayMs = 1000,

        [int]$TimeoutSec = 30,

        [string]$OperationName = 'REST Call'
    )

    $attempt = 0
    $requestId = [guid]::NewGuid().ToString('N').Substring(0, 8)

    while ($attempt -le $MaxRetries) {
        $attempt++

        try {
            Write-Verbose "[$requestId] $Method $Uri (attempt $attempt/$($MaxRetries + 1))"

            $params = @{
                Uri                = $Uri
                Method             = $Method
                Headers            = $Headers
                ContentType        = 'application/json'
                TimeoutSec         = $TimeoutSec
                StatusCodeVariable = 'statusCode'
                ResponseHeadersVariable = 'responseHeaders'
                ErrorAction        = 'Stop'
            }

            if ($Body) {
                $params.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 10 }
            }

            $response = Invoke-RestMethod @params

            # Log success
            Write-SecOpsAuditLog -RequestId $requestId -Operation $OperationName `
                -Method $Method -Uri $Uri -StatusCode $statusCode -Success

            return New-SecOpsResult -Success -Data $response -StatusCode $statusCode `
                -RequestId $requestId

        }
        catch {
            $ex = $_.Exception
            $httpStatus = 0
            $errorBody = $null

            # Extract HTTP status code from exception
            if ($ex.Response) {
                $httpStatus = [int]$ex.Response.StatusCode
                try {
                    $stream = $ex.Response.GetResponseStream()
                    $reader = [System.IO.StreamReader]::new($stream)
                    $errorBody = $reader.ReadToEnd() | ConvertFrom-Json -ErrorAction SilentlyContinue
                }
                catch { }
            }

            $errorCode = $errorBody.error.code
            $errorMessage = $errorBody.error.message ?? $ex.Message

            # --- Decide: retry or return error ---

            # HTTP 429 — Throttled: respect Retry-After header
            if ($httpStatus -eq 429) {
                $retryAfter = $null
                if ($ex.Response.Headers) {
                    $retryAfter = $ex.Response.Headers['Retry-After'] |
                        Select-Object -First 1
                }
                $waitSec = if ($retryAfter) { [int]$retryAfter } else { 30 }
                $waitSec = [Math]::Min($waitSec, 120)  # Cap at 2 minutes

                Write-Warning "[$requestId] Throttled (429). Waiting $waitSec seconds..."
                Start-Sleep -Seconds $waitSec
                continue
            }

            # Transient errors — retry with exponential backoff
            $transientCodes = @(408, 500, 502, 503, 504)
            if ($httpStatus -in $transientCodes -and $attempt -le $MaxRetries) {
                $delay = $RetryBaseDelayMs * [Math]::Pow(2, $attempt - 1)
                $jitter = Get-Random -Minimum 0 -Maximum ($delay * 0.25)
                $totalDelayMs = $delay + $jitter

                Write-Warning "[$requestId] Transient error ($httpStatus). Retrying in $([int]($totalDelayMs/1000))s..."
                Start-Sleep -Milliseconds $totalDelayMs
                continue
            }

            # Non-retryable error — return structured failure
            Write-SecOpsAuditLog -RequestId $requestId -Operation $OperationName `
                -Method $Method -Uri $Uri -StatusCode $httpStatus `
                -ErrorMessage $errorMessage -ErrorCode $errorCode

            return New-SecOpsResult -Error $errorMessage -StatusCode $httpStatus `
                -ErrorCode $errorCode -RequestId $requestId
        }
    }

    # Exhausted retries
    return New-SecOpsResult -Error "Max retries ($MaxRetries) exhausted for $Method $Uri" `
        -StatusCode 0 -ErrorCode 'RetryExhausted' -RequestId $requestId
}
```

## Retry Logic with Exponential Backoff

### Backoff Strategy

```
Attempt 1: 1s   + jitter (0-250ms)
Attempt 2: 2s   + jitter (0-500ms)
Attempt 3: 4s   + jitter (0-1000ms)
Attempt 4: 8s   + jitter (0-2000ms)  (if MaxRetries >= 4)
```

### Retryable vs Non-Retryable Errors

| Status Code | Meaning | Retry? | Strategy |
|---|---|---|---|
| **408** | Request Timeout | Yes | Exponential backoff |
| **429** | Too Many Requests | Yes | Respect `Retry-After` header |
| **500** | Internal Server Error | Yes | Exponential backoff |
| **502** | Bad Gateway | Yes | Exponential backoff |
| **503** | Service Unavailable | Yes | Exponential backoff |
| **504** | Gateway Timeout | Yes | Exponential backoff |
| **400** | Bad Request | No | Fix request |
| **401** | Unauthorized | No | Re-authenticate |
| **403** | Forbidden | No | Check permissions |
| **404** | Not Found | No | Check resource path |
| **409** | Conflict | No | Resolve conflict, then retry manually |

## Throttling Detection (HTTP 429)

### Microsoft API Throttling Patterns

Microsoft Security APIs apply per-app and per-tenant throttling limits:

| API | Limit | Scope |
|---|---|---|
| **Microsoft Graph** | 10,000 requests / 10 minutes | Per app per tenant |
| **MDE API** | 100 calls / minute (some endpoints) | Per app |
| **Sentinel REST API** | ARM rate limits (1200 reads/5min) | Per subscription |
| **Resource Graph** | 15 requests / 5 seconds | Per tenant |

### Throttle-Aware Batch Processing

```powershell
function Invoke-SecOpsBatchOperation {
    <#
    .SYNOPSIS
        Executes a batch of API operations with throttle-aware pacing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Items,

        [Parameter(Mandatory)]
        [scriptblock]$Operation,

        [int]$BatchSize = 20,

        [int]$DelayBetweenBatchesMs = 2000
    )

    $results = @()
    $batches = [Math]::Ceiling($Items.Count / $BatchSize)

    for ($i = 0; $i -lt $Items.Count; $i += $BatchSize) {
        $batchNum = [Math]::Floor($i / $BatchSize) + 1
        $batch = $Items[$i..([Math]::Min($i + $BatchSize - 1, $Items.Count - 1))]

        Write-Verbose "Processing batch $batchNum/$batches ($($batch.Count) items)"

        foreach ($item in $batch) {
            $result = & $Operation $item
            $results += $result

            # If we got throttled, the wrapper already waited — but add a small delay
            if ($result.StatusCode -eq 429) {
                Start-Sleep -Milliseconds 500
            }
        }

        # Pace between batches to stay under limits
        if ($i + $BatchSize -lt $Items.Count) {
            Start-Sleep -Milliseconds $DelayBetweenBatchesMs
        }
    }

    return $results
}
```

## Audit Logging

### Security Operations Audit Trail

SOC operations require audit trails for compliance and post-incident review. Every API call is logged with request context.

```powershell
function Write-SecOpsAuditLog {
    <#
    .SYNOPSIS
        Writes an audit log entry for a security operation.
    .DESCRIPTION
        Structured JSON log entries for compliance and forensic review.
        Logs are appended to a daily file in the configured audit log path.
    #>
    [CmdletBinding()]
    param(
        [string]$RequestId,
        [string]$Operation,
        [string]$Method,
        [string]$Uri,
        [int]$StatusCode,
        [switch]$Success,
        [string]$ErrorMessage,
        [string]$ErrorCode
    )

    $entry = [ordered]@{
        timestamp   = [DateTimeOffset]::UtcNow.ToString('o')
        request_id  = $RequestId
        operation   = $Operation
        method      = $Method
        uri         = $Uri -replace '\?(.*)', '?<params-redacted>'  # Redact query params
        status_code = $StatusCode
        success     = [bool]$Success
        operator    = $env:USERNAME ?? $env:USER ?? 'unknown'
        hostname    = $env:COMPUTERNAME ?? (hostname)
    }

    if ($ErrorMessage) { $entry.error_message = $ErrorMessage }
    if ($ErrorCode)    { $entry.error_code = $ErrorCode }

    $logDir = $script:Config.AuditLogPath ?? './logs'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

    $logFile = Join-Path $logDir "secops-audit-$(Get-Date -Format 'yyyy-MM-dd').jsonl"
    $entry | ConvertTo-Json -Compress | Out-File -FilePath $logFile -Append -Encoding utf8
}
```

### Log Format (JSONL)

```json
{"timestamp":"2026-04-30T17:08:00+00:00","request_id":"a1b2c3d4","operation":"Get-SecOpsIncident","method":"GET","uri":"https://management.azure.com/.../incidents?<params-redacted>","status_code":200,"success":true,"operator":"socadmin","hostname":"SOC-WS01"}
{"timestamp":"2026-04-30T17:08:05+00:00","request_id":"e5f6g7h8","operation":"Set-SecOpsDeviceIsolation","method":"POST","uri":"https://api.securitycenter.microsoft.com/api/machines/.../isolate?<params-redacted>","status_code":200,"success":true,"operator":"socadmin","hostname":"SOC-WS01"}
```

## Common Microsoft Security API Errors

### Sentinel / SecurityInsights

| Error Code | Status | Cause | Remediation |
|---|---|---|---|
| `WorkspaceNotFound` | 404 | Workspace ID invalid or deleted | Verify workspace ID in `.secops/workspaces/` |
| `InsufficientPermissions` | 403 | Missing Sentinel Contributor/Reader role | Check RBAC assignments |
| `SubscriptionNotRegistered` | 409 | SecurityInsights provider not registered | `Register-AzResourceProvider -ProviderNamespace Microsoft.SecurityInsights` |
| `InvalidQuery` | 400 | KQL syntax error in analytics rule query | Validate with `secops-squad kql validate` |
| `DuplicateRuleName` | 409 | Analytics rule with same name exists | Use unique names or check before creating |

### Defender for Endpoint (MDE)

| Error Code | Status | Cause | Remediation |
|---|---|---|---|
| `Authorization_RequestDenied` | 403 | Missing API permissions in app registration | Grant `Machine.ReadWrite.All` or required scope |
| `BadRequest` | 400 | Invalid device ID or action parameters | Verify device ID format (GUID) |
| `ResourceNotFound` | 404 | Device not found or offboarded | Check device onboarding status |
| `TooManyRequests` | 429 | API rate limit exceeded | Implement retry with `Retry-After` header |
| `AdvancedHuntingQueryTimeout` | 504 | KQL query took too long | Optimize query — add time filters, reduce joins |

### Microsoft Graph

| Error Code | Status | Cause | Remediation |
|---|---|---|---|
| `Authorization_RequestDenied` | 403 | Missing Graph API permissions | Check app registration API permissions |
| `Request_BadRequest` | 400 | Malformed OData query or invalid filter | Check OData syntax, remove unsupported `$filter` |
| `TenantNotFound` | 404 | Tenant ID invalid | Verify tenant ID in `.secops/identity/tenants.yaml` |
| `InvalidAuthenticationToken` | 401 | Token expired or invalid | Re-authenticate — check token cache |
| `ServiceNotAvailable` | 503 | Graph service issue | Retry with exponential backoff |

### Error Handler Helper

```powershell
function Get-SecOpsErrorRemediation {
    <#
    .SYNOPSIS
        Returns remediation guidance for common Microsoft Security API errors.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ErrorCode,

        [int]$StatusCode
    )

    $remediations = @{
        'WorkspaceNotFound'             = 'Verify workspace ID in .secops/workspaces/. Run: secops-squad env status'
        'InsufficientPermissions'       = 'Check RBAC — need Microsoft Sentinel Contributor or equivalent'
        'SubscriptionNotRegistered'     = 'Register provider: Register-AzResourceProvider -ProviderNamespace Microsoft.SecurityInsights'
        'Authorization_RequestDenied'   = 'Check app registration API permissions in Entra ID portal'
        'InvalidAuthenticationToken'    = 'Token expired — run Connect-SecOps to re-authenticate'
        'TooManyRequests'               = 'Throttled — reduce request rate or increase batch delay'
        'ResourceNotFound'              = 'Verify resource exists and you have access'
    }

    $guidance = $remediations[$ErrorCode]
    if (-not $guidance) {
        $guidance = switch ($StatusCode) {
            400 { 'Bad request — check parameters and request body format' }
            401 { 'Unauthorized — re-authenticate with Connect-SecOps' }
            403 { 'Forbidden — check RBAC assignments and API permissions' }
            404 { 'Not found — verify resource ID and subscription context' }
            409 { 'Conflict — resource may already exist or be in a conflicting state' }
            429 { 'Throttled — retry is automatic, but consider reducing request rate' }
            default { 'Check Azure service health and retry the operation' }
        }
    }

    return $guidance
}
```

## Best Practices

1. **Never throw for API errors** — Return `SecOps.Result` objects with `.Ok`, `.Error`, `.StatusCode`
2. **Always retry transient failures** — 408, 500, 502, 503, 504 are retryable
3. **Respect Retry-After** — Never hardcode wait times for 429 responses
4. **Cap retry wait times** — Maximum 120 seconds per retry, maximum 4 retries
5. **Log every API call** — Audit trail is mandatory for SOC operations
6. **Redact sensitive data** — Strip query parameters and request bodies from logs
7. **Include request IDs** — Every operation gets a unique ID for correlation
8. **Fail fast on auth errors** — 401/403 are not retryable without human intervention

## Environment Context

Before implementing error handling, agents MUST consult:

- **`.secops/environment.yaml`** — Cloud environment affects error codes and API behavior
- **`.secops/compliance/requirements.yaml`** — Audit log requirements may mandate specific log formats or retention

## Related Skills

- `skills/powershell/auth-patterns.md` — Authentication errors and token refresh
- `skills/powershell/module-foundation.md` — Module structure for error handling integration
- `skills/msft-security/microsoft-graph-security.md` — Graph API error patterns
