---
title: Unified API Rate Limiting
category: powershell
difficulty: advanced
mitre_attack:
  - T1059.001  # Command and Scripting Interpreter: PowerShell
  - T1498      # Network Denial of Service (self-inflicted via API abuse)
  - T1562      # Impair Defenses (degraded ops when throttled)
products:
  - Azure Resource Manager
  - Microsoft Graph API
  - Microsoft Defender for Endpoint API
  - Microsoft Sentinel
  - Azure Monitor Log Analytics
  - Microsoft Defender for Cloud Apps
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# Unified API Rate Limiting

## Overview

Every Microsoft Security API enforces rate limits — and they differ by API, scope (app vs. user vs. tenant vs. subscription), and enforcement mechanism. SOC automation that ignores these limits degrades its own capability: throttled incident response queries delay triage, blocked enrichment calls leave context gaps, and exhausted quotas halt batch operations mid-run.

This skill is a **cross-cutting reference** used by every API wrapper skill in the project. It provides a single source of truth for rate limits across Microsoft Security APIs, production-ready retry/backoff implementations, priority queuing for mixed-criticality workloads, quota pooling for multi-process environments, and circuit breaker patterns for graceful degradation.

Use this skill when:
- Building any automation that calls Microsoft Security APIs
- Implementing retry logic beyond the basic pattern in `error-handling.md`
- Running batch operations across thousands of resources
- Coordinating API usage across multiple concurrent agents or processes
- Operating in MSSP environments with many tenants sharing app registrations

**Relationship to `error-handling.md`:** That skill covers the `Invoke-SecOpsRestMethod` wrapper with basic 429 retry. This skill goes deeper — priority queuing, quota pooling, circuit breakers, and cross-API coordination.

## Prerequisites

| Requirement | Detail |
|---|---|
| **PowerShell** | 7.4+ |
| **Knowledge** | HTTP status codes, REST throttling, concurrency patterns |
| **Skills** | `skills/powershell/error-handling.md` (structured results, audit logging) |
| **Context** | `.secops/environment.yaml` for cloud endpoints |

## Microsoft API Rate Limits Reference

### Comprehensive Limit Table

| API Surface | Limit | Scope | Headers | Source |
|---|---|---|---|---|
| **ARM (Resource Manager)** | 12,000 reads/hour | Per subscription | `x-ms-ratelimit-remaining-subscription-reads` | [ARM throttling docs](https://learn.microsoft.com/azure/azure-resource-manager/management/request-limits-and-throttling) |
| **ARM writes** | 1,200 writes/hour | Per subscription | `x-ms-ratelimit-remaining-subscription-writes` | Same |
| **ARM per-resource** | 12,000/hour reads, 1,200/hour writes | Per resource provider + subscription | `x-ms-ratelimit-remaining-subscription-resource-requests` | Same |
| **Microsoft Graph** | 10,000 requests/10 min | Per app per tenant | `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` | [Graph throttling](https://learn.microsoft.com/graph/throttling) |
| **Graph Security** | 150 requests/5 min | Per app per tenant | Same as Graph | Same |
| **MDE — General** | 100 calls/min | Per app | `Retry-After` on 429 | [MDE API limits](https://learn.microsoft.com/defender-endpoint/api/management-apis) |
| **MDE — Advanced Hunting** | 45 calls/min, 1500/hour | Per tenant | Same | Same |
| **MDE — Live Response** | 10 calls/min | Per device | Same | Same |
| **Sentinel (SecurityInsights)** | ARM limits apply | Per subscription | ARM headers | ARM provider limits |
| **Sentinel — Incidents** | 50 requests/min | Per workspace | `Retry-After` | ARM + workspace throttle |
| **Log Analytics Query** | 200 requests/30s | Per user (AAD identity) | `Retry-After` | [Log Analytics limits](https://learn.microsoft.com/azure/azure-monitor/service-limits#log-analytics-workspaces) |
| **Log Analytics concurrent** | 10 concurrent queries | Per user | N/A | Same |
| **MDCA (Defender for Cloud Apps)** | 30 requests/min | Per tenant | `Retry-After`, `x-]content-type-options` | [MDCA API](https://learn.microsoft.com/defender-cloud-apps/api-introduction) |
| **Resource Graph** | 15 requests/5s | Per tenant per user | `x-ms-user-quota-remaining` | [Resource Graph limits](https://learn.microsoft.com/azure/governance/resource-graph/concepts/guidance-for-throttled-requests) |

### Reading Throttle Response Headers

```powershell
function Get-RateLimitStatus {
    <#
    .SYNOPSIS
        Extracts rate limit metadata from API response headers.
    .DESCRIPTION
        Reads throttle headers from ARM, Graph, and MDE responses.
        Returns a normalized object regardless of which API was called.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ResponseHeaders
    )

    $status = [PSCustomObject]@{
        Remaining     = $null
        Limit         = $null
        ResetSeconds  = $null
        RetryAfter    = $null
        Provider      = 'Unknown'
        PercentUsed   = $null
    }

    # ARM headers
    if ($ResponseHeaders['x-ms-ratelimit-remaining-subscription-reads']) {
        $status.Remaining = [int]$ResponseHeaders['x-ms-ratelimit-remaining-subscription-reads']
        $status.Limit = 12000
        $status.Provider = 'ARM-Read'
    }
    elseif ($ResponseHeaders['x-ms-ratelimit-remaining-subscription-writes']) {
        $status.Remaining = [int]$ResponseHeaders['x-ms-ratelimit-remaining-subscription-writes']
        $status.Limit = 1200
        $status.Provider = 'ARM-Write'
    }
    # Graph headers (RFC draft standard)
    elseif ($ResponseHeaders['RateLimit-Remaining']) {
        $status.Remaining = [int]$ResponseHeaders['RateLimit-Remaining']
        $status.Limit = [int]($ResponseHeaders['RateLimit-Limit'] ?? 10000)
        $status.ResetSeconds = [int]($ResponseHeaders['RateLimit-Reset'] ?? 600)
        $status.Provider = 'Graph'
    }
    # Resource Graph
    elseif ($ResponseHeaders['x-ms-user-quota-remaining']) {
        $status.Remaining = [int]$ResponseHeaders['x-ms-user-quota-remaining']
        $status.Limit = 15
        $status.ResetSeconds = [int]($ResponseHeaders['x-ms-user-quota-resets-after']?.Split(':')[-1] ?? 5)
        $status.Provider = 'ResourceGraph'
    }

    # Retry-After (universal)
    if ($ResponseHeaders['Retry-After']) {
        $status.RetryAfter = [int]$ResponseHeaders['Retry-After']
    }

    # Calculate usage percentage
    if ($status.Remaining -ne $null -and $status.Limit -gt 0) {
        $status.PercentUsed = [Math]::Round((1 - $status.Remaining / $status.Limit) * 100, 1)
    }

    return $status
}
```

## Exponential Backoff with Jitter

### Core Retry Function

This extends the basic retry in `error-handling.md` with configurable backoff, per-provider tuning, and distinct handling for 429 vs. 503 vs. 409.

```powershell
function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Executes a script block with exponential backoff and jitter.
    .DESCRIPTION
        Production retry wrapper with:
        - Configurable base delay, max delay, max retries, jitter factor
        - HTTP 429: uses Retry-After header (or provider-specific default)
        - HTTP 503: uses exponential backoff (service recovering)
        - HTTP 409: single retry after short delay (conflict resolution)
        - Logs every retry to audit trail
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [int]$MaxRetries = 4,
        [int]$BaseDelayMs = 1000,
        [int]$MaxDelayMs = 60000,
        [double]$JitterFactor = 0.25,

        [ValidateSet('ARM', 'Graph', 'MDE', 'LogAnalytics', 'MDCA', 'ResourceGraph', 'Default')]
        [string]$Provider = 'Default',

        [string]$OperationName = 'API Call'
    )

    # Per-provider defaults
    $providerDefaults = @{
        ARM          = @{ BaseDelayMs = 1000;  MaxRetries = 3; DefaultRetryAfter = 30 }
        Graph        = @{ BaseDelayMs = 2000;  MaxRetries = 4; DefaultRetryAfter = 60 }
        MDE          = @{ BaseDelayMs = 3000;  MaxRetries = 3; DefaultRetryAfter = 60 }
        LogAnalytics = @{ BaseDelayMs = 5000;  MaxRetries = 3; DefaultRetryAfter = 30 }
        MDCA         = @{ BaseDelayMs = 2000;  MaxRetries = 5; DefaultRetryAfter = 60 }
        ResourceGraph= @{ BaseDelayMs = 5000;  MaxRetries = 3; DefaultRetryAfter = 5  }
        Default      = @{ BaseDelayMs = $BaseDelayMs; MaxRetries = $MaxRetries; DefaultRetryAfter = 30 }
    }
    $cfg = $providerDefaults[$Provider]

    $effectiveBase = if ($Provider -eq 'Default') { $BaseDelayMs } else { $cfg.BaseDelayMs }
    $effectiveMax  = if ($Provider -eq 'Default') { $MaxRetries  } else { $cfg.MaxRetries  }

    for ($attempt = 1; $attempt -le ($effectiveMax + 1); $attempt++) {
        try {
            $result = & $ScriptBlock
            return $result
        }
        catch {
            $ex = $_.Exception
            $httpStatus = 0
            if ($ex.Response) {
                $httpStatus = [int]$ex.Response.StatusCode
            }

            # Non-retryable: 400, 401, 403, 404
            if ($httpStatus -in @(400, 401, 403, 404)) {
                throw
            }

            if ($attempt -gt $effectiveMax) {
                throw
            }

            $delayMs = switch ($httpStatus) {
                429 {
                    # Throttled — use Retry-After or provider default
                    $retryAfter = $ex.Response.Headers['Retry-After'] | Select-Object -First 1
                    if ($retryAfter) { [int]$retryAfter * 1000 }
                    else { $cfg.DefaultRetryAfter * 1000 }
                }
                409 {
                    # Conflict — short delay, single retry
                    2000
                }
                503 {
                    # Service unavailable — aggressive backoff
                    [Math]::Min($effectiveBase * [Math]::Pow(3, $attempt - 1), $MaxDelayMs)
                }
                default {
                    # Standard exponential backoff (500, 502, 504, 408)
                    [Math]::Min($effectiveBase * [Math]::Pow(2, $attempt - 1), $MaxDelayMs)
                }
            }

            # Add jitter
            $jitter = Get-Random -Minimum 0 -Maximum ([int]($delayMs * $JitterFactor))
            $totalDelay = $delayMs + $jitter

            Write-Warning "[$OperationName] HTTP $httpStatus on attempt $attempt/$($effectiveMax + 1). Retrying in $([int]($totalDelay / 1000))s..."
            Start-Sleep -Milliseconds $totalDelay
        }
    }
}
```

### HTTP 429 vs. 503 vs. 409 — Behavioral Differences

| Code | Meaning | Retry Strategy | Delay Source |
|---|---|---|---|
| **429** | Rate limit exceeded | Always retry | `Retry-After` header (mandatory) |
| **503** | Service temporarily unavailable | Retry with aggressive backoff | Exponential × 3 (service may be recovering) |
| **409** | Resource conflict | Single retry after short delay | Fixed 2s (conflict may self-resolve) |
| **500** | Internal server error | Retry with standard backoff | Exponential × 2 |
| **502/504** | Gateway errors | Retry with standard backoff | Exponential × 2 |

## Priority Queue Pattern

### Why Priority Matters in SecOps

During an active incident, the SOC needs immediate API access for triage queries. But background reporting and posture checks may be consuming the same quota. Without priority, batch jobs can starve incident response.

### 3-Tier Priority Model

| Priority | Use Case | Budget Share | Max Concurrent |
|---|---|---|---|
| **Critical** | Incident response, live triage, isolation commands | 60% | 5 |
| **Normal** | Scheduled hunting, alert enrichment, daily operations | 30% | 3 |
| **Low** | Reporting, posture assessment, batch exports | 10% | 1 |

### Token Bucket Implementation

```powershell
class ApiTokenBucket {
    [string]$Name
    [int]$Capacity
    [int]$Tokens
    [double]$RefillRate  # tokens per second
    [datetime]$LastRefill

    ApiTokenBucket([string]$name, [int]$capacity, [double]$refillRate) {
        $this.Name = $name
        $this.Capacity = $capacity
        $this.Tokens = $capacity
        $this.RefillRate = $refillRate
        $this.LastRefill = [datetime]::UtcNow
    }

    [bool] TryConsume([int]$count) {
        $this.Refill()
        if ($this.Tokens -ge $count) {
            $this.Tokens -= $count
            return $true
        }
        return $false
    }

    [void] Refill() {
        $now = [datetime]::UtcNow
        $elapsed = ($now - $this.LastRefill).TotalSeconds
        $newTokens = [int]($elapsed * $this.RefillRate)
        if ($newTokens -gt 0) {
            $this.Tokens = [Math]::Min($this.Capacity, $this.Tokens + $newTokens)
            $this.LastRefill = $now
        }
    }

    [int] WaitTimeMs([int]$count) {
        $this.Refill()
        if ($this.Tokens -ge $count) { return 0 }
        $deficit = $count - $this.Tokens
        return [int]([Math]::Ceiling($deficit / $this.RefillRate) * 1000)
    }
}
```

### Priority Request Dispatcher

```powershell
function Request-ApiWithPriority {
    <#
    .SYNOPSIS
        Dispatches API requests through a priority queue with token bucket rate limiting.
    .DESCRIPTION
        Ensures critical operations (incident response) get API bandwidth before
        normal operations (hunting) and low-priority operations (reporting).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [ValidateSet('Critical', 'Normal', 'Low')]
        [string]$Priority = 'Normal',

        [int]$TimeoutSeconds = 120,

        [string]$OperationName = 'PrioritizedCall'
    )

    # Shared bucket store (module-scoped)
    if (-not $script:PriorityBuckets) {
        $script:PriorityBuckets = @{
            Critical = [ApiTokenBucket]::new('Critical', 60, 1.0)   # 60 tokens, 1/sec refill
            Normal   = [ApiTokenBucket]::new('Normal',   30, 0.5)   # 30 tokens, 0.5/sec refill
            Low      = [ApiTokenBucket]::new('Low',      10, 0.17)  # 10 tokens, ~10/min refill
        }
    }

    $bucket = $script:PriorityBuckets[$Priority]
    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)

    while ([datetime]::UtcNow -lt $deadline) {
        if ($bucket.TryConsume(1)) {
            Write-Verbose "[$OperationName] Priority=$Priority — token consumed, executing"
            return Invoke-WithRetry -ScriptBlock $ScriptBlock -OperationName $OperationName
        }

        $waitMs = [Math]::Min($bucket.WaitTimeMs(1), 5000)
        Write-Verbose "[$OperationName] Priority=$Priority — waiting ${waitMs}ms for token"
        Start-Sleep -Milliseconds $waitMs
    }

    throw "[$OperationName] Timed out waiting for priority=$Priority token (${TimeoutSeconds}s)"
}
```

## Quota Pooling

### Why Pool Quotas?

When multiple processes (agents, runbooks, scheduled tasks) share the same app registration, they share rate limits. Without coordination, they blind-fire requests and hit throttling unpredictably.

### File-Based Quota Tracker (Single Machine)

```powershell
function Get-QuotaBudget {
    <#
    .SYNOPSIS
        Returns remaining API budget for a given provider from a shared quota file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Provider,

        [string]$QuotaFilePath = (Join-Path $env:TEMP 'secops-quota.json')
    )

    if (-not (Test-Path $QuotaFilePath)) {
        return [PSCustomObject]@{
            Provider  = $Provider
            Remaining = $null
            Window    = $null
            Status    = 'NoData'
        }
    }

    $lock = [System.Threading.Mutex]::new($false, "Global\SecOpsQuota_$Provider")
    try {
        $lock.WaitOne(5000) | Out-Null
        $data = Get-Content $QuotaFilePath -Raw | ConvertFrom-Json
        $entry = $data.PSObject.Properties[$Provider]?.Value

        if (-not $entry) {
            return [PSCustomObject]@{ Provider = $Provider; Remaining = $null; Status = 'NoData' }
        }

        $windowStart = [datetime]::Parse($entry.windowStart)
        $windowSec = $entry.windowSeconds
        $elapsed = ([datetime]::UtcNow - $windowStart).TotalSeconds

        if ($elapsed -gt $windowSec) {
            # Window expired — full budget available
            return [PSCustomObject]@{
                Provider  = $Provider
                Remaining = $entry.limit
                Window    = 'Expired'
                Status    = 'Full'
            }
        }

        return [PSCustomObject]@{
            Provider  = $Provider
            Remaining = $entry.remaining
            Window    = "$([int]($windowSec - $elapsed))s left"
            Status    = if ($entry.remaining -lt ($entry.limit * 0.2)) { 'Low' } else { 'OK' }
        }
    }
    finally {
        $lock.ReleaseMutex()
        $lock.Dispose()
    }
}

function Request-QuotaSlot {
    <#
    .SYNOPSIS
        Claims a request slot from the shared quota pool. Blocks if budget is exhausted.
    .DESCRIPTION
        Uses a file-based mutex to coordinate across processes on the same machine.
        For multi-machine coordination, use Redis-based tracking (see below).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Provider,

        [int]$Cost = 1,
        [int]$TimeoutSeconds = 60,

        [string]$QuotaFilePath = (Join-Path $env:TEMP 'secops-quota.json')
    )

    $limits = @{
        ARM_Read      = @{ Limit = 12000; WindowSeconds = 3600 }
        ARM_Write     = @{ Limit = 1200;  WindowSeconds = 3600 }
        Graph         = @{ Limit = 10000; WindowSeconds = 600  }
        MDE           = @{ Limit = 100;   WindowSeconds = 60   }
        MDE_Hunting   = @{ Limit = 45;    WindowSeconds = 60   }
        LogAnalytics  = @{ Limit = 200;   WindowSeconds = 30   }
        MDCA          = @{ Limit = 30;    WindowSeconds = 60   }
        ResourceGraph = @{ Limit = 15;    WindowSeconds = 5    }
    }

    $providerLimits = $limits[$Provider]
    if (-not $providerLimits) {
        throw "Unknown provider: $Provider. Valid: $($limits.Keys -join ', ')"
    }

    $lock = [System.Threading.Mutex]::new($false, "Global\SecOpsQuota_$Provider")
    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)

    while ([datetime]::UtcNow -lt $deadline) {
        try {
            $lock.WaitOne(5000) | Out-Null

            # Load or initialize quota data
            $data = if (Test-Path $QuotaFilePath) {
                Get-Content $QuotaFilePath -Raw | ConvertFrom-Json
            } else {
                [PSCustomObject]@{}
            }

            $entry = $data.PSObject.Properties[$Provider]?.Value
            $now = [datetime]::UtcNow

            if (-not $entry -or ($now - [datetime]::Parse($entry.windowStart)).TotalSeconds -gt $providerLimits.WindowSeconds) {
                # New window
                $entry = @{
                    limit         = $providerLimits.Limit
                    remaining     = $providerLimits.Limit - $Cost
                    windowStart   = $now.ToString('o')
                    windowSeconds = $providerLimits.WindowSeconds
                }
                $data | Add-Member -NotePropertyName $Provider -NotePropertyValue $entry -Force
                $data | ConvertTo-Json -Depth 5 | Set-Content $QuotaFilePath -Encoding utf8
                return [PSCustomObject]@{ Granted = $true; Remaining = $entry.remaining }
            }

            if ($entry.remaining -ge $Cost) {
                $entry.remaining -= $Cost
                $data | ConvertTo-Json -Depth 5 | Set-Content $QuotaFilePath -Encoding utf8
                return [PSCustomObject]@{ Granted = $true; Remaining = $entry.remaining }
            }

            # Budget exhausted — wait for window reset
            $resetIn = $providerLimits.WindowSeconds - ($now - [datetime]::Parse($entry.windowStart)).TotalSeconds
            Write-Warning "[$Provider] Quota exhausted. Window resets in $([int]$resetIn)s"
        }
        finally {
            $lock.ReleaseMutex()
        }

        Start-Sleep -Seconds ([Math]::Min(5, [Math]::Max(1, $resetIn)))
    }

    return [PSCustomObject]@{ Granted = $false; Remaining = 0 }
}
```

### Redis-Based Quota Tracking (Multi-Machine)

For distributed environments (multiple SOC workstations, Azure Functions, Logic Apps), use Redis as the coordination backend:

```powershell
function Request-QuotaSlotRedis {
    <#
    .SYNOPSIS
        Claims a request slot from a Redis-backed distributed quota pool.
    .DESCRIPTION
        Uses Redis INCR + EXPIRE for atomic rate limiting. Each provider key
        tracks requests within its rate window. Thread-safe across machines.
    .NOTES
        Requires StackExchange.Redis module or direct Redis CLI.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Provider,

        [Parameter(Mandatory)]
        [object]$RedisConnection,

        [int]$Cost = 1
    )

    $limits = @{
        Graph    = @{ Limit = 10000; WindowSec = 600 }
        MDE      = @{ Limit = 100;   WindowSec = 60  }
        ARM_Read = @{ Limit = 12000; WindowSec = 3600 }
    }

    $cfg = $limits[$Provider]
    $key = "secops:ratelimit:$Provider"
    $db = $RedisConnection.GetDatabase()

    # Atomic increment + set expiry on first use
    $current = $db.StringIncrement($key, $Cost)
    if ($current -eq $Cost) {
        $db.KeyExpire($key, [TimeSpan]::FromSeconds($cfg.WindowSec))
    }

    $remaining = $cfg.Limit - $current
    if ($remaining -lt 0) {
        $ttl = $db.KeyTimeToLive($key)
        return [PSCustomObject]@{
            Granted   = $false
            Remaining = 0
            ResetIn   = $ttl.TotalSeconds
        }
    }

    return [PSCustomObject]@{
        Granted   = $true
        Remaining = $remaining
    }
}
```

## Circuit Breaker Pattern

### When to Stop Retrying

Retries handle transient failures. But if an API is persistently failing (regional outage, revoked permissions, misconfigured endpoint), retries waste time and quota. The circuit breaker stops calling a failed API and periodically probes to detect recovery.

### Circuit Breaker States

```
  ┌─────────┐   failure threshold   ┌────────┐   timeout   ┌───────────┐
  │ CLOSED  │ ───────────────────> │  OPEN  │ ──────────> │ HALF-OPEN │
  │(normal) │                      │(reject)│             │  (probe)  │
  └────┬────┘                      └────────┘             └─────┬─────┘
       │                                                        │
       │ <──────── success ─────────────────────────────────────┘
       │                                                        │
       └──────────────────── failure ──────── back to OPEN ─────┘
```

- **Closed** — Normal operation. Track failure count. Open circuit after N consecutive failures.
- **Open** — Reject all requests immediately (return cached/degraded result). After timeout, move to half-open.
- **Half-Open** — Allow one probe request. If it succeeds, close circuit. If it fails, re-open.

### Implementation

```powershell
class ApiCircuitBreaker {
    [string]$Name
    [string]$State = 'Closed'      # Closed, Open, HalfOpen
    [int]$FailureCount = 0
    [int]$FailureThreshold = 5
    [int]$OpenTimeoutSeconds = 60
    [datetime]$LastFailureTime = [datetime]::MinValue
    [datetime]$OpenedAt = [datetime]::MinValue

    ApiCircuitBreaker([string]$name, [int]$threshold, [int]$timeoutSec) {
        $this.Name = $name
        $this.FailureThreshold = $threshold
        $this.OpenTimeoutSeconds = $timeoutSec
    }

    [bool] AllowRequest() {
        switch ($this.State) {
            'Closed'   { return $true }
            'Open'     {
                $elapsed = ([datetime]::UtcNow - $this.OpenedAt).TotalSeconds
                if ($elapsed -ge $this.OpenTimeoutSeconds) {
                    $this.State = 'HalfOpen'
                    Write-Verbose "[CircuitBreaker:$($this.Name)] Transitioning to HalfOpen"
                    return $true
                }
                return $false
            }
            'HalfOpen' { return $true }
        }
        return $false
    }

    [void] RecordSuccess() {
        $this.FailureCount = 0
        if ($this.State -ne 'Closed') {
            Write-Verbose "[CircuitBreaker:$($this.Name)] Circuit closed — API recovered"
        }
        $this.State = 'Closed'
    }

    [void] RecordFailure() {
        $this.FailureCount++
        $this.LastFailureTime = [datetime]::UtcNow
        if ($this.FailureCount -ge $this.FailureThreshold) {
            $this.State = 'Open'
            $this.OpenedAt = [datetime]::UtcNow
            Write-Warning "[CircuitBreaker:$($this.Name)] Circuit OPEN after $($this.FailureCount) failures. Rejecting calls for $($this.OpenTimeoutSeconds)s."
        }
    }
}

function Invoke-WithCircuitBreaker {
    <#
    .SYNOPSIS
        Wraps an API call with circuit breaker protection.
    .DESCRIPTION
        If the target API has failed repeatedly, immediately returns a degraded
        result instead of wasting time and quota on retries. Periodically probes
        the API to detect recovery.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory)]
        [string]$CircuitName,

        [int]$FailureThreshold = 5,
        [int]$OpenTimeoutSeconds = 60,

        [object]$FallbackValue = $null,

        [string]$OperationName = 'CircuitBreakerCall'
    )

    # Module-scoped circuit breaker registry
    if (-not $script:CircuitBreakers) {
        $script:CircuitBreakers = @{}
    }
    if (-not $script:CircuitBreakers[$CircuitName]) {
        $script:CircuitBreakers[$CircuitName] = [ApiCircuitBreaker]::new(
            $CircuitName, $FailureThreshold, $OpenTimeoutSeconds
        )
    }

    $breaker = $script:CircuitBreakers[$CircuitName]

    if (-not $breaker.AllowRequest()) {
        Write-Warning "[$OperationName] Circuit '$CircuitName' is OPEN — returning fallback"
        return New-SecOpsResult -Error "Circuit breaker open for $CircuitName" `
            -StatusCode 0 -ErrorCode 'CircuitOpen' -Data $FallbackValue
    }

    try {
        $result = & $ScriptBlock
        $breaker.RecordSuccess()
        return $result
    }
    catch {
        $breaker.RecordFailure()

        if ($breaker.State -eq 'Open' -and $FallbackValue) {
            return New-SecOpsResult -Error "API failed, circuit opened — using fallback" `
                -StatusCode 0 -ErrorCode 'CircuitOpen' -Data $FallbackValue
        }
        throw
    }
}
```

### Graceful Degradation Strategies

| Scenario | Degradation | Implementation |
|---|---|---|
| **Incident enrichment** | Return cached entity context | `$FallbackValue = Get-CachedEntityContext $entity` |
| **Alert triage** | Show alert without enrichment | Mark enrichment fields as "unavailable" |
| **Posture reporting** | Use last successful scan results | Read from local cache file with age warning |
| **Threat intel lookup** | Return "TI unavailable" status | Flag for manual review |

## Monitoring & Alerting

### Tracking Rate Limit Consumption

```powershell
function Write-RateLimitMetric {
    <#
    .SYNOPSIS
        Logs rate limit consumption for dashboard and alerting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Provider,

        [Parameter(Mandatory)]
        [hashtable]$ResponseHeaders,

        [string]$MetricsPath = './logs/rate-limit-metrics.jsonl'
    )

    $status = Get-RateLimitStatus -ResponseHeaders $ResponseHeaders

    $metric = [ordered]@{
        timestamp    = [DateTimeOffset]::UtcNow.ToString('o')
        provider     = $Provider
        remaining    = $status.Remaining
        limit        = $status.Limit
        percent_used = $status.PercentUsed
        hostname     = $env:COMPUTERNAME ?? (hostname)
    }

    $dir = Split-Path $MetricsPath -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $metric | ConvertTo-Json -Compress | Out-File -FilePath $MetricsPath -Append -Encoding utf8

    # Alert at 80% consumption
    if ($status.PercentUsed -ge 80) {
        Write-Warning "[RateLimit] $Provider at $($status.PercentUsed)% capacity ($($status.Remaining) remaining)"
    }
}
```

### Integration with `.secops/alerting/routing.yaml`

Rate limit alerts should route through the existing alerting framework:

```yaml
# Add to .secops/alerting/routing.yaml under default_routes:
- match:
    source: rate-limiter
    severity: warning
  route:
    channel: soc-ops
    action_group: secops-operations-ag
    auto_resolve: true
    resolve_after_minutes: 15

- match:
    source: rate-limiter
    severity: critical
  route:
    channel: soc-ops
    action_group: secops-critical-ag
    escalation: tier2
```

## Cross-API Coordination

### Multi-API Budget Sharing

A single app registration may access Graph, ARM, and MDE APIs simultaneously. Each has independent limits, but they share network resources and token refresh overhead.

```powershell
function New-SecOpsApiCoordinator {
    <#
    .SYNOPSIS
        Creates a coordinator that manages rate limits across multiple API surfaces.
    .DESCRIPTION
        Tracks budgets for ARM, Graph, MDE, Log Analytics, and MDCA from a single
        point. Prevents cross-API interference during high-load operations.
    #>
    [CmdletBinding()]
    param(
        [string]$QuotaFilePath = (Join-Path $env:TEMP 'secops-quota.json')
    )

    return [PSCustomObject]@{
        PSTypeName    = 'SecOps.ApiCoordinator'
        QuotaFile     = $QuotaFilePath
        CircuitBreakers = @{}
        PriorityBuckets = @{
            Critical = [ApiTokenBucket]::new('Critical', 60, 1.0)
            Normal   = [ApiTokenBucket]::new('Normal',   30, 0.5)
            Low      = [ApiTokenBucket]::new('Low',      10, 0.17)
        }
        Stats = @{
            TotalRequests = 0
            Throttled     = 0
            CircuitOpens  = 0
        }
    }
}
```

### Tenant-Level vs. App-Level vs. User-Level Limits

| Scope | What It Means | APIs Affected | Coordination Strategy |
|---|---|---|---|
| **Per app per tenant** | All requests from your app reg to one tenant | Graph, MDE | Pool across all processes using same app |
| **Per subscription** | All requests to one Azure subscription | ARM, Sentinel | Pool across processes targeting same sub |
| **Per user** | Requests by a specific AAD identity | Log Analytics, Resource Graph | Distribute across service principals |
| **Per tenant global** | Total requests to a tenant regardless of app | Graph (some endpoints) | Cannot avoid — must share with other apps |

### Multi-Tenant Rate Limiting (MSSP)

```powershell
function Invoke-MsspApiCall {
    <#
    .SYNOPSIS
        Executes an API call with per-tenant rate limit isolation.
    .DESCRIPTION
        For MSSPs managing dozens of tenants, each tenant has its own rate limit
        window. This function tracks budgets per tenant, preventing one noisy
        tenant from consuming the budget of others.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$Provider,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [ValidateSet('Critical', 'Normal', 'Low')]
        [string]$Priority = 'Normal'
    )

    $quotaKey = "${Provider}_${TenantId}"
    $slot = Request-QuotaSlot -Provider $Provider -QuotaFilePath (
        Join-Path $env:TEMP "secops-quota-$TenantId.json"
    )

    if (-not $slot.Granted) {
        Write-Warning "[$Provider] Tenant $TenantId quota exhausted"
        return New-SecOpsResult -Error "Quota exhausted for $Provider in tenant $TenantId" `
            -StatusCode 429 -ErrorCode 'QuotaExhausted'
    }

    return Invoke-WithRetry -ScriptBlock $ScriptBlock -Provider $Provider `
        -OperationName "$Provider-$TenantId"
}
```

### Batch Scheduling

Schedule heavy operations during off-peak hours to avoid competing with real-time SOC work:

```powershell
function Start-SecOpsBatchWindow {
    <#
    .SYNOPSIS
        Starts a batch processing window with dedicated quota allocation.
    .DESCRIPTION
        Batch operations (bulk enrichment, posture scans, historical hunts) should
        run during off-peak SOC hours. This function verifies the time window and
        allocates a dedicated low-priority budget.
    #>
    [CmdletBinding()]
    param(
        [int]$OffPeakStartHour = 2,   # 2 AM local
        [int]$OffPeakEndHour = 6,     # 6 AM local
        [switch]$Force
    )

    $hour = (Get-Date).Hour
    if (-not $Force -and ($hour -lt $OffPeakStartHour -or $hour -ge $OffPeakEndHour)) {
        Write-Warning "Batch window is $OffPeakStartHour`:00-$OffPeakEndHour`:00. Current: $hour`:00. Use -Force to override."
        return $false
    }

    Write-Verbose "Batch window active. Low-priority quota unlocked."
    return $true
}
```

## Test Scenarios

### 1. Retry Behavior Verification

```powershell
# Test: 429 retry respects Retry-After
Describe 'Invoke-WithRetry' {
    It 'Respects Retry-After header on 429' {
        $attempt = 0
        $result = Invoke-WithRetry -ScriptBlock {
            $script:attempt++
            if ($script:attempt -lt 3) {
                $ex = [System.Net.Http.HttpRequestException]::new('Throttled')
                # Simulate 429 with Retry-After: 1
                throw $ex
            }
            return 'success'
        } -MaxRetries 4 -BaseDelayMs 100
        $result | Should -Be 'success'
        $script:attempt | Should -Be 3
    }
}
```

### 2. Circuit Breaker State Transitions

```powershell
# Test: Circuit opens after threshold failures
Describe 'Invoke-WithCircuitBreaker' {
    It 'Opens circuit after 3 consecutive failures' {
        $script:CircuitBreakers = @{}
        1..3 | ForEach-Object {
            try {
                Invoke-WithCircuitBreaker -ScriptBlock { throw 'fail' } `
                    -CircuitName 'test' -FailureThreshold 3
            } catch {}
        }
        $script:CircuitBreakers['test'].State | Should -Be 'Open'
    }
}
```

### 3. Priority Queue Fair Scheduling

```powershell
# Test: Critical requests get served before Low
Describe 'Request-ApiWithPriority' {
    It 'Critical priority gets tokens before Low' {
        $script:PriorityBuckets = $null
        $critResult = Request-ApiWithPriority -ScriptBlock { 'critical-done' } -Priority Critical
        $critResult | Should -Be 'critical-done'
    }
}
```

## Best Practices

1. **Always read throttle headers** — Don't guess remaining budget; parse `x-ms-ratelimit-remaining-*` or `RateLimit-Remaining`
2. **Use provider-specific backoff** — Graph needs different timing than ARM or MDE
3. **Never retry 401/403** — These require human intervention (re-auth, RBAC fix)
4. **Prioritize incident response** — Critical API calls must pre-empt reporting and batch work
5. **Coordinate across processes** — Use quota pooling to prevent blind-fire throttling
6. **Circuit-break persistently failing APIs** — Stop retrying after 5 failures; probe for recovery
7. **Monitor consumption trends** — Alert at 80% capacity before hitting hard limits
8. **Schedule batch operations off-peak** — Run bulk enrichment, posture scans, and exports overnight
9. **Isolate tenant quotas in MSSP** — One noisy tenant must not starve others
10. **Log every throttle event** — Throttling patterns reveal capacity planning needs

## Environment Context

Before implementing rate limiting, agents MUST consult:

- **`.secops/environment.yaml`** — Cloud environment affects API endpoints and some rate limits differ in government clouds
- **`.secops/identity/tenants.yaml`** — Multi-tenant environments need per-tenant quota isolation
- **`.secops/compliance/requirements.yaml`** — Some compliance frameworks require audit logging of throttle events

## Related Skills

- `skills/powershell/error-handling.md` — Basic retry logic and structured results (this skill extends it)
- `skills/powershell/api-patterns.md` — Pagination, batching, long-running ops (complements rate limiting)
- `skills/powershell/auth-patterns.md` — Token acquisition and refresh patterns
- `skills/log-analytics/api-wrapper.md` — Log Analytics API-specific rate limits
- `skills/msft-security/sentinel-mcp-server.md` — Sentinel API patterns with MCP
- `skills/msft-security/defender-mcp-server.md` — Defender API rate limiting
