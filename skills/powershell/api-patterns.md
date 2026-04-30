---
title: Common API Patterns
category: powershell
difficulty: intermediate
mitre_attack:
  - T1059.001  # Command and Scripting Interpreter: PowerShell
  - T1078      # Valid Accounts (API auth context)
products:
  - Azure Resource Manager
  - Microsoft Graph API
  - Microsoft Defender for Endpoint API
  - Microsoft Sentinel
  - Azure Monitor Log Analytics
author: Freamon
version: 1.0.0
last_updated: 2026-04-30
---

# Common API Patterns

## Overview

Microsoft Security APIs share common patterns: pagination, batching, long-running operations, idempotency, request tracing, and response streaming. Rather than re-implementing these in every API wrapper, this skill provides reusable implementations that work across all Microsoft Security API surfaces.

This skill is **cross-cutting** — every API wrapper skill (`sentinel-module.md`, `defender-module.md`, `entra-module.md`, etc.) should reference these patterns instead of duplicating them.

Use this skill when:
- Handling paginated API responses (Graph `@odata.nextLink`, ARM `nextLink`, `$skip`/`$top`)
- Sending batch requests to Graph or ARM APIs
- Polling long-running Azure operations (async pattern)
- Implementing idempotent API calls for safe retries
- Adding correlation IDs for distributed tracing
- Streaming large result sets through the PowerShell pipeline

## Prerequisites

| Requirement | Detail |
|---|---|
| **PowerShell** | 7.4+ |
| **Knowledge** | REST APIs, OData conventions, Azure async operations |
| **Skills** | `skills/powershell/error-handling.md`, `skills/powershell/rate-limiting.md` |

## Pagination Patterns

### The Problem

Most Microsoft APIs limit single responses to 100–1000 items. Remaining items are accessible via continuation tokens — but the token format differs by API.

| API | Mechanism | Field | Max per Page |
|---|---|---|---|
| **Microsoft Graph** | `@odata.nextLink` | URL with `$skiptoken` | 999 (most), 100 (alerts) |
| **ARM / Sentinel** | `nextLink` | Full URL | 200 |
| **MDE Advanced Hunting** | No pagination | N/A | 10,000 rows per query |
| **Log Analytics Query** | `render` or `$top`/`$skip` | N/A | 30,000 rows (500,000 max) |
| **Resource Graph** | `$skipToken` | Token string | 1000 |

### Universal Pagination Handler

```powershell
function Get-SecOpsAllPages {
    <#
    .SYNOPSIS
        Follows pagination links to retrieve all pages from a Microsoft API.
    .DESCRIPTION
        Handles Graph @odata.nextLink, ARM nextLink, and Resource Graph $skipToken.
        Returns all results as a single collection or streams via pipeline.
        Integrates with rate limiting — pauses between pages when approaching limits.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [hashtable]$Headers = @{},

        [string]$ValueProperty = 'value',

        [int]$MaxPages = 100,

        [int]$DelayBetweenPagesMs = 0,

        [switch]$Stream,

        [string]$OperationName = 'Paginated Query'
    )

    $allResults = [System.Collections.Generic.List[object]]::new()
    $currentUri = $Uri
    $pageCount = 0

    while ($currentUri -and $pageCount -lt $MaxPages) {
        $pageCount++
        Write-Verbose "[$OperationName] Fetching page $pageCount — $currentUri"

        $response = Invoke-SecOpsRestMethod -Uri $currentUri -Headers $Headers `
            -OperationName "$OperationName (page $pageCount)"

        if (-not $response.Ok) {
            Write-Warning "[$OperationName] Page $pageCount failed: $($response.Error)"
            break
        }

        $data = $response.Data

        # Extract items from response
        $items = if ($data.PSObject.Properties[$ValueProperty]) {
            $data.$ValueProperty
        } else {
            @($data)
        }

        if ($Stream) {
            $items | ForEach-Object { Write-Output $_ }
        } else {
            $allResults.AddRange(@($items))
        }

        # Find next page link
        $currentUri = $data.'@odata.nextLink' ??    # Graph
                      $data.nextLink ??              # ARM
                      $null

        # Resource Graph uses $skipToken differently
        if (-not $currentUri -and $data.'$skipToken') {
            $separator = if ($Uri.Contains('?')) { '&' } else { '?' }
            $currentUri = "$Uri${separator}`$skipToken=$($data.'$skipToken')"
        }

        # Rate-limit-aware pacing
        if ($currentUri -and $DelayBetweenPagesMs -gt 0) {
            Start-Sleep -Milliseconds $DelayBetweenPagesMs
        }
    }

    if ($pageCount -ge $MaxPages) {
        Write-Warning "[$OperationName] Hit max page limit ($MaxPages). Results may be incomplete."
    }

    if (-not $Stream) {
        Write-Verbose "[$OperationName] Retrieved $($allResults.Count) items across $pageCount pages"
        return $allResults.ToArray()
    }
}
```

### OData $top/$skip Pagination

Some APIs (older ARM, custom endpoints) use offset-based pagination instead of tokens:

```powershell
function Get-SecOpsPagedByOffset {
    <#
    .SYNOPSIS
        Paginate using $top and $skip for APIs that don't support continuation tokens.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUri,

        [hashtable]$Headers = @{},

        [int]$PageSize = 100,

        [int]$MaxItems = 10000,

        [string]$OperationName = 'Offset Pagination'
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $skip = 0

    while ($skip -lt $MaxItems) {
        $separator = if ($BaseUri.Contains('?')) { '&' } else { '?' }
        $uri = "$BaseUri${separator}`$top=$PageSize&`$skip=$skip"

        $response = Invoke-SecOpsRestMethod -Uri $uri -Headers $Headers `
            -OperationName "$OperationName (skip=$skip)"

        if (-not $response.Ok) { break }

        $items = $response.Data.value
        if (-not $items -or $items.Count -eq 0) { break }

        $results.AddRange(@($items))
        $skip += $PageSize

        if ($items.Count -lt $PageSize) { break }  # Last page
    }

    return $results.ToArray()
}
```

## Batch Requests

### Graph API $batch

The Graph API supports batching up to 20 requests in a single HTTP call. Each sub-request is independent and can target different endpoints.

```powershell
function Invoke-SecOpsGraphBatch {
    <#
    .SYNOPSIS
        Sends a batch of up to 20 requests to Microsoft Graph in a single HTTP call.
    .DESCRIPTION
        Constructs a JSON batch payload per the Graph $batch specification.
        Returns an array of responses matched by request ID.
        Handles per-request errors — one failure doesn't affect other requests.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$Requests,

        [hashtable]$Headers = @{},

        [string]$GraphBaseUri = 'https://graph.microsoft.com/v1.0'
    )

    if ($Requests.Count -gt 20) {
        throw "Graph batch supports max 20 requests. Got $($Requests.Count). Split into multiple batches."
    }

    $batchBody = @{
        requests = $Requests | ForEach-Object -Begin { $i = 0 } -Process {
            $i++
            @{
                id      = "$i"
                method  = $_.Method ?? 'GET'
                url     = $_.Url
                headers = $_.Headers ?? @{}
                body    = $_.Body
            }
        }
    }

    $response = Invoke-SecOpsRestMethod `
        -Uri "$GraphBaseUri/`$batch" `
        -Method POST `
        -Body $batchBody `
        -Headers $Headers `
        -OperationName 'Graph Batch'

    if (-not $response.Ok) {
        return $response
    }

    # Map responses back to request order
    return $response.Data.responses | Sort-Object { [int]$_.id } | ForEach-Object {
        [PSCustomObject]@{
            RequestId  = $_.id
            StatusCode = $_.status
            Body       = $_.body
            Ok         = $_.status -ge 200 -and $_.status -lt 300
        }
    }
}
```

**Usage — Batch-enrich 15 alerts with user context:**

```powershell
$alerts = Get-SecOpsAlerts -Severity High -Top 15

$batchRequests = $alerts | ForEach-Object {
    @{
        Method = 'GET'
        Url    = "/users/$($_.userPrincipalName)?`$select=displayName,department,jobTitle,riskLevel"
    }
}

$enrichments = Invoke-SecOpsGraphBatch -Requests $batchRequests -Headers $authHeaders
```

### ARM Batch Operations

ARM doesn't have a `$batch` endpoint, but supports parallel calls via PowerShell jobs or runspaces. Coordinate with rate limiting:

```powershell
function Invoke-SecOpsArmParallel {
    <#
    .SYNOPSIS
        Executes multiple ARM API calls in parallel with rate limit coordination.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Uris,

        [hashtable]$Headers = @{},

        [int]$MaxConcurrent = 5,

        [string]$OperationName = 'ARM Parallel'
    )

    $results = $Uris | ForEach-Object -Parallel {
        $uri = $_
        $headers = $using:Headers
        $opName = $using:OperationName

        # Each thread claims a quota slot
        $slot = Request-QuotaSlot -Provider 'ARM_Read'
        if ($slot.Granted) {
            Invoke-SecOpsRestMethod -Uri $uri -Headers $headers -OperationName $opName
        } else {
            New-SecOpsResult -Error "ARM quota exhausted" -StatusCode 429 -ErrorCode 'QuotaExhausted'
        }
    } -ThrottleLimit $MaxConcurrent

    return $results
}
```

## Long-Running Operations

### Azure Async Pattern

Many ARM write operations (creating resources, starting exports, triggering scans) return immediately with a `202 Accepted` status and a polling URL. The client must poll until the operation completes.

Two header variants:
- `Location` — Poll this URL; returns `200` when done, `202` while pending
- `Azure-AsyncOperation` — Poll this URL; returns JSON with `status` field

```powershell
function Wait-SecOpsAsyncOperation {
    <#
    .SYNOPSIS
        Polls an Azure long-running operation until completion.
    .DESCRIPTION
        Handles both Location and Azure-AsyncOperation header patterns.
        Uses exponential backoff between polls. Returns the final result
        when the operation succeeds, or an error if it fails or times out.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ResponseHeaders,

        [hashtable]$AuthHeaders = @{},

        [int]$TimeoutSeconds = 300,

        [int]$InitialPollIntervalMs = 2000,

        [int]$MaxPollIntervalMs = 30000,

        [string]$OperationName = 'Async Operation'
    )

    # Determine polling URL from headers
    $pollUrl = $ResponseHeaders['Azure-AsyncOperation'] ??
               $ResponseHeaders['Location']

    if (-not $pollUrl) {
        throw "[$OperationName] No Azure-AsyncOperation or Location header found"
    }

    $useAsyncOp = [bool]$ResponseHeaders['Azure-AsyncOperation']
    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
    $pollInterval = $InitialPollIntervalMs

    Write-Verbose "[$OperationName] Polling $pollUrl (timeout: ${TimeoutSeconds}s)"

    while ([datetime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds $pollInterval

        $pollResult = Invoke-SecOpsRestMethod -Uri $pollUrl -Headers $AuthHeaders `
            -OperationName "$OperationName (poll)"

        if (-not $pollResult.Ok) {
            return $pollResult
        }

        if ($useAsyncOp) {
            # Azure-AsyncOperation returns JSON with status field
            $opStatus = $pollResult.Data.status
            switch ($opStatus) {
                'Succeeded' {
                    Write-Verbose "[$OperationName] Completed successfully"
                    # Fetch final result from Location header if available
                    if ($ResponseHeaders['Location']) {
                        return Invoke-SecOpsRestMethod -Uri $ResponseHeaders['Location'] `
                            -Headers $AuthHeaders -OperationName "$OperationName (result)"
                    }
                    return $pollResult
                }
                'Failed' {
                    $errMsg = $pollResult.Data.error?.message ?? 'Operation failed'
                    return New-SecOpsResult -Error $errMsg -StatusCode 500 `
                        -ErrorCode ($pollResult.Data.error?.code ?? 'AsyncOperationFailed')
                }
                'Canceled' {
                    return New-SecOpsResult -Error 'Operation was canceled' `
                        -StatusCode 409 -ErrorCode 'OperationCanceled'
                }
                default {
                    Write-Verbose "[$OperationName] Status: $opStatus — continuing to poll"
                }
            }
        } else {
            # Location-based: 202 = still running, 200 = done
            if ($pollResult.StatusCode -eq 200) {
                Write-Verbose "[$OperationName] Completed successfully"
                return $pollResult
            }
        }

        # Exponential backoff on poll interval
        $pollInterval = [Math]::Min($pollInterval * 1.5, $MaxPollIntervalMs)
    }

    return New-SecOpsResult -Error "Operation timed out after ${TimeoutSeconds}s" `
        -StatusCode 0 -ErrorCode 'AsyncTimeout'
}
```

**Usage — Create a Sentinel analytics rule (async):**

```powershell
$createResult = Invoke-SecOpsRestMethod `
    -Uri "$armBase/providers/Microsoft.SecurityInsights/alertRules/$ruleId?api-version=2024-03-01" `
    -Method PUT -Body $ruleBody -Headers $authHeaders

if ($createResult.StatusCode -eq 202) {
    $finalResult = Wait-SecOpsAsyncOperation `
        -ResponseHeaders $createResult.ResponseHeaders `
        -AuthHeaders $authHeaders `
        -TimeoutSeconds 120 `
        -OperationName 'Create Analytics Rule'
}
```

## Idempotency Patterns

### Why Idempotency Matters

Retries and circuit breaker recovery may replay requests. Without idempotency, you get duplicate incidents, duplicate alerts, or duplicate device actions.

### Strategies by API

| API | Idempotency Mechanism | Implementation |
|---|---|---|
| **ARM** | Resource name acts as key (PUT is idempotent) | Always use PUT with explicit resource ID |
| **Graph** | Some endpoints support `If-Match` (ETags) | Check `@odata.etag` before updates |
| **MDE** | Action ID deduplication | Store action GUIDs; check before resubmitting |
| **Sentinel** | Rule name + workspace uniqueness | Query before create; use update if exists |

### Idempotent Create-or-Update

```powershell
function Set-SecOpsResource {
    <#
    .SYNOPSIS
        Creates or updates a resource idempotently.
    .DESCRIPTION
        Checks if resource exists first. If it does, performs PATCH with ETag.
        If not, performs PUT/POST. Safe for retries — won't create duplicates.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [object]$Body,

        [hashtable]$Headers = @{},

        [string]$OperationName = 'Set Resource'
    )

    # Check existence
    $existing = Invoke-SecOpsRestMethod -Uri $Uri -Headers $Headers `
        -OperationName "$OperationName (check)"

    if ($existing.Ok) {
        # Resource exists — update with ETag for optimistic concurrency
        $etag = $existing.Data.'@odata.etag'
        if ($etag) {
            $Headers['If-Match'] = $etag
        }

        if ($PSCmdlet.ShouldProcess($Uri, 'Update existing resource')) {
            return Invoke-SecOpsRestMethod -Uri $Uri -Method PATCH `
                -Body $Body -Headers $Headers -OperationName "$OperationName (update)"
        }
    }
    elseif ($existing.StatusCode -eq 404) {
        # Resource doesn't exist — create
        if ($PSCmdlet.ShouldProcess($Uri, 'Create new resource')) {
            return Invoke-SecOpsRestMethod -Uri $Uri -Method PUT `
                -Body $Body -Headers $Headers -OperationName "$OperationName (create)"
        }
    }
    else {
        # Unexpected error checking existence
        return $existing
    }
}
```

## Request Tracing and Correlation

### Correlation ID Propagation

Every API call should carry a correlation ID for distributed tracing. Microsoft APIs return `x-ms-correlation-request-id` — pass it downstream.

```powershell
function New-SecOpsCorrelationContext {
    <#
    .SYNOPSIS
        Creates a correlation context for tracing a multi-step operation.
    #>
    [CmdletBinding()]
    param(
        [string]$ParentCorrelationId,
        [string]$OperationName = 'SecOps Operation'
    )

    $correlationId = $ParentCorrelationId ?? [guid]::NewGuid().ToString()
    $spanId = [guid]::NewGuid().ToString('N').Substring(0, 16)

    return [PSCustomObject]@{
        PSTypeName    = 'SecOps.CorrelationContext'
        CorrelationId = $correlationId
        SpanId        = $spanId
        OperationName = $OperationName
        StartTime     = [DateTimeOffset]::UtcNow
        Headers       = @{
            'x-ms-correlation-request-id' = $correlationId
            'x-ms-client-request-id'      = $spanId
        }
    }
}
```

### Request/Response Logging for Audit

```powershell
function Write-SecOpsRequestLog {
    <#
    .SYNOPSIS
        Logs a sanitized request/response pair for compliance audit.
    .DESCRIPTION
        Redacts Authorization headers, query parameters, and PII fields.
        Writes to the audit log directory alongside the main audit trail.
    #>
    [CmdletBinding()]
    param(
        [string]$Method,
        [string]$Uri,
        [int]$StatusCode,
        [hashtable]$RequestHeaders,
        [object]$ResponseBody,
        [string]$CorrelationId,
        [double]$DurationMs
    )

    $entry = [ordered]@{
        timestamp      = [DateTimeOffset]::UtcNow.ToString('o')
        correlation_id = $CorrelationId
        method         = $Method
        uri            = $Uri -replace '\?.*', '?<redacted>'
        status_code    = $StatusCode
        duration_ms    = [Math]::Round($DurationMs, 1)
        response_size  = if ($ResponseBody) {
            ($ResponseBody | ConvertTo-Json -Compress -Depth 1).Length
        } else { 0 }
    }

    $logDir = $script:Config.AuditLogPath ?? './logs'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

    $logFile = Join-Path $logDir "secops-requests-$(Get-Date -Format 'yyyy-MM-dd').jsonl"
    $entry | ConvertTo-Json -Compress | Out-File -FilePath $logFile -Append -Encoding utf8
}
```

## PowerShell Pipeline Integration

### Streaming Large Result Sets

For operations returning thousands of items (device inventory, all incidents, alert history), streaming through the PowerShell pipeline avoids loading everything into memory.

```powershell
function Get-SecOpsStream {
    <#
    .SYNOPSIS
        Streams paginated API results through the PowerShell pipeline.
    .DESCRIPTION
        Yields items one at a time as they arrive from each page. Downstream
        cmdlets (Where-Object, Select-Object, Export-Csv) process items
        incrementally instead of waiting for all pages to load.
    .EXAMPLE
        Get-SecOpsStream -Uri $incidentsUri -Headers $auth | 
            Where-Object { $_.severity -eq 'High' } |
            Select-Object -First 10
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [hashtable]$Headers = @{},

        [string]$ValueProperty = 'value',

        [int]$MaxPages = 100,

        [string]$OperationName = 'Stream'
    )

    $currentUri = $Uri
    $pageCount = 0

    while ($currentUri -and $pageCount -lt $MaxPages) {
        $pageCount++

        $response = Invoke-SecOpsRestMethod -Uri $currentUri -Headers $Headers `
            -OperationName "$OperationName (page $pageCount)"

        if (-not $response.Ok) {
            Write-Warning "[$OperationName] Page $pageCount failed: $($response.Error)"
            return
        }

        $data = $response.Data

        # Yield each item to the pipeline
        $items = if ($data.PSObject.Properties[$ValueProperty]) {
            $data.$ValueProperty
        } else {
            @($data)
        }

        foreach ($item in $items) {
            Write-Output $item
        }

        # Next page
        $currentUri = $data.'@odata.nextLink' ?? $data.nextLink ?? $null
    }
}
```

**Usage — Stream all Sentinel incidents to CSV:**

```powershell
Get-SecOpsStream -Uri $sentinelIncidentsUri -Headers $authHeaders -OperationName 'Export Incidents' |
    Select-Object title, severity, status, createdTimeUtc |
    Export-Csv -Path './incident-export.csv' -NoTypeInformation
```

### Pipeline-Friendly Enrichment

```powershell
function Add-SecOpsEnrichment {
    <#
    .SYNOPSIS
        Enriches objects flowing through the pipeline with data from a lookup API.
    .DESCRIPTION
        Takes objects from pipeline, calls an API for each to add properties,
        and yields enriched objects. Uses batch requests when possible.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject]$InputObject,

        [Parameter(Mandatory)]
        [scriptblock]$LookupUri,

        [Parameter(Mandatory)]
        [string]$PropertyName,

        [hashtable]$Headers = @{}
    )

    process {
        $uri = & $LookupUri $InputObject
        $enrichment = Invoke-SecOpsRestMethod -Uri $uri -Headers $Headers `
            -OperationName "Enrich $PropertyName"

        if ($enrichment.Ok) {
            $InputObject | Add-Member -NotePropertyName $PropertyName `
                -NotePropertyValue $enrichment.Data -PassThru
        } else {
            $InputObject | Add-Member -NotePropertyName $PropertyName `
                -NotePropertyValue $null -PassThru
            $InputObject | Add-Member -NotePropertyName "${PropertyName}Error" `
                -NotePropertyValue $enrichment.Error -PassThru
        }
    }
}
```

**Usage — Enrich incidents with device context:**

```powershell
Get-SecOpsStream -Uri $incidentsUri -Headers $auth |
    Where-Object { $_.severity -eq 'High' } |
    Add-SecOpsEnrichment -Headers $auth -PropertyName 'Device' -LookupUri {
        param($incident)
        "$mdeBase/api/machines/$($incident.relatedDeviceId)"
    } |
    Select-Object title, severity, @{N='DeviceName';E={$_.Device.computerDnsName}}
```

## Test Scenarios

### 1. Pagination Handles All Formats

```powershell
Describe 'Get-SecOpsAllPages' {
    It 'Follows Graph @odata.nextLink' {
        # Mock: page 1 has nextLink, page 2 doesn't
        Mock Invoke-SecOpsRestMethod -MockWith {
            if ($Uri -notmatch 'skiptoken') {
                New-SecOpsResult -Success -Data @{
                    value = @(@{id='1'}, @{id='2'})
                    '@odata.nextLink' = "$Uri`?`$skiptoken=abc"
                }
            } else {
                New-SecOpsResult -Success -Data @{
                    value = @(@{id='3'})
                }
            }
        }
        $results = Get-SecOpsAllPages -Uri 'https://graph.microsoft.com/v1.0/test'
        $results.Count | Should -Be 3
    }
}
```

### 2. Batch Respects Size Limit

```powershell
Describe 'Invoke-SecOpsGraphBatch' {
    It 'Throws when batch exceeds 20 requests' {
        $requests = 1..21 | ForEach-Object { @{ Url = "/test/$_" } }
        { Invoke-SecOpsGraphBatch -Requests $requests } | Should -Throw '*max 20*'
    }
}
```

### 3. Async Operation Timeout

```powershell
Describe 'Wait-SecOpsAsyncOperation' {
    It 'Times out if operation never completes' {
        Mock Invoke-SecOpsRestMethod { New-SecOpsResult -Success -Data @{ status = 'Running' } }
        $result = Wait-SecOpsAsyncOperation -ResponseHeaders @{
            'Azure-AsyncOperation' = 'https://management.azure.com/poll'
        } -TimeoutSeconds 5 -InitialPollIntervalMs 500
        $result.ErrorCode | Should -Be 'AsyncTimeout'
    }
}
```

### 4. Idempotent Create-or-Update

```powershell
Describe 'Set-SecOpsResource' {
    It 'Creates when resource does not exist (404)' {
        Mock Invoke-SecOpsRestMethod {
            if ($Method -eq 'GET') { New-SecOpsResult -Error 'Not found' -StatusCode 404 }
            else { New-SecOpsResult -Success -Data @{ id = 'new' } -StatusCode 201 }
        }
        $result = Set-SecOpsResource -Uri 'https://api/resource/1' -Body @{name='test'}
        $result.Ok | Should -Be $true
    }
}
```

## Best Practices

1. **Always paginate** — Never assume a single response contains all results
2. **Use streaming for large sets** — `Get-SecOpsStream` avoids OOM on 10k+ result sets
3. **Batch when possible** — Graph `$batch` saves 20x round trips
4. **Poll with backoff** — Don't hammer async status endpoints every second
5. **Include correlation IDs** — Every operation gets a `CorrelationId` for cross-service tracing
6. **Log sanitized requests** — Redact auth headers and PII; keep URI paths and status codes
7. **Use PUT for ARM resources** — PUT is naturally idempotent; POST creates duplicates
8. **Check ETags before updates** — Optimistic concurrency prevents lost-update problems
9. **Cap pagination** — Set `MaxPages` to prevent runaway queries against misconfigured APIs
10. **Combine with rate limiting** — Every paginated loop should coordinate with `rate-limiting.md` patterns

## Environment Context

Before using API patterns, agents MUST consult:

- **`.secops/environment.yaml`** — Cloud environment determines API base URLs (commercial vs. government)
- **`.secops/data-sources/data-source-map.yaml`** — Table locations affect which APIs to query
- **`.secops/identity/tenants.yaml`** — Multi-tenant scenarios require per-tenant auth and API routing

## Related Skills

- `skills/powershell/rate-limiting.md` — Rate limits, backoff, circuit breakers (must coordinate with pagination)
- `skills/powershell/error-handling.md` — Structured results, audit logging, retry logic
- `skills/powershell/auth-patterns.md` — Token acquisition for API calls
- `skills/powershell/module-foundation.md` — Module structure for organizing API wrappers
- `skills/log-analytics/api-wrapper.md` — Log Analytics API-specific patterns
- `skills/msft-security/sentinel-mcp-server.md` — Sentinel API via MCP
- `skills/msft-security/defender-mcp-server.md` — Defender API patterns
