---
title: External Threat Intelligence Enrichment
category: detection
difficulty: advanced
mitre_attack:
  - T1071      # Application Layer Protocol — C2 domains in TI feeds
  - T1566      # Phishing — malicious URL/domain indicators
  - T1190      # Exploit Public-Facing Application — KEV-linked CVEs
  - T1059      # Command and Scripting Interpreter — malware hash IOCs
products:
  - Microsoft Sentinel
  - Microsoft Defender Threat Intelligence
  - CISA KEV
  - VirusTotal
  - Shodan
  - AlienVault OTX
  - MISP
  - abuse.ch
author: Freamon
version: 1.0.0
last_updated: 2026-05-04
---

# External Threat Intelligence Enrichment

## Overview

Internal telemetry tells you what happened; external TI tells you whether those events match known-bad activity globally. Without external TI, your SOC is blind to known-bad indicators, actively exploited vulnerabilities (CISA KEV), and coordinated campaigns.

This skill covers feed integration, Sentinel/Defender TI workflows, PowerShell automation for multi-source aggregation, and KQL correlation patterns.

**Complements:** [watchlist-driven-detection.md](watchlist-driven-detection.md), [sentinel-api-wrapper.md](../powershell/sentinel-api-wrapper.md), [rate-limiting.md](../powershell/rate-limiting.md).

## Environment Context

| File | Check |
|---|---|
| `data-sources/data-source-map.yaml` | Existing TI sources, connector status |
| `workspaces/*.yaml` | Target workspace IDs for TI indicator import |
| `compliance/requirements.yaml` | Data residency for external feed storage |

## Feed Integration

### CISA KEV (Known Exploited Vulnerabilities)

CISA's [JSON catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) lists CVEs confirmed as actively exploited — the highest-confidence vulnerability prioritization source.

```powershell
function Import-CISAKevFeed {
    [CmdletBinding()]
    param(
        [string]$WorkspaceName = (Get-SecOpsConfig).PrimaryWorkspace,
        [string]$WatchlistAlias = "CISA_KEV",
        [string]$FeedUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    $response = Invoke-SecOpsRestMethod -Uri $FeedUrl -Method GET
    if (-not $response.ok) { return New-SecOpsResult -Ok $false -Error "KEV fetch failed: $($response.error)" }

    $vulns = ($response.data | ConvertFrom-Json).vulnerabilities
    $items = $vulns | ForEach-Object {
        [PSCustomObject]@{
            cveID = $_.cveID; vendorProject = $_.vendorProject; product = $_.product
            dateAdded = $_.dateAdded; knownRansomware = $_.knownRansomwareCampaignUse
        }
    }
    Update-SentinelWatchlist -WorkspaceName $WorkspaceName -WatchlistAlias $WatchlistAlias `
        -Items $items -SearchKey "cveID"
}
```

### abuse.ch Feeds

| Feed | Endpoint | Content | Frequency |
|---|---|---|---|
| **URLhaus** | `urlhaus-api.abuse.ch/v1/urls/recent/` | Malicious URLs | ~5 min |
| **MalBazaar** | `mb-api.abuse.ch/api/v1/` | Malware hashes | ~10 min |
| **ThreatFox** | `threatfox-api.abuse.ch/api/v1/` | IOCs (IP/domain/URL/hash) | ~15 min |

```powershell
function Import-AbuseCHFeed {
    [CmdletBinding()]
    param(
        [ValidateSet("URLhaus", "MalBazaar", "ThreatFox")][string]$Feed = "ThreatFox",
        [int]$DaysBack = 7
    )
    $endpoints = @{
        URLhaus   = @{ Uri = "https://urlhaus-api.abuse.ch/v1/urls/recent/"; Method = "GET" }
        MalBazaar = @{ Uri = "https://mb-api.abuse.ch/api/v1/"; Method = "POST"; Body = @{ query = "get_recent"; selector = $DaysBack } }
        ThreatFox = @{ Uri = "https://threatfox-api.abuse.ch/api/v1/"; Method = "POST"; Body = @{ query = "get_iocs"; days = $DaysBack } }
    }
    $ep = $endpoints[$Feed]
    $params = @{ Uri = $ep.Uri; Method = $ep.Method }
    if ($ep.Body) { $params.Body = ($ep.Body | ConvertTo-Json) }
    $response = Invoke-SecOpsRestMethod @params
    if (-not $response.ok) { return New-SecOpsResult -Ok $false -Error "$Feed fetch failed" }
    $iocs = Convert-AbuseCHToIndicators -Feed $Feed -RawData $response.data
    Update-SentinelWatchlist -WatchlistAlias "AbuseCH_$Feed" -Items $iocs -SearchKey "indicator_value"
    return New-SecOpsResult -Ok $true -Data @{ Feed = $Feed; Count = $iocs.Count }
}
```

### VirusTotal API

File/URL/domain/IP reputation lookups. Free tier: 4 req/min, 500/day. Premium unlocks bulk and hunting.

```powershell
function Get-VirusTotalEnrichment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Indicator,
        [ValidateSet("file","url","domain","ip")][string]$Type = "file"
    )
    $apiKey = Get-SecOpsSecret -Name "VirusTotal-ApiKey"
    $uri = switch ($Type) {
        "file"   { "https://www.virustotal.com/api/v3/files/$Indicator" }
        "url"    { "https://www.virustotal.com/api/v3/urls/$(ConvertTo-Base64Url $Indicator)" }
        "domain" { "https://www.virustotal.com/api/v3/domains/$Indicator" }
        "ip"     { "https://www.virustotal.com/api/v3/ip_addresses/$Indicator" }
    }
    $response = Invoke-SecOpsRestMethod -Uri $uri -Headers @{"x-apikey"=$apiKey} -Method GET -RateLimitTier "External"
    if (-not $response.ok) { return New-SecOpsResult -Ok $false -Error "VT lookup failed: $($response.error)" }
    $attrs = ($response.data | ConvertFrom-Json).data.attributes
    return New-SecOpsResult -Ok $true -Data @{
        Indicator = $Indicator; Malicious = $attrs.last_analysis_stats.malicious
        Suspicious = $attrs.last_analysis_stats.suspicious; Reputation = $attrs.reputation
    }
}
```

### Shodan API

Internet-facing asset discovery and exposure validation — verify whether assets are externally visible and what services are exposed.

```powershell
function Get-ShodanHostInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$IPAddress)
    $apiKey = Get-SecOpsSecret -Name "Shodan-ApiKey"
    $response = Invoke-SecOpsRestMethod -Uri "https://api.shodan.io/shodan/host/$IPAddress`?key=$apiKey" -Method GET
    if (-not $response.ok) { return New-SecOpsResult -Ok $false -Error "Shodan lookup failed" }
    $data = $response.data | ConvertFrom-Json
    return New-SecOpsResult -Ok $true -Data @{
        IP = $data.ip_str; Org = $data.org; Ports = $data.ports
        Vulns = $data.vulns; Hostnames = $data.hostnames
    }
}
```

### AlienVault OTX

Pulse subscriptions deliver community-curated IOCs grouped by threat campaign.

```powershell
function Import-OTXPulseIOCs {
    [CmdletBinding()]
    param([int]$DaysSubscribed = 30, [string]$WatchlistAlias = "OTX_Indicators")
    $apiKey = Get-SecOpsSecret -Name "OTX-ApiKey"
    $since = (Get-Date).AddDays(-$DaysSubscribed).ToString("yyyy-MM-ddTHH:mm:ss")
    $response = Invoke-SecOpsRestMethod -Uri "https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since=$since" `
        -Headers @{"X-OTX-API-KEY"=$apiKey} -Method GET -RateLimitTier "External"
    if (-not $response.ok) { return New-SecOpsResult -Ok $false -Error "OTX fetch failed" }
    $pulses = ($response.data | ConvertFrom-Json).results
    $indicators = $pulses | ForEach-Object { $_.indicators | ForEach-Object {
        [PSCustomObject]@{ indicator_value = $_.indicator; indicator_type = $_.type; created = $_.created }
    }}
    Update-SentinelWatchlist -WatchlistAlias $WatchlistAlias -Items $indicators -SearchKey "indicator_value"
    return New-SecOpsResult -Ok $true -Data @{ Indicators = $indicators.Count; Pulses = $pulses.Count }
}
```

### MISP Integration (TAXII/STIX)

Sentinel consumes MISP feeds natively via TAXII 2.1 connector (Content Hub → Threat Intelligence TAXII solution → Data connectors). Configure with MISP's TAXII API root, collection UUID, and API key as username. For non-TAXII instances, use `Import-MISPEvents` — fetches `/events/restSearch` filtered by tags and `enforceWarninglist`, extracting attributes where `to_ids` is true.

## Sentinel TI Integration

### Data Connector Paths

| Path | Use Case |
|---|---|
| **TAXII connector** | MISP, CISA, any TAXII 2.x server |
| **Graph API (tiIndicators)** | Custom feeds — requires `ThreatIndicators.ReadWrite.OwnedBy` |
| **Upload Indicators API** | Bulk STIX 2.1 import via Sentinel workspace API |

### ThreatIntelligenceIndicator Table

All indicators land in `ThreatIntelligenceIndicator` regardless of source:

```kql
ThreatIntelligenceIndicator
| where TimeGenerated > ago(24h)
| where Active == true
| summarize Count = count() by SourceSystem, IndicatorType
| sort by Count desc
```

### Built-In TI Analytics Rules

Sentinel ships rule templates that auto-join TI against logs: `TI map IP → SigninLogs`, `TI map Domain → DnsEvents`, `TI map FileHash → DeviceFileEvents`, `TI map URL → UrlClickEvents`, `TI map Email → SecurityAlert`.

## Defender TI Integration

### Reputation Scoring & Intelligence Articles

```powershell
function Get-DefenderTIReputation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Indicator,
        [ValidateSet("host","ipAddress")][string]$Type = "host"
    )
    $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
    $headers = @{ Authorization = "Bearer $token" }
    $rep = Invoke-SecOpsRestMethod -Uri "https://graph.microsoft.com/beta/security/threatIntelligence/${Type}s/$Indicator/reputation" `
        -Headers $headers -Method GET
    $articles = Invoke-SecOpsRestMethod -Uri "https://graph.microsoft.com/beta/security/threatIntelligence/articles?`$filter=indicators/any(i:i/artifact eq '$Indicator')" `
        -Headers $headers -Method GET
    return New-SecOpsResult -Ok $true -Data @{
        Score = ($rep.data | ConvertFrom-Json).score
        Category = ($rep.data | ConvertFrom-Json).classification
        Articles = ($articles.data | ConvertFrom-Json).value | Select-Object title, createdDateTime
    }
}
```

## PowerShell Automation

### Multi-Source Feed Orchestrator

```powershell
function Import-ThreatIntelFeed {
    [CmdletBinding()]
    param(
        [ValidateSet("All","CISA_KEV","AbuseCH","OTX","MISP","DefenderTI")]
        [string[]]$Sources = @("All"),
        [switch]$DryRun
    )
    $config = Get-SecOpsConfig -File "data-sources/ti-feeds.yaml"
    if (-not $config) {
        Write-Warning "No .secops/data-sources/ti-feeds.yaml — using defaults"
        $config = @{ feeds = @{ cisa_kev = @{ enabled = $true }; abusech = @{ enabled = $true; feeds = @("ThreatFox","URLhaus") } } }
    }
    $results = @{}
    if (($Sources -contains "All" -or $Sources -contains "CISA_KEV") -and $config.feeds.cisa_kev.enabled) {
        $results.CISA_KEV = if ($DryRun) { "[DryRun]" } else { Import-CISAKevFeed }
    }
    if (($Sources -contains "All" -or $Sources -contains "AbuseCH") -and $config.feeds.abusech.enabled) {
        foreach ($f in $config.feeds.abusech.feeds) {
            $results["AbuseCH_$f"] = if ($DryRun) { "[DryRun]" } else { Import-AbuseCHFeed -Feed $f }
        }
    }
    return New-SecOpsResult -Ok $true -Data $results
}
```

### IOC Enrichment Aggregator

```powershell
function Get-IOCEnrichment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Indicator,
        [ValidateSet("ip","domain","url","hash")][string]$Type,
        [string[]]$Sources = @("VirusTotal","Shodan","DefenderTI","Sentinel")
    )
    $enrichment = @{ Indicator = $Indicator; Type = $Type; Sources = @{} }; $hits = 0
    if ($Sources -contains "VirusTotal") {
        $vt = Get-VirusTotalEnrichment -Indicator $Indicator -Type $(if($Type -eq "hash"){"file"}else{$Type})
        $enrichment.Sources.VirusTotal = $vt
        if ($vt.ok -and $vt.data.Malicious -gt 0) { $hits++ }
    }
    if ($Sources -contains "Shodan" -and $Type -eq "ip") {
        $enrichment.Sources.Shodan = Get-ShodanHostInfo -IPAddress $Indicator
    }
    if ($Sources -contains "DefenderTI" -and $Type -in @("ip","domain")) {
        $dti = Get-DefenderTIReputation -Indicator $Indicator -Type $(if($Type -eq "ip"){"ipAddress"}else{"host"})
        $enrichment.Sources.DefenderTI = $dti
        if ($dti.ok -and $dti.data.Score -lt 0) { $hits++ }
    }
    $enrichment.Confidence = switch ($hits) { 0 {"None"} 1 {"Low"} 2 {"Medium"} {$_ -ge 3} {"High"} }
    return New-SecOpsResult -Ok $true -Data $enrichment
}
```

## KQL Correlation

### Join TI Against Sign-In Logs

```kql
let TI_IPs = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(14d) and Active == true and ExpirationDateTime > now()
    | where isnotempty(NetworkIP)
    | summarize arg_max(TimeGenerated, *) by NetworkIP;
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == 0
| join kind=inner TI_IPs on $left.IPAddress == $right.NetworkIP
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ThreatType, ConfidenceScore
```

### Multi-Source IOC Scoring

IOCs appearing in 3+ feeds get high confidence:

```kql
ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d) and Active == true and ExpirationDateTime > now()
| extend IndicatorValue = coalesce(NetworkIP, DomainName, Url, FileHashValue)
| where isnotempty(IndicatorValue)
| summarize SourceCount = dcount(SourceSystem), Sources = make_set(SourceSystem),
    MaxConfidence = max(ConfidenceScore) by IndicatorValue, IndicatorType
| extend AggregateScore = case(SourceCount >= 3, "High", SourceCount == 2, "Medium", "Low")
| where AggregateScore in ("High", "Medium")
| sort by SourceCount desc
```

### Time-Decay Indicator Freshness

```kql
let DecayHalfLifeDays = 30.0;
ThreatIntelligenceIndicator
| where Active == true and ExpirationDateTime > now()
| extend IndicatorValue = coalesce(NetworkIP, DomainName, Url, FileHashValue)
| where isnotempty(IndicatorValue)
| extend AgeDays = datetime_diff('day', now(), TimeGenerated)
| extend DecayedConfidence = toint(ConfidenceScore * exp(-0.693 * toreal(AgeDays) / DecayHalfLifeDays))
| where DecayedConfidence > 20
| project IndicatorValue, IndicatorType, ConfidenceScore, DecayedConfidence, AgeDays, SourceSystem
| sort by DecayedConfidence desc
```

## `.secops/` Integration

### Feed Config Template (`data-sources/ti-feeds.yaml`)

```yaml
schema_version: "1.0"
feeds:
  cisa_kev:
    enabled: true
    schedule: daily
    watchlist_alias: CISA_KEV
  abusech:
    enabled: true
    schedule: hourly
    feeds: [ThreatFox, URLhaus]
  virustotal:
    enabled: true
    api_key_vault: "VirusTotal-ApiKey"
    tier: free  # free | premium
    daily_quota: 500
  shodan:
    enabled: false
    api_key_vault: "Shodan-ApiKey"
  otx:
    enabled: false
    api_key_vault: "OTX-ApiKey"
  misp:
    enabled: false
    base_url: "https://misp.example.com"
    api_key_vault: "MISP-ApiKey"
    tags_filter: ["tlp:white", "tlp:green"]
  defender_ti:
    enabled: true
    schedule: daily
api_keys:
  key_vault_name: "secops-kv-prod"
```

### Feed Health Monitoring

```powershell
function Test-TIFeedHealth {
    [CmdletBinding()]
    param()
    $config = Get-SecOpsConfig -File "data-sources/ti-feeds.yaml"
    $health = foreach ($feedName in $config.feeds.Keys) {
        $feed = $config.feeds[$feedName]
        if (-not $feed.enabled) { continue }
        $lastIndicator = Invoke-SecOpsQuery -Query "ThreatIntelligenceIndicator | where SourceSystem contains '$feedName' | summarize LastSeen = max(TimeGenerated)"
        $staleHours = if ($lastIndicator) { [math]::Round(((Get-Date) - [datetime]$lastIndicator.LastSeen).TotalHours, 1) } else { -1 }
        [PSCustomObject]@{
            Feed = $feedName; Schedule = $feed.schedule; StaleHours = $staleHours
            Status = if ($staleHours -lt 0){"NoData"} elseif ($staleHours -gt 48){"Critical"} elseif ($staleHours -gt 24){"Warning"} else {"Healthy"}
        }
    }
    $health | Format-Table -AutoSize
    return New-SecOpsResult -Ok $true -Data $health
}
```

## Quick Reference

| Function | Purpose |
|---|---|
| `Import-CISAKevFeed` | Import CISA KEV to watchlist |
| `Import-AbuseCHFeed` | Import URLhaus/MalBazaar/ThreatFox |
| `Get-VirusTotalEnrichment` | Single IOC VT lookup |
| `Get-ShodanHostInfo` | IP exposure validation |
| `Import-OTXPulseIOCs` | AlienVault OTX pulse import |
| `Import-MISPEvents` | MISP event/attribute import |
| `Get-DefenderTIReputation` | Defender TI reputation & articles |
| `Import-ThreatIntelFeed` | Multi-source orchestrator |
| `Get-IOCEnrichment` | Multi-source IOC aggregator |
| `Test-TIFeedHealth` | Feed freshness monitoring |
