---
title: Hunt for Suspicious Sign-Ins (Splunk)
category: identity
difficulty: intermediate
intent: hunt.suspicious-signins
adapter: splunk
mitre_attack:
  - T1110       # Brute Force
  - T1110.001   # Password Guessing
  - T1110.003   # Password Spraying
  - T1078       # Valid Accounts
products:
  - Splunk Enterprise
  - Splunk Cloud
  - Splunk Enterprise Security
---

# Hunt for Suspicious Sign-Ins (Splunk)

## Overview

This skill implements the `hunt.suspicious-signins` intent for Splunk deployments.
It covers three hunting patterns: brute-force detection, impossible travel, and
credential stuffing.

## Prerequisites

| Requirement | Detail |
|---|---|
| **Splunk** | Splunk Enterprise 8.x+ or Splunk Cloud |
| **Data** | Authentication events (Azure AD, Windows Security, or Okta sourcetypes) |
| **Permissions** | `admin` or `power_user` role for search execution |
| **Add-ons** | Recommended: Splunk Add-on for Microsoft Azure, Splunk Add-on for Microsoft Office 365 |

## Data Source Mapping

This skill adapts to whatever authentication data you have in Splunk:

| Sourcetype | Source | Key Fields |
|---|---|---|
| `azure:aad:signin` | Azure AD Sign-in logs | `user`, `src_ip`, `app`, `Location`, `ResultType` |
| `o365:management:activity` | O365 audit | `UserId`, `ClientIP`, `Operation` |
| `wineventlog:security` | Windows Event 4624/4625 | `TargetUserName`, `IpAddress`, `LogonType`, `EventCode` |
| `okta:identity` | Okta System Log | `actor.alternateId`, `client.ipAddress`, `eventType` |
| `aws:cloudtrail` | AWS CloudTrail | `userIdentity.arn`, `sourceIPAddress`, `eventName` |

## Hunt 1: Brute-Force / Password Spraying

### SPL Query

```spl
index=* sourcetype IN (azure:aad:signin, wineventlog:security, okta:identity)
  (EventCode=4625 OR ResultType!=0 OR eventType="user.session.start" AND outcome.result="FAILURE")
| eval user=coalesce(user, TargetUserName, actor.alternateId, userIdentity.arn)
| eval src_ip=coalesce(src_ip, IpAddress, client.ipAddress, sourceIPAddress)
| bin _time span=5m
| stats count as attempts, dc(user) as unique_users by src_ip, _time
| where attempts > 10 AND unique_users > 3
| sort -attempts
```

### Tuning Notes

- `attempts > 10` -- lower for sensitive environments, raise for high-volume ones
- `unique_users > 3` -- distinguishes spraying (many users) from credential stuffing (one user)
- Add `NOT src_ip IN (known_admin_ips)` to exclude legitimate scanners

## Hunt 2: Impossible Travel

### SPL Query

```spl
index=* sourcetype IN (azure:aad:signin, okta:identity)
  (ResultType=0 OR outcome.result="SUCCESS")
| eval user=coalesce(user, actor.alternateId)
| eval src_ip=coalesce(src_ip, client.ipAddress)
| eval lat=coalesce(latitudedegrees, 0), lon=coalesce(longitudedegrees, 0)
| sort user _time
| streamstats current=f last(lat) as prev_lat last(lon) as prev_lon last(_time) as prev_time by user
| eval distance_km=6371*acos(cos(radians(lat))*cos(radians(prev_lat))*cos(radians(prev_lon)-radians(lon))+sin(radians(lat))*sin(radians(prev_lat)))
| eval time_diff_hours=(_time-prev_time)/3600
| eval speed_kmh=if(time_diff_hours>0, distance_km/time_diff_hours, 0)
| where speed_kmh > 800
| table _time, user, src_ip, prev_lat, lat, speed_kmh
```

### Tuning Notes

- `speed_kmh > 800` -- roughly 500 mph, adjust for your environment
- Requires geo-enrichment (iplocation command or latitude/longitude fields from Azure AD)
- If using `iplocation`, add `| iplocation src_ip` before the eval chain

## Hunt 3: Credential Stuffing

### SPL Query

```spl
index=* sourcetype IN (azure:aad:signin, wineventlog:security, okta:identity)
  (EventCode=4625 OR ResultType!=0 OR outcome.result="FAILURE")
| eval user=coalesce(user, TargetUserName, actor.alternateId)
| eval src_ip=coalesce(src_ip, IpAddress, client.ipAddress)
| bin _time span=1h
| stats count as failures, dc(src_ip) as source_ips by user, _time
| where failures > 20 AND source_ips < 3
| sort -failures
```

### Tuning Notes

- Pattern: many failures from few IPs against one user = credential stuffing
- Compare against Hunt 1: spraying = many users, few IPs; stuffing = one user, few IPs
- Cross-reference with threat intel: `| lookup threat_intel_ip ip AS src_ip OUTPUT reputation | where reputation="malicious"`

## Saved Searches for Alerting

Convert any hunt into a Splunk alert:

1. Save as **Alert** via Splunk Web or `savedsearches.conf`
2. Set trigger condition: `where count > threshold`
3. Action: email, webhook to SOAR, or Splunk SOAR playbook trigger

### Example: savedsearches.conf

```ini
[suspicious_signins_brute_force]
search = index=* sourcetype IN (azure:aad:signin, wineventlog:security) (EventCode=4625 OR ResultType!=0) | stats count as attempts by src_ip, user | where attempts > 10
dispatch.earliest_time = -5m
dispatch.latest_time = now
alert.severity = 3
alert_type = number of events
alert_threshold = 1
action.email = 1
action.email.to = soc@example.com
```
