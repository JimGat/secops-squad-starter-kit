---
title: Detect Brute-Force Attacks (Splunk)
category: identity
difficulty: intermediate
intent: detect.brute-force
adapter: splunk
mitre_attack:
  - T1110       # Brute Force
  - T1110.001   # Password Guessing
  - T1110.003   # Password Spraying
  - T1110.004   # Credential Stuffing
products:
  - Splunk Enterprise
  - Splunk Cloud
  - Splunk Enterprise Security
---

# Detect Brute-Force Attacks (Splunk)

## Overview

This skill implements the `detect.brute-force` intent for Splunk deployments.
It creates a correlation search that alerts when authentication failure patterns
indicate brute-force activity.

## Detection Logic

### Password Spraying Detection (Scheduled)

Triggers when a single source IP fails authentication against many distinct
accounts within a short window.

```spl
index=auth (action=failure OR status=failed OR EventCode=4625)
| bin _time span=5m
| stats count as failures, dc(user) as unique_targets by src_ip, _time
| where failures > $threshold$ AND unique_targets > 3
| eval attack_type="password_spraying"
| sort -failures
```

### Credential Stuffing Detection (Scheduled)

Triggers when many distinct source IPs fail authentication against a single
account, suggesting a credential stuffing list.

```spl
index=auth (action=failure OR status=failed OR EventCode=4625)
| bin _time span=1h
| stats count as failures, dc(src_ip) as unique_sources by user, _time
| where failures > $threshold$ AND unique_sources > 5
| eval attack_type="credential_stuffing"
| sort -failures
```

### Single-Source Brute Force (Scheduled)

A single IP hammering a single account.

```spl
index=auth (action=failure OR status=failed OR EventCode=4625)
| bin _time span=5m
| stats count as failures by src_ip, user, _time
| where failures > $threshold$
| eval attack_type="single_source_bruteforce"
| sort -failures
```

## Deployment as Correlation Search

1. **Splunk Enterprise Security:** Content > Content Management > New Correlation Search
2. **Vanilla Splunk:** Settings > Searches, Reports, and Alerts > New Alert

### Key Settings

| Setting | Value |
|---|---|
| Search | One of the SPL queries above |
| Time range | `-5m` to `now` (or `-1h` for stuffing) |
| Trigger | Number of results > 0 |
| Severity | Medium (spraying) / High (single-source) |
| Actions | Email, SOAR webhook, notable event (ES) |

## SOAR Integration

When using Splunk SOAR, configure the alert to trigger a playbook:

```yaml
playbook: brute_force_response
trigger: splunk_alert
actions:
  - enrich_source_ip:
      type: ip_reputation
      tools: [virustotal, shodan, abuseipdb]
  - check_user_accounts:
      type: identity_lookup
      tools: [active_directory, okta]
  - assess_and_respond:
      type: conditional
      branches:
        high_confidence:
          - block_ip_firewall
          - lock_user_account
          - notify_soc_teams
        low_confidence:
          - create_notable_event
          - assign_to_analyst
```

## Tuning Guidelines

- **Threshold:** Start at 10 failures per 5 minutes, adjust after 1 week of FP analysis
- **Whitelisting:** Add `NOT src_ip IN (scanner_ips, admin_workstations)` 
- **Business logic:** Exclude service accounts that legitimately retry
- **ES integration:** Map to `Authentication` data model for acceleration

## Response Procedures

See `respond.compromised-account` intent and `adapters/splunk/skills/respond-compromised-account.md`.
