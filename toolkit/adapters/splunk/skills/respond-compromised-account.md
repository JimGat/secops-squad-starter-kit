---
title: Respond to Compromised Account (Splunk)
category: identity
difficulty: advanced
intent: respond.compromised-account
adapter: splunk
mitre_attack:
  - T1078       # Valid Accounts
  - T1530       # Data from Cloud Storage
products:
  - Splunk Enterprise
  - Splunk SOAR
---

# Respond to Compromised Account (Splunk)

## Overview

This skill implements the `respond.compromised-account` intent for Splunk
deployments. It covers the full response lifecycle from detection through
containment, investigation, and recovery.

## Response Workflow

### Phase 1: Immediate Containment (Automated)

```yaml
playbook: compromised_account_response
priority: critical
sla: 15 minutes
steps:
  - action: revoke_active_sessions
    description: >
      Terminate all active sessions for the affected user.
      Implementation varies by identity provider.
    implementations:
      okta: |
        POST /api/v1/users/{userId}/sessions?deleteOngoingSessions=true
      azure_ad: |
        POST https://graph.microsoft.com/v1.0/users/{userId}/revokeSignInSessions
      active_directory: |
        # Reset password and force change at next logon
        Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $tempPassword -Force)
        Set-ADUser -Identity $user -ChangePasswordAtLogon $true

  - action: disable_account
    description: >
      Disable the account to prevent further authentication.
      Coordinate with service desk for user communication.
    implementations:
      okta: |
        POST /api/v1/users/{userId}/lifecycle/deactivate
      azure_ad: |
        PATCH https://graph.microsoft.com/v1.0/users/{userId}
        { "accountEnabled": false }
      active_directory: |
        Disable-ADAccount -Identity $user
```

### Phase 2: Blast Radius Assessment (Automated + Analyst)

Run this Splunk query to understand what the compromised account accessed:

```spl
index=* user={compromised_user}
| eval action=coalesce(action, Operation, eventName)
| stats count as events, dc(dest) as systems_accessed, 
        earliest(_time) as first_seen, latest(_time) as last_seen
        by sourcetype, action
| convert ctime(first_seen) ctime(last_seen)
| sort -events
```

Data exfiltration check:

```spl
index=* user={compromised_user} (action=file_download OR action=share_created OR EventCode=4663)
| stats sum(file_size) as total_bytes, count as operations by dest, file_path
| eval total_mb=round(total_bytes/1048576, 2)
| where total_mb > 100
| sort -total_mb
```

### Phase 3: Persistence Hunting (Analyst)

Check for persistence mechanisms the attacker may have left:

```spl
index=* user={compromised_user}
  (action IN ("app.consent.grant", "Add member", "Add app role assignment") 
   OR EventCode IN (4720, 4728, 4732, 4756))
| table _time, action, target_user, target_group, Computer
```

### Phase 4: Recovery

| Step | Action | Automation |
|---|---|---|
| 1 | Re-enable account | SOAR playbook (manual approval) |
| 2 | Enforce MFA enrollment | Identity provider API |
| 3 | Update detection rules | Add IOCs to threat intel |
| 4 | Document in SIEM | Create notable event with full timeline |
| 5 | User communication | Service desk notification |

## SOAR Playbook Template

```json
{
  "name": "Compromised Account Response - Splunk",
  "description": "Automated response to compromised user accounts",
  "triggers": [
    { "type": "splunk_alert", "search_name": "compromised_account_*" },
    { "type": "manual", "role": "soc_analyst" }
  ],
  "actions": [
    { "id": "enrich_user", "type": "identity_lookup", "timeout": 30 },
    { "id": "revoke_sessions", "type": "api_call", "requires_approval": false },
    { "id": "assess_blast", "type": "splunk_search", "timeout": 120 },
    { "id": "check_persistence", "type": "splunk_search", "timeout": 120 },
    { "id": "decision_gate", "type": "conditional", "requires_human": true,
      "branches": {
        "confirm_compromise": ["disable_account", "block_ips", "notify_user"],
        "false_positive": ["close_incident", "tune_detection"]
      }
    },
    { "id": "generate_report", "type": "report", "format": "markdown" }
  ]
}
```

## Escalation Criteria

Escalate to IR lead immediately if:
- Compromised account has admin/elevated privileges
- Evidence of data exfiltration > 1 GB
- Lateral movement detected to critical systems
- Persistence mechanisms found (new service accounts, app consent grants)
- Attack is ongoing (events in the last 30 minutes)
