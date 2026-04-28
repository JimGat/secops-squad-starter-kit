---
title: "Phishing Incident Auto-Triage & Remediation"
category: soar
difficulty: advanced
trigger_type: sentinel-incident
products:
  - Microsoft Sentinel
  - Microsoft Defender for Office 365
  - Office 365
  - Entra ID
  - Microsoft Defender Threat Intelligence
api_connections:
  - azuresentinel
  - office365
  - azuread
  - teams
  - virustotal
author: Herc
version: 1.0.0
mitre_attack:
  - T1566.001  # Spearphishing Attachment
  - T1566.002  # Spearphishing Link
---

# Phishing Incident Auto-Triage & Remediation

## Overview

This playbook automates the full lifecycle of a phishing incident — from initial triage through enrichment, verdict, remediation, and closure. It is triggered by a Microsoft Sentinel incident created from phishing-related analytics rules (e.g., "Phishing email detected by MDO", "Suspicious URL clicked", "Mail forwarding rule created").

**Business justification:** Phishing is the #1 initial access vector. SOC analysts spend 15-30 minutes per phishing incident on manual triage. At 50+ incidents/day, that's 12+ analyst-hours burned on repetitive work. This playbook cuts mean-time-to-respond from 25 minutes to under 90 seconds for commodity phishing attempts, and under 5 minutes for targeted campaigns that require human review.

**What it does:**
1. Extracts email metadata and IOCs from the Sentinel incident entities
2. Enriches URLs and sender domains via VirusTotal and MDTI
3. Validates SPF/DKIM/DMARC for the sender domain
4. Applies a verdict: auto-close (spam), auto-remediate (known-bad), or escalate (targeted)
5. Remediates: purges email from all mailboxes, blocks sender domain, pushes IOCs to Threat Intelligence
6. Updates the Sentinel incident with findings, tags, and severity adjustments

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Microsoft Sentinel                            │
│  Analytics Rule fires → Incident created → Trigger fires        │
└──────────────┬───────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────┐
│  1. Parse Incident       │
│  Extract: sender, URLs,  │
│  subject, recipients,    │
│  attachment hashes        │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐     ┌─────────────────────┐
│  2. Enrich IOCs          │────▶│  VirusTotal API     │
│  - URL reputation        │     │  MDTI API           │
│  - Domain age/reputation │     │  Whois lookup       │
│  - File hash check       │     └─────────────────────┘
│  - SPF/DKIM/DMARC check  │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  3. Verdict Engine       │
│  Score = f(reputation,   │
│    domain age, auth,     │
│    URL detections,       │
│    targeted indicators)  │
├──────────────────────────┤
│  Score ≥ 80 → Auto-close │  (obvious spam / marketing)
│  Score 40-79 → Remediate │  (known-bad phishing)
│  Score < 40 → Escalate   │  (targeted / novel campaign)
└──────┬──────┬──────┬─────┘
       │      │      │
       ▼      ▼      ▼
┌──────┐ ┌────────┐ ┌──────────┐
│Close │ │Purge + │ │ Escalate │
│      │ │Block + │ │ to Tier2 │
│      │ │IOC push│ │ + enrich │
└──────┘ └────────┘ └──────────┘
               │
               ▼
┌──────────────────────────┐
│  4. Update Incident      │
│  - Add comments          │
│  - Set severity/status   │
│  - Tag with verdict      │
│  - Attach enrichment     │
└──────────────────────────┘
```

## Prerequisites

### API Connections

| Connection          | Purpose                                  | Auth Method           |
|---------------------|------------------------------------------|-----------------------|
| `azuresentinel`     | Read/update incidents, push TI indicators | Managed Identity      |
| `office365`         | Purge emails, read mail metadata         | Managed Identity      |
| `azuread`           | Look up recipient details                | Managed Identity      |
| `teams`             | Notify SOC channel on escalation         | Managed Identity      |
| VirusTotal (HTTP)   | URL and file hash reputation             | API Key (Key Vault)   |

### Required Permissions

| Permission                              | Type        | Justification                       |
|-----------------------------------------|-------------|-------------------------------------|
| `Microsoft Sentinel Responder`          | Azure RBAC  | Update incidents, run playbooks     |
| `Mail.ReadWrite`                        | Application | Search and purge emails             |
| `Mail.Send`                             | Application | Send notification to affected users |
| `ThreatIndicators.ReadWrite.OwnedBy`    | Application | Push IOCs to Sentinel TI            |
| `SecurityEvents.ReadWrite.All`          | Application | Read security alerts                |
| `User.Read.All`                         | Application | Look up recipient / manager info    |

### Managed Identity Setup

```bash
# Enable system-assigned managed identity on the Logic App
az logic workflow identity assign \
  --resource-group rg-soc-automation \
  --name la-phishing-response \
  --system-assigned

# Grant Sentinel Responder on the workspace
az role assignment create \
  --assignee <logic-app-principal-id> \
  --role "Microsoft Sentinel Responder" \
  --scope /subscriptions/<sub>/resourceGroups/rg-soc/providers/Microsoft.OperationalInsights/workspaces/law-soc

# Grant Graph API permissions (requires admin consent)
az ad app permission add \
  --id <app-id> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions \
    Mail.ReadWrite=Role \
    Mail.Send=Role \
    ThreatIndicators.ReadWrite.OwnedBy=Role \
    User.Read.All=Role
```

### Key Vault Secrets

| Secret Name             | Description                    |
|-------------------------|--------------------------------|
| `VirusTotal-ApiKey`     | VT API key (free tier: 4 req/min) |

## Logic Apps Design

### Trigger

**Type:** `Microsoft Sentinel incident`
**Trigger name:** `Microsoft_Sentinel_incident`

```json
{
  "type": "ApiConnectionWebhook",
  "inputs": {
    "host": {
      "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" }
    },
    "body": {
      "callback_url": "@listCallbackUrl()"
    },
    "path": "/incident-creation"
  }
}
```

**Incident filter:** The analytics rule should be scoped to phishing-related rules. Apply a condition early in the workflow to check:
```
triggerBody()?['object']?['properties']?['relatedAnalyticRuleIds']
```
contains a rule tagged with `Phishing` or the incident title matches patterns like `*phish*`, `*suspicious email*`, `*malicious URL*`.

### Step 1: Parse Incident Entities

**Action:** `Entities - Get Accounts`, `Entities - Get URLs`, `Entities - Get FileHashes`, `Entities - Get Mailboxes`

Extract from the incident:
- **Sender address** — from mailbox or account entities
- **URLs** — all URL entities attached to the incident
- **File hashes** — SHA256 of any attachments
- **Recipients** — mailbox entities that received the email
- **Subject line** — from incident custom fields or alert evidence

```json
{
  "Entities_-_Get_URLs": {
    "type": "ApiConnection",
    "inputs": {
      "host": {
        "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" }
      },
      "method": "post",
      "path": "/entities/url"
    }
  }
}
```

Use `Parse JSON` actions to normalize each entity list into arrays you can iterate.

### Step 2: Enrich IOCs

#### 2a. VirusTotal URL Scan

**Action:** `HTTP` (for each URL entity)

```json
{
  "For_each_URL": {
    "type": "Foreach",
    "foreach": "@body('Entities_-_Get_URLs')?['URLs']",
    "actions": {
      "VT_URL_Report": {
        "type": "Http",
        "inputs": {
          "method": "GET",
          "uri": "https://www.virustotal.com/api/v3/urls/@{base64(items('For_each_URL')?['url'])}",
          "headers": {
            "x-apikey": "@body('Get_VT_Key')?['value']"
          }
        },
        "runtimeConfiguration": {
          "contentTransfer": { "transferMode": "Chunked" }
        }
      }
    },
    "runtimeConfiguration": {
      "concurrency": { "repetitions": 1 }
    }
  }
}
```

> **Rate limit:** VirusTotal free tier allows 4 requests/minute. Set concurrency to 1 and add a 15-second delay between iterations if processing multiple URLs.

#### 2b. MDTI Domain Lookup

**Action:** `HTTP` — call Microsoft Defender Threat Intelligence API

```
GET https://graph.microsoft.com/beta/security/threatIntelligence/hosts/{domain}
```

Extract: reputation score, first/last seen, associated threat actors, tags.

#### 2c. SPF/DKIM/DMARC Validation

**Action:** `HTTP` — query DNS TXT records for the sender domain

```
GET https://dns.google/resolve?name={sender_domain}&type=TXT
```

Parse the response for:
- `v=spf1` record → check if sending IP is authorized
- `v=DKIM1` selector records
- `_dmarc.{domain}` → check policy (none/quarantine/reject)

Flag if DMARC policy is `none` or missing (higher phishing risk).

#### 2d. File Hash Check (if attachments exist)

**Action:** `HTTP` — VirusTotal file report

```
GET https://www.virustotal.com/api/v3/files/{sha256}
```

### Step 3: Verdict Engine

**Action:** `Compose` + `Condition`

Calculate a phishing confidence score:

```json
{
  "Compose_Verdict_Score": {
    "type": "Compose",
    "inputs": {
      "score": "@add(
        if(greater(body('VT_URL_Report')?['data']?['attributes']?['last_analysis_stats']?['malicious'], 5), 30, 0),
        if(equals(variables('dmarc_policy'), 'none'), 15, 0),
        if(less(variables('domain_age_days'), 30), 20, 0),
        if(greater(length(body('Entities_-_Get_URLs')?['URLs']), 0), 10, 0),
        if(contains(triggerBody()?['object']?['properties']?['title'], 'targeted'), -25, 0)
      )",
      "verdict": "pending"
    }
  }
}
```

**Decision tree:**

| Score   | Verdict        | Action                                    |
|---------|----------------|-------------------------------------------|
| ≥ 80    | `spam`         | Auto-close incident, add comment          |
| 40 – 79 | `known-bad`   | Purge + block + push IOCs + close         |
| < 40    | `investigate`  | Escalate to Tier 2, add enrichment data   |

### Step 4: Remediate (known-bad verdict)

#### 4a. Purge Email from All Mailboxes

**Action:** `HTTP` — Microsoft Graph Content Search and Purge

```
POST https://graph.microsoft.com/v1.0/security/collaboration/contentSearches
{
  "displayName": "Phishing purge - @{triggerBody()?['object']?['properties']?['incidentNumber']}",
  "contentSources": {
    "mailboxes": {
      "includedMailboxes": ["All"]
    }
  },
  "queryText": "from:@{variables('sender_address')} AND subject:\"@{variables('email_subject')}\" AND received:@{variables('email_date')}"
}
```

Then initiate purge:
```
POST https://graph.microsoft.com/v1.0/security/collaboration/contentSearches/{id}/purge
{
  "purgeType": "softDelete"
}
```

> **Important:** Use `softDelete` (not `hardDelete`) so emails can be recovered from the Recoverable Items folder if this is a false positive.

#### 4b. Block Sender Domain

**Action:** `HTTP` — Add to Exchange Online Tenant Allow/Block List

```
POST https://graph.microsoft.com/v1.0/security/threatSubmission/emailThreatSubmissionPolicies
```

Or use the Sentinel TI connector to push the domain as an indicator:

```json
{
  "Add_TI_Indicator": {
    "type": "ApiConnection",
    "inputs": {
      "host": {
        "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" }
      },
      "method": "post",
      "path": "/threatintelligence/createIndicator",
      "body": {
        "action": "block",
        "domainName": "@{variables('sender_domain')}",
        "description": "Phishing domain - Incident @{triggerBody()?['object']?['properties']?['incidentNumber']}",
        "expirationDateTime": "@{addDays(utcNow(), 90)}",
        "threatType": "Phishing",
        "tlpLevel": "amber",
        "confidence": "@variables('verdict_score')"
      }
    }
  }
}
```

#### 4c. Push IOCs to Threat Intelligence

Push all extracted IOCs (URLs, domains, file hashes) as TI indicators with a 90-day expiry and `Phishing` threat type.

### Step 5: Update Incident

**Action:** `Microsoft Sentinel - Update incident`

```json
{
  "Update_incident": {
    "type": "ApiConnection",
    "inputs": {
      "host": {
        "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" }
      },
      "method": "put",
      "path": "/incidents",
      "body": {
        "incidentArmId": "@triggerBody()?['object']?['id']",
        "severity": "@if(equals(variables('verdict'), 'investigate'), 'High', 'Low')",
        "status": "@if(equals(variables('verdict'), 'investigate'), 'Active', 'Closed')",
        "classification": "@if(equals(variables('verdict'), 'spam'), 'FalsePositive', 'TruePositive')",
        "classificationReason": "@if(equals(variables('verdict'), 'spam'), 'InaccurateData', 'SuspiciousActivity')",
        "tagsToAdd": [ "@variables('verdict')", "auto-triaged", "phishing" ],
        "description": "Auto-triage verdict: @{variables('verdict')} (score: @{variables('verdict_score')})"
      }
    }
  }
}
```

**Action:** `Microsoft Sentinel - Add comment`

Add a structured comment with all enrichment findings:

```
## Automated Phishing Triage Report
**Verdict:** @{variables('verdict')} (confidence: @{variables('verdict_score')}/100)

### Sender Analysis
- **Sender:** @{variables('sender_address')}
- **Domain age:** @{variables('domain_age_days')} days
- **SPF:** @{variables('spf_result')}
- **DKIM:** @{variables('dkim_result')}
- **DMARC:** @{variables('dmarc_policy')}

### URL Analysis
@{body('Format_URL_Results')}

### Actions Taken
- ☑ Emails purged from all mailboxes (soft delete)
- ☑ Sender domain blocked via TI indicator (90-day expiry)
- ☑ IOCs pushed to Sentinel Threat Intelligence
```

### Error Handling

Every HTTP action should have these configured:

```json
{
  "retryPolicy": {
    "type": "exponential",
    "count": 3,
    "interval": "PT20S",
    "minimumInterval": "PT10S",
    "maximumInterval": "PT1H"
  }
}
```

Add a **Scope** around the enrichment steps with a `runAfter` condition on `Failed`:

```json
{
  "Scope_Error_Handler": {
    "type": "Scope",
    "actions": {
      "Add_error_comment": {
        "type": "ApiConnection",
        "inputs": {
          "body": {
            "message": "⚠️ Playbook error: @{result('Scope_Enrichment')?['error']?['message']}. Manual triage required."
          }
        }
      }
    },
    "runAfter": {
      "Scope_Enrichment": ["Failed", "TimedOut"]
    }
  }
}
```

If enrichment fails, the playbook should:
1. Add an error comment to the incident
2. Set incident status to `Active` (do not auto-close)
3. Tag with `enrichment-failed`
4. Send a Teams notification to the SOC channel

## Bicep Template Reference

```bicep
@description('Phishing Response SOAR Playbook')
param location string = resourceGroup().location
param workspaceName string
param workspaceResourceGroup string

@secure()
param virusTotalApiKey string

var playbookName = 'la-phishing-response'
var sentinelConnectionName = 'azuresentinel-${playbookName}'
var office365ConnectionName = 'office365-${playbookName}'

// --- API Connections ---

resource sentinelConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: sentinelConnectionName
  location: location
  kind: 'V1'
  properties: {
    displayName: sentinelConnectionName
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
    }
    parameterValueType: 'Alternative'
  }
}

resource office365Connection 'Microsoft.Web/connections@2016-06-01' = {
  name: office365ConnectionName
  location: location
  kind: 'V1'
  properties: {
    displayName: office365ConnectionName
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'office365')
    }
    parameterValueType: 'Alternative'
  }
}

// --- Logic App ---

resource playbook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: playbookName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
      }
      triggers: {
        Microsoft_Sentinel_incident: {
          type: 'ApiConnectionWebhook'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            body: {
              callback_url: '@listCallbackUrl()'
            }
            path: '/incident-creation'
          }
        }
      }
      actions: {}
    }
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: sentinelConnection.id
            connectionName: sentinelConnectionName
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
          }
          office365: {
            connectionId: office365Connection.id
            connectionName: office365ConnectionName
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'office365')
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
          }
        }
      }
    }
  }
}

// --- Role Assignments ---

resource sentinelResponderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(playbook.id, 'sentinel-responder')
  scope: resourceId(workspaceResourceGroup, 'Microsoft.OperationalInsights/workspaces', workspaceName)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3e150fc0-dc56-4d40-8ad3-0a932e68a9a4') // Sentinel Responder
    principalId: playbook.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// --- Key Vault Secret Reference ---

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: 'kv-soc-automation'
}

resource vtApiKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'VirusTotal-ApiKey'
  properties: {
    value: virusTotalApiKey
  }
}
```

## Rollback / Destroy

### Remove the Automation

```bash
# 1. Disable the playbook first (stop new executions)
az logic workflow update \
  --resource-group rg-soc-automation \
  --name la-phishing-response \
  --state Disabled

# 2. Wait for in-flight runs to complete (check via portal or CLI)
az logic workflow run list \
  --resource-group rg-soc-automation \
  --workflow-name la-phishing-response \
  --filter "status eq 'Running'" \
  --query "[].name"

# 3. Remove role assignments
az role assignment delete \
  --assignee <logic-app-principal-id> \
  --role "Microsoft Sentinel Responder" \
  --scope /subscriptions/<sub>/resourceGroups/rg-soc/providers/Microsoft.OperationalInsights/workspaces/law-soc

# 4. Delete the Logic App and connections
az logic workflow delete \
  --resource-group rg-soc-automation \
  --name la-phishing-response --yes

az resource delete --ids <sentinel-connection-resource-id>
az resource delete --ids <office365-connection-resource-id>

# 5. Remove automation rule linking in Sentinel (if configured)
# This must be done in the Sentinel portal: Settings → Automation → delete the rule
```

### Reverse Remediation Actions

If the playbook acted on a false positive:

1. **Restore purged emails:** Recoverable Items folder retains soft-deleted mail for 14 days (default). Use Compliance Center eDiscovery or `New-ComplianceSearchAction -Purge -PurgeType SoftDelete` to preview, then restore.

2. **Unblock sender domain:** Remove the TI indicator from Sentinel:
   ```bash
   az sentinel threat-indicator delete \
     --workspace-name law-soc \
     --resource-group rg-soc \
     --name <indicator-id>
   ```

3. **Remove IOCs:** Query Sentinel TI for indicators tagged with the incident number and delete them.

## Testing Checklist

> For Carver (Detection/Validation Engineer) to verify before production deployment.

- [ ] **Trigger test:** Create a test incident with phishing analytics rule → playbook triggers within 60 seconds
- [ ] **Entity parsing:** Verify URL, mailbox, and file hash entities are correctly extracted from a multi-entity incident
- [ ] **VirusTotal enrichment:** Submit a known-malicious URL (use EICAR test URL) → VT returns detection count > 0
- [ ] **MDTI enrichment:** Query a known-bad domain → MDTI returns reputation data
- [ ] **SPF/DKIM/DMARC check:** Test with a domain that has `p=reject` → correctly parsed as DMARC enforced
- [ ] **Verdict - spam path:** Incident with score ≥ 80 → auto-closed with `FalsePositive` classification
- [ ] **Verdict - known-bad path:** Incident with score 40-79 → emails purged, domain blocked, IOCs pushed, incident closed
- [ ] **Verdict - escalate path:** Incident with score < 40 → incident stays Active, severity set to High, Tier 2 notified
- [ ] **Email purge:** Confirm soft-delete purge removes email from test mailbox, verify it exists in Recoverable Items
- [ ] **TI indicator creation:** Confirm domain indicator appears in Sentinel Threat Intelligence blade with correct expiry and threat type
- [ ] **Error handling:** Disable VT API key → playbook adds error comment, does NOT auto-close, tags with `enrichment-failed`
- [ ] **Rate limiting:** Submit 10 URLs → playbook processes them sequentially without hitting VT rate limit
- [ ] **Idempotency:** Run playbook twice on same incident → no duplicate purge actions or TI indicators
- [ ] **Rollback:** After test, successfully restore purged emails and remove test TI indicators

## Tuning Guide

### Common Customizations

| Parameter              | Default  | Tuning Notes                                                   |
|------------------------|----------|----------------------------------------------------------------|
| Verdict threshold (spam)     | ≥ 80     | Raise to 90 if getting false auto-closes                       |
| Verdict threshold (remediate)| 40 – 79  | Lower the floor to 30 if you want more auto-remediation        |
| VT detection threshold | > 5      | Raise to 10 for fewer false positives from VT community        |
| Domain age threshold   | < 30 days| Some legitimate new domains exist; raise to 7 for stricter     |
| TI indicator expiry    | 90 days  | Shorten to 30 for high-churn domains, extend to 180 for APTs   |
| Email purge type       | softDelete| Switch to `hardDelete` only if retention policy allows it      |
| Rate limit delay       | 15s      | Adjust based on your VT API tier (premium = no delay needed)   |

### Exclusions

Add a `Condition` after entity parsing to skip known-good senders:

```json
{
  "Condition_Sender_Allowlist": {
    "type": "If",
    "expression": {
      "not": {
        "contains": [
          "@variables('sender_allowlist')",
          "@variables('sender_domain')"
        ]
      }
    }
  }
}
```

Maintain the allowlist as a Logic App parameter or in a Storage Table for easy updates without redeploying.

### Severity-Based Routing

To route different severity incidents to different response paths:

```
Incident Severity = High → Always escalate (skip auto-close)
Incident Severity = Medium → Run full verdict engine
Incident Severity = Low/Informational → Auto-close if score ≥ 60
```

### Multi-Tenant Considerations

If operating across multiple tenants (MSSP scenario):
- Use separate API connections per tenant
- Add a `Switch` on the incident's workspace ID to route to the correct tenant's connections
- Store per-tenant configuration in a shared Storage Table
