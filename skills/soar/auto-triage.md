---
title: "L1 Auto-Triage — Evidence-Based Incident Routing"
category: soar
difficulty: advanced
trigger_type: sentinel-incident
products:
  - Microsoft Sentinel
  - Entra ID
api_connections:
  - azuresentinel
  - azuread
author: Herc
version: 1.0.0
last_updated: 2026-04-28
mitre_attack: []
---

# L1 Auto-Triage — Evidence-Based Incident Routing

## Overview

This playbook replaces manual L1 triage for new Sentinel incidents. It evaluates alert confidence, entity reputation, and organizational context to make an automated decision: auto-close benign incidents, assign severity-based ownership for real incidents, or escalate unknown/novel threats for human review.

**Business justification:** L1 analysts spend 60-70% of their time closing false positives and routing true positives. In a SOC handling 100+ incidents/day, that's 6+ analyst-hours on repetitive decision-making. This playbook automates the straightforward decisions (obvious false positives, known-good entities, well-understood alert types) so human analysts focus exclusively on incidents that require judgment — targeted attacks, novel TTPs, and edge cases.

**What it does:**
1. Triggers on any new Sentinel incident
2. Evaluates alert provider confidence scores
3. Checks entities against known-good watchlists and allowlists
4. Checks entities against known-bad watchlists
5. Evaluates incident patterns against historical false positive data
6. Routes: auto-close (benign), auto-assign (confirmed), or escalate (unknown)
7. Documents the triage decision with full reasoning in the incident comments

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Microsoft Sentinel                            │
│  Any new incident → Trigger fires                               │
└──────────────┬───────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────┐
│  1. Extract Evidence     │
│  - Alert confidence      │
│  - Entity list           │
│  - Analytics rule info   │
│  - Alert provider        │
└──────────┬───────────────┘
               │
               ├──────────────────┐
               ▼                  ▼
┌──────────────────────┐ ┌────────────────────────┐
│  2a. Known-Good      │ │  2b. Known-Bad         │
│  Check               │ │  Check                 │
│  - IP allowlist      │ │  - IP blocklist        │
│  - User allowlist    │ │  - Domain watchlist    │
│  - Service accounts  │ │  - Hash watchlist      │
│  - Expected tools    │ │  - Threat intel match  │
└──────────┬───────────┘ └──────────┬─────────────┘
               │                    │
               └────────┬───────────┘
                        ▼
               ┌──────────────────────────┐
               │  3. Triage Decision      │
               │  Engine                  │
               ├──────────────────────────┤
               │  All entities known-good │
               │  + low confidence alert  │
               │  → AUTO-CLOSE            │
               ├──────────────────────────┤
               │  Any entity known-bad    │
               │  OR high confidence      │
               │  → CONFIRMED (assign)    │
               ├──────────────────────────┤
               │  Unknown / mixed signals │
               │  → ESCALATE to Tier 2    │
               └──────┬──────┬──────┬─────┘
                      │      │      │
                      ▼      ▼      ▼
               ┌──────┐ ┌────────┐ ┌────────┐
               │Close │ │Assign  │ │Escalate│
               │as FP │ │owner + │ │to T2   │
               │      │ │severity│ │+ enrich│
               └──────┘ └────────┘ └────────┘
                              │
                              ▼
               ┌──────────────────────────┐
               │  4. Update Incident      │
               │  - Decision comment      │
               │  - Tags + classification │
               │  - Owner assignment      │
               └──────────────────────────┘
```

## Prerequisites

### API Connections

| Connection          | Purpose                                    | Auth Method           |
|---------------------|--------------------------------------------|-----------------------|
| `azuresentinel`     | Read/update incidents, query watchlists    | Managed Identity      |
| `azuread`           | Validate user entities, check service accts | Managed Identity     |

### Required Permissions

| Permission                              | Type        | Justification                       |
|-----------------------------------------|-------------|-------------------------------------|
| `Microsoft Sentinel Responder`          | Azure RBAC  | Update incidents, close, assign     |
| `Microsoft Sentinel Reader`             | Azure RBAC  | Read watchlists and analytics rules |
| `User.Read.All`                         | Application | Validate user accounts              |

### Managed Identity Setup

```bash
# Enable system-assigned managed identity
az logic workflow identity assign \
  --resource-group rg-soc-automation \
  --name la-auto-triage \
  --system-assigned

# Grant Sentinel Responder
az role assignment create \
  --assignee <logic-app-principal-id> \
  --role "Microsoft Sentinel Responder" \
  --scope /subscriptions/<sub>/resourceGroups/rg-soc/providers/Microsoft.OperationalInsights/workspaces/law-soc

# Grant Graph API permissions
az ad app permission add \
  --id <app-id> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions User.Read.All=Role
```

### Required Watchlists

These Sentinel watchlists must be created before deploying this playbook:

| Watchlist Alias         | Purpose                              | Key Column      |
|-------------------------|--------------------------------------|-----------------|
| `IP-Allowlist`          | Known-good IPs (scanners, services)  | `IPAddress`     |
| `IP-KnownBad`           | Known-bad IPs from threat intel      | `IPAddress`     |
| `User-ServiceAccounts`  | Expected service/automation accounts | `UPN`           |
| `Domain-Allowlist`      | Known-good domains                   | `Domain`        |
| `Hash-KnownBad`         | Malware hashes                       | `SHA256`        |
| `FP-Patterns`           | Known false positive alert patterns  | `RuleId`        |

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

### Step 1: Extract Evidence

**Action:** `Compose` + Entity extraction

```json
{
  "Extract_Alert_Confidence": {
    "type": "Compose",
    "inputs": {
      "alert_count": "@triggerBody()?['object']?['properties']?['additionalData']?['alertsCount']",
      "severity": "@triggerBody()?['object']?['properties']?['severity']",
      "provider": "@triggerBody()?['object']?['properties']?['providerName']",
      "rule_ids": "@triggerBody()?['object']?['properties']?['relatedAnalyticRuleIds']",
      "tactics": "@triggerBody()?['object']?['properties']?['additionalData']?['tactics']"
    }
  }
}
```

Extract all entity types:
```json
{
  "Get_IPs": {
    "type": "ApiConnection",
    "inputs": { "method": "post", "path": "/entities/ip" }
  },
  "Get_Accounts": {
    "type": "ApiConnection",
    "inputs": { "method": "post", "path": "/entities/account" }
  },
  "Get_Hosts": {
    "type": "ApiConnection",
    "inputs": { "method": "post", "path": "/entities/host" }
  },
  "Get_URLs": {
    "type": "ApiConnection",
    "inputs": { "method": "post", "path": "/entities/url" }
  },
  "Get_FileHashes": {
    "type": "ApiConnection",
    "inputs": { "method": "post", "path": "/entities/filehash" }
  }
}
```

### Step 2a: Known-Good Checks

**Action:** `HTTP` — query watchlists via Log Analytics API

Check IPs against allowlist:
```json
{
  "Check_IP_Allowlist": {
    "type": "Http",
    "inputs": {
      "method": "POST",
      "uri": "https://api.loganalytics.io/v1/workspaces/@{parameters('workspace_id')}/query",
      "body": {
        "query": "let ips = dynamic([@{body('Format_IP_List')}]); _GetWatchlist('IP-Allowlist') | where IPAddress in (ips) | project IPAddress, Reason"
      },
      "authentication": {
        "type": "ManagedServiceIdentity",
        "audience": "https://api.loganalytics.io"
      }
    }
  }
}
```

Check users against service account list:
```json
{
  "Check_Service_Accounts": {
    "type": "Http",
    "inputs": {
      "body": {
        "query": "let upns = dynamic([@{body('Format_UPN_List')}]); _GetWatchlist('User-ServiceAccounts') | where UPN in (upns) | project UPN, ServiceName, ExpectedActivity"
      }
    }
  }
}
```

Check analytics rule against known FP patterns:
```json
{
  "Check_FP_Patterns": {
    "type": "Http",
    "inputs": {
      "body": {
        "query": "_GetWatchlist('FP-Patterns') | where RuleId in (@{body('Format_Rule_IDs')}) | project RuleId, FPCondition, AutoCloseReason"
      }
    }
  }
}
```

### Step 2b: Known-Bad Checks

Check IPs against known-bad watchlist:
```json
{
  "Check_IP_KnownBad": {
    "type": "Http",
    "inputs": {
      "body": {
        "query": "let ips = dynamic([@{body('Format_IP_List')}]); _GetWatchlist('IP-KnownBad') | where IPAddress in (ips) | project IPAddress, ThreatType, Source"
      }
    }
  }
}
```

Check file hashes:
```json
{
  "Check_Hash_KnownBad": {
    "type": "Http",
    "inputs": {
      "body": {
        "query": "let hashes = dynamic([@{body('Format_Hash_List')}]); _GetWatchlist('Hash-KnownBad') | where SHA256 in (hashes) | project SHA256, MalwareFamily, Source"
      }
    }
  }
}
```

### Step 3: Triage Decision Engine

**Action:** `Compose` + `Switch`

```json
{
  "Compose_Triage_Decision": {
    "type": "Compose",
    "inputs": {
      "all_entities_known_good": "@and(
        equals(length(body('Check_IP_KnownBad')?['tables']?[0]?['rows']), 0),
        equals(length(body('Check_Hash_KnownBad')?['tables']?[0]?['rows']), 0),
        or(
          greater(length(body('Check_IP_Allowlist')?['tables']?[0]?['rows']), 0),
          greater(length(body('Check_Service_Accounts')?['tables']?[0]?['rows']), 0)
        )
      )",
      "any_entity_known_bad": "@or(
        greater(length(body('Check_IP_KnownBad')?['tables']?[0]?['rows']), 0),
        greater(length(body('Check_Hash_KnownBad')?['tables']?[0]?['rows']), 0)
      )",
      "known_fp_pattern": "@greater(length(body('Check_FP_Patterns')?['tables']?[0]?['rows']), 0)",
      "severity": "@triggerBody()?['object']?['properties']?['severity']"
    }
  }
}
```

**Decision logic:**

```json
{
  "Triage_Switch": {
    "type": "If",
    "expression": {
      "or": [
        "@outputs('Compose_Triage_Decision')?['known_fp_pattern']",
        "@and(outputs('Compose_Triage_Decision')?['all_entities_known_good'], not(equals(outputs('Compose_Triage_Decision')?['severity'], 'High')))"
      ]
    },
    "actions": {
      "Auto_Close": {
        "type": "ApiConnection",
        "inputs": {
          "body": {
            "incidentArmId": "@triggerBody()?['object']?['id']",
            "status": "Closed",
            "classification": "BenignPositive",
            "classificationReason": "InaccurateData",
            "tagsToAdd": ["auto-closed", "l1-triage"]
          }
        }
      }
    },
    "else": {
      "actions": {
        "Check_Known_Bad": {
          "type": "If",
          "expression": "@outputs('Compose_Triage_Decision')?['any_entity_known_bad']",
          "actions": {
            "Assign_Confirmed": {
              "type": "ApiConnection",
              "inputs": {
                "body": {
                  "incidentArmId": "@triggerBody()?['object']?['id']",
                  "status": "Active",
                  "severity": "High",
                  "owner": { "assignedTo": "@{parameters('tier1_owner')}" },
                  "tagsToAdd": ["confirmed-threat", "l1-triage", "known-bad-entity"]
                }
              }
            }
          },
          "else": {
            "actions": {
              "Escalate_Unknown": {
                "type": "ApiConnection",
                "inputs": {
                  "body": {
                    "incidentArmId": "@triggerBody()?['object']?['id']",
                    "status": "Active",
                    "owner": { "assignedTo": "@{parameters('tier2_owner')}" },
                    "tagsToAdd": ["needs-review", "l1-triage", "escalated"]
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### Step 4: Document Triage Decision

**Action:** `Microsoft Sentinel - Add comment`

```
## L1 Auto-Triage Report
**Decision:** @{variables('triage_decision')}
**Reason:** @{variables('triage_reason')}

### Evidence Evaluated
- **Alert severity:** @{triggerBody()?['object']?['properties']?['severity']}
- **Alert provider:** @{outputs('Extract_Alert_Confidence')?['provider']}
- **Alert count:** @{outputs('Extract_Alert_Confidence')?['alert_count']}
- **MITRE tactics:** @{outputs('Extract_Alert_Confidence')?['tactics']}

### Entity Analysis
- **IPs checked:** @{length(body('Get_IPs')?['IPs'])}
  - On allowlist: @{length(body('Check_IP_Allowlist')?['tables']?[0]?['rows'])}
  - On known-bad: @{length(body('Check_IP_KnownBad')?['tables']?[0]?['rows'])}
- **Accounts checked:** @{length(body('Get_Accounts')?['Accounts'])}
  - Service accounts: @{length(body('Check_Service_Accounts')?['tables']?[0]?['rows'])}
- **File hashes checked:** @{length(body('Get_FileHashes')?['FileHashes'])}
  - On known-bad: @{length(body('Check_Hash_KnownBad')?['tables']?[0]?['rows'])}
- **Known FP pattern match:** @{if(outputs('Compose_Triage_Decision')?['known_fp_pattern'], 'Yes', 'No')}

### Routing
- **Assigned to:** @{variables('assigned_to')}
- **Tags added:** @{variables('tags_added')}
```

### Error Handling

```json
{
  "Scope_Error_Handler": {
    "type": "Scope",
    "actions": {
      "Add_error_comment": {
        "type": "ApiConnection",
        "inputs": {
          "body": {
            "message": "⚠️ Auto-triage playbook error: @{result('Scope_Triage')?['error']?['message']}. Incident requires manual triage."
          }
        }
      },
      "Tag_manual_triage": {
        "type": "ApiConnection",
        "inputs": {
          "body": {
            "incidentArmId": "@triggerBody()?['object']?['id']",
            "tagsToAdd": ["triage-failed", "manual-triage-required"]
          }
        }
      }
    },
    "runAfter": {
      "Scope_Triage": ["Failed", "TimedOut"]
    }
  }
}
```

On failure, the playbook NEVER auto-closes — it tags the incident for manual triage.

## Bicep Template Reference

```bicep
@description('L1 Auto-Triage SOAR Playbook')
param location string = resourceGroup().location
param workspaceName string
param workspaceResourceGroup string
param workspaceId string
param tier1Owner string = ''
param tier2Owner string = ''

var playbookName = 'la-auto-triage'
var sentinelConnectionName = 'azuresentinel-${playbookName}'
var azureadConnectionName = 'azuread-${playbookName}'

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

resource azureadConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: azureadConnectionName
  location: location
  kind: 'V1'
  properties: {
    displayName: azureadConnectionName
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuread')
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
        workspace_id: {
          defaultValue: workspaceId
          type: 'String'
        }
        tier1_owner: {
          defaultValue: tier1Owner
          type: 'String'
        }
        tier2_owner: {
          defaultValue: tier2Owner
          type: 'String'
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
          azuread: {
            connectionId: azureadConnection.id
            connectionName: azureadConnectionName
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuread')
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
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3e150fc0-dc56-4d40-8ad3-0a932e68a9a4')
    principalId: playbook.identity.principalId
    principalType: 'ServicePrincipal'
  }
}
```

## Rollback / Destroy

### Remove the Automation

```bash
# 1. Disable the playbook
az logic workflow update \
  --resource-group rg-soc-automation \
  --name la-auto-triage \
  --state Disabled

# 2. Wait for in-flight runs
az logic workflow run list \
  --resource-group rg-soc-automation \
  --workflow-name la-auto-triage \
  --filter "status eq 'Running'" \
  --query "[].name"

# 3. Remove role assignments
az role assignment delete \
  --assignee <logic-app-principal-id> \
  --role "Microsoft Sentinel Responder" \
  --scope /subscriptions/<sub>/resourceGroups/rg-soc/providers/Microsoft.OperationalInsights/workspaces/law-soc

# 4. Delete Logic App and connections
az logic workflow delete \
  --resource-group rg-soc-automation \
  --name la-auto-triage --yes

az resource delete --ids <sentinel-connection-resource-id>
az resource delete --ids <azuread-connection-resource-id>
```

### Reopen Auto-Closed Incidents

If the triage logic was flawed and incidents were incorrectly auto-closed:

```bash
# Find auto-closed incidents via Log Analytics
az monitor log-analytics query \
  --workspace law-soc \
  --analytics-query "SecurityIncident
    | where Labels has 'auto-closed' and Labels has 'l1-triage'
    | where TimeGenerated > ago(24h)
    | project IncidentNumber, Title, Status, ClosedTime
    | order by ClosedTime desc" \
  --output table

# Reopen incidents via Sentinel API (PowerShell)
$incidents = @("incident-arm-id-1", "incident-arm-id-2")
foreach ($id in $incidents) {
  az rest --method PUT \
    --url "https://management.azure.com${id}?api-version=2023-11-01" \
    --body '{"properties": {"status": "Active", "severity": "Medium", "labels": [{"labelName": "reopened"}, {"labelName": "triage-review"}]}}'
}
```

## Testing Checklist

> For Carver (Detection/Validation Engineer) to verify before production deployment.

- [ ] **Trigger test:** Create a test incident → playbook triggers and runs triage logic
- [ ] **Auto-close path:** Create incident where all IPs are on allowlist → incident auto-closed with `BenignPositive` classification
- [ ] **Confirmed threat path:** Create incident with known-bad IP → incident assigned to Tier 1, severity set to High, `confirmed-threat` tag added
- [ ] **Escalation path:** Create incident with unknown entities → incident assigned to Tier 2, `needs-review` tag added
- [ ] **High severity override:** Create High severity incident with all known-good entities → NOT auto-closed (High severity always gets human review)
- [ ] **Known FP pattern:** Add analytics rule to `FP-Patterns` watchlist → matching incidents auto-closed
- [ ] **Service account recognition:** Create incident involving a service account from watchlist → recognized as known-good
- [ ] **Triage comment:** Verify structured triage report with entity counts and decision reasoning
- [ ] **Error handling:** Simulate watchlist query failure → incident tagged `manual-triage-required`, NOT auto-closed
- [ ] **Watchlist dependency:** Remove a required watchlist → playbook handles gracefully without crashing
- [ ] **Rollback:** Reopen a batch of auto-closed test incidents → incidents active again with `reopened` tag

## Related Skills

- [Sentinel Enrichment — IP](./sentinel-enrichment-ip.md) — deeper IP enrichment for escalated incidents
- [Sentinel Enrichment — User](./sentinel-enrichment-user.md) — user context for incidents with account entities
- [Ticket Create](./ticket-create.md) — ITSM ticket creation typically runs after auto-triage
