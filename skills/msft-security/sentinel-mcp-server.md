---
title: Sentinel MCP Server Integration
category: msft-security
difficulty: advanced
mitre_attack:
  - T1059  # Command and Scripting Interpreter (automation context)
  - T1078  # Valid Accounts (auth patterns)
  - T1530  # Data from Cloud Storage
  - T1190  # Exploit Public-Facing Application (incident triage)
products:
  - Microsoft Sentinel
  - Azure MCP Server
  - Azure Resource Manager
  - Azure Monitor
author: Kima
version: 1.0.0
last_updated: 2026-04-30
---

# Sentinel MCP Server Integration

## Overview

The Azure MCP Server (github.com/Azure/azure-mcp-server) is Microsoft's official Model Context Protocol server for Azure services. It exposes Azure resource management operations as MCP tools that AI agents can invoke — listing resources, reading configurations, executing queries, and performing CRUD operations against Azure services including Microsoft Sentinel.

Use this skill when:
- Configuring AI agents (Copilot, Claude, etc.) to interact with Sentinel workspaces via MCP
- Building agent workflows that triage incidents, manage analytics rules, or query threat intelligence
- Integrating MCP-based Sentinel operations with the `.secops/` environment framework
- Deciding between MCP, direct REST API, or PowerShell for a given Sentinel operation
- Setting up multi-workspace or government cloud MCP configurations

### MCP vs. REST vs. PowerShell — When to Use What

| Approach | Best For | Limitations |
|---|---|---|
| **MCP Server** | Agent-driven workflows, interactive investigation, real-time triage | Requires MCP-compatible client; subset of full API surface |
| **REST API** | Automation pipelines, CI/CD, Logic Apps, custom integrations | Requires explicit auth token management, verbose payloads |
| **PowerShell** | Ad-hoc admin tasks, scripted bulk operations, SOC engineer daily work | Not agent-native, requires PowerShell runtime |

**Rule of thumb:** If an AI agent is performing the operation, use MCP. If a pipeline or automation is performing it, use REST. If a human is running it manually, use PowerShell.

## Prerequisites

| Requirement | Detail |
|---|---|
| **Azure MCP Server** | Install from `github.com/Azure/azure-mcp-server` (npx, Docker, or binary) |
| **Authentication** | `DefaultAzureCredential` chain (Azure CLI, managed identity, or service principal) |
| **Permissions** | `Microsoft Sentinel Reader` minimum for read ops; `Microsoft Sentinel Contributor` for writes |
| **MCP Client** | VS Code with Copilot, GitHub Copilot CLI, Claude Desktop, or any MCP-compatible client |
| **Network** | Access to `management.azure.com` (or gov cloud equivalent) |

## Environment Context

Before configuring MCP for Sentinel, check the `.secops/` framework:

1. **`.secops/environment.yaml`** — Cloud type determines API endpoint (`azure-commercial` vs `azure-government`)
2. **`.secops/workspaces/*.yaml`** — Workspace IDs, subscriptions, resource groups for MCP scoping
3. **`.secops/identity/rbac-conventions.yaml`** — Verify the agent's identity has required Sentinel RBAC roles
4. **`.secops/data-sources/data-source-map.yaml`** — Understand which tables live where before querying

If `.secops/` doesn't exist, suggest `secops-squad init --secops` before proceeding.

---

## Section 1: What Is the Azure MCP Server

### Architecture

The Azure MCP Server sits between an AI agent and Azure Resource Manager (ARM):

```
┌──────────────┐     MCP Protocol      ┌──────────────────┐     ARM REST     ┌─────────────┐
│  AI Agent    │ ◄──────────────────► │  Azure MCP Server │ ◄─────────────► │  Azure ARM  │
│ (Copilot,    │   stdio / SSE         │  (Node.js process)│   HTTPS          │  (Sentinel)  │
│  Claude)     │                       └──────────────────┘                   └─────────────┘
└──────────────┘                              │
                                              ▼
                                    DefaultAzureCredential
                                    (CLI, MI, SP, env vars)
```

### Sentinel-Specific MCP Capabilities

The Azure MCP Server exposes Sentinel operations through the ARM resource provider `Microsoft.SecurityInsights`. Key capabilities:

- **Resource listing** — Enumerate incidents, analytics rules, data connectors, watchlists, threat intelligence, automation rules, bookmarks
- **Resource reading** — Get full details of any Sentinel resource by ID
- **Resource modification** — Create, update, delete Sentinel resources (incidents, rules, watchlists, TI indicators)
- **KQL execution** — Run queries against Log Analytics workspaces via the Query API
- **Batch operations** — Multiple resource operations in a single agent turn

### What MCP Adds Over Raw REST

| Feature | Raw REST | Via MCP |
|---|---|---|
| Auth management | Manual token acquisition/refresh | Handled by MCP server (DefaultAzureCredential) |
| Resource discovery | Must know full resource IDs | Can list and browse resources |
| Error handling | Parse HTTP status codes | Structured MCP error responses |
| Agent integration | Custom code per agent | Standard MCP protocol |
| Pagination | Manual `nextLink` handling | MCP server handles continuation |

---

## Section 2: Configuration & Setup

### MCP Server Configuration

Configure the Azure MCP Server in your MCP configuration file. The location depends on your client:

**GitHub Copilot (`.copilot/mcp-config.json`):**

```json
{
  "mcpServers": {
    "azure": {
      "command": "npx",
      "args": ["-y", "@azure/mcp-server@latest"],
      "env": {
        "AZURE_SUBSCRIPTION_ID": "11111111-2222-3333-4444-555555555555",
        "AZURE_TENANT_ID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
      }
    }
  }
}
```

**VS Code (`settings.json`):**

```json
{
  "mcp": {
    "servers": {
      "azure": {
        "command": "npx",
        "args": ["-y", "@azure/mcp-server@latest"],
        "env": {
          "AZURE_SUBSCRIPTION_ID": "11111111-2222-3333-4444-555555555555"
        }
      }
    }
  }
}
```

**Claude Desktop (`claude_desktop_config.json`):**

```json
{
  "mcpServers": {
    "azure": {
      "command": "npx",
      "args": ["-y", "@azure/mcp-server@latest"],
      "env": {
        "AZURE_SUBSCRIPTION_ID": "11111111-2222-3333-4444-555555555555"
      }
    }
  }
}
```

### Authentication Methods

The Azure MCP Server uses `DefaultAzureCredential`, which tries these methods in order:

| Priority | Method | Use Case |
|---|---|---|
| 1 | Environment variables | CI/CD pipelines (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`) |
| 2 | Workload identity | Kubernetes-hosted agents |
| 3 | Managed identity | Azure-hosted agents (VM, App Service, Container Instance) |
| 4 | Azure CLI | Developer workstations (`az login` first) |
| 5 | Azure PowerShell | PowerShell-based environments (`Connect-AzAccount` first) |
| 6 | Azure Developer CLI | `azd auth login` |

**For local development:**

```bash
# Authenticate via Azure CLI before starting the MCP server
az login --tenant "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

# Verify access to the target subscription
az account set --subscription "11111111-2222-3333-4444-555555555555"
az resource list --resource-group "rg-soc-prod" --resource-type "Microsoft.SecurityInsights/incidents" --query "[].name" -o tsv
```

**For service principal (CI/CD or unattended):**

```bash
# Environment variables for service principal auth
export AZURE_TENANT_ID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
export AZURE_CLIENT_ID="cccccccc-dddd-eeee-ffff-000000000000"
export AZURE_CLIENT_SECRET="<secret>"  # Use cert-based auth in production
```

### Scoping to Specific Subscriptions and Resource Groups

Limit the MCP server's scope to reduce blast radius and improve performance:

```json
{
  "mcpServers": {
    "azure-sentinel": {
      "command": "npx",
      "args": ["-y", "@azure/mcp-server@latest"],
      "env": {
        "AZURE_SUBSCRIPTION_ID": "11111111-2222-3333-4444-555555555555",
        "AZURE_RESOURCE_GROUP": "rg-soc-prod",
        "AZURE_TENANT_ID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
      }
    }
  }
}
```

### Multi-Workspace Configuration

For MSSP or multi-tenant environments, configure separate MCP server instances per workspace:

```json
{
  "mcpServers": {
    "sentinel-prod": {
      "command": "npx",
      "args": ["-y", "@azure/mcp-server@latest"],
      "env": {
        "AZURE_SUBSCRIPTION_ID": "11111111-2222-3333-4444-555555555555",
        "AZURE_RESOURCE_GROUP": "rg-soc-prod"
      }
    },
    "sentinel-dev": {
      "command": "npx",
      "args": ["-y", "@azure/mcp-server@latest"],
      "env": {
        "AZURE_SUBSCRIPTION_ID": "22222222-3333-4444-5555-666666666666",
        "AZURE_RESOURCE_GROUP": "rg-soc-dev"
      }
    }
  }
}
```

### Connecting to `.secops/` Workspace Context

Agents should auto-discover MCP configuration from `.secops/workspaces/*.yaml`:

```
Agent workflow:
1. Read .secops/environment.yaml → get cloud type and subscriptions
2. Read .secops/workspaces/*.yaml → get workspace names, IDs, resource groups
3. Match workspace to MCP server config (by subscription + resource group)
4. If no MCP server configured for workspace → suggest adding to mcp-config.json
5. If .secops/ missing → suggest `secops-squad init --secops`
```

### Government Cloud Configuration

For Azure Government (GCC-High, DoD):

```json
{
  "mcpServers": {
    "azure-gov": {
      "command": "npx",
      "args": ["-y", "@azure/mcp-server@latest"],
      "env": {
        "AZURE_SUBSCRIPTION_ID": "11111111-2222-3333-4444-555555555555",
        "AZURE_AUTHORITY_HOST": "https://login.microsoftonline.us",
        "AZURE_RESOURCE_MANAGER_ENDPOINT": "https://management.usgovcloudapi.net"
      }
    }
  }
}
```

| Cloud | ARM Endpoint | Authority Host |
|---|---|---|
| Commercial | `management.azure.com` | `login.microsoftonline.com` |
| US Government | `management.usgovcloudapi.net` | `login.microsoftonline.us` |
| China (21Vianet) | `management.chinacloudapi.cn` | `login.chinacloudapi.cn` |

---

## Section 3: Sentinel Resources via MCP

### Resource Listing Patterns

Use MCP `list_resources` to enumerate Sentinel resources. The resource provider is `Microsoft.SecurityInsights` scoped to a Log Analytics workspace.

**Analytics Rules:**

```
MCP tool: list_resources
Resource type: Microsoft.SecurityInsights/alertRules
Scope: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}
```

Returns rule types:
- `Microsoft.SecurityInsights/alertRules` — Scheduled rules
- `Fusion` kind — Fusion ML correlation rules
- `MLBehaviorAnalytics` kind — ML behavior analytics
- `NRT` kind — Near-real-time rules
- `MicrosoftSecurityIncidentCreation` kind — Product alert rules

**Incidents:**

```
MCP tool: list_resources
Resource type: Microsoft.SecurityInsights/incidents
Scope: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}

# Filter by severity
$filter=properties/severity eq 'High'

# Filter by status
$filter=properties/status eq 'New'

# Compound filter
$filter=properties/severity eq 'High' and properties/status eq 'New'
```

**Data Connectors:**

```
MCP tool: list_resources
Resource type: Microsoft.SecurityInsights/dataConnectors
# Returns all configured connectors with their status and properties
```

**Watchlists:**

```
MCP tool: list_resources
Resource type: Microsoft.SecurityInsights/watchlists
# Returns watchlist metadata; use get_resource for items
```

**Threat Intelligence Indicators:**

```
MCP tool: list_resources
Resource type: Microsoft.SecurityInsights/threatIntelligence/main/indicators
# Returns TI indicators with confidence, pattern, valid dates
```

**Automation Rules:**

```
MCP tool: list_resources
Resource type: Microsoft.SecurityInsights/automationRules
# Returns rules sorted by order (execution priority)
```

### Resource Schema Key Fields

| Resource | Key Properties |
|---|---|
| **Incident** | `severity`, `status` (New/Active/Closed), `owner`, `title`, `description`, `labels`, `firstActivityTimeUtc`, `lastActivityTimeUtc` |
| **Analytics Rule** | `displayName`, `query`, `queryFrequency`, `queryPeriod`, `severity`, `triggerOperator`, `triggerThreshold`, `enabled`, `tactics` |
| **Watchlist** | `displayName`, `alias`, `source`, `itemsSearchKey`, `numberOfLinesToSkip` |
| **TI Indicator** | `pattern`, `threatTypes`, `confidence`, `validFrom`, `validUntil`, `source` |
| **Data Connector** | `kind`, `connectorId`, `dataTypes` (with `state`: Enabled/Disabled) |
| **Automation Rule** | `displayName`, `order`, `triggeringLogic`, `actions` |

---

## Section 4: Sentinel Operations via MCP (call_tool)

### Incident Management

**List open high-severity incidents:**

```
Tool: azure_list_resources
Parameters:
  subscription: "11111111-2222-3333-4444-555555555555"
  resourceGroup: "rg-soc-prod"
  resourceType: "Microsoft.SecurityInsights/incidents"
  workspaceName: "soc-sentinel-prod"
  filter: "properties/severity eq 'High' and properties/status ne 'Closed'"
```

**Update incident (assign + change status):**

```
Tool: azure_update_resource
Parameters:
  resourceId: "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/incidents/{id}"
  properties:
    status: "Active"
    owner:
      assignedTo: "analyst@contoso.com"
      objectId: "user-object-id"
    severity: "High"
    classification: null
    classificationComment: null
```

**Add incident comment:**

```
Tool: azure_create_resource
Parameters:
  resourceType: "Microsoft.SecurityInsights/incidents/{incidentId}/comments"
  properties:
    message: "Investigating suspicious login from IP 203.0.113.50. Initial triage: confirmed anomalous geolocation. Escalating to Tier 2."
```

**Close incident with classification:**

```
Tool: azure_update_resource
Parameters:
  resourceId: "...incidents/{id}"
  properties:
    status: "Closed"
    classification: "TruePositive"
    classificationReason: "SuspiciousActivity"
    classificationComment: "Confirmed compromised credentials. Password reset completed. MFA enforced."
```

Classification values: `BenignPositive`, `FalsePositive`, `TruePositive`, `Undetermined`

### Analytics Rule CRUD

**Create a scheduled analytics rule:**

```
Tool: azure_create_resource
Parameters:
  resourceType: "Microsoft.SecurityInsights/alertRules"
  kind: "Scheduled"
  properties:
    displayName: "High-CredentialAccess-BruteForceEntraID"
    description: "Detects brute force attempts against Entra ID accounts"
    severity: "High"
    enabled: true
    query: |
      SigninLogs
      | where TimeGenerated > ago(1h)
      | where ResultType != "0"
      | summarize FailureCount=count(), DistinctIPs=dcount(IPAddress)
          by UserPrincipalName, bin(TimeGenerated, 5m)
      | where FailureCount > 10
    queryFrequency: "PT5M"
    queryPeriod: "PT1H"
    triggerOperator: "GreaterThan"
    triggerThreshold: 0
    tactics:
      - "CredentialAccess"
    techniques:
      - "T1110"
    entityMappings:
      - entityType: "Account"
        fieldMappings:
          - identifier: "FullName"
            columnName: "UserPrincipalName"
    incidentConfiguration:
      createIncident: true
      groupingConfiguration:
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: "PT5H"
        matchingMethod: "AllEntities"
```

**Enable/disable a rule:**

```
Tool: azure_update_resource
Parameters:
  resourceId: "...alertRules/{ruleId}"
  properties:
    enabled: false  # or true to enable
```

### Watchlist Management

**Create a watchlist:**

```
Tool: azure_create_resource
Parameters:
  resourceType: "Microsoft.SecurityInsights/watchlists"
  properties:
    displayName: "VIP Users"
    alias: "wl-vip-users"
    source: "Local file"
    itemsSearchKey: "UserPrincipalName"
    contentType: "Text/Csv"
    rawContent: "UserPrincipalName,Department,RiskLevel\nceo@contoso.com,Executive,Critical\ncfo@contoso.com,Finance,Critical"
```

**Add watchlist items:**

```
Tool: azure_create_resource
Parameters:
  resourceType: "Microsoft.SecurityInsights/watchlists/{alias}/watchlistItems"
  properties:
    itemsKeyValue:
      UserPrincipalName: "ciso@contoso.com"
      Department: "Security"
      RiskLevel: "Critical"
```

### Threat Intelligence Operations

**Create a TI indicator:**

```
Tool: azure_create_resource
Parameters:
  resourceType: "Microsoft.SecurityInsights/threatIntelligence/main/createIndicator"
  properties:
    displayName: "C2 Server - APT29"
    pattern: "[ipv4-addr:value = '203.0.113.50']"
    patternType: "ipv4-addr"
    threatTypes:
      - "malicious-activity"
    source: "SOC Investigation - INC-2026-0042"
    confidence: 85
    validFrom: "2026-04-30T00:00:00Z"
    validUntil: "2026-07-30T00:00:00Z"
    killChainPhases:
      - killChainName: "lockheed-martin-cyber-kill-chain"
        phaseName: "C2"
```

### Hunting Queries

**Run a KQL query via the Log Analytics Query API:**

```
Tool: azure_query_logs
Parameters:
  workspaceId: "aabbccdd-1234-5678-abcd-ef0123456789"
  query: |
    SecurityEvent
    | where TimeGenerated > ago(24h)
    | where EventID == 4625
    | summarize FailedLogons=count() by TargetAccount, IpAddress
    | where FailedLogons > 5
    | sort by FailedLogons desc
  timespan: "P1D"
```

**Create a bookmark from hunting results:**

```
Tool: azure_create_resource
Parameters:
  resourceType: "Microsoft.SecurityInsights/bookmarks"
  properties:
    displayName: "Suspicious failed logons from 203.0.113.50"
    query: "SecurityEvent | where EventID == 4625 | where IpAddress == '203.0.113.50'"
    queryResult: "{serialized result data}"
    notes: "Part of threat hunt TH-2026-015. 47 failed logons in 2 hours."
    labels:
      - "threat-hunt"
      - "brute-force"
    tactics:
      - "CredentialAccess"
    techniques:
      - "T1110"
```

### Data Connector Management

**Check connector status:**

```
Tool: azure_list_resources
Parameters:
  resourceType: "Microsoft.SecurityInsights/dataConnectors"
  # Parse results: connector.properties.dataTypes.{tableName}.state == "Enabled"
```

---

## Section 5: Safe Query Execution

### Read vs. Write Operation Boundaries

| Operation | Permission Level | Risk |
|---|---|---|
| List/read resources | `Microsoft Sentinel Reader` | Low — no state changes |
| Run KQL queries | `Log Analytics Reader` | Low — read-only, but can be expensive |
| Create incidents/comments | `Microsoft Sentinel Responder` | Medium — creates artifacts |
| Modify analytics rules | `Microsoft Sentinel Contributor` | High — changes detection coverage |
| Delete resources | `Microsoft Sentinel Contributor` | **Critical** — data loss possible |

**Agent permission model:** Agents should operate with `Microsoft Sentinel Responder` for incident triage workflows. Elevate to `Contributor` only for rule management tasks with explicit user approval.

### Query Safety Guidelines

**Always bound queries by time:**

```kql
// GOOD — bounded time range
SecurityEvent | where TimeGenerated > ago(1h) | summarize count() by EventID

// BAD — unbounded time scan (will be slow and expensive)
SecurityEvent | summarize count() by EventID
```

**Avoid full table scans on high-volume tables:**

```kql
// Check .secops/workspaces/*.yaml for daily_gb to identify expensive tables
// Tables > 10 GB/day: Always filter by TimeGenerated first, then add specific filters
// Tables on Basic tier: Cannot use join, summarize, or make-series
```

**Query timeout handling:**

- Default timeout: 3 minutes for standard queries
- Set explicit timeout for large queries: `set query_take_max_records = 10000;`
- If a query times out, narrow the time range or add filters before retrying
- Never retry an expensive query without reducing its scope

**Result size limits:**

- Default: 500,000 records max per query
- MCP may impose additional limits — check response for truncation indicators
- Use `| take 1000` during investigation to preview before running full queries
- Paginate with `| serialize | where _RowNumber > {offset} | take {pageSize}`

### Cross-Workspace Queries

```kql
// Query across workspaces (requires reader access to all)
union
  workspace("soc-sentinel-prod").SecurityEvent,
  workspace("soc-sentinel-dev").SecurityEvent
| where TimeGenerated > ago(1h)
| summarize count() by _SubscriptionId
```

Cross-workspace queries are more expensive — use only when correlation across workspaces is specifically needed.

### Audit Logging

All MCP operations are logged in Azure Activity Log:

```kql
// Monitor MCP-initiated changes to Sentinel resources
AzureActivity
| where TimeGenerated > ago(24h)
| where ResourceProvider == "MICROSOFT.SECURITYINSIGHTS"
| where OperationNameValue has_any ("write", "delete", "action")
| project TimeGenerated, Caller, OperationNameValue, ResourceId, ActivityStatusValue
| sort by TimeGenerated desc
```

---

## Section 6: Rate Limiting & Throttling

### ARM Throttling Limits

Azure Resource Manager enforces per-subscription rate limits:

| Operation | Limit | Scope |
|---|---|---|
| **Reads** | 12,000 per hour | Per subscription |
| **Writes** | 1,200 per hour | Per subscription |
| **Deletes** | 1,200 per hour | Per subscription |
| **Tenant reads** | 12,000 per hour | Per tenant |

### Sentinel-Specific Limits

| API | Limit | Notes |
|---|---|---|
| Incident operations | 100 per minute | Per workspace |
| Analytics rule operations | 50 per minute | Per workspace |
| TI indicator creation | 100 per request (bulk) | Use bulk API for large imports |
| Watchlist items | 10 MB per upload | Paginate large watchlists |
| Log Analytics queries | 200 per 30 seconds | Per workspace, per user |
| Query result size | 64 MB | Per query response |

### Retry Pattern with Exponential Backoff

```javascript
async function callWithRetry(operation, maxRetries = 5) {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const result = await operation();

    if (result.ok) return result;

    if (result.status === 429) {
      // Parse retry-after header
      const retryAfter = parseInt(result.headers?.['retry-after'] || '0');
      const backoff = Math.max(retryAfter, Math.pow(2, attempt)) * 1000;
      const jitter = Math.random() * 1000;
      await new Promise(r => setTimeout(r, backoff + jitter));
      continue;
    }

    if (result.status >= 500) {
      // Server error — retry with backoff
      await new Promise(r => setTimeout(r, Math.pow(2, attempt) * 1000));
      continue;
    }

    // Client error (4xx) — don't retry
    return result;
  }
  return { ok: false, error: 'Max retries exceeded' };
}
```

### Monitoring Throttle Headers

Check response headers for remaining quota:

```
x-ms-ratelimit-remaining-subscription-reads: 11999
x-ms-ratelimit-remaining-subscription-writes: 1199
x-ms-ratelimit-remaining-tenant-reads: 11999
```

When remaining reads drop below 1,000 or writes below 100, reduce request rate.

### Priority Queue for Operations

During incident response, prioritize operations:

| Priority | Operations | Budget |
|---|---|---|
| **P0 — Critical** | Incident updates, active threat queries | 50% of rate budget |
| **P1 — High** | TI indicator creation, rule enable/disable | 30% of rate budget |
| **P2 — Normal** | Reporting queries, health checks | 15% of rate budget |
| **P3 — Low** | Bulk exports, historical analysis | 5% of rate budget |

---

## Section 7: Agent Integration Patterns

### Discovery and Tool Selection

Agents should follow this pattern when performing Sentinel operations:

```
1. Check .secops/environment.yaml for cloud type and tenant config
2. Read .secops/workspaces/*.yaml for workspace details
3. Check if MCP server is configured in .copilot/mcp-config.json
4. If MCP available → use MCP tools (preferred)
5. If MCP unavailable → fall back to REST API with az rest
6. If az CLI unavailable → fall back to PowerShell Az.SecurityInsights
```

### Graceful Degradation to REST

When the MCP server is unavailable, use direct REST calls:

```bash
# Equivalent of MCP list_resources for incidents
az rest --method GET \
  --url "https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/incidents?api-version=2024-03-01" \
  --query "value[?properties.severity=='High' && properties.status!='Closed']"
```

```powershell
# PowerShell fallback
Get-AzSentinelIncident -ResourceGroupName "rg-soc-prod" -WorkspaceName "soc-sentinel-prod" |
    Where-Object { $_.Severity -eq "High" -and $_.Status -ne "Closed" }
```

### Caching MCP Results

Cache Sentinel resource listings to reduce API calls:

| Resource Type | Cache TTL | Rationale |
|---|---|---|
| Analytics rules | 5 minutes | Rules change infrequently |
| Data connectors | 10 minutes | Connector status is relatively stable |
| Incidents (list) | 30 seconds | Incidents change frequently during triage |
| Watchlist items | 5 minutes | Updated in batches, not continuously |
| TI indicators | 2 minutes | May be updated during active investigation |
| Workspace config | 30 minutes | Infrastructure-level, rarely changes |

### Multi-Agent Coordination

When multiple agents access the same Sentinel workspace, prevent conflicts:

1. **Incident ownership** — Before updating an incident, check `owner.assignedTo`. If already assigned to another agent or analyst, add a comment instead of reassigning.
2. **Rule modifications** — Only one agent should modify analytics rules at a time. Use the rule's `etag` for optimistic concurrency.
3. **Comment-based coordination** — Agents should leave structured comments on incidents they're working:

```json
{
  "agent": "kima-secops",
  "action": "triage-started",
  "timestamp": "2026-04-30T17:00:00Z",
  "summary": "Automated triage: checking entity enrichment and TI correlation"
}
```

4. **Discovery log** — Agents append environment discoveries to `.secops/discovery-log.yaml`, never overwrite.

---

## Section 8: Practical Examples

### Example 1: Triage Incoming Incidents

```
Workflow: List high-severity incidents → assess each → assign → comment

Step 1: List new high-severity incidents
  Tool: azure_list_resources (incidents, filter: severity=High AND status=New)

Step 2: For each incident, get details + related alerts
  Tool: azure_get_resource (incident details)
  Tool: azure_list_resources (incident relations — alerts, bookmarks, entities)

Step 3: Enrich with threat intelligence
  Tool: azure_query_logs (query ThreatIntelligenceIndicator table for IOCs from alerts)

Step 4: Assign and update status
  Tool: azure_update_resource (set status=Active, assign to analyst)

Step 5: Add triage comment
  Tool: azure_create_resource (incident comment with findings)
```

**KQL for triage enrichment:**

```kql
// Correlate incident entities with TI
let IncidentIPs = dynamic(["203.0.113.50", "198.51.100.25"]);
ThreatIntelligenceIndicator
| where TimeGenerated > ago(90d)
| where isnotempty(NetworkIP) and NetworkIP in (IncidentIPs)
| project IndicatorId=ExternalIndicatorId, ThreatType, Confidence=ConfidenceScore,
    Description, Source=SourceSystem, Active, NetworkIP
| sort by Confidence desc
```

### Example 2: Deploy a New Analytics Rule

```
Workflow: Validate KQL → create rule → test → enable

Step 1: Test the detection query
  Tool: azure_query_logs
  Query: Run the KQL with a safe time range (1h) to validate syntax and results

Step 2: Check for duplicate rules
  Tool: azure_list_resources (alertRules)
  Logic: Compare displayName and query against existing rules

Step 3: Create the rule (initially disabled)
  Tool: azure_create_resource (alertRule, kind=Scheduled, enabled=false)

Step 4: Validate rule was created
  Tool: azure_get_resource (read back the created rule)

Step 5: Enable the rule after validation
  Tool: azure_update_resource (set enabled=true)

Step 6: Monitor for first trigger (optional)
  Tool: azure_query_logs (check SecurityIncident for new incidents from this rule)
```

### Example 3: Threat Intel Enrichment Workflow

```
Workflow: Query TI → correlate with alerts → create indicators for new IOCs

Step 1: Extract IOCs from recent high-severity incidents
  Tool: azure_query_logs
  Query: SecurityAlert | where TimeGenerated > ago(24h) | where AlertSeverity == "High"
         | mv-expand Entity=parse_json(Entities) | where Entity.Type == "ip"

Step 2: Check existing TI indicators
  Tool: azure_list_resources (threatIntelligence/main/indicators)
  Logic: Filter for matching IOCs to avoid duplicates

Step 3: Enrich with external sources (if available)
  Logic: Cross-reference with MDTI, VirusTotal, or other TI feeds

Step 4: Create new TI indicators for confirmed threats
  Tool: azure_create_resource (threatIntelligence indicator)
  Properties: pattern, confidence, source, validFrom/validUntil

Step 5: Verify indicator appears in workspace
  Tool: azure_query_logs (query ThreatIntelligenceIndicator table)
```

### Example 4: Workspace Health Check

```
Workflow: Connectors status → rule effectiveness → ingestion stats

Step 1: Check data connector health
  Tool: azure_list_resources (dataConnectors)
  Logic: Flag any connector with status != "connected"

Step 2: Check analytics rule status
  Tool: azure_list_resources (alertRules)
  Logic: Count enabled vs disabled, check for rules with errors

Step 3: Ingestion volume check
  Tool: azure_query_logs
  Query:
    Usage
    | where TimeGenerated > ago(24h)
    | summarize IngestedGB=sum(Quantity)/1024 by DataType
    | sort by IngestedGB desc
    | take 20

Step 4: Detection effectiveness
  Tool: azure_query_logs
  Query:
    SecurityIncident
    | where TimeGenerated > ago(30d)
    | summarize
        Total=count(),
        TruePositive=countif(Classification == "TruePositive"),
        FalsePositive=countif(Classification == "FalsePositive"),
        BenignPositive=countif(Classification == "BenignPositive")
    | extend TPRate=round(100.0 * TruePositive / Total, 1)

Step 5: Report findings
  Logic: Generate summary with connector status, top tables by volume,
         rule effectiveness rate, and recommendations
```

---

## Related Skills

- **[Sentinel Workspace Setup](sentinel-workspace-setup.md)** — Provisioning and configuring the workspace that MCP connects to
- **[Microsoft Graph Security API](microsoft-graph-security.md)** — Alternative API surface for security data (Graph vs ARM)
- **[Sentinel API Reference](sentinel-api-reference.md)** — REST API details for fallback when MCP is unavailable
- **[Threat Hunting Foundations](../kql/threat-hunting-foundations.md)** — KQL patterns used in MCP query operations
- **[Detection Lifecycle](../detection/detection-lifecycle.md)** — End-to-end workflow that MCP tooling supports
- **[SecOps Environment Context](.copilot/skills/secops-environment-context.md)** — `.secops/` discovery protocol

## References

- [Azure MCP Server — GitHub](https://github.com/Azure/azure-mcp-server)
- [Model Context Protocol — Specification](https://modelcontextprotocol.io)
- [Microsoft Sentinel REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/)
- [Azure Resource Manager Throttling](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling)
- [DefaultAzureCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.defaultazurecredential)
