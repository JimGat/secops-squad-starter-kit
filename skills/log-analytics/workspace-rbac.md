---
title: Workspace RBAC
category: log-analytics
difficulty: intermediate
mitre_attack:
  - T1078  # Valid Accounts — access control is the defense against credential misuse
products:
  - Azure Monitor Log Analytics
  - Microsoft Sentinel
  - Microsoft Entra ID
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Workspace RBAC

## Overview

Role-Based Access Control (RBAC) for Log Analytics workspaces determines who can read logs, run queries, configure data collection, and manage Sentinel resources. Getting RBAC right is critical — too permissive and you violate least privilege; too restrictive and your SOC team can't do their job. This skill covers built-in roles, resource-context access, table-level RBAC, and service principal patterns.

Use this skill when:
- You need to grant SOC analysts read access to Sentinel without full workspace admin
- You want infrastructure teams to see only their own resource logs (resource-context RBAC)
- You need to restrict access to specific tables (e.g., HR data, executive sign-ins)
- You are configuring service principal or managed identity access for automation
- You need to design a RBAC model for a multi-team organization

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Owner` or `User Access Administrator` for role assignments; `Log Analytics Contributor` for workspace configuration |
| **Products** | Azure Monitor Log Analytics, Microsoft Entra ID |
| **Knowledge** | Azure RBAC concepts (roles, scopes, assignments), Entra ID groups |

## Core Patterns

### Pattern 1 — Built-in Roles Reference

| Role | Read Logs | Write Logs | Manage Workspace | Sentinel Access | Scope |
|---|---|---|---|---|---|
| **Log Analytics Reader** | ✅ | ❌ | ❌ | ❌ | Workspace |
| **Log Analytics Contributor** | ✅ | ✅ | ✅ (config) | ❌ | Workspace |
| **Sentinel Reader** | ✅ | ❌ | ❌ | Read incidents, rules, workbooks | Workspace |
| **Sentinel Responder** | ✅ | ❌ | ❌ | Read + manage incidents (assign, change status) | Workspace |
| **Sentinel Contributor** | ✅ | ✅ | ❌ | Full Sentinel management (rules, workbooks, playbooks) | Workspace |
| **Sentinel Playbook Operator** | ❌ | ❌ | ❌ | Run playbooks on incidents | Workspace |
| **Monitoring Reader** | ✅ (metrics/logs) | ❌ | ❌ | ❌ | Resource/RG/Sub |
| **Reader** | ❌ (no log query) | ❌ | ❌ | ❌ | Resource/RG/Sub |

```bash
# Assign Sentinel Responder to SOC Tier 1 analysts group
az role assignment create \
  --assignee-object-id "SOC_TIER1_GROUP_OBJECT_ID" \
  --role "Microsoft Sentinel Responder" \
  --scope "/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-central"

# Assign Sentinel Contributor to detection engineers
az role assignment create \
  --assignee-object-id "DETECTION_ENG_GROUP_OBJECT_ID" \
  --role "Microsoft Sentinel Contributor" \
  --scope "/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-central"

# Assign Log Analytics Reader for read-only query access
az role assignment create \
  --assignee-object-id "THREAT_HUNTERS_GROUP_OBJECT_ID" \
  --role "Log Analytics Reader" \
  --scope "/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-central"
```

---

### Pattern 2 — Resource-Context RBAC

Resource-context RBAC lets users query logs from resources they already have Azure Reader (or higher) access to — without granting workspace-level permissions. This is ideal for infrastructure teams and application developers.

```bash
# Enable resource-context access on the workspace
az monitor log-analytics workspace update \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --set features.enableLogAccessUsingOnlyResourcePermissions=true
```

**How it works:**

```
┌─────────────────────────────────────────────────────────────────┐
│                    Log Analytics Workspace                       │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │ VM Logs      │  │ Key Vault    │  │ Security     │           │
│  │ (Heartbeat,  │  │ Logs (AzDiag)│  │ Alerts       │           │
│  │  Perf, Event)│  │              │  │              │           │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │
│         │                  │                  │                   │
│         ▼                  ▼                  ▼                   │
│   Infra team sees    App team sees     SOC sees all              │
│   only their VMs'    only their KV's   (workspace-level          │
│   logs via           logs via          Reader or Sentinel         │
│   resource-context   resource-context  role)                     │
└─────────────────────────────────────────────────────────────────┘
```

**Resource-context access rules:**
- User needs `Reader` (or higher) on the Azure resource
- Workspace must have `enableLogAccessUsingOnlyResourcePermissions` set to `true`
- User accesses logs via the resource's **Logs** blade in the Azure portal
- Custom tables (`_CL` suffix) are NOT accessible via resource-context
- Some tables (e.g., `SecurityAlert`, `SecurityIncident`) are workspace-only — no resource-context access

---

### Pattern 3 — Table-Level RBAC

Restrict access to specific tables within a workspace. This is essential when sensitive data (HR records, executive sign-ins, financial transactions) shares a workspace with general security data.

```bash
# Create a custom role that grants read access to only specific tables
az role definition create --role-definition '{
  "Name": "Sentinel Restricted Reader - Identity Only",
  "Description": "Can query only identity-related tables in the workspace",
  "Actions": [
    "Microsoft.OperationalInsights/workspaces/read",
    "Microsoft.OperationalInsights/workspaces/query/read"
  ],
  "NotActions": [],
  "DataActions": [
    "Microsoft.OperationalInsights/workspaces/tables/SignInLogs/read",
    "Microsoft.OperationalInsights/workspaces/tables/AuditLogs/read",
    "Microsoft.OperationalInsights/workspaces/tables/AADNonInteractiveUserSignInLogs/read",
    "Microsoft.OperationalInsights/workspaces/tables/AADServicePrincipalSignInLogs/read"
  ],
  "NotDataActions": [],
  "AssignableScopes": [
    "/subscriptions/SUB_ID"
  ]
}'

# Assign the custom role to an identity analyst group
az role assignment create \
  --assignee-object-id "IDENTITY_ANALYSTS_GROUP_ID" \
  --role "Sentinel Restricted Reader - Identity Only" \
  --scope "/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-central"
```

```bash
# Alternative: Set table-level RBAC using workspace table properties
# This hides a table from all workspace-level readers (opt-in access only)
az monitor log-analytics workspace table update \
  --resource-group rg-sentinel \
  --workspace-name sentinel-central \
  --name ConfidentialHRData_CL \
  --set properties.schema.tableSubType=DataCollectionRuleBased

# Then grant specific access via custom role with DataActions
```

---

### Pattern 4 — Service Principal and Managed Identity Access

Automation (Logic Apps, Azure Functions, DevOps pipelines) needs programmatic access to Log Analytics. Use managed identities wherever possible; fall back to service principals for cross-tenant scenarios.

```bash
# Create a service principal for Log Analytics query access
az ad sp create-for-rbac \
  --name "sp-sentinel-query-automation" \
  --role "Log Analytics Reader" \
  --scopes "/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-central"

# For Logic Apps: assign managed identity access
az role assignment create \
  --assignee-object-id "LOGIC_APP_MANAGED_IDENTITY_OID" \
  --role "Microsoft Sentinel Responder" \
  --scope "/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-central"
```

```bicep
// Bicep: Assign managed identity access to workspace
param workspaceId string
param managedIdentityPrincipalId string

var sentinelResponderRoleId = '3e150fc0-0e72-4d56-ada6-6a36c1d12110'

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(workspaceId, managedIdentityPrincipalId, sentinelResponderRoleId)
  scope: resourceId('Microsoft.OperationalInsights/workspaces', last(split(workspaceId, '/')))
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', sentinelResponderRoleId)
    principalId: managedIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}
```

---

### Pattern 5 — Auditing RBAC Assignments

Regularly audit who has access to your workspace. Stale assignments are a privilege escalation risk.

```kql
// Monitor workspace access via Azure Activity logs
AzureActivity
| where TimeGenerated > ago(30d)
| where ResourceProviderValue == "MICROSOFT.OPERATIONALINSIGHTS"
| where OperationNameValue has_any (
    "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
    "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/DELETE"
)
| project
    TimeGenerated,
    Caller,
    OperationNameValue,
    ActivityStatusValue,
    Properties = parse_json(Properties)
| extend
    RoleDefinition = tostring(Properties.requestbody)
| order by TimeGenerated desc
```

```bash
# List all role assignments on the workspace
az role assignment list \
  --scope "/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-central" \
  --output table

# List assignments including inherited (from subscription/RG)
az role assignment list \
  --scope "/subscriptions/SUB_ID/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-central" \
  --include-inherited \
  --output table
```

```kql
// Track who is querying the workspace (requires LAQueryLogs diagnostic setting)
LAQueryLogs
| where TimeGenerated > ago(7d)
| summarize
    QueryCount = count(),
    AvgDuration = avg(ResponseDurationMs),
    TablesQueried = make_set(RequestTarget, 20)
    by AADEmail
| order by QueryCount desc
```

## Best Practices

1. **Use Entra ID groups, not individual assignments** — Assign roles to groups; manage membership in Entra ID
2. **Prefer managed identity over service principal** — Managed identities don't need credential rotation
3. **Enable resource-context access** — Let infrastructure teams self-serve their own resource logs
4. **Audit RBAC quarterly** — Stale assignments from departed employees or decommissioned automation are privilege escalation vectors
5. **Use table-level RBAC for sensitive data** — If HR data or executive sign-ins are in the workspace, restrict access at the table level
6. **Apply least privilege** — SOC Tier 1 analysts need `Sentinel Responder`, not `Contributor`; detection engineers need `Contributor`, not `Owner`
7. **Document role assignments** — Maintain a RBAC matrix showing which groups have which roles and why

## Cost Implications

| Factor | Impact |
|---|---|
| RBAC configuration | No direct cost — RBAC is free |
| LAQueryLogs | Enabling query auditing (LAQueryLogs) generates billable data; typically low volume |
| Resource-context queries | Same query cost as workspace-context — no additional charge |
| Service principals | No Azure cost; management overhead for credential rotation |

## Related Skills

- **[Workspace Architecture](workspace-architecture.md)** — Workspace topology determines RBAC boundaries.
- **[Entra Sign-in Analysis](../kql/entra-signin-analysis.md)** — Detect credential misuse that RBAC is designed to prevent.
- **[Cost Optimization](cost-optimization.md)** — RBAC doesn't affect cost, but table-level access controls pair with Basic Logs and Sentinel data lake tier decisions.
- **[Custom Tables & DCR](custom-tables-dcr.md)** — Custom tables have specific RBAC considerations for resource-context access.
