---
title: Workspace Architecture
category: log-analytics
difficulty: intermediate
mitre_attack:
  - General  # Foundational — applies to all detection and monitoring
products:
  - Azure Monitor Log Analytics
  - Microsoft Sentinel
  - Azure Lighthouse
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Workspace Architecture

## Overview

The workspace architecture decision is one of the highest-leverage choices in a Sentinel/Log Analytics deployment. It determines your cost structure, compliance posture, query performance, RBAC boundaries, and operational complexity for years to come. There is no universal right answer — the correct topology depends on your regulatory environment, organizational structure, data residency requirements, and team operating model.

Use this skill when:
- You are designing a greenfield Sentinel deployment and need to decide single vs. multi-workspace
- You are evaluating whether to consolidate existing workspaces
- You are an MSSP designing multi-tenant monitoring architecture
- You need to understand resource-context vs. workspace-context log access trade-offs
- You are planning a workspace migration or consolidation

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Log Analytics Contributor` for workspace creation; `Owner` or `User Access Administrator` for RBAC configuration |
| **Products** | Azure Monitor Log Analytics, optionally Microsoft Sentinel |
| **Knowledge** | Basic understanding of Azure subscriptions, resource groups, and RBAC |
| **Networking** | Understanding of data residency requirements for your organization |

## Core Patterns

### Pattern 1 — Single Workspace (Recommended Starting Point)

A single workspace is the simplest and most cost-effective architecture. All logs flow to one workspace, and cross-table queries are native — no `workspace()` calls needed.

**When to use:**
- Single-region deployments or no data residency requirements
- Small to medium organizations (< 50 TB/day ingestion)
- Teams that need full correlation across all data sources
- Budget-conscious deployments — a single workspace qualifies for commitment tier discounts as a single pool

```bash
# Create a single centralized workspace
az monitor log-analytics workspace create \
  --resource-group rg-sentinel-prod \
  --workspace-name sentinel-central \
  --location eastus2 \
  --retention-time 90 \
  --sku PerGB2018 \
  --tags environment=production purpose=sentinel

# Enable Sentinel on the workspace
az sentinel onboarding-state create \
  --resource-group rg-sentinel-prod \
  --workspace-name sentinel-central \
  --name default
```

```bicep
// Bicep: Single workspace with Sentinel enabled
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'sentinel-central'
  location: 'eastus2'
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true  // Enable resource-context RBAC
    }
  }
  tags: {
    environment: 'production'
    purpose: 'sentinel'
  }
}

resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  name: 'default'
  scope: workspace
  properties: {}
}
```

**Pros:**
- Simplest to manage, cheapest to operate (single commitment tier pool)
- Native cross-table correlation — no cross-workspace query overhead
- Single pane of glass for all incidents, analytics rules, and workbooks
- Easier RBAC management with resource-context access

**Cons:**
- Single region — may not meet data residency requirements
- All-or-nothing data access without careful RBAC (mitigated by resource-context and table-level RBAC)
- Blast radius — a misconfiguration affects all data

---

### Pattern 2 — Multi-Workspace by Region (Data Residency)

When regulations require data to stay within specific geographic boundaries, deploy one workspace per region. Use cross-workspace queries for federated hunting.

```bash
# Create workspaces in required regions
az monitor log-analytics workspace create \
  --resource-group rg-sentinel-eu \
  --workspace-name sentinel-eu-west \
  --location westeurope \
  --retention-time 90

az monitor log-analytics workspace create \
  --resource-group rg-sentinel-us \
  --workspace-name sentinel-us-east \
  --location eastus2 \
  --retention-time 90

az monitor log-analytics workspace create \
  --resource-group rg-sentinel-apac \
  --workspace-name sentinel-apac-east \
  --location australiaeast \
  --retention-time 90
```

```kql
// Verify workspace deployment and configuration across regions
resources
| where type == "microsoft.operationalinsights/workspaces"
| project
    WorkspaceName = name,
    Region = location,
    RetentionDays = tostring(properties.retentionInDays),
    Sku = tostring(properties.sku.name),
    ResourceId = id
| order by Region asc
```

**When to use:**
- GDPR, CCPA, or sector-specific data residency mandates
- Multi-national organizations with sovereign cloud requirements
- Government workloads requiring in-country data processing

---

### Pattern 3 — Multi-Workspace by Environment

Separate production, development, and staging logs to prevent noise from polluting production detections and to isolate cost centers.

```bicep
// Bicep: Environment-separated workspaces
@allowed(['prod', 'dev', 'staging'])
param environment string

var workspaceName = 'sentinel-${environment}'
var retentionDays = environment == 'prod' ? 90 : 30

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: resourceGroup().location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionDays
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
  tags: {
    environment: environment
  }
}
```

**Decision matrix:**

| Factor | Single Workspace | Per-Region | Per-Environment | Per-Tenant (MSSP) |
|---|---|---|---|---|
| Cross-table queries | Native | Cross-workspace | Cross-workspace | Cross-workspace + Lighthouse |
| Commitment tier pooling | Single pool | Per-workspace | Per-workspace | Per-customer |
| Data residency | Single region | ✅ Compliant | Region-dependent | Per-customer region |
| RBAC complexity | Low | Medium | Medium | High |
| Sentinel cost (per GB) | Single billing | Multiplied per workspace | Multiplied per workspace | Per-customer billing |

---

### Pattern 4 — Cross-Tenant Architecture with Azure Lighthouse

MSSPs use Azure Lighthouse to manage customer workspaces from a single managing tenant. Each customer retains ownership of their data; the MSSP gets delegated read (and optionally write) access.

```bash
# Delegate customer workspace to MSSP managing tenant
# This runs in the customer's context
az deployment group create \
  --resource-group rg-customer-sentinel \
  --template-file lighthouse-delegation.bicep \
  --parameters \
    managingTenantId="MSSP_TENANT_ID" \
    principalId="MSSP_SOC_GROUP_OBJECT_ID" \
    roleDefinitionId="43d0d8ad-25c7-4714-9337-8ba259a9fe05" \
    principalIdDisplayName="MSSP SOC Analysts"
```

```bicep
// Bicep: Lighthouse delegation for MSSP workspace access
param managingTenantId string
param principalId string
param roleDefinitionId string
param principalIdDisplayName string

resource delegation 'Microsoft.ManagedServices/registrationDefinitions@2022-10-01' = {
  name: guid('mssp-delegation-sentinel')
  properties: {
    registrationDefinitionName: 'MSSP Sentinel Access'
    managedByTenantId: managingTenantId
    authorizations: [
      {
        principalId: principalId
        roleDefinitionId: roleDefinitionId  // Microsoft Sentinel Reader
        principalIdDisplayName: principalIdDisplayName
      }
    ]
  }
}
```

---

### Pattern 5 — Resource-Context vs. Workspace-Context Access

Resource-context access lets users see only logs from Azure resources they already have permissions on — without granting workspace-level access. This is critical for large organizations where infrastructure teams should see their VMs' logs but not security alerts.

```bash
# Enable resource-context access on a workspace
az monitor log-analytics workspace update \
  --resource-group rg-sentinel-prod \
  --workspace-name sentinel-central \
  --set features.enableLogAccessUsingOnlyResourcePermissions=true
```

```kql
// Verify resource-context access setting
resources
| where type == "microsoft.operationalinsights/workspaces"
| project
    WorkspaceName = name,
    ResourceContextEnabled = tostring(properties.features.enableLogAccessUsingOnlyResourcePermissions)
```

**Access mode comparison:**

| Aspect | Workspace-Context | Resource-Context |
|---|---|---|
| Access via | Log Analytics workspace blade | Azure resource Logs blade |
| Sees data from | All tables user has workspace-level access to | Only tables with data from resources user has Reader on |
| Custom logs (_CL) | ✅ Visible with workspace access | ❌ Not accessible via resource-context |
| Best for | SOC analysts, security teams | Infrastructure teams, app developers |

---

### Pattern 6 — Workspace Consolidation Migration

Migrating from multiple workspaces to fewer workspaces requires careful planning. Data cannot be moved — you redirect data connectors and wait for old data to age out.

```bash
# Step 1: Inventory existing workspaces and their data sources
az monitor log-analytics workspace list \
  --query "[].{Name:name, Location:location, RG:resourceGroup, Retention:retentionInDays}" \
  --output table

# Step 2: List data sources on the source workspace
az monitor log-analytics workspace data-source list \
  --resource-group rg-old-workspace \
  --workspace-name old-workspace-01 \
  --resource-type AzureActivityLog \
  --output table

# Step 3: Redirect diagnostic settings to new workspace
az monitor diagnostic-settings create \
  --name "redirect-to-consolidated" \
  --resource "/subscriptions/SUB_ID/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/vm-01" \
  --workspace "/subscriptions/SUB_ID/resourceGroups/rg-sentinel-prod/providers/Microsoft.OperationalInsights/workspaces/sentinel-central" \
  --logs '[{"category":"Administrative","enabled":true}]'
```

```kql
// Monitor data volume in old vs new workspace during migration
// Run in each workspace to compare ingestion trends
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize
    DailyGB = sum(Quantity) / 1024.0
    by bin(TimeGenerated, 1d), DataType
| summarize TotalDailyGB = sum(DailyGB) by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
| render timechart
```

**Migration checklist:**
- [ ] Inventory all workspaces, data connectors, analytics rules, and workbooks
- [ ] Redirect data connectors to target workspace
- [ ] Recreate analytics rules, workbooks, and automation rules
- [ ] Maintain read access to old workspaces until retention expires
- [ ] Monitor ingestion volume in both old and new workspaces during transition
- [ ] Update any Logic Apps or automation that references old workspace IDs

## Best Practices

1. **Start with one workspace** unless you have a specific regulatory or organizational reason to split
2. **Enable resource-context access** on every workspace to support infrastructure team self-service
3. **Use resource IDs** (not names) for all `workspace()` references in KQL queries
4. **Tag workspaces** with environment, purpose, and cost center for governance
5. **Plan for Sentinel-specific costs** — each workspace with Sentinel enabled incurs separate analytics rule processing costs
6. **Document your architecture decision** in an ADR (Architecture Decision Record) with the specific constraints that drove it

## Cost Implications

| Architecture | Cost Impact |
|---|---|
| Single workspace | Best commitment tier efficiency; single Sentinel instance cost |
| Per-region | Commitment tier per workspace; cross-region bandwidth costs for queries |
| Per-environment | Dev/staging may not justify commitment tiers; use pay-as-you-go |
| Per-tenant (MSSP) | Each customer workspace billed independently; Lighthouse queries incur no extra data transfer cost |

**Key cost rule:** Sentinel charges are per-workspace. Every workspace you add with Sentinel multiplies your analytics rule processing costs. Consolidate unless compliance prevents it.

## Related Skills

- **[Cross-Workspace Queries](../kql/cross-workspace-queries.md)** — KQL patterns for querying across workspace boundaries.
- **[Workspace RBAC](workspace-rbac.md)** — Role assignments and access control patterns for workspaces.
- **[Cost Optimization](cost-optimization.md)** — Pricing tiers, commitment tiers, and cost reduction strategies.
- **[Retention & Archive](retention-archive.md)** — Retention policies and long-term archival strategies.
- **[Diagnostic Settings](diagnostic-settings.md)** — How to route Azure resource logs into your workspace architecture.
