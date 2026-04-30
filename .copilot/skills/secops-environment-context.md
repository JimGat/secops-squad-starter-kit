# Skill: SecOps Environment Context

> Teaches agents how to discover, read, and use the `.secops/` customer knowledge framework before performing any security operations task.

## When to Use This Skill

Use this skill **before any task** that references:

- Azure resources (subscriptions, resource groups, regions)
- Log Analytics workspaces or Sentinel instances
- KQL tables or data sources
- Data connectors or ingestion pipelines
- Sentinel analytics rules or detection deployments
- SOAR playbooks or Logic Apps deployments
- ADX clusters or databases
- Compliance, data residency, or regulatory constraints

If the task is purely about framework code, CLI tooling, or documentation that doesn't touch customer infrastructure, this skill is not needed.

---

## Discovery Flow

Follow these 7 steps before executing any environment-aware task:

### Step 1: Check Environment Context

Read `.secops/environment.yaml` to understand:
- **Organization name** and cloud type (`azure-commercial`, `azure-government`, `azure-china`, `azure-stack`)
- **Primary region** for SOC infrastructure
- **Tenant configuration** — single-tenant, multi-tenant, MSSP, or Lighthouse-delegated
- **Managed customers** (if MSSP)

```yaml
# Key fields to check:
organization.name        # Customer name
organization.cloud       # Cloud type — affects API endpoints
organization.primary_region  # Default region
tenants[].type           # primary | managed | lighthouse-delegated
```

### Step 2: Check Data Source Map

Read `.secops/data-sources/data-source-map.yaml` to understand WHERE data lives:
- Which tables exist and their locations (`sentinel`, `adx`, `external`)
- Data tiers (`Analytics`, `Basic`, `Auxiliary`, `Archive`)
- Workspace or ADX cluster assignments
- Retention periods

This is the **most critical file for KQL work** — never assume a table is in Sentinel without checking.

### Step 3: Check Active Migrations

Read `.secops/data-sources/migrations.yaml` to understand what's MOVING:
- Active migrations between locations (e.g., Sentinel → ADX)
- Migration status and timelines
- Dual-write periods where data exists in multiple locations

**Never recommend moving a data source that is already being migrated.**

### Step 4: Check Workspace Configuration

Read `.secops/workspaces/<name>.yaml` for workspace specifics:
- Workspace ID and resource ID
- Pricing tier and commitment tier
- Retention and archive settings
- Naming conventions and tagging standards
- Connected data connectors

### Step 5: Check Compliance Requirements

Read `.secops/compliance/requirements.yaml` for constraints:
- Regulatory frameworks (SOC2, HIPAA, FedRAMP, etc.)
- Data residency requirements — allowed and prohibited regions
- Retention minimums mandated by regulation
- Encryption and access control requirements

### Step 6: Execute Task with Environment-Aware Decisions

Now execute the task using the context gathered in Steps 1–5. Make decisions that respect:
- The actual data locations (not assumptions)
- Active migrations (don't conflict)
- Compliance boundaries (don't violate)
- Workspace configurations (use correct IDs, tiers, naming)

### Step 7: Log New Discoveries

If you discovered a new fact about the environment during task execution, append it to `.secops/discovery-log.yaml`.

---

## Critical Rules

These rules are **non-negotiable** — violating them can cause incorrect queries, failed deployments, or compliance violations:

1. **ALWAYS check `data-source-map.yaml` before writing KQL queries** that reference specific tables. Tables may be in Sentinel, ADX, or external sources — never assume.

2. **ALWAYS check `migrations.yaml` before recommending data source changes.** A data source may already be mid-migration. Conflicting changes cause data loss or duplication.

3. **ALWAYS check `compliance/requirements.yaml` before deploying to a region.** Prohibited regions are absolute — no exceptions, no workarounds.

4. **If `.secops/` doesn't exist**, work without it but suggest the user run:
   ```
   secops-squad init --secops
   ```
   This scaffolds the `.secops/` directory with templates the user can fill in.

---

## How to Write to discovery-log.yaml

When you discover a new fact about the customer's environment during normal operations (e.g., a table exists, a workspace uses a specific tier, an API endpoint is different than expected):

### Append Rules

- **Append** to the `discoveries` list — never modify or delete existing entries
- Use **ISO 8601 timestamps** with timezone offset
- Include all required fields; add optional structured fields when applicable

### Required Fields

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 datetime when the fact was discovered |
| `agent` | Name of the agent that discovered the fact (e.g., `freamon`, `kima`) |
| `confidence` | Confidence level: `high`, `medium`, or `low` |
| `fact` | Human-readable description of what was discovered |
| `source` | How the agent discovered this (query, API call, error message, etc.) |

### Optional Structured Fields

| Field | Description |
|-------|-------------|
| `data_source` | Table or data source name (e.g., `SecurityEvent`) |
| `location` | Where the data lives: `sentinel`, `adx`, `external` |
| `workspace` | Workspace short name (references `.secops/workspaces/`) |
| `cluster` | ADX cluster name |
| `database` | ADX database name |
| `tier` | Data tier: `Analytics`, `Basic`, `Auxiliary`, `Archive` |
| `tenant_id` | Entra ID tenant GUID |
| `region` | Azure region |
| `notes` | Additional context for the human reviewer |

### Confidence Levels

| Level | When to Use |
|-------|-------------|
| `high` | Direct API or query confirmation — you ran a query and got results, or called an API and got a definitive response |
| `medium` | Indirect evidence — error messages, naming patterns that strongly suggest a fact, cross-referencing multiple sources |
| `low` | Pattern inference — the fact is likely true based on naming conventions, documentation, or common configurations, but not directly confirmed |

### Example Entry

```yaml
discoveries:
  - timestamp: "2026-04-30T15:05:00-05:00"
    agent: "freamon"
    confidence: "high"
    fact: "SecurityEvent table exists in workspace soc-sentinel-prod with Analytics tier"
    source: "KQL query: SecurityEvent | take 1 — returned results"
    data_source: "SecurityEvent"
    location: "sentinel"
    workspace: "soc-sentinel-prod"
    tier: "Analytics"
```

---

## Government Cloud Awareness

Check the `organization.cloud` field in `.secops/environment.yaml` before any API calls or deployments.

### Azure Government (`azure-government`)

- Use `.usgovcloudapi.net` endpoints instead of `.azure.com`
- Log Analytics API: `https://api.loganalytics.us`
- Azure Resource Manager: `https://management.usgovcloudapi.net`
- Microsoft Graph: `https://graph.microsoft.us`
- **Feature gaps:** Some Sentinel features, data connectors, and SOAR connectors may not be available. Always verify feature availability before recommending.
- **Compliance:** FedRAMP High and DoD IL4/IL5 boundaries apply — never route data outside government cloud regions.

### Azure China (`azure-china`)

- Use `.chinacloudapi.cn` endpoints
- Log Analytics API: `https://api.loganalytics.azure.cn`
- Azure Resource Manager: `https://management.chinacloudapi.cn`
- Microsoft Graph: `https://microsoftgraph.chinacloudapi.cn`
- **Feature gaps:** More limited than government cloud. Many third-party connectors unavailable.

### Azure Commercial (`azure-commercial`)

- Standard endpoints — no special handling needed.

---

## Multi-Tenant Awareness

Check the `tenants` section in `.secops/environment.yaml` to understand the tenant topology.

### Single Tenant

Standard operations — one tenant, one set of credentials, full access.

### Lighthouse-Delegated

- The agent operates in a **delegated context** — permissions are scoped by the Lighthouse delegation.
- **No Entra ID access** in the customer tenant (unless explicitly delegated).
- Operations are performed from the managing tenant with cross-tenant projections.
- Check `lighthouse.delegated_permissions` for what's actually available.

### MSSP (Managed Security Service Provider)

- Multiple customer tenants managed from a central SOC.
- Iterate over `managed_customers` for cross-tenant operations.
- Each customer may have different workspace configurations, data sources, and compliance requirements.
- **Never assume uniformity** — always check per-customer `.secops/` context.

---

## Data Residency Awareness

Before any cross-region operation (deploying resources, creating workspaces, configuring data export):

1. Read `.secops/compliance/requirements.yaml`
2. Check `data_residency.allowed_regions` — only deploy to listed regions
3. Check `data_residency.prohibited_regions` — **these are absolute**; never deploy to a prohibited region, even if the user requests it
4. If a task would require using a prohibited region, **stop and explain** why it can't be done

### Example Check

```yaml
# In compliance/requirements.yaml:
data_residency:
  allowed_regions:
    - eastus2
    - westus2
  prohibited_regions:
    - chinaeast
    - chinanorth
```

If asked to deploy to `chinaeast`, refuse and explain the compliance constraint.

---

## Quick Reference

| What You Need | Where to Find It |
|---------------|------------------|
| Tenant, cloud type, region | `.secops/environment.yaml` |
| Table locations | `.secops/data-sources/data-source-map.yaml` |
| Active migrations | `.secops/data-sources/migrations.yaml` |
| Workspace details | `.secops/workspaces/<name>.yaml` |
| Compliance constraints | `.secops/compliance/requirements.yaml` |
| Identity & RBAC | `.secops/identity/` |
| Alerting config | `.secops/alerting/` |
| Log new discoveries | `.secops/discovery-log.yaml` |
| Framework overview | `.secops/README.md` |
