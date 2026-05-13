# `.secops/` Schema Reference

> **Version:** 1.0 | **Last Updated:** 2026-05-04 | **Schema Version:** 1.0

Complete field-level documentation for every YAML file in the `.secops/` customer knowledge framework. All files include `schema_version: "1.0"` for forward compatibility.

For working examples, see [`samples/secops-contoso/.secops/`](../samples/secops-contoso/.secops/).

---

## File Overview

| File | Purpose | Agent Priority |
|------|---------|---------------|
| `environment.yaml` | Root config: org, tenants, subscriptions | 🔴 Read first |
| `data-sources/data-source-map.yaml` | Table → location mapping | 🔴 Read before every query |
| `data-sources/migrations.yaml` | Active data migrations | 🟡 Check before assuming table location is stable |
| `workspaces/<name>.yaml` | Workspace details, connectors, retention | 🟡 Read when targeting a specific workspace |
| `identity/tenants.yaml` | Multi-tenant topology | 🟡 Read for cross-tenant operations |
| `identity/rbac-conventions.yaml` | RBAC naming patterns | 🟢 Read when creating role assignments |
| `alerting/routing.yaml` | Alert routing rules | 🟡 Read when configuring notifications |
| `alerting/escalation.yaml` | Escalation procedures | 🟢 Read for IR workflows |
| `compliance/requirements.yaml` | Regulatory constraints | 🔴 Read before deploying or moving data |
| `discovery-log.yaml` | Agent-discovered facts | 🟡 Append when discovering new facts |

---

## `environment.yaml`

Root configuration file. Agents read this **first** to understand tenant, subscription, and cloud context.

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `schema_version` | string | ✅ | `"1.0"` | Schema version for forward compatibility |
| `organization.name` | string | ✅ | — | Display name of the customer organization |
| `organization.cloud` | string | ✅ | `azure-commercial` \| `azure-government` \| `azure-china` \| `azure-stack` | Cloud environment type |
| `organization.primary_region` | string | ✅ | Azure region | Primary region for SOC infrastructure |
| `organization.data_residency` | string | ✅ | ISO 3166-1 code | Data residency zone (e.g., `us`, `eu`) |
| `organization.org_type` | string | ✅ | `enterprise` \| `mssp` | Organization type |
| `tenants[]` | list | ✅ | — | Azure AD/Entra ID tenants |
| `tenants[].id` | string | ✅ | GUID | Tenant ID |
| `tenants[].name` | string | ✅ | — | Display name |
| `tenants[].type` | string | ✅ | `primary` \| `secondary` \| `managed` \| `lighthouse-delegated` \| `csp` | Tenant relationship type |
| `subscriptions[]` | list | ✅ | — | Azure subscriptions used by the SOC |
| `subscriptions[].id` | string | ✅ | GUID | Subscription ID |
| `subscriptions[].name` | string | ✅ | — | Display name |
| `subscriptions[].tenant` | string | ✅ | GUID | Reference to tenant ID |
| `subscriptions[].purpose` | string | ✅ | — | What this subscription holds (e.g., `sentinel, soar-playbooks`) |
| `default_workspace` | string | ✅ | — | Workspace filename (without `.yaml`) in `.secops/workspaces/` |
| `lighthouse` | object | — | — | Azure Lighthouse delegations (MSSP/cross-tenant) |
| `managed_customers[]` | list | — | — | MSSP customer list (only when `org_type: mssp`) |

---

## `data-sources/data-source-map.yaml`

**The key file.** Maps every data table to its physical location. Agents MUST check this before writing queries.

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `sources.<TableName>` | object | ✅ | — | Entry keyed by KQL table name |
| `.location` | string | ✅ | `sentinel` \| `adx` \| `external` | Where the data physically resides |
| `.workspace` | string | — | — | Workspace name (when `location: sentinel`) |
| `.cluster` | string | — | — | ADX cluster name (when `location: adx`) |
| `.database` | string | — | — | ADX database name (when `location: adx`) |
| `.tier` | string | — | `Analytics` \| `Basic` \| `Sentinel data lake` \| `Archive` | Data tier (affects available KQL operators) |
| `.daily_gb` | number | — | — | Approximate daily ingestion volume in GB |
| `.ingestion_method` | string | — | `ama-agent` \| `mma-agent` \| `api` \| `dcr` \| `connector` \| `s3-to-eventhub` | How data enters the table |
| `.api_endpoint` | string | — | URL | API endpoint (when `location: external`) |
| `.notes` | string | — | — | Free-text context for agents |

### Tier Impact on Queries

| Tier | Join | Summarize | Full KQL | Search-Only | Cost |
|------|------|-----------|----------|-------------|------|
| Analytics | ✅ | ✅ | ✅ | ✅ | $$$$ |
| Basic | ❌ | ❌ | ❌ | ✅ | $$ |
| Auxiliary | ❌ | ❌ | ❌ | ✅ | $ |

> **Note:** "Auxiliary" is the modern **Sentinel data lake** tier — Microsoft's low-cost retention option.
| Archive | ❌ | ❌ | ❌ | Restore first | $ |

---

## `data-sources/migrations.yaml`

Tracks active, planned, and completed data migrations between platforms.

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `migrations[]` | list | ✅ | — | Migration entries |
| `.id` | string | ✅ | — | Unique migration ID (e.g., `mig-001`) |
| `.status` | string | ✅ | `planned` \| `in-progress` \| `completed` \| `cancelled` | Migration state |
| `.description` | string | ✅ | — | What is being migrated |
| `.source` | object | ✅ | — | Where data currently lives |
| `.source.location` | string | ✅ | `sentinel` \| `adx` \| `external` | Source location type |
| `.target` | object | ✅ | — | Where data is moving to |
| `.target.location` | string | ✅ | `sentinel` \| `adx` \| `external` | Target location type |
| `.started` | string | — | ISO 8601 date | Migration start date |
| `.estimated_completion` | string | — | ISO 8601 date | Expected completion |
| `.owner` | string | — | — | Person or team responsible |
| `.notes` | string | — | — | Additional context for agents |

**Agent rule:** During `in-progress` migrations, data may exist in **both** locations. Query both and prefer the target.

---

## `workspaces/<name>.yaml`

One file per Log Analytics workspace. Referenced from `environment.yaml` and `data-source-map.yaml`.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | ✅ | Azure resource name |
| `workspace_id` | string | ✅ | Log Analytics workspace GUID |
| `resource_group` | string | ✅ | Azure resource group |
| `subscription` | string | ✅ | Subscription GUID |
| `region` | string | ✅ | Azure region |
| `sentinel_enabled` | boolean | ✅ | Whether Sentinel is enabled |
| `tier` | string | ✅ | `PerGB2018` \| `CapacityReservation` |
| `commitment_tier_gb` | number | — | GB/day commitment (capacity reservation only) |
| `retention` | object | ✅ | Retention settings |
| `retention.default_days` | number | ✅ | Default table retention |
| `retention.interactive_days` | number | ✅ | Full KQL query retention |
| `retention.archive_days` | number | ✅ | Archive-only retention |
| `custom_tables[]` | list | — | Tables with non-standard tiers/config |
| `data_connectors[]` | list | — | Active data connectors and their tables |
| `naming_conventions` | object | — | Patterns for Sentinel resource names |

---

## `identity/tenants.yaml`

Complete tenant topology for cross-tenant operations. See [Architecture Guide](ARCHITECTURE.md#7-multi-tenant-architecture) for patterns.

| Field | Type | Required | Values | Description |
|-------|------|----------|--------|-------------|
| `tenants[].id` | string | ✅ | GUID | Entra ID tenant GUID |
| `tenants[].name` | string | ✅ | — | Display name |
| `tenants[].type` | string | ✅ | `primary` \| `secondary` \| `managed` \| `lighthouse-delegated` \| `csp` | Tenant relationship |
| `tenants[].cloud` | string | ✅ | `azure-commercial` \| `azure-government` \| `azure-china` | Cloud environment |
| `tenants[].notes` | string | — | — | Access context |

---

## `alerting/routing.yaml`

Alert routing rules evaluated in order (first match wins).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `default_channel` | string | ✅ | Fallback channel (e.g., `teams://soc-general`) |
| `default_severity_threshold` | string | ✅ | Min severity for notifications: `Informational` \| `Low` \| `Medium` \| `High` \| `Critical` |
| `routes[]` | list | ✅ | Ordered routing rules |
| `routes[].match` | object | ✅ | Match criteria (AND logic; arrays use OR within field) |
| `routes[].match.severity` | list | — | Severity values to match |
| `routes[].match.product` | list | — | Product names to match |
| `routes[].match.mitre_tactic` | list | — | MITRE tactic names to match |
| `routes[].destination.type` | string | ✅ | `teams` \| `slack` \| `pagerduty` \| `email` \| `ticket` \| `webhook` |
| `routes[].destination.channel` | string | ✅ | Target channel or endpoint |
| `routes[].sla_minutes` | number | — | Expected response SLA |

---

## `compliance/requirements.yaml`

Regulatory constraints agents MUST respect. Overrides all other considerations.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `data_residency.primary_region` | string | ✅ | Primary Azure region |
| `data_residency.allowed_regions` | list | ✅ | Regions where data MAY be deployed |
| `data_residency.prohibited_regions` | list | — | Regions where data MUST NOT go |
| `data_residency.reason` | string | — | Why constraints exist |
| `data_residency.constraints` | list | — | Additional rules agents must enforce |

---

## `discovery-log.yaml`

Append-only log of agent-discovered facts. **Never modify or delete entries.**

### Entry Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timestamp` | string | ✅ | ISO 8601 datetime with timezone |
| `agent` | string | ✅ | Agent name that discovered the fact |
| `confidence` | string | ✅ | `high` (direct query) \| `medium` (inferred) \| `low` (assumption) |
| `fact` | string | ✅ | Human-readable description |
| `source` | string | ✅ | How it was discovered (query, API call, error, etc.) |
| `data_source` | string | — | Table or data source name |
| `location` | string | — | `sentinel` \| `adx` \| `external` |
| `workspace` | string | — | Workspace short name |
| `cluster` | string | — | ADX cluster name |
| `database` | string | — | ADX database name |
| `tier` | string | — | Data tier |
| `tenant_id` | string | — | Entra ID tenant GUID |
| `region` | string | — | Azure region |
| `notes` | string | — | Additional context |
| `promoted_to` | string | — | File path (set by human after review) |

---

## Related Documentation

- [Architecture Guide](ARCHITECTURE.md) — Full platform architecture including `.secops/` framework
- [Integration Guide](INTEGRATION.md) — Step-by-step environment setup
- [Sample Configuration](../samples/secops-contoso/) — Complete working example
