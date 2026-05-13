# Contoso Corp SOC — Sample `.secops/` Configuration

> A complete, realistic demonstration of the secops-squad customer knowledge framework.

## What This Is

This sample shows how **Contoso Corp**, a fictional enterprise with 12,000 employees, configures their `.secops/` directory to give AI agents full context about their security operations environment.

Contoso has a mature SOC with:
- **2 Entra ID tenants** (Production + Dev/Test)
- **3 Azure subscriptions** (SOC-Production, SOC-ADX, SOC-Dev)
- **~500 GB/day** ingestion across Sentinel and ADX
- **Cross-cloud monitoring** — AWS (acquired SaaS) + GCP (recent acquisition)
- **Data tiering** — Analytics, Basic, and Sentinel data lake tiers to optimize cost
- **Active migrations** — moving high-volume data between platforms
- **Regulatory compliance** — NIST 800-53, PCI-DSS, SOC 2 Type II

## How to Use This as a Starting Point

1. **Copy the `.secops/` directory** into your repo root:
   ```bash
   cp -r samples/secops-contoso/.secops /path/to/your/repo/.secops
   ```

2. **Replace Contoso values** with your environment data:
   - Tenant IDs, subscription IDs, workspace GUIDs
   - Table names, daily volumes, connector lists
   - Contact info, team channels, PagerDuty services

3. **Remove what doesn't apply** — every section is optional:
   - No ADX? Delete `workspaces/soc-adx.yaml`
   - No cross-cloud? Remove AWS/GCP sources from `data-source-map.yaml`
   - No MSSP? Leave `managed_customers: []` in `environment.yaml`

4. **Run the doctor check** to validate your config:
   ```bash
   npx secops-squad doctor
   ```

## File Guide

| File | Purpose | Key Demo Feature |
|------|---------|-----------------|
| `.secops/environment.yaml` | Top-level org config | Multi-tenant, cross-cloud, Lighthouse (commented) |
| `.secops/workspaces/prod-sentinel.yaml` | Production Sentinel | 500GB commitment, 10 custom tables, 8 connectors |
| `.secops/workspaces/dev-sentinel.yaml` | Dev/Test Sentinel | Detection testing, attack simulation |
| `.secops/workspaces/soc-adx.yaml` | ADX cluster | Long-term retention, external tables over blob |
| `.secops/data-sources/data-source-map.yaml` | Data location map | 20+ sources, 3 tiers, cross-cloud, migration flags |
| `.secops/data-sources/migrations.yaml` | Data migrations | In-progress, planned, and completed examples |
| `.secops/identity/tenants.yaml` | Tenant topology | B2B access, service principals, Lighthouse prep |
| `.secops/identity/rbac-conventions.yaml` | RBAC standards | L1-L3 role bundles, PIM, custom roles |
| `.secops/alerting/routing.yaml` | Alert routing | 7 rules, Teams + PagerDuty + ServiceNow |
| `.secops/alerting/escalation.yaml` | Escalation tiers | L1 → L2 → L3 → CISO with timeouts |
| `.secops/compliance/requirements.yaml` | Compliance config | NIST + PCI-DSS + SOC 2, per-table retention |
| `.secops/discovery-log.yaml` | Agent discoveries | 6 realistic entries from daily operations |

## Cross-References

These files are designed to be cross-referenced. For example:

- **Subscription IDs** in `environment.yaml` match the `subscription` fields in workspace files
- **Workspace names** in workspace files (`prod-sentinel`, `dev-sentinel`) match the `workspace` field in `data-source-map.yaml`
- **Table names** in `data-source-map.yaml` match `custom_tables` entries in workspace files
- **Migration IDs** (`mig-001`) are referenced in both `migrations.yaml` and `data-source-map.yaml`
- **Tenant IDs** are consistent across `environment.yaml`, `tenants.yaml`, and `rbac-conventions.yaml`
- **Discovery log entries** reference workspaces, tables, and tiers that exist in the authoritative files

## What Agents Learn From This Config

When an agent reads this `.secops/` setup, it understands:

1. **Where to query** — `data-source-map.yaml` tells it exactly which workspace or ADX database holds each table
2. **Query limitations** — Basic/Sentinel data lake tier tables can't use `join` or `summarize`
3. **Active migrations** — query both source and target during `in-progress` migrations
4. **Permission boundaries** — RBAC conventions and Lighthouse limitations
5. **Compliance constraints** — never deploy to non-US regions, never reduce PCI-scoped retention
6. **Alert routing** — where to notify when creating automation rules
7. **Escalation paths** — who to contact and how quickly for each severity level

## Schema Version

All files use `schema_version: "1.0"`. This enables forward compatibility — agents and tools can detect the schema version and adapt behavior as the framework evolves.
