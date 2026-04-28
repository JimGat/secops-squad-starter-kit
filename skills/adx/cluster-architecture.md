---
title: Cluster Architecture
category: Azure Data Explorer
difficulty: advanced
mitre_attack:
  - General  # Foundational — infrastructure design for security data lake
products:
  - Azure Data Explorer
  - Microsoft Sentinel
  - Azure Monitor Log Analytics
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Cluster Architecture

## Overview

An Azure Data Explorer (ADX) cluster is the backbone of a security data lake. Cluster architecture decisions — SKU selection, cache tiering, cluster topology, and multi-tenant isolation — determine your query performance, ingestion throughput, cost structure, and ability to scale as telemetry volumes grow. Security workloads have unique characteristics: bursty ingestion from incidents, long retention mandated by compliance, ad-hoc hunting queries that scan billions of rows, and strict tenant isolation for MSSPs.

Use this skill when:
- You are designing a new ADX cluster for security telemetry
- You need to right-size an existing cluster for changing ingestion volumes
- You are implementing hot/warm/cold cache strategies for cost-effective retention
- You are designing multi-tenant ADX architecture for MSSP or multi-BU deployments
- You need to evaluate compute-optimized vs. storage-optimized SKUs

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Contributor` on the resource group for cluster creation; `AllDatabasesAdmin` for database-level configuration |
| **Products** | Azure Data Explorer, optionally Microsoft Sentinel for data export integration |
| **Knowledge** | Understanding of your ingestion volume (GB/day), query concurrency, and retention requirements |
| **Networking** | VNet injection planning for private clusters; ExpressRoute for hybrid environments |

## Core Patterns

### Pattern 1 — SKU Selection Framework

ADX offers compute-optimized (D-series) and storage-optimized (L-series, E-series) SKUs. Security workloads typically favor storage-optimized SKUs because they hold more data in local SSD cache, reducing query latency over large time windows.

| Workload Profile | Recommended SKU Family | Nodes | Use Case |
|---|---|---|---|
| Dev/Test (< 50 GB/day) | Dev(No SLA) D11_v2 | 2 | Lab environments, PoC, skill development |
| Small SOC (50–200 GB/day) | E8s_v4+1TB_PS | 2–4 | Single-team SOC with moderate retention |
| Mid SOC (200 GB–1 TB/day) | L8s_v3 | 4–8 | Multi-source ingestion, active hunting teams |
| Large SOC (1–5 TB/day) | L16s_v3 | 8–16 | Enterprise SOC with full EDR + network telemetry |
| Hyperscale (5+ TB/day) | L32s_v3 | 16+ | MSSP, national CERT, global enterprise |

```bash
# Create a storage-optimized ADX cluster for production security workloads
az kusto cluster create \
  --name "securityadx" \
  --resource-group "rg-adx-security" \
  --location "eastus2" \
  --sku name="Standard_L8s_v3" tier="Standard" capacity=4 \
  --enable-streaming-ingest true \
  --enable-auto-stop false \
  --enable-purge true \
  --tags environment=production purpose=security-data-lake

# Create the security database with 365-day hot cache
az kusto database create \
  --cluster-name "securityadx" \
  --resource-group "rg-adx-security" \
  --database-name "SecurityLogs" \
  --read-write-database soft-delete-period="P3650D" hot-cache-period="P365D"
```

**Key decisions:**
- **`--enable-streaming-ingest`**: Required for real-time security telemetry (< 10 second latency).
- **`--enable-auto-stop`**: Disable in production — auto-stop pauses the cluster after inactivity, which breaks continuous ingestion pipelines.
- **`--enable-purge`**: Required for GDPR/CCPA data subject deletion requests. Adds ~2% cost overhead.

---

### Pattern 2 — Hot/Warm/Cold Cache Tiering

ADX caches data in local SSD (hot cache) for fast queries. Data beyond the hot cache period is stored in Azure Blob Storage (cold) and loaded on demand. The cache policy is the single most impactful performance and cost knob.

```kql
// Review current cache and retention policies across all tables in the database
.show database SecurityLogs policy caching

// Show table-level cache overrides
.show table * policy caching
```

```kql
// Set tiered caching: 30-day hot cache for high-query tables,
// 7-day hot cache for noisy operational tables
.alter table SecurityEvent policy caching hot = 30d
.alter table SignInLogs policy caching hot = 30d
.alter table DeviceProcessEvents policy caching hot = 14d

// Network flow data: high volume, queried less frequently
.alter table NetworkFlow policy caching hot = 7d

// Compliance audit logs: long retention, rarely queried interactively
.alter table AuditLogs policy caching hot = 3d
```

**Cache tier strategy for security data:**

| Data Type | Hot Cache | Rationale |
|---|---|---|
| Identity (SignInLogs, AADLogs) | 30 days | Active hunting window, high-value for investigation |
| Endpoint (DeviceProcessEvents) | 14 days | Incident response typically within 2 weeks |
| Network flow (NetFlow, DNS) | 7 days | Extremely high volume, investigate specific incidents only |
| Audit / compliance logs | 3 days | Rarely queried interactively, mostly compliance exports |
| Threat intelligence | 90 days | IOC sweeps need wide windows for retrospective matching |

---

### Pattern 3 — Cluster Scaling and Autoscale

Security workloads are bursty — a major incident can spike ingestion 10x while analysts run expensive queries simultaneously. Configure autoscale to absorb spikes without degrading interactive hunting.

```bash
# Configure optimized autoscale: 4-16 nodes based on demand
az kusto cluster update \
  --name "securityadx" \
  --resource-group "rg-adx-security" \
  --sku name="Standard_L8s_v3" tier="Standard" capacity=4 \
  --optimized-autoscale version=1 minimum=4 maximum=16 is-enabled=true
```

```kql
// Monitor cluster utilization to validate autoscale boundaries
// Run this in your ADX cluster to review resource consumption patterns
.show diagnostics
| project Timestamp, MachineTotal, MachineCPU = CPU, IngestionUtilization,
    CacheUtilization = CacheUtilizationFactor
```

```kql
// Query cluster metrics to determine if you need to adjust autoscale bounds
// High CPU sustained above 80% → increase minimum node count
// Cache utilization above 90% → either increase hot cache or add nodes
.show capacity
| project Resource, Total, Consumed, Utilization = round(todouble(Consumed) / todouble(Total) * 100, 1)
```

---

### Pattern 4 — Multi-Tenant Architecture (MSSP)

MSSPs managing multiple customer tenants need strict data isolation while enabling cross-tenant threat intelligence sharing. ADX supports this through database-per-tenant with centralized analytics.

```kql
// Create per-tenant databases with isolated retention and caching
.create database CustomerA_Logs persist (
    @"https://storageaccount.blob.core.windows.net/customerA"
) with (hot_cache_period = 14d, softdelete = 3650d)
```

```bash
# Database-per-tenant with different cache policies per customer SLA
az kusto database create \
  --cluster-name "securityadx" \
  --resource-group "rg-adx-security" \
  --database-name "TenantA_Logs" \
  --read-write-database soft-delete-period="P730D" hot-cache-period="P30D"

az kusto database create \
  --cluster-name "securityadx" \
  --resource-group "rg-adx-security" \
  --database-name "TenantB_Logs" \
  --read-write-database soft-delete-period="P365D" hot-cache-period="P14D"

# Grant tenant-specific access with database-level RBAC
az kusto database add-principal \
  --cluster-name "securityadx" \
  --resource-group "rg-adx-security" \
  --database-name "TenantA_Logs" \
  --value name="TenantA SOC Team" type="AADGroup" role="Viewer" \
    fqn="aadgroup=<tenant-a-soc-group-object-id>"
```

**Multi-tenant isolation model:**

| Pattern | Isolation | Query Flexibility | Operational Overhead |
|---|---|---|---|
| Database-per-tenant | ✅ Strong (RBAC per DB) | Cross-DB queries possible for MSSP analysts | Moderate — one DB per tenant |
| Table-per-tenant | ⚠️ Moderate (RLS needed) | Simple cross-table queries | Low — single DB, many tables |
| Row-level security | ⚠️ Moderate (policy-based) | Transparent to analysts | Low setup, but RLS policies need maintenance |
| Cluster-per-tenant | ✅ Strongest (network isolation) | No cross-tenant queries | High — separate infrastructure per customer |

---

### Pattern 5 — Network Security and Private Endpoints

Production security clusters should use VNet injection or private endpoints to prevent data exfiltration and ensure telemetry never traverses the public internet.

```bash
# Create cluster with VNet injection for network isolation
az kusto cluster create \
  --name "securityadx" \
  --resource-group "rg-adx-security" \
  --location "eastus2" \
  --sku name="Standard_L8s_v3" tier="Standard" capacity=4 \
  --vnet-configuration \
    data-management-public-ip-id="/subscriptions/SUB_ID/resourceGroups/rg-network/providers/Microsoft.Network/publicIPAddresses/adx-dm-pip" \
    engine-public-ip-id="/subscriptions/SUB_ID/resourceGroups/rg-network/providers/Microsoft.Network/publicIPAddresses/adx-engine-pip" \
    subnet-id="/subscriptions/SUB_ID/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-security/subnets/snet-adx" \
  --enable-streaming-ingest true

# Alternatively, use private endpoints (simpler than VNet injection)
az network private-endpoint create \
  --name "pe-adx-security" \
  --resource-group "rg-adx-security" \
  --vnet-name "vnet-security" \
  --subnet "snet-private-endpoints" \
  --private-connection-resource-id "/subscriptions/SUB_ID/resourceGroups/rg-adx-security/providers/Microsoft.Kusto/clusters/securityadx" \
  --group-id "cluster" \
  --connection-name "adx-private-connection"
```

## Best Practices

1. **Start with storage-optimized SKUs** (L-series) for security workloads — they hold more data in hot cache per dollar
2. **Enable streaming ingestion** at cluster creation — retrofitting later requires a cluster restart
3. **Set hot cache per table**, not just at database level — one size does not fit all security data types
4. **Disable auto-stop** for production clusters — an ingestion pipeline hitting a stopped cluster drops data
5. **Plan for 3x peak ingestion** when sizing minimum node count — security incidents are spiky
6. **Enable purge** if you are subject to GDPR, CCPA, or any regulation requiring data subject deletion

## Cost Implications

| Component | Cost Driver | Optimization |
|---|---|---|
| Compute (nodes) | Hourly per-node, biggest cost component | Right-size with autoscale; use Dev/Test SKU for non-prod |
| Storage | Per-GB Azure Blob Storage for cold data | Minimal — Azure Storage is ~$0.018/GB/month |
| Hot cache | Implied in node count — more hot data = more nodes | Reduce hot cache period on low-query tables |
| Ingestion | Compute cycles for parsing/indexing | Batch ingestion (vs streaming) uses ~30% fewer CPU cycles |
| Egress | Cross-region query traffic | Co-locate ADX cluster with primary data sources |

## Related Skills

- **[ADX Integration](../kql/adx-integration.md)** — Querying ADX from Log Analytics using `adx()` proxy.
- **[Data Ingestion](data-ingestion.md)** — How to get security data into your ADX cluster efficiently.
- **[Long-Term Retention](long-term-retention.md)** — Extending retention beyond hot cache with tiered storage.
- **[Security Data Modeling](security-data-modeling.md)** — Table schema design for security telemetry.
- **[Workspace Architecture](../log-analytics/workspace-architecture.md)** — Deciding what stays in Log Analytics vs. ADX.
