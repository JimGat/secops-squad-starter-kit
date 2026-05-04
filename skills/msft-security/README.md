---
title: Microsoft Security Skills Domain
category: msft-security
author: Kima
version: 1.0.0
last_updated: 2026-05-04
---

# Microsoft Security Skills Domain

## Overview

The `skills/msft-security/` domain covers the full Microsoft Security product stack — Defender XDR, Sentinel, Entra ID Protection, Purview, and cross-product integration surfaces like Microsoft Graph Security and Copilot for Security. These skills teach agents how to configure, query, and automate across the entire Microsoft security ecosystem.

## Why This Matters

Microsoft Security is not a single product — it's a constellation of services with overlapping APIs, distinct permission models, and product-specific conventions. SOC teams need agents that understand how these products interrelate: how a Defender for Endpoint alert becomes a Sentinel incident, how Entra risk signals feed into Conditional Access, and how Purview DLP policies protect sensitive data. These skills provide that unified view.

## Skill Files

### Defender

| Skill | File | Description |
|---|---|---|
| **Defender API Permissions** | `defender-api-permissions.md` | API permission reference for all Defender APIs |
| **Defender Cloud Apps** | `defender-cloud-apps.md` | Defender for Cloud Apps configuration |
| **Defender for Cloud Policies** | `defender-for-cloud-policies.md` | Defender for Cloud policy management |
| **Defender for Endpoint** | `defender-for-endpoint.md` | MDE API integration and management |
| **Defender for Identity** | `defender-for-identity.md` | MDI configuration and monitoring |
| **Defender MCP Server** | `defender-mcp-server.md` | MCP server for Defender tool integration |
| **Defender XDR Configuration** | `defender-xdr-configuration.md` | Unified XDR portal configuration |

### Sentinel

| Skill | File | Description |
|---|---|---|
| **Sentinel API Reference** | `sentinel-api-reference.md` | Sentinel REST API reference |
| **Sentinel MCP Server** | `sentinel-mcp-server.md` | MCP server for Sentinel tool integration |
| **Sentinel Workspace Setup** | `sentinel-workspace-setup.md` | Sentinel workspace provisioning |

### Entra

| Skill | File | Description |
|---|---|---|
| **Entra ID Protection** | `entra-id-protection.md` | Entra identity risk and protection |

### Purview

| Skill | File | Description |
|---|---|---|
| **eDiscovery API Wrapper** | `ediscovery-api-wrapper.md` | Legal hold and eDiscovery automation |
| **Purview API Wrapper** | `purview-api-wrapper.md` | Purview compliance API automation |
| **Purview DLP Patterns** | `purview-dlp-patterns.md` | Data Loss Prevention configuration |

### Cross-Product

| Skill | File | Description |
|---|---|---|
| **Attack Simulation API** | `attack-simulation-api.md` | Attack simulation and training automation |
| **Cloud App Discovery API** | `cloud-app-discovery-api.md` | Cloud app discovery and shadow IT |
| **Copilot for Security** | `copilot-for-security.md` | Microsoft Copilot for Security integration |
| **Microsoft Graph Security** | `microsoft-graph-security.md` | Graph Security API for alerts, incidents, TI |

## Dependencies

Microsoft Security skills reference these domain skills:

- `skills/powershell/` — API wrappers for Sentinel, Defender, and Entra cmdlets
- `skills/kql/` — Hunting queries executed via product APIs
- `lib/graph-security/` — Graph Security API client library

## Environment Context

Before interacting with any Microsoft Security product, agents MUST consult the `.secops/` framework:

- **`.secops/environment.yaml`** — Cloud type (commercial, GCC, GCC-High, DoD) affects all API endpoints
- **`.secops/workspaces/`** — Sentinel workspace IDs and Defender portal mappings
- **`.secops/identity/tenants.yaml`** — Multi-tenant context for cross-tenant operations
- **`.secops/compliance/requirements.yaml`** — Regulatory constraints on data handling

If `.secops/` does not exist, suggest running `secops-squad init --secops` to scaffold it.

## How Agents Should Use These Skills

1. **Check cloud environment** — commercial vs. government cloud changes every API endpoint
2. **Verify API permissions** — consult `defender-api-permissions.md` before making API calls
3. **Use MCP servers when available** — prefer `sentinel-mcp-server.md` and `defender-mcp-server.md` for tool integration
4. **Route through Graph Security** — use `microsoft-graph-security.md` for unified alert and incident access
5. **Respect product boundaries** — each product has distinct auth, throttling, and data models
6. **Enrich across products** — combine Defender, Entra, and Sentinel data for full investigation context

## Related Skills

- `skills/powershell/sentinel-module.md` — PowerShell wrappers for Sentinel API calls
- `skills/powershell/defender-module.md` — PowerShell wrappers for Defender API calls
- `skills/detection/detection-lifecycle.md` — Detection rules deployed via Sentinel APIs
- `skills/soar/auto-triage.md` — Automated triage consuming security product alerts
