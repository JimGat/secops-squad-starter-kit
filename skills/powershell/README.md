# PowerShell Skills Domain

## Overview

The `skills/powershell/` domain teaches agents how to build, structure, and operate a PowerShell module for Microsoft Security operations. These are **knowledge documents** — they describe patterns, conventions, and code examples that agents use when generating PowerShell code for SOC engineers.

PowerShell is the primary automation language for Microsoft Security practitioners. These skills bridge the gap between raw REST APIs and production-grade tooling that SOC teams can adopt immediately.

## Module Architecture

The skills describe a single logical PowerShell module — **SecOps.Tools** — composed of six submodules, each wrapping a distinct Microsoft Security API surface:

| Submodule | Skill File | API Surface |
|---|---|---|
| **Sentinel** | `sentinel-module.md` | SecurityInsights provider, Log Analytics Query API |
| **Defender** | `defender-module.md` | MDE, Defender for Cloud, Defender for Identity |
| **Entra** | `entra-module.md` | Microsoft Graph Identity endpoints |
| **AzureMonitor** | `azure-monitor-module.md` | Action Groups, Alert Rules, Diagnostic Settings |
| **ResourceGraph** | `resource-graph-module.md` | Azure Resource Graph |
| **DataTiering** | `data-tiering-module.md` | Log Analytics table management, retention |

## Cross-Cutting Skills

Three foundational skills apply to all submodules:

| Skill | File | Scope |
|---|---|---|
| **Module Foundation** | `module-foundation.md` | PSDepend, manifest, submodule structure, initialization |
| **Auth Patterns** | `auth-patterns.md` | MSAL, multi-tenant, managed identity, government cloud |
| **Error Handling** | `error-handling.md` | Retry logic, throttling, structured errors, audit logging |

## How Agents Should Use These Skills

1. **Before generating PowerShell code**, check `module-foundation.md` for project structure conventions
2. **Before any API call**, check `auth-patterns.md` for the correct authentication flow
3. **Before any REST call**, check `error-handling.md` for retry/throttle patterns
4. **For domain-specific work**, consult the relevant submodule skill
5. **Always** check `.secops/environment.yaml` for cloud environment (commercial vs. government affects all endpoints)
6. **Always** check `.secops/identity/tenants.yaml` for multi-tenant context

## Environment Context

Before generating any PowerShell code, agents MUST consult the `.secops/` framework:

- **`.secops/environment.yaml`** — Cloud type, primary region, org type (enterprise vs MSSP)
- **`.secops/identity/tenants.yaml`** — Tenant topology, cross-tenant access model
- **`.secops/data-sources/data-source-map.yaml`** — Table locations and tiers
- **`.secops/compliance/requirements.yaml`** — Data residency and regulatory constraints

If `.secops/` does not exist, suggest running `secops-squad init --secops` to scaffold it.

## Related Skills

- `skills/kql/` — KQL query patterns (PowerShell modules execute these)
- `skills/log-analytics/` — Workspace architecture (modules target these workspaces)
- `skills/msft-security/` — Graph Security API (modules wrap these endpoints)
- `skills/soar/` — Logic Apps and Functions (modules integrate with these)
- `skills/adx/` — Azure Data Explorer (modules query these clusters)
