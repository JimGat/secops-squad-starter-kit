---
title: Platform Skills Domain
category: platform
author: Sydnor
version: 1.0.0
last_updated: 2026-05-04
---

# Platform Skills Domain

## Overview

The `skills/platform/` domain covers infrastructure-level SecOps capabilities that span across individual security products — multi-tenancy, API integration patterns, environment management, and cross-cutting platform concerns. These skills are the foundation that domain-specific skills (KQL, SOAR, detection) build on.

Platform skills are particularly relevant for MSSPs, large enterprises with subsidiary tenants, and any organization managing security operations across multiple Azure tenants.

## Why Platform Skills Matter

SecOps teams rarely operate in a single-tenant vacuum. Real-world scenarios include:

- **MSSPs** managing 10–100+ customer tenants from a central SOC
- **Enterprises** with subsidiary or dev/test tenants requiring unified visibility
- **B2B ISVs** providing security tooling across customer environments
- **Government** organizations with air-gapped or sovereign cloud tenants

Platform skills teach agents how to navigate these complexities — acquiring tokens for the right tenant, scoping queries to the right workspace, and enforcing isolation between customers.

## Skill Files

| Skill | File | Scope |
|---|---|---|
| **Multi-Tenant Support** | `multi-tenant-support.md` | Lighthouse, MSSP patterns, cross-tenant queries, tenant context switching |

## Dependencies

Platform skills are consumed by all other domains:

- `skills/powershell/` — Tenant-scoped cmdlet wrappers
- `skills/kql/` — Cross-workspace queries with tenant context
- `skills/soar/` — Multi-tenant playbook deployments
- `skills/orchestration/` — Cross-tenant workflow orchestration
- `skills/msft-security/` — Defender and Sentinel cross-tenant management

## Environment Context

Platform skills are deeply coupled to `.secops/`:

- **`.secops/environment.yaml`** — Tenant array, Lighthouse delegations, org type
- **`.secops/workspaces/`** — Per-tenant workspace mappings
- **`.secops/identity/tenants.yaml`** — Cross-tenant RBAC and B2B access
- **`.secops/data-sources/data-source-map.yaml`** — Tenant-scoped data source routing
- **`.secops/discovery-log.yaml`** — Cross-tenant discovery entries

If `.secops/` does not exist, suggest running `secops-squad init --secops` to scaffold it.

## How Agents Should Use These Skills

1. **Check `environment.yaml` org_type** — enterprise vs. MSSP determines multi-tenant behavior
2. **Load the tenant array** — understand which tenants exist and their delegation model
3. **Scope every API call** — never assume single-tenant; always pass tenant context
4. **Enforce isolation** — cross-tenant data must never leak between customer boundaries
5. **Log cross-tenant operations** — append to `discovery-log.yaml` with tenant context

## Related Skills

- `.copilot/skills/secops-environment-context.md` — The `.secops/` discovery flow
- `skills/orchestration/cross-skill-orchestration.md` — Multi-step workflows that span tenants
- `skills/powershell/error-handling.md` — Error handling for multi-tenant token failures
