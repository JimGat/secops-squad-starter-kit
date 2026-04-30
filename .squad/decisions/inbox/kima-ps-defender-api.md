# Decision: Defender API Wrapper Skill Architecture

**Date:** 2026-04-30T17:08:05-05:00
**Author:** Kima (SecOps Engineer)
**Status:** Implemented
**Requested by:** Jose

## What

Created `skills/powershell/defender-api-wrapper.md` — a comprehensive PowerShell skill covering 20+ production-ready REST API wrappers across four Defender products (MDE, Defender for Cloud, XDR, MDI).

## Key Design Decisions

1. **Complement, don't duplicate** — defender-module.md has the base functions (Get-SecOpsAlert, Invoke-SecOpsAdvancedHunting, Set-SecOpsDeviceIsolation). This skill extends with MDE-specific wrappers (Live Response, TVM, custom detections), Defender for Cloud, XDR, and MDI coverage.

2. **Shared pagination helper** — `Invoke-SecOpsPaginatedRequest` is a reusable function for all Defender APIs that return `@odata.nextLink`. Safety-capped at 50 pages to prevent runaway queries.

3. **MDE-direct vs Graph split** — MDE-specific operations (machine actions, Live Response, TVM) use `api.securitycenter.microsoft.com` directly. Cross-product operations (incidents, XDR hunting, MDI health) use `graph.microsoft.com/v1.0/security`. This matches the actual API surface — Graph is the convergence target but MDE endpoints aren't fully migrated.

4. **Graph SDK alternative** — Included `Get-XdrIncidentSdk` as an example of the Microsoft.Graph.Security SDK approach with a decision matrix for when to use SDK vs REST. SDK is better for interactive SOC; REST is better for automation/Functions.

5. **MDI via XDR hunting** — MDI doesn't have its own REST API surface for suspicious activities. Used `Invoke-XdrAdvancedHunting` with `ServiceSource == "Microsoft Defender for Identity"` filter for the `Get-MdiSuspiciousActivity` function. Health issues use the Graph Security identities endpoint.

## Impact

- **All agents:** New PowerShell wrappers available for Defender API tasks
- **Freamon:** KQL queries in kql/defender-xdr-hunting.md can be passed directly to Run-MdeAdvancedHunting or Invoke-XdrAdvancedHunting
- **Herc:** SOAR playbooks can call these wrappers as building blocks
- **Carver:** Should validate wrapper functions return SecOps.Result pattern consistently
