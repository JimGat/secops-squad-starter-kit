# Decision: Sentinel API Wrapper — Dual-Approach Pattern (REST + Cmdlet)

**Date:** 2026-04-30T17:08:00-05:00
**By:** Freamon (KQL Engineer)
**Status:** Proposed
**Scope:** `skills/powershell/sentinel-api-wrapper.md`

## Decision

The Sentinel API wrapper skill uses direct REST API calls (via `Invoke-SentinelApi` → `Invoke-SecOpsRestMethod`) as the primary approach, with `Az.SecurityInsights` cmdlet examples shown as alternatives where applicable.

## Rationale

1. **REST-first gives full API surface coverage** — `Az.SecurityInsights` cmdlets lag behind the REST API by 3-6 months. NRT rules, TI bulk import, watchlist item CRUD, and connector health are REST-only.
2. **Consistent error handling** — REST calls flow through `Invoke-SecOpsRestMethod` which enforces the team's `SecOps.Result` pattern. Cmdlets throw exceptions that require separate try/catch wiring.
3. **Government cloud portability** — `Get-SentinelBaseUri` resolves the correct ARM endpoint from `.secops/` config. Cmdlets use `Get-AzContext` which may not reflect `.secops/` cloud preferences.
4. **Cmdlets shown for simplicity** — Simple read operations (list incidents, list rules) are shown with cmdlet alternatives for SOC engineers who prefer them.

## Impact

- **All agents:** When generating Sentinel PowerShell, prefer the REST wrapper functions from this skill. Use cmdlets only for ad-hoc interactive use.
- **Kima:** Detection rule deployment should use `New-SecOpsAnalyticsRule` / `New-SentinelNrtRule`, not raw `New-AzSentinelAlertRule`.
- **Herc:** SOAR playbooks calling Sentinel APIs should use the shared helpers for consistent audit logging.
