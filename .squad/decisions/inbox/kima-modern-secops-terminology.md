# Decision: Modern SecOps Terminology Standards

**Date:** 2026-05-13T07:58:33-05:00
**By:** Kima (SecOps Engineer)
**Status:** Accepted

## What

Standardized terminology across all `skills/msft-security/` and `skills/detection/` files to reflect Microsoft's modern SecOps platform:

1. **"Sentinel data lake"** is the modern low-cost retention tier (replaces "Basic Logs" / "Auxiliary Logs" as the primary term in tiering discussions). "Basic Logs" remains valid as a Log Analytics concept but Sentinel-facing docs should lead with "Sentinel data lake."

2. **Unified SOC platform** at security.microsoft.com — Sentinel + Defender XDR share a single portal experience. References to "the Sentinel portal" now acknowledge this unified option.

3. **ADX repositioned** — Azure Data Explorer is a specialized option (custom ML, cross-org federation, massive scale). Sentinel data lake is the default for long-term retention within Sentinel.

4. **Content Hub** — Portal references updated to use Content Hub as the modern deployment path for Sentinel solutions.

5. **Summary rules** — Added as a modern cost-optimization pattern (aggregate Sentinel data lake tables into compact Analytics-tier tables).

## Why

John directed that all content reflect modern Microsoft SecOps approaches. The platform has evolved significantly — the unified SOC portal, Sentinel data lake tier, and summary rules are all GA features that should be the default guidance.

## Impact

- **All agents:** When referencing Sentinel portal, include the unified SOC platform at security.microsoft.com. When discussing data tiers, lead with Sentinel data lake as the modern low-cost tier.
- **Freamon:** PowerShell scripts referencing Sentinel should note the unified portal URL.
- **log-analytics skills:** Already correctly reference both "Basic Logs" and "Sentinel data lake" — no changes needed there.
- **Future skills:** Should follow these terminology standards from the start.
