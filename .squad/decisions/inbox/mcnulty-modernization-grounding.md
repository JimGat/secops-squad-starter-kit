# Decision: Technology Grounding Sections in All Agent Charters

**Date:** 2026-05-13T07:58:33-05:00
**By:** McNulty (Lead)
**Status:** Implemented

## What

Added a `## Technology Grounding` section to all 6 agent charters (McNulty, Kima, Freamon, Herc, Sydnor, Carver) with agent-specific guidance on modern Microsoft Sentinel and SecOps patterns. Updated `team.md` project context to reflect the modern platform.

## Why

An agent used "Aux Logs" and "ADX" as default long-term retention guidance. The modern (2025-2026) approach is **Sentinel data lake** — a low-cost, long-term retention tier within Sentinel itself. ADX remains valid but is an advanced option, not the default. The unified SOC platform (security.microsoft.com) is now the converged operational surface.

## Key Terminology Changes

- "Aux Logs" / "Auxiliary Logs" → **Sentinel data lake**
- ADX → advanced option requiring justification (custom ML, cross-org federation, existing investments)
- Standalone Sentinel portal → **unified SOC platform** (security.microsoft.com)

## Impact

- **All agents:** Must use modern terminology and default to Sentinel data lake for long-term retention guidance.
- **McNulty:** Reviews PRs for modern pattern compliance — rejects "Aux Logs" references and unjustified ADX usage.
- **Kima:** References Content Hub, unified SOC platform, Microsoft Security Exposure Management.
- **Freamon:** Aware of query differences across Analytics/Basic/Sentinel data lake tiers; uses Summary Rules for aggregation.
- **Herc:** Targets unified SOC platform APIs; playbooks query Sentinel data lake, not ADX, by default.
- **Sydnor:** IaC templates provision Sentinel data lake tables by default, ADX as optional add-on.
- **Carver:** Validates queries target correct data tier; flags tier mismatches in test coverage.

## Convention

When the platform evolves again, apply the same pattern: update all charters' Technology Grounding sections, not just the one that triggered the issue.
