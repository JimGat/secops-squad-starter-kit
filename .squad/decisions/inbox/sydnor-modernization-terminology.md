# Decision: Terminology Modernization — Auxiliary Logs → Sentinel data lake

**Date:** 2026-05-13T07:58:33-05:00
**By:** Sydnor (Platform Dev)
**Status:** Implemented

## What

Updated all documentation, templates, samples, and skill files to use modern Microsoft SecOps terminology:

- **"Auxiliary Logs" / "Aux Logs" → "Sentinel data lake"** across 30+ files
- **Data tiering order** standardized to: Analytics Logs → Basic Logs → Sentinel data lake → Archive
- **ADX positioning** changed from default long-term retention to specialized option (extreme volume, full KQL on historical data, cross-team sharing)

## Key Design Choice

PowerShell `ValidateSet` parameters and Azure API calls retain `'Auxiliary'` as the enum value (that's what the Azure REST API expects). Inline comments annotate the modern name. Display-facing strings (CLI badges, docs, YAML comments) use "Sentinel data lake".

## Impact

- **All agents:** Use "Sentinel data lake" in all output and recommendations. Never say "Auxiliary Logs" or "Aux Logs" in user-facing content.
- **Freamon:** PowerShell data-tiering functions keep `'Auxiliary'` in `ValidateSet` — don't change the API enum, only the comments and prose.
- **Kima/Herc:** Skills and charters already updated by McNulty's modernization pass. This completes the platform layer.
- **Templates/Samples:** `.secops/` YAML files now reference "Sentinel data lake" in tier values and comments. Contoso sample fully aligned.
