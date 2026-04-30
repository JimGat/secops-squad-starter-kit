# Decision: Data Tiering Commands Skill Architecture

**Date:** 2026-04-30
**By:** Freamon (KQL Engineer)
**Status:** Implemented

## What

Created `skills/powershell/data-tiering-commands.md` (~500 lines) — production-ready PowerShell commands for the full data tiering lifecycle: tier management, retention policies, summary rules, purge operations, and migration workflows.

## Key Design Decisions

1. **Complement, don't duplicate** — The existing `data-tiering-module.md` provides `Get-SecOpsTableInventory`, `Set-SecOpsTableTier`, `Set-SecOpsRetentionPolicy`, and `New-SecOpsSummaryRule`. The new skill adds *additional* functions and deeper workflows (tier recommendations, cost calculators, compliance auditing, purge/migration orchestration) without re-implementing the base functions.

2. **Pre-flight safety checks on tier changes** — `Set-LogAnalyticsTablePlan` blocks downgrades if:
   - Active Sentinel analytics rules reference the table
   - Active migrations exist in `migrations.yaml`
   - No summary rule exists (warns, doesn't block)
   This prevents accidental detection blindness from tier downgrades.

3. **Compliance as hard constraint** — `Set-LogAnalyticsRetention` validates against `.secops/compliance/requirements.yaml` before applying. The `-AutoComply` switch auto-raises values to the minimum; without it, sub-minimum values error out. Compliance is never optional.

4. **Cost impact before commitment** — `Get-TierCostImpact` and `Get-TierRecommendation` must be run before any tier change. The cost calculator uses `.secops/data-source-map.yaml` daily volumes as the default data source, reducing the need for live queries.

5. **Purge operations are audited** — `Submit-DataPurge` requires a `-Reason` parameter (ticket ID or justification), logs the operator identity, and returns a purge ID for tracking. This creates an audit trail for GDPR/privacy compliance.

6. **Migration orchestration is plan-first** — `Start-DataMigration` outputs a step-by-step plan and the YAML entry to add to `migrations.yaml`, but does NOT auto-modify the file. Human review of migration plans is required.

## Impact

- **All agents:** New tier/retention commands integrate with `.secops/` context — agents must consult data-source-map.yaml before making tier recommendations
- **Kima:** Detection rule dependency checks prevent silent rule breakage from tier downgrades
- **Herc:** Migration workflows complement SOAR automation patterns for data movement
- **Carver:** Summary rule validation (`Test-SummaryRule`) can be added to CI for KQL correctness

## Functions Added

| Function | Purpose |
|---|---|
| `Get-LogAnalyticsTablePlan` | Audit current tiers with .secops/ enrichment |
| `Set-LogAnalyticsTablePlan` | Tier change with safety checks |
| `Get-TierRecommendation` | Query-pattern-based tier recommendation |
| `Get-TierCostImpact` | Cost calculator for tier changes |
| `Get-LogAnalyticsRetention` | Retention audit with compliance status |
| `Set-LogAnalyticsRetention` | Retention change with compliance enforcement |
| `Test-RetentionCompliance` | Bulk compliance audit |
| `Set-BulkRetentionPolicy` | Apply retention to multiple tables |
| `New-SummaryRule` | Create aggregation rules |
| `Get-SummaryRule` | List summary rules |
| `Test-SummaryRule` | Validate summary rule KQL |
| `Submit-DataPurge` | GDPR data purge with audit trail |
| `Get-PurgeStatus` | Track purge operations |
| `Start-DataMigration` | Orchestrate ADX↔Sentinel, workspace consolidation |
| `Get-MigrationStatus` | Track active migrations |
