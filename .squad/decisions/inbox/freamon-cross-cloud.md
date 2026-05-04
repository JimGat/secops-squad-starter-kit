# Decision: Cross-Cloud Connectors Skill & Platform Domain

**Date:** 2026-05-04T08:41:39-05:00
**By:** Freamon (KQL Engineer)
**Status:** Implemented
**Requested by:** Jose

## What

Created `skills/platform/cross-cloud-connectors.md` (509 lines) — a comprehensive skill document covering AWS, GCP, and multi-SIEM data ingestion into Microsoft Sentinel. Also created the new `skills/platform/` domain directory.

## Key Decisions

1. **New `skills/platform/` domain** — Cross-cloud connectors span KQL, Log Analytics, and PowerShell domains. Rather than forcing this into an existing domain, created `platform/` for cross-cutting infrastructure skills that don't belong to a single product area.

2. **ASIM as the unification layer** — All cross-cloud KQL examples normalize to ASIM schemas (Authentication, NetworkSession). This enables unifying parsers that transparently query Azure + AWS + GCP in a single query. Cross-cloud correlation queries depend on consistent ASIM field mapping.

3. **Tier recommendations per source** — Embedded cost-aware tier guidance directly in the skill. CloudTrail → Basic, GuardDuty → Analytics, VPC Flow Logs → Auxiliary. These align with `.secops/data-source-map.yaml` tier field conventions.

4. **SPL→KQL translation table** — Included 10 common SPL-to-KQL patterns for Splunk migration. This is the most common multi-SIEM scenario for Sentinel customers.

5. **PowerShell health functions use `.secops/`** — `Get-CrossCloudConnectorHealth` and `Test-CrossCloudIngestionVolume` read from `data-source-map.yaml` to auto-discover cross-cloud sources, following the established `.secops/` auto-loading pattern.

## Impact

- **Kima:** Can reference ASIM parsers for cross-cloud detection rules
- **Herc:** Connector setup automation patterns available for SOAR playbooks
- **All agents:** New `platform/` domain available for future cross-cutting skills
- **`.secops/`:** data-source-map.yaml examples for `source_cloud: aws/gcp` entries established as templates
