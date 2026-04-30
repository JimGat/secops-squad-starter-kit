# Decision: `.secops/` Customer Knowledge Framework — Schema v1.0

**Date:** 2026-04-30T16:42:00-05:00
**Author:** Sydnor (Platform Dev)
**Status:** Proposed
**Blocks:** All Phase 1 downstream work (skills integration, agent routing, CLI env commands)

## Decision

Created the `.secops/` directory as the customer-specific environment knowledge framework for secops-squad. This is the foundational schema that all agents, skills, and CLI commands will depend on for environment-aware operations.

## Structure

```
.secops/ (16 files across 6 subdirectories)
├── README.md + environment.yaml
├── workspaces/    (README.md + example-workspace.yaml)
├── data-sources/  (README.md + data-source-map.yaml + migrations.yaml)
├── identity/      (README.md + tenants.yaml + rbac-conventions.yaml)
├── alerting/      (README.md + routing.yaml + escalation.yaml)
├── compliance/    (README.md + requirements.yaml)
└── discovery-log.yaml
```

## Key Design Decisions

1. **Schema version `1.0` in every YAML file** — Enables version-aware agent behavior and backward compatibility. Unknown fields preserved (forward-compatible).

2. **Separate from `.squad/`** — `.secops/` is customer environment data; `.squad/` is framework internals. Clean separation of concerns.

3. **YAML, not JSON** — Human-editable with inline comments. SOC engineers will hand-edit these files. Comments are critical for documenting "why."

4. **All files standalone** — Any single file works without the others existing. Missing files = "unknown," not "error." This supports incremental population.

5. **Append-only discovery log** — `discovery-log.yaml` is the bridge between agent auto-discovery and human-verified authoritative data. Agents append; humans promote.

6. **MSSP-first multi-tenancy** — Schema supports enterprise (simple) through full MSSP with Lighthouse delegations, CSP, B2B guest access, and managed customers.

7. **Cross-cloud metadata** — `source_cloud` field on data sources enables AWS/GCP correlation context. `cross_cloud_identity_mapping` describes how identities map across clouds.

8. **Compliance as hard constraint** — `prohibited_regions` in requirements.yaml are enforced constraints, not suggestions. Agents MUST NOT violate them.

9. **Escalation with severity overrides** — Critical alerts can skip triage tiers. After-hours policy adjusts timeouts.

10. **Templates, not real data** — All files use "Contoso Corp" examples. The `.secops/` directory will be `.gitignored` in production but templates are committed for reference.

## Scenarios Supported

- Single-tenant enterprise
- Multi-tenant enterprise (primary + secondary tenants)
- MSSP with Lighthouse delegations (scoped roles, hard limitations)
- CSP relationships
- Government cloud (azure-government, azure-china, azure-stack)
- GDPR/NIS2/DORA/PCI-DSS/FedRAMP compliance
- Cross-cloud (AWS CloudTrail, GCP audit logs)
- Data tiering (Analytics, Basic, Auxiliary, Archive)
- Active migrations with parallel-query guidance
- ADX + Sentinel hybrid architectures

## Impact on Team

- **Freamon:** Consult `data-source-map.yaml` before KQL queries
- **Kima:** Check `tenants.yaml` for cross-tenant detection rules
- **Herc:** Check `compliance/requirements.yaml` before SOAR deployments
- **Sydnor:** Build `secops-squad env init` CLI command against this schema
- **All agents:** Append to `discovery-log.yaml` when discovering environment facts

## Next Steps

- Wire `.secops/` schema into `secops-squad.config.schema.json`
- Build `secops-squad env init` CLI command to scaffold `.secops/`
- Update `.squad/routing.md` to instruct agents to consult `.secops/`
- Create `skills/customer-knowledge/environment-setup.md`
- Add `.secops/` to `.gitignore` (separate work item)
