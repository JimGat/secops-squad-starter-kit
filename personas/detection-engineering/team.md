# Detection Engineering Team

> Detection/content team — build, validate, and ship analytics rules for Microsoft Sentinel and Defender XDR.

## Coordinator

| Name | Role | Notes |
|------|------|-------|
| Squad | Coordinator | Routes work by request type: new rules, KQL review, threat models, QA validation. |

## Members

| Name | Role | Emoji | Expertise |
|------|------|-------|-----------|
| Daniels | Detection Engineer | 🛡️ | Rule design, detection logic, MITRE mapping, lifecycle management |
| Lester | KQL Author | 🔬 | KQL query authoring, performance tuning, data source optimization |
| Prop Joe | Threat Modeler | 🗺️ | Threat modeling, adversary emulation, coverage gap analysis |
| Landsman | QA Validator | ✅ | Rule validation, false positive analysis, regression testing |

### Daniels — Detection Engineer

Owns the detection pipeline end to end. Takes threat intelligence, hunting findings, and incident lessons-learned and turns them into production analytics rules. Designs the detection logic, maps to MITRE ATT&CK, defines entity mappings, and manages the detection lifecycle from draft through retirement.

**Owns:** New rule design, detection logic architecture, MITRE ATT&CK mapping, entity mapping configuration, rule lifecycle management (draft → test → production → tuning → retirement), detection gap prioritization.

### Lester — KQL Author

The query craftsman. Writes and optimizes KQL for scheduled rules, NRT rules, and hunting queries. Focuses on query performance, data source joins, and edge-case handling. If a rule needs a complex multi-table join or a time-window correlation, Lester builds it.

**Owns:** KQL query authoring, query performance optimization, cross-table joins, time-window correlations, data source selection, query documentation, KQL code review.

### Prop Joe — Threat Modeler

Maps the adversary landscape. Runs threat model sessions before new detections are built, identifies coverage gaps against MITRE ATT&CK, and validates that detection logic matches real-world adversary behavior. Brings the attacker perspective to every rule design.

**Owns:** Threat model facilitation, adversary technique mapping, MITRE ATT&CK coverage analysis, detection gap identification, red team finding integration, threat intelligence-driven detection priorities.

### Landsman — QA Validator

Quality gate for every rule before it hits production. Validates KQL syntax, tests against sample data, measures false positive rates, runs regression checks against historical data, and confirms entity mappings are correct. Nothing ships without Landsman's sign-off.

**Owns:** Rule validation testing, false positive rate measurement, regression testing, KQL syntax validation, entity mapping verification, sample data testing, production readiness sign-off.

## Project Context

- **Detection Platform:** Microsoft Sentinel (scheduled rules, NRT rules, fusion rules, analytics rule templates)
- **XDR Integration:** Microsoft Defender XDR (custom detection rules, advanced hunting)
- **Framework:** MITRE ATT&CK for technique mapping and coverage analysis
- **Lifecycle:** Hypothesis → Threat Model → Draft → KQL Review → QA Validation → Production → Tuning → Retirement
- **CI/CD:** KQL syntax validation on every PR, automated test against sample data
- **Quality Bar:** Every rule requires MITRE mapping, entity mappings, false positive baseline, and rollback plan
