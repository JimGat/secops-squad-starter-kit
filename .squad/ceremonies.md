# Ceremonies

> Team meetings that happen before or after work. Each squad configures their own.

## Threat Model Review

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | before |
| **Condition** | multi-domain task involving 2+ agents or new threat detection scope |
| **Facilitator** | McNulty |
| **Participants** | Kima, Freamon |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Review the threat scenario and MITRE ATT&CK mapping
2. Agree on data sources, KQL patterns, and detection thresholds
3. Identify false positive risks and tuning strategy
4. Assign action items across detection, query, and automation tracks

---

## Detection Validation

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | after |
| **Condition** | detection rule work (new or modified analytics rules, hunting queries) |
| **Facilitator** | Carver |
| **Participants** | Freamon, Kima |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Review detection rule against test cases (true positive, true negative, edge case)
2. Validate KQL query performance and correctness
3. Check MITRE ATT&CK mapping accuracy
4. Confirm alert severity and incident creation logic
5. Sign off or reject with specific remediation items

---

## Architecture Review

| Field | Value |
|-------|-------|
| **Trigger** | manual |
| **When** | before |
| **Condition** | invoked manually for major architectural decisions |
| **Facilitator** | McNulty |
| **Participants** | all |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Review the proposed architecture or design change
2. Assess impact on existing templates, queries, and automation
3. Identify risks, dependencies, and migration paths
4. Reach consensus and document the decision

---

## Retrospective

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | after |
| **Condition** | build failure, test failure, or reviewer rejection |
| **Facilitator** | McNulty |
| **Participants** | all-involved |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. What happened? (facts only)
2. Root cause analysis
3. What should change?
4. Action items for next iteration
