# Ceremonies

> SOC-specific ceremonies for shift operations, incident review, and continuous improvement.

## Shift Handoff

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | before |
| **Condition** | shift change (start of new shift) |
| **Facilitator** | Daniels |
| **Participants** | outgoing shift, incoming shift |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Review open incident queue — count by severity, assigned analyst, current status
2. Brief on pending escalations — what's waiting, what's expected, any deadlines
3. Context handover for in-progress investigations — findings so far, next steps, blockers
4. Active hunt status — hypothesis, progress, preliminary findings
5. Flag any SLA items at risk of breach

**Handoff Template:**

```
## Shift Handoff — [DATE] [OUTGOING SHIFT] → [INCOMING SHIFT]

### Open Incidents
| ID | Severity | Status | Assigned | Summary | Notes |
|----|----------|--------|----------|---------|-------|
|    |          |        |          |         |       |

### Pending Escalations
- [ ] [Incident ID]: [Brief description] — escalated to [tier/person], awaiting [action]

### In-Progress Investigations
- **[Incident ID]:** [Current hypothesis], [findings so far], [next steps]

### Active Hunts
- **[Hunt name]:** [Hypothesis], [progress], [preliminary findings]

### SLA Watch
- [ ] [Incident ID]: [Severity] — [time remaining] until SLA breach

### Notes for Incoming Shift
- [Anything unusual, expected activity, maintenance windows, etc.]
```

---

## Incident Review

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | after |
| **Condition** | closure of any High or Critical severity incident |
| **Facilitator** | Daniels |
| **Participants** | all-involved |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Timeline reconstruction — from first alert to full containment, with timestamps
2. Root cause analysis — initial access vector, what the attacker achieved, what stopped them
3. Detection efficacy — which rules fired, which missed, time-to-detect vs. time-to-respond
4. Response assessment — what went well, what was slow, where did handoffs break
5. Improvement actions — detection tuning, new rules needed, playbook updates, process fixes

**Post-Incident Review Template:**

```
## Incident Review — [INCIDENT ID]

### Summary
- **Severity:** [High/Critical]
- **Duration:** [First alert] → [Containment] → [Closure]
- **Impact:** [Affected users/systems/data]
- **MITRE ATT&CK:** [Techniques observed]

### Timeline
| Time (UTC) | Event | Source | Actor |
|------------|-------|--------|-------|
|            |       |        |       |

### Root Cause
- **Initial access:** [Vector]
- **Attacker objective:** [What they were after]
- **Containment action:** [What stopped it]

### Detection Analysis
| Detection Rule | Fired? | Time to Alert | Notes |
|----------------|--------|---------------|-------|
|                |        |               |       |

- **Detection gaps:** [What should have fired but didn't]
- **False positive noise:** [Alerts that distracted during response]

### Response Assessment
- **What went well:** [Effective actions]
- **What was slow:** [Bottlenecks]
- **Handoff issues:** [Escalation or coordination problems]

### Improvement Actions
| Action | Owner | Deadline | Status |
|--------|-------|----------|--------|
|        |       |          |        |
```

---

## Daily Standup

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | before |
| **Condition** | start of primary shift, daily |
| **Facilitator** | Daniels |
| **Participants** | all |
| **Time budget** | 15 minutes max |
| **Enabled** | ✅ yes |

**Agenda:**
1. Open incident count by severity — quick numbers, not details
2. SLA status — any breaches or at-risk items
3. Blocked items — what's waiting on external teams, approvals, or access
4. Hunt status — brief update from Freamon on active hunts
5. Shift priorities — Daniels sets focus for the day

**Standup Template:**

```
## Daily Standup — [DATE]

### Incident Queue
| Severity | Open | In Progress | Pending Escalation |
|----------|------|-------------|-------------------|
| Critical |      |             |                   |
| High     |      |             |                   |
| Medium   |      |             |                   |
| Low      |      |             |                   |
| Info     |      |             |                   |

### SLA Status
- 🟢 All clear / 🟡 [N] at risk / 🔴 [N] breached
- At-risk items: [list if any]

### Blocked Items
- [ ] [Item]: blocked on [reason]

### Hunt Status
- [Active hunt summary from Freamon]

### Today's Priorities
1. [Priority 1]
2. [Priority 2]
3. [Priority 3]
```

---

## Weekly Detection Review

| Field | Value |
|-------|-------|
| **Trigger** | manual |
| **When** | before |
| **Condition** | weekly, scheduled |
| **Facilitator** | Kima |
| **Participants** | Freamon, Bunk, Daniels |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Alert volume trends — week-over-week by rule, by severity, by source
2. False positive rates — top offenders, tuning candidates, suppression requests
3. Detection gap review — incidents that bypassed existing rules, new threat intel
4. New detection proposals — hypotheses from hunting, threat intel-driven rules
5. Tuning requests — pending rule changes, threshold adjustments, entity mapping fixes

**Detection Review Template:**

```
## Weekly Detection Review — Week of [DATE]

### Alert Volume
| Analytics Rule | Alerts This Week | Prior Week | Trend | FP Rate |
|----------------|-----------------|------------|-------|---------|
|                |                 |            |       |         |

### Top False Positive Sources
| Rule | FP Count | Root Cause | Proposed Fix |
|------|----------|------------|--------------|
|      |          |            |              |

### Detection Gaps Identified
| Gap | Source (Incident/Hunt/Intel) | MITRE Technique | Proposed Rule |
|-----|------------------------------|-----------------|---------------|
|     |                              |                 |               |

### New Detection Proposals
| Proposal | Author | MITRE Mapping | Data Source | Status |
|----------|--------|---------------|-------------|--------|
|          |        |               |             |        |

### Tuning Requests
| Rule | Change Requested | Justification | Owner | Status |
|------|-----------------|---------------|-------|--------|
|      |                 |               |       |        |
```
