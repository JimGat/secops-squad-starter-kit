# Ceremonies

> Full SOC ceremonies spanning shift operations, incident management, detection engineering, threat hunting, and continuous improvement.

## Daily Standup

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | before |
| **Condition** | start of primary shift, daily |
| **Facilitator** | Bunny Colvin |
| **Participants** | all |
| **Time budget** | 15 minutes max |
| **Enabled** | ✅ yes |

**Agenda:**
1. Open incident count by severity — quick numbers, not details
2. SLA status — any breaches or at-risk items
3. Blocked items — what's waiting on external teams, approvals, or access
4. Hunt status — brief update from McNulty on active hunts
5. Detection pipeline — Herc flags rules in review or pending deployment
6. Automation status — Cutty flags playbook issues or new automation in progress
7. Intel highlights — Lester shares any critical threat intel since last standup
8. Shift priorities — Bunny Colvin sets focus for the day

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

### Cross-Functional Updates
- **Hunting:** [McNulty — active hunt status]
- **Detection:** [Herc — pipeline status]
- **Automation:** [Cutty — playbook status]
- **Intel:** [Lester — critical updates]

### Blocked Items
- [ ] [Item]: blocked on [reason]

### Today's Priorities
1. [Priority 1]
2. [Priority 2]
3. [Priority 3]
```

---

## Shift Handoff

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | before |
| **Condition** | shift change |
| **Facilitator** | Bunny Colvin |
| **Participants** | outgoing shift, incoming shift |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Open incident queue — count by severity, assigned analyst, current status
2. Pending escalations — what's waiting, what's expected, any deadlines
3. In-progress investigations — findings so far, next steps, blockers
4. Active hunts — hypothesis, progress, preliminary findings
5. Pending automation — playbooks in development or testing
6. SLA items at risk of breach

**Handoff Template:**

```
## Shift Handoff — [DATE] [OUTGOING SHIFT] → [INCOMING SHIFT]

### Open Incidents
| ID | Severity | Status | Assigned | Summary | Notes |
|----|----------|--------|----------|---------|-------|
|    |          |        |          |         |       |

### Pending Escalations
- [ ] [Incident ID]: [Brief] — escalated to [tier], awaiting [action]

### In-Progress Investigations
- **[Incident ID]:** [Hypothesis], [findings], [next steps]

### Active Hunts
- **[Hunt name]:** [Hypothesis], [progress], [preliminary findings]

### Automation Notes
- [Playbooks in development, known issues, pending deployments]

### SLA Watch
- [ ] [Incident ID]: [Severity] — [time remaining]

### Notes for Incoming Shift
- [Anything unusual, maintenance windows, expected activity]
```

---

## Incident Review

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | after |
| **Condition** | closure of any High or Critical severity incident |
| **Facilitator** | Bunny Colvin |
| **Participants** | all-involved, Herc (detection), Cutty (automation) |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Timeline reconstruction — from first alert to full containment, with timestamps
2. Root cause analysis — initial access vector, attacker objectives, what stopped them
3. Detection efficacy — which rules fired, which missed, time-to-detect vs. time-to-respond
4. Automation assessment — which playbooks ran, which should have, automation gaps
5. Response assessment — what went well, what was slow, handoff issues
6. Improvement actions — detection tuning (Herc), new automation (Cutty), process fixes

**Incident Review Template:**

```
## Incident Review — [INCIDENT ID]

### Summary
- **Severity:** [Level]
- **Duration:** [Detection → Containment → Closure]
- **Impact:** [Affected users/systems/data]
- **MITRE ATT&CK:** [Techniques observed]

### Timeline
| Time (UTC) | Event | Source | Actor |
|------------|-------|--------|-------|
|            |       |        |       |

### Detection Analysis
| Rule | Fired? | Time to Alert | Notes |
|------|--------|---------------|-------|
|      |        |               |       |

### Automation Analysis
| Playbook | Triggered? | Result | Notes |
|----------|-----------|--------|-------|
|          |           |        |       |

### Response Assessment
- **What went well:** [Effective actions]
- **What was slow:** [Bottlenecks]
- **Handoff issues:** [Escalation or coordination problems]

### Improvement Actions
| Action | Type | Owner | Deadline | Status |
|--------|------|-------|----------|--------|
|        |      |       |          |        |
```

---

## Detection Review

| Field | Value |
|-------|-------|
| **Trigger** | manual |
| **When** | before |
| **Condition** | weekly, scheduled |
| **Facilitator** | Herc |
| **Participants** | Carver, McNulty, Lester, Bunny Colvin |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Alert volume trends — week-over-week by rule, severity, source
2. False positive rates — top offenders, tuning candidates
3. Detection gap review — incidents that bypassed rules, new threat intel from Lester
4. Hunt-to-detection pipeline — McNulty's findings that need rules
5. New detection proposals — intel-driven rules, incident-driven rules
6. MITRE coverage update — coverage changes, remaining gaps

**Detection Review Template:**

```
## Detection Review — Week of [DATE]

### Alert Volume
| Rule | This Week | Prior Week | Trend | FP Rate |
|------|-----------|------------|-------|---------|
|      |           |            |       |         |

### Top False Positive Sources
| Rule | FP Count | Root Cause | Proposed Fix | Owner |
|------|----------|------------|--------------|-------|
|      |          |            |              |       |

### Hunt-to-Detection Pipeline
| Hunt Finding | MITRE Technique | Proposed Rule | Priority | Status |
|-------------|-----------------|---------------|----------|--------|
|             |                 |               |          |        |

### Intel-Driven Detections
| Threat | Source | Technique | Proposed Rule | Priority |
|--------|--------|-----------|---------------|----------|
|        |        |           |               |          |

### MITRE Coverage
- **Current coverage:** [X] / [Y] techniques ([%])
- **Changes this week:** [+N added, -N retired]
- **Priority gaps:** [Top 3 uncovered techniques]
```

---

## Hunt Debrief

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | after |
| **Condition** | hunt campaign completed |
| **Facilitator** | McNulty |
| **Participants** | Carver, Lester, Herc, Bunny Colvin |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Hypothesis outcome — confirmed, refuted, or inconclusive
2. Findings summary — what was found, evidence quality, affected entities
3. Detection recommendations — findings that should become rules (route to Herc)
4. Intelligence output — new IOCs or TTPs for Lester's collection
5. Process improvements — methodology lessons, tooling gaps

**Hunt Debrief Template:**

```
## Hunt Debrief — [HUNT NAME]

### Outcome
- **Hypothesis:** [Restated]
- **Result:** ✅ Confirmed / ❌ Refuted / ⚠️ Inconclusive
- **Summary:** [Brief explanation]

### Findings
| Finding | Severity | Evidence Quality | Affected Entities |
|---------|----------|-----------------|-------------------|
|         |          |                 |                   |

### Detection Recommendations → Herc
| Finding | Rule Type | MITRE Mapping | Priority |
|---------|-----------|---------------|----------|
|         |           |               |          |

### Intelligence Output → Lester
| Type | Value | Context | Confidence |
|------|-------|---------|------------|
|      |       |         |            |

### Lessons Learned
- [Methodology improvements, tooling needs, process changes]
```

---

## Weekly Retro

| Field | Value |
|-------|-------|
| **Trigger** | manual |
| **When** | after |
| **Condition** | end of week, scheduled |
| **Facilitator** | Bunny Colvin |
| **Participants** | all |
| **Time budget** | 30 minutes max |
| **Enabled** | ✅ yes |

**Agenda:**
1. Key metrics — incidents handled, MTTR, MTTD, SLA compliance
2. Wins — what worked well across all SOC functions
3. Pain points — blockers, process friction, tooling issues
4. Cross-team feedback — how routing and handoffs worked
5. Improvement actions — concrete changes for next week, with owners

**Weekly Retro Template:**

```
## Weekly Retro — Week of [DATE]

### Key Metrics
| Metric | This Week | Prior Week | Trend | Target |
|--------|-----------|------------|-------|--------|
| Incidents handled |  |  |  |  |
| MTTD (mean time to detect) |  |  |  |  |
| MTTR (mean time to respond) |  |  |  |  |
| SLA compliance |  |  |  |  |
| False positive rate |  |  |  |  |
| Detection rules shipped |  |  |  |  |
| Hunts completed |  |  |  |  |
| Playbooks deployed |  |  |  |  |

### Wins 🎉
- [What went well — be specific]

### Pain Points 😤
| Issue | Impact | Proposed Fix | Owner |
|-------|--------|--------------|-------|
|       |        |              |       |

### Cross-Team Feedback
- **Triage → Investigation:** [How handoffs worked]
- **Investigation → Detection:** [Gap-to-rule pipeline]
- **Hunting → Detection:** [Finding-to-rule pipeline]
- **Intel → All:** [Intel consumption feedback]
- **Automation:** [Playbook effectiveness]

### Actions for Next Week
| Action | Owner | Deadline |
|--------|-------|----------|
|        |       |          |
```
