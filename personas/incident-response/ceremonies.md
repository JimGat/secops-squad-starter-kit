# Ceremonies

> Incident response ceremonies for incident management, containment review, and continuous improvement.

## IR Kickoff

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | before |
| **Condition** | new High or Critical severity incident declared |
| **Facilitator** | Rawls |
| **Participants** | Sydnor, Beadie, Prez |
| **Time budget** | 15 minutes max |
| **Enabled** | ✅ yes |

**Agenda:**
1. Incident summary — what triggered it, initial severity, affected systems/users
2. Evidence status — what Sydnor has collected so far, what's still needed
3. Intel context — Prez shares any immediate IOC/adversary context
4. Containment posture — current exposure, immediate containment actions needed
5. Task assignments — who does what in the next operational period
6. Comms plan — Beadie confirms stakeholder notification timeline and audience

**IR Kickoff Template:**

```
## IR Kickoff — [INCIDENT ID]

### Incident Summary
- **Severity:** [Critical / High]
- **Detected:** [Timestamp UTC]
- **Detection source:** [Sentinel rule / Defender alert / User report / External notification]
- **Affected scope:** [Users / Devices / Applications / Data]
- **Initial hypothesis:** [What we think happened]

### Evidence Status
| Evidence Type | Status | Location | Notes |
|---------------|--------|----------|-------|
| Logs |  |  |  |
| Endpoint artifacts |  |  |  |
| Network captures |  |  |  |
| Email/Identity data |  |  |  |

### Intel Context
- **Known IOCs:** [IPs, domains, hashes — if any]
- **Adversary assessment:** [Known actor / Unknown / Opportunistic]
- **Related campaigns:** [Any known connections]

### Containment Status
- **Current exposure:** [What's still at risk]
- **Immediate actions:** [Containment steps taken or needed]
- **Authorization needed:** [Actions requiring approval]

### Task Assignments
| Task | Owner | Priority | Deadline |
|------|-------|----------|----------|
|      |       |          |          |

### Comms Plan
- **Internal notification:** [Who, when, what level of detail]
- **Executive briefing:** [Scheduled time, attendees]
- **Regulatory:** [Applicable / Not applicable — notification deadline if applicable]
```

---

## Containment Review

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | after |
| **Condition** | containment actions executed, before moving to eradication |
| **Facilitator** | Rawls |
| **Participants** | Sydnor, Prez |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Containment actions taken — what was isolated, blocked, disabled, revoked
2. Effectiveness assessment — is the attacker stopped? Any signs of continued activity?
3. Collateral impact — business operations affected by containment actions
4. Evidence update — new findings from Sydnor, updated IOCs from Prez
5. Eradication readiness — can we proceed to clean up, or do we need more containment?
6. Updated comms — Beadie updates stakeholders on containment status

**Containment Review Template:**

```
## Containment Review — [INCIDENT ID]

### Containment Actions
| Action | Target | Timestamp | Status | Verified |
|--------|--------|-----------|--------|----------|
|        |        |           |        |          |

### Effectiveness
- **Attacker activity stopped?** [Yes / No / Uncertain]
- **Evidence of continued access:** [Findings]
- **Monitoring in place:** [What we're watching]

### Business Impact
| System/Service | Impact | Duration | Workaround |
|----------------|--------|----------|------------|
|                |        |          |            |

### Updated Findings
- **New IOCs:** [From Sydnor and Prez]
- **Attack timeline update:** [New events discovered]
- **Scope change:** [Broader / Narrower than initial assessment]

### Eradication Decision
- [ ] ✅ Proceed to eradication — containment verified effective
- [ ] 🔄 Additional containment needed: [details]
- [ ] ⚠️ Escalate — scope is larger than expected: [details]
```

---

## Lessons Learned

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | after |
| **Condition** | incident closed (all severity levels) |
| **Facilitator** | Rawls |
| **Participants** | Sydnor, Beadie, Prez, stakeholders |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Incident timeline — end-to-end reconstruction from detection to closure
2. What worked — effective detections, fast containment, good comms
3. What didn't — missed alerts, slow response, communication gaps, tooling issues
4. Detection improvements — rules that should be created, tuned, or retired
5. Process improvements — playbook updates, escalation path changes, training needs
6. Action items — specific improvements with owners and deadlines

**Lessons Learned Template:**

```
## Lessons Learned — [INCIDENT ID]

### Incident Summary
- **Severity:** [Level]
- **Duration:** [Detection → Containment → Closure]
- **Impact:** [Affected users/systems/data]
- **Root cause:** [How the attacker got in]
- **MITRE ATT&CK:** [Techniques observed]

### Timeline
| Time (UTC) | Event | Source | Actor |
|------------|-------|--------|-------|
|            |       |        |       |

### What Worked Well
| Area | Detail |
|------|--------|
|      |        |

### What Needs Improvement
| Area | Issue | Impact | Proposed Fix |
|------|-------|--------|--------------|
|      |       |        |              |

### Detection Improvements
| Action | Type | MITRE Mapping | Owner | Route To |
|--------|------|---------------|-------|----------|
|        |      |               |       |          |

### Process Improvements
| Action | Category | Owner | Deadline | Status |
|--------|----------|-------|----------|--------|
|        |          |       |          |        |

### Key Metrics
- **Time to detect:** [Duration]
- **Time to contain:** [Duration]
- **Time to eradicate:** [Duration]
- **Time to recover:** [Duration]
- **Total incident duration:** [Duration]
```
