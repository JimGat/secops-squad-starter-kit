# Ceremonies

> Hunt team ceremonies for hunt planning, execution debrief, and findings presentation.

## Hunt Kickoff

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | before |
| **Condition** | new hunt campaign approved |
| **Facilitator** | Omar |
| **Participants** | Slim Charles, Bubbles, Rhonda |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Hypothesis statement — what are we looking for, why do we believe it may be present
2. Threat intelligence context — Bubbles briefs on relevant adversary TTPs and IOCs
3. MITRE ATT&CK mapping — which techniques and tactics does this hunt target
4. Data source availability — which tables and log sources are needed, any gaps
5. Query plan — Slim Charles outlines the query approach, data volume estimates
6. Timeline and scope — hunt duration, affected environments, success criteria
7. Reporting expectations — what Rhonda needs to deliver the final report

**Hunt Kickoff Template:**

```
## Hunt Kickoff — [HUNT NAME]

### Hypothesis
- **Statement:** [What we expect to find and why]
- **Source:** [Threat intel / incident finding / MITRE gap / ad hoc]
- **Confidence:** [Low / Medium / High]

### Threat Intelligence
- **Relevant adversaries:** [APT groups, crimeware families]
- **TTPs of interest:** [Specific techniques]
- **IOCs (if any):** [Hashes, IPs, domains, behavioral indicators]

### MITRE ATT&CK Mapping
| Tactic | Technique | Sub-technique | Notes |
|--------|-----------|---------------|-------|
|        |           |               |       |

### Data Sources
| Table / Log Source | Workspace | Retention | Notes |
|--------------------|-----------|-----------|-------|
|                    |           |           |       |

### Query Plan
- **Approach:** [Behavioral pattern / IOC sweep / anomaly detection / correlation]
- **Estimated data volume:** [Rows / time range]
- **Cross-domain?:** [Yes/No — which domains]

### Scope
- **Duration:** [Estimated hunt duration]
- **Environments:** [Production / staging / specific tenants]
- **Success criteria:** [What confirms or refutes the hypothesis]
```

---

## Hunt Debrief

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | after |
| **Condition** | hunt campaign completed (hypothesis confirmed or refuted) |
| **Facilitator** | Omar |
| **Participants** | Slim Charles, Bubbles, Rhonda |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Hypothesis outcome — confirmed, refuted, or inconclusive with explanation
2. Findings summary — what was found, evidence quality, affected entities
3. Query effectiveness — which queries produced signal, which were noisy, performance notes
4. Detection recommendations — should findings become analytics rules, which persona owns that
5. Intelligence gaps — what Bubbles couldn't find, what sources would have helped
6. Report plan — Rhonda outlines deliverables and timeline

**Hunt Debrief Template:**

```
## Hunt Debrief — [HUNT NAME]

### Outcome
- **Hypothesis:** [Restated]
- **Result:** ✅ Confirmed / ❌ Refuted / ⚠️ Inconclusive
- **Summary:** [One paragraph explanation]

### Findings
| Finding | Severity | Evidence Quality | Affected Entities | Action Needed |
|---------|----------|-----------------|-------------------|---------------|
|         |          |                 |                   |               |

### Query Analysis
| Query | Signal Quality | Rows Scanned | Performance | Notes |
|-------|---------------|-------------|-------------|-------|
|       |               |             |             |       |

### Detection Recommendations
| Finding | Recommended Detection | MITRE Mapping | Priority | Route To |
|---------|----------------------|---------------|----------|----------|
|         |                      |               |          |          |

### Intelligence Gaps
- [What additional intelligence would have improved the hunt]

### Report Deliverables
- [ ] Technical hunt report — [Owner: Rhonda] — [Due date]
- [ ] Executive summary — [Owner: Rhonda] — [Due date]
- [ ] Detection recommendations — [Owner: Omar → Detection Engineering] — [Due date]
```

---

## Findings Presentation

| Field | Value |
|-------|-------|
| **Trigger** | manual |
| **When** | after |
| **Condition** | hunt report finalized, stakeholder briefing scheduled |
| **Facilitator** | Rhonda |
| **Participants** | Omar, stakeholders (SOC leadership, detection engineering, CISO staff) |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Hunt objective and scope — brief context for the audience
2. Key findings — what was found, risk level, affected assets
3. Evidence walkthrough — selected evidence for technical audiences, risk narrative for executives
4. Recommendations — detection rules, process changes, hardening actions
5. Questions and next steps

**Findings Presentation Template:**

```
## Hunt Findings Presentation — [HUNT NAME]

### Executive Summary
- **Hunt objective:** [One sentence]
- **Key finding:** [One sentence — the headline]
- **Risk level:** [Critical / High / Medium / Low / Informational]
- **Recommendation:** [One sentence — the ask]

### Findings Detail
| # | Finding | Risk | Evidence | Recommendation |
|---|---------|------|----------|----------------|
|   |         |      |          |                |

### Evidence Highlights
- [Selected evidence items with context — screenshots, query results, timeline excerpts]

### Recommendations
| # | Recommendation | Owner | Priority | Status |
|---|---------------|-------|----------|--------|
|   |               |       |          |        |

### Next Steps
- [ ] [Action item with owner and due date]
```
