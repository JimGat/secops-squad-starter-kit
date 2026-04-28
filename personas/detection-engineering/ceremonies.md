# Ceremonies

> Detection engineering ceremonies for rule design, threat modeling, and quality assurance.

## Detection Review

| Field | Value |
|-------|-------|
| **Trigger** | manual |
| **When** | before |
| **Condition** | new detection rule ready for team review |
| **Facilitator** | Daniels |
| **Participants** | Lester, Prop Joe, Landsman |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Detection hypothesis — what are we trying to detect, what adversary behavior does it map to
2. MITRE ATT&CK mapping — technique IDs, tactic coverage, sub-technique specificity
3. KQL walkthrough — Lester walks through query logic, data sources, join strategy, performance
4. Threat model alignment — Prop Joe validates adversary realism and coverage contribution
5. QA plan — Landsman outlines validation approach, sample data needs, FP baseline expectations
6. Ship decision — Daniels calls go/no-go for QA validation stage

**Detection Review Template:**

```
## Detection Review — [RULE NAME]

### Detection Hypothesis
- **What we're detecting:** [Adversary behavior / technique]
- **MITRE ATT&CK:** [Technique ID(s)] — [Tactic(s)]
- **Data source(s):** [Tables / log sources]
- **Trigger logic:** [What pattern fires the alert]

### KQL Review
- **Query complexity:** [Simple / Medium / Complex]
- **Performance notes:** [Join strategy, time window, estimated row scan]
- **Edge cases:** [Known scenarios that might miss or false-fire]

### Threat Model Alignment
- **Adversary relevance:** [Which threat actors use this technique]
- **Coverage contribution:** [What gap does this fill]
- **Evasion risk:** [How an adversary might avoid this detection]

### QA Plan
- **Test approach:** [Sample data, historical replay, lab simulation]
- **FP baseline:** [Expected false positive rate and acceptable threshold]
- **Regression scope:** [Which existing rules might be affected]

### Decision
- [ ] ✅ Approved for QA
- [ ] 🔄 Revisions needed: [details]
- [ ] ❌ Rejected: [reason]
```

---

## Threat Model Session

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | before |
| **Condition** | new detection entering the pipeline (before KQL authoring) |
| **Facilitator** | Prop Joe |
| **Participants** | Daniels, Lester |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Adversary profile — who uses this technique, what's the typical kill chain context
2. Technique decomposition — break the ATT&CK technique into observable behaviors
3. Data source mapping — which logs/tables capture the relevant telemetry
4. Detection approach — what query logic best captures the behavior with minimal noise
5. Evasion analysis — how would a sophisticated adversary avoid this detection
6. Coverage assessment — what this detection adds to overall MITRE coverage

**Threat Model Template:**

```
## Threat Model — [TECHNIQUE NAME] ([TECHNIQUE ID])

### Adversary Profile
- **Known users:** [APT groups, crimeware families]
- **Kill chain context:** [Where this technique fits in typical attack flows]
- **Prevalence:** [Common / Targeted / Rare]

### Technique Decomposition
| Observable Behavior | Data Source | Table | Confidence |
|---------------------|------------|-------|------------|
|                     |            |       |            |

### Detection Approach
- **Primary signal:** [Main indicator]
- **Correlation signals:** [Supporting evidence]
- **Time window:** [Detection window]
- **Entity focus:** [User / Device / IP / Application]

### Evasion Analysis
| Evasion Method | Likelihood | Mitigation |
|----------------|------------|------------|
|                |            |            |

### Coverage Impact
- **Before:** [Current coverage for this tactic]
- **After:** [Coverage with this detection added]
- **Remaining gaps:** [What's still not covered]
```

---

## Rule Tuning Review

| Field | Value |
|-------|-------|
| **Trigger** | manual |
| **When** | after |
| **Condition** | production rule generating excessive false positives or missed detections reported |
| **Facilitator** | Daniels |
| **Participants** | Lester, Landsman |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Performance data — alert volume, false positive rate, true positive rate, time in production
2. Root cause — why is the rule misfiring (data drift, threshold too low, entity mapping issue)
3. Proposed change — Lester presents KQL modification or threshold adjustment
4. QA impact — Landsman assesses regression risk and re-validation plan
5. Decision — tune, suppress, or retire

**Tuning Review Template:**

```
## Rule Tuning Review — [RULE NAME]

### Current Performance
- **Time in production:** [Duration]
- **Alert volume (30d):** [Count]
- **True positive rate:** [%]
- **False positive rate:** [%]
- **SLA impact:** [Any SLA breaches caused by noise]

### Root Cause Analysis
- **Issue:** [What's wrong — FPs, missed detections, performance]
- **Root cause:** [Data drift / threshold / logic gap / entity mapping]
- **Examples:** [Specific false positive or missed detection examples]

### Proposed Change
- **Change type:** [Threshold / Logic / Entity mapping / Suppression / Retirement]
- **KQL diff:** [Before and after query logic]
- **Expected impact:** [Projected FP reduction / detection improvement]

### QA Re-validation
- **Regression risk:** [Low / Medium / High]
- **Test plan:** [How Landsman will validate the change]
- **Rollback plan:** [How to revert if the change makes things worse]

### Decision
- [ ] ✅ Approved — proceed with change and QA
- [ ] 🔄 Needs more data: [what additional analysis is needed]
- [ ] 🗑️ Retire rule: [replacement plan]
```
