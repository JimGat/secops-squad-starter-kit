---
title: Detection Lifecycle — Design → Test → Deploy → Tune
category: detection
difficulty: intermediate
mitre_attack:
  - T1110  # Brute Force
  - T1110.003  # Password Spraying
  - T1566  # Phishing
  - T1566.001  # Spearphishing Attachment
  - T1078  # Valid Accounts
  - T1133  # External Remote Services
products:
  - Microsoft Sentinel
  - Microsoft Defender for Endpoint
  - Microsoft Defender for Identity
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# Detection Lifecycle — Design → Test → Deploy → Tune

## Overview

A detection that isn't tuned in production doesn't work. This skill covers the full lifecycle of a detection from initial threat hypothesis to retirement, with quality gates at each phase transition. Every detection in this framework follows this lifecycle — no exceptions.

Use this skill when:
- Starting a new detection engineering effort
- Reviewing a detection's maturity and readiness for production
- Setting up detection engineering processes for a team
- Evaluating whether an existing detection should be tuned or retired

## Prerequisites

| Requirement | Detail |
|---|---|
| **Workspace** | Sentinel-enabled Log Analytics workspace (dev and prod) |
| **Permissions** | `Microsoft Sentinel Contributor` (prod), `Log Analytics Contributor` (dev) |
| **Process** | Team agreement on review/approval workflow |
| **Tooling** | Source control for analytics rules (Git repo) |

## The Four Phases

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Phase 1    │───►│  Phase 2    │───►│  Phase 3    │───►│  Phase 4    │
│  RESEARCH   │    │  DEVELOP    │    │  DEPLOY     │    │  TUNE       │
│             │    │             │    │             │    │             │
│ Threat model│    │ KQL query   │    │ Rule config │    │ Monitor     │
│ MITRE map   │    │ Test data   │    │ Entity maps │    │ FP review   │
│ Hypothesis  │    │ Validation  │    │ Staging     │    │ Threshold   │
│ Data audit  │    │ Peer review │    │ Go-live     │    │ Retire/keep │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │ Gate 1          │ Gate 2          │ Gate 3          │ Gate 4
      ▼                 ▼                 ▼                 ▼
  Threat model       Query runs        Rule fires       TP rate ≥ 80%
  approved           on real data      on staging        FP rate ≤ 20%
  Data exists        FP rate < 50%     No errors         MTTR tracked
```

---

### Phase 1: Threat Research and Hypothesis

**Goal:** Define *what* you're detecting and *why* it matters before writing any KQL.

**Activities:**

1. **Write the threat model** (mandatory — team decision #7)
   - Threat actor profile and motivation
   - Attack path (step by step)
   - Data sources required
   - Detection approach
   - Use the [Threat Model Template](threat-model-template.md)

2. **Map to MITRE ATT&CK** (mandatory — team decision #8)
   - Identify tactic, technique, and sub-technique
   - Check current coverage — is this gap already addressed?
   - Document confidence level (high/medium/low)
   - See [MITRE ATT&CK Mapping](mitre-attack-mapping.md)

3. **Audit data availability**
   - Verify required tables exist in your workspace
   - Check data freshness and ingestion latency
   - Confirm retention covers your lookback needs

4. **Write the hypothesis**
   - One sentence: "We will detect [technique] by looking for [observable behavior] in [data source]."
   - Example: "We will detect password spraying (T1110.003) by looking for a single IP producing 50+ failed sign-ins against 5+ accounts within 10 minutes in SignInLogs."

**Checklist — Phase 1 Exit (Gate 1):**

- [ ] Threat model document completed and reviewed
- [ ] MITRE ATT&CK technique(s) assigned
- [ ] Required data sources confirmed present in workspace
- [ ] Hypothesis written as a single testable statement
- [ ] Approved by detection lead or team review

---

### Phase 2: KQL Query Development and Testing

**Goal:** Write a query that catches the behavior described in the hypothesis, validate it against real data, and confirm acceptable noise levels.

**Activities:**

1. **Develop the KQL query**
   - Start in Log Analytics query editor against the dev workspace
   - Follow KQL performance patterns (filter early, project before join)
   - Reference [Threat Hunting Foundations](../kql/threat-hunting-foundations.md)

2. **Test against historical data**
   - Run against 30 days of data minimum
   - Count total results — understand the volume
   - Manually classify the first 50 results as TP (true positive) or FP (false positive)

3. **Calculate initial metrics**
   ```
   True Positive Rate = TP / (TP + FN)   ← Can you find known-bad events?
   False Positive Rate = FP / (TP + FP)   ← How noisy is it?
   ```

4. **Peer review the query**
   - Another engineer runs the same query independently
   - Review KQL for correctness, performance, and edge cases
   - Verify entity mapping columns are present in the output

**Checklist — Phase 2 Exit (Gate 2):**

- [ ] Query executes successfully on real data
- [ ] 50+ results manually classified
- [ ] False positive rate < 50% (tune further if not)
- [ ] Query execution time < 30 seconds on 14-day lookback
- [ ] Peer review completed
- [ ] Entity mapping columns confirmed in output

---

### Phase 3: Analytics Rule Configuration and Deployment

**Goal:** Package the query as a Sentinel analytics rule, deploy to staging, and verify it fires correctly.

**Activities:**

1. **Configure the analytics rule**
   - Use the [Scheduled Rule Pattern](scheduled-rule-pattern.md) or [NRT Rule Pattern](nrt-rule-pattern.md) template
   - Set frequency, lookback, and suppression
   - Configure entity mappings
   - Set alert grouping and incident creation

2. **Deploy to staging environment**
   - Deploy via ARM/Bicep template to a dev/test workspace
   - Or create manually in the Sentinel UI for initial testing

3. **Validate rule execution**
   - Confirm the rule runs on schedule (check `SentinelHealth` table)
   - Verify alerts are generated with correct entity mappings
   - Verify incidents are created with expected grouping
   - Test alert details override formatting

4. **Deploy to production**
   - Merge ARM/Bicep template to main branch
   - Deploy via CI/CD pipeline or manual ARM deployment
   - Enable the rule in production workspace

**Checklist — Phase 3 Exit (Gate 3):**

- [ ] Analytics rule deployed and enabled
- [ ] Rule executes without errors (SentinelHealth confirms)
- [ ] Entity mappings produce valid entities on incidents
- [ ] Alert details override renders correctly
- [ ] Incident grouping works as expected
- [ ] Rule committed to source control

---

### Phase 4: Monitoring, Tuning, and Iteration

**Goal:** Track detection quality in production and continuously improve signal-to-noise ratio.

**Activities:**

1. **Monitor detection metrics (weekly for first month, monthly after)**

   ```kql
   // Detection quality metrics — run monthly per rule
   let RuleName = "Brute Force - Password Spray Detected";
   let ReviewPeriod = 30d;
   SecurityIncident
   | where TimeGenerated > ago(ReviewPeriod)
   | where Title has RuleName
   | summarize
       TotalIncidents = count(),
       TruePositives = countif(Classification == "TruePositive"),
       FalsePositives = countif(Classification == "FalsePositive"),
       BenignPositives = countif(Classification == "BenignPositive"),
       Undetermined = countif(Classification == "Undetermined"),
       AvgCloseTimeHours = avg(datetime_diff('hour', ClosedTime, CreatedTime))
   | extend
       TPRate = round(100.0 * TruePositives / TotalIncidents, 1),
       FPRate = round(100.0 * FalsePositives / TotalIncidents, 1)
   ```

2. **Tune based on production data**
   - Adjust thresholds to reduce FPs
   - Add exclusions for known-good behavior (service accounts, expected IPs)
   - Use watchlists for dynamic exclusions — see [Watchlist-Driven Detection](watchlist-driven-detection.md)

3. **Track key metrics**

   | Metric | Target | Action if Missed |
   |---|---|---|
   | True Positive Rate | ≥ 80% | Tighten thresholds, add exclusions |
   | False Positive Rate | ≤ 20% | Add allowlists, refine query logic |
   | Mean Time to Response (MTTR) | < 4 hours | Improve playbook, add enrichment |
   | Alert Volume | < 25/day per rule | Lower sensitivity or split into tiers |
   | Rule Execution Success | 100% | Fix query errors, reduce complexity |

4. **Retirement criteria**
   - Rule hasn't produced a true positive in 90 days → review for retirement
   - Underlying data source is decommissioned → retire immediately
   - MITRE technique is now covered by a better detection → consolidate
   - FP rate stays above 50% after 3 tuning cycles → retire and redesign

## Lifecycle Tracking

Maintain a detection registry to track where each detection is in its lifecycle:

| Detection Name | MITRE | Phase | TP Rate | FP Rate | Owner | Last Review |
|---|---|---|---|---|---|---|
| Password Spray | T1110.003 | Phase 4 — Tuning | 87% | 13% | Kima | 2026-04-15 |
| Tor Sign-in | T1133 | Phase 3 — Deploy | N/A | N/A | Kima | 2026-04-20 |
| Phishing Link | T1566.001 | Phase 2 — Dev | 72% | 28% | Freamon | 2026-04-25 |

## Best Practices

1. **Never skip Phase 1.** A detection without a threat model is a query looking for a purpose. Team decision #7 makes threat models mandatory.
2. **Test on real data, not synthetic.** Lab-generated events rarely match production behavior. Use your actual workspace data for Phase 2 testing.
3. **Deploy incrementally.** Start with `createIncident: false` to observe alert volume before creating incidents. Enable incident creation after 1 week of clean operation.
4. **Automate metrics collection.** Schedule the quality metrics query as a workbook or dashboard tile.
5. **Retire without guilt.** A retired detection frees up analyst attention for better detections. Track retirements in the registry with a reason.
6. **Version control everything.** Analytics rule ARM templates, threat models, and tuning notes all belong in Git.

## Related Skills

- **[Scheduled Rule Pattern](scheduled-rule-pattern.md)** — Phase 3 configuration for scheduled rules.
- **[NRT Rule Pattern](nrt-rule-pattern.md)** — Phase 3 configuration for NRT rules.
- **[MITRE ATT&CK Mapping](mitre-attack-mapping.md)** — Phase 1 technique identification.
- **[Threat Model Template](threat-model-template.md)** — Phase 1 threat model document.
- **[Custom KQL Function](custom-kql-function.md)** — Phase 2 reusable query components.
- **[Threat Hunting Foundations](../kql/threat-hunting-foundations.md)** — Phase 2 KQL development patterns.
