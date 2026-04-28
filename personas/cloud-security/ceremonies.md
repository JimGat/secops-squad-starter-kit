# Ceremonies

> Cloud security ceremonies for posture assessment, policy review, and cloud threat modeling.

## Posture Review

| Field | Value |
|-------|-------|
| **Trigger** | auto |
| **When** | before |
| **Condition** | weekly, scheduled (start of week) |
| **Facilitator** | D'Angelo |
| **Participants** | Avon, Stringer |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Secure Score update — current score, trend, biggest movers (positive and negative)
2. New findings — misconfigurations discovered since last review, prioritized by risk
3. Remediation status — open items from prior reviews, blockers, completion tracking
4. Subscription coverage — any subscriptions without Defender plans, data collection gaps
5. Remediation assignments — D'Angelo assigns new findings to Avon with priority and deadline

**Posture Review Template:**

```
## Posture Review — [DATE]

### Secure Score
- **Current:** [Score] / 100
- **Trend:** [Up/Down/Flat] from [Prior score]
- **Biggest movers:** [Rules/recommendations that changed score]

### New Findings
| Finding | Severity | Subscription | Resource | Assigned To | Deadline |
|---------|----------|-------------|----------|-------------|----------|
|         |          |             |          |             |          |

### Remediation Status
| Finding | Owner | Status | Notes |
|---------|-------|--------|-------|
|         |       |        |       |

### Coverage Gaps
| Subscription | Defender Plans Enabled | Missing Plans | Data Collection |
|-------------|----------------------|---------------|-----------------|
|             |                      |               |                 |

### Action Items
- [ ] [Action with owner and deadline]
```

---

## Policy Review

| Field | Value |
|-------|-------|
| **Trigger** | manual |
| **When** | before |
| **Condition** | new compliance requirement, policy change request, or quarterly review |
| **Facilitator** | Stringer |
| **Participants** | Avon, D'Angelo |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Policy inventory — current assignments, initiatives, custom definitions
2. Compliance gap analysis — framework requirements vs. current policy coverage
3. Policy effectiveness — violations trending up or down, exemption review
4. New policy proposals — requirements from compliance, audit findings, or posture gaps
5. Exemption audit — review active exemptions, check expiration, assess continued justification

**Policy Review Template:**

```
## Policy Review — [DATE]

### Framework: [CIS / NIST / PCI-DSS / Custom]

### Compliance Status
| Control | Policy Assignment | Status | Gap | Action |
|---------|------------------|--------|-----|--------|
|         |                  |        |     |        |

### Policy Effectiveness
| Policy | Violations (30d) | Trend | Top Violators | Action |
|--------|-----------------|-------|---------------|--------|
|        |                 |       |               |        |

### New Policy Proposals
| Proposal | Source | Framework Mapping | Impact Assessment | Status |
|----------|--------|-------------------|-------------------|--------|
|          |        |                   |                   |        |

### Exemption Audit
| Exemption | Resource | Justification | Expiration | Renew? |
|-----------|----------|---------------|------------|--------|
|           |          |               |            |        |

### Action Items
- [ ] [Action with owner and deadline]
```

---

## Cloud Threat Model

| Field | Value |
|-------|-------|
| **Trigger** | manual |
| **When** | before |
| **Condition** | new cloud workload deployment, architecture change, or post-incident review |
| **Facilitator** | Avon |
| **Participants** | Stringer, D'Angelo |
| **Time budget** | focused |
| **Enabled** | ✅ yes |

**Agenda:**
1. Workload overview — what's being deployed or changed, architecture diagram
2. Threat surface — public endpoints, identity exposure, data sensitivity, network boundaries
3. Control mapping — existing controls vs. required controls for the threat surface
4. Policy requirements — Stringer maps required policies for the new workload
5. Monitoring requirements — what D'Angelo needs to add to posture assessment scope
6. Remediation plan — gaps found, hardening actions, timeline

**Cloud Threat Model Template:**

```
## Cloud Threat Model — [WORKLOAD NAME]

### Workload Overview
- **Description:** [What this workload does]
- **Resources:** [VMs, storage, databases, networking, identity]
- **Data classification:** [Public / Internal / Confidential / Restricted]
- **Subscription:** [Subscription name/ID]

### Threat Surface
| Surface | Exposure | Risk Level | Notes |
|---------|----------|------------|-------|
| Public endpoints |  |  |  |
| Identity / RBAC |  |  |  |
| Data at rest |  |  |  |
| Data in transit |  |  |  |
| Network boundaries |  |  |  |

### Control Mapping
| Threat | Required Control | Current Status | Gap |
|--------|-----------------|----------------|-----|
|        |                 |                |     |

### Policy Requirements
| Policy | Initiative | Assignment Scope | Status |
|--------|-----------|-----------------|--------|
|        |           |                 |        |

### Monitoring Requirements
| Signal | Data Source | Defender Plan | Status |
|--------|------------|---------------|--------|
|        |            |               |        |

### Hardening Actions
| Action | Owner | Priority | Deadline | Status |
|--------|-------|----------|----------|--------|
|        |       |          |          |        |
```
