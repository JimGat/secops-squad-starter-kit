# Work Routing

How work routes across the full SOC, by severity, domain, and operational function.

## Severity-Based Routing (Incident Triage)

| Severity | Route To | Action |
|----------|----------|--------|
| Informational | Bodie (L1) | Auto-triage: check against known-good baselines, close or flag for review |
| Low | Bodie (L1) | Template-driven triage: run standard playbook, enrich basic IOCs, close or escalate |
| Medium | Poot (L2) | Full investigation: entity enrichment, timeline reconstruction, correlation, decide escalate vs. close |
| High | Carver (L3) | Deep investigation: cross-domain correlation, threat hunting, MITRE mapping, containment recommendations |
| Critical / Multi-domain | Bunny Colvin (SOC Manager) | SOC Manager coordinates: assembles responders, manages stakeholder comms, tracks containment |

## Domain-Based Routing

| Domain | Route To | Examples |
|--------|----------|----------|
| Alert triage | Bodie (L1) | New Sentinel alert, Defender alert classification, bulk alert closure |
| Phishing response | Bodie (L1) | Reported phishing email, email-based IOC lookup, mailbox remediation |
| Medium-severity investigation | Poot (L2) | Suspicious sign-in patterns, lateral movement signals, data exfiltration indicators |
| Entity enrichment | Poot (L2) | IP reputation, user risk assessment, host timeline, geo-anomaly checks |
| Advanced investigation | Carver (L3) | APT indicators, complex attack chains, cross-domain correlation |
| KQL query development | Carver (L3) | Custom hunting queries, cross-workspace joins, performance optimization |
| Detection rule design | Herc (Det Eng) | New analytics rules, MITRE-mapped detections, NRT rules, scheduled rules |
| Detection tuning | Herc (Det Eng) | False positive reduction, threshold adjustment, entity mapping fixes, rule retirement |
| Playbook development | Cutty (Automation) | Logic Apps playbooks, automated enrichment, response automation |
| Automation requests | Cutty (Automation) | SOAR integrations, automated triage, enrichment workflows |
| Threat hunting | McNulty (Hunt Lead) | Hypothesis-driven hunts, IOC sweeps, behavioral pattern searches |
| Hunt campaign management | McNulty (Hunt Lead) | Hunt planning, scope definition, findings triage |
| IOC research | Lester (Threat Intel) | Threat feed lookups, adversary attribution, campaign correlation |
| Threat intelligence briefing | Lester (Threat Intel) | Threat landscape updates, emerging TTPs, priority actor tracking |
| Stakeholder communication | Bunny Colvin (SOC Manager) | Executive briefings, metrics reporting, resource requests |
| Shift management | Bunny Colvin (SOC Manager) | Shift handoff oversight, workload balancing, SLA tracking |

## Cross-Functional Routing

| Scenario | Primary | Supporting | Coordination |
|----------|---------|------------|-------------|
| Active incident (High+) | Carver (L3) | Lester (intel), Cutty (automation) | Bunny Colvin |
| Hunt finding → Detection | McNulty (finding) | Herc (rule design) | Bunny Colvin |
| Incident → Lessons learned | Bunny Colvin (facilitator) | All involved | Herc (detection improvements) |
| New threat intel → Hunt | Lester (intel) | McNulty (hypothesis) | Bunny Colvin |
| Repeated manual task → Automation | Any requester | Cutty (build) | Bunny Colvin |
| Detection gap found | Carver or McNulty | Herc (rule design), Lester (intel) | Bunny Colvin |

## Escalation Path

```
Bodie (L1) → Poot (L2) → Carver (L3) → Bunny Colvin (SOC Manager) → External (CISO, Legal)
```

### Escalation Triggers

| From | To | When |
|------|----|------|
| Bodie → Poot | Alert doesn't match known playbook, multiple related alerts, needs entity enrichment |
| Poot → Carver | Complex attack chain, APT indicators, cross-domain correlation needed, detection gap found |
| Carver → Bunny Colvin | Major incident declaration, stakeholder notification required, resource coordination needed |
| McNulty → Carver | Hunt finds active compromise — shift from hunting to incident response |
| McNulty → Herc | Hunt confirms detection gap — detection rule needed |
| Lester → McNulty | New threat intel warrants proactive hunt |
| Lester → Herc | New adversary TTP needs detection coverage |
| Bunny Colvin → External | Critical business impact, regulatory reporting, executive escalation |

## Rules

1. **Severity drives initial routing** — every alert enters through its severity tier.
2. **Escalate up, never down** — once escalated, the higher tier owns it. Lower tiers assist if asked.
3. **Bodie auto-closes informational** — known-good patterns don't need human eyes. Log and move on.
4. **Poot decides the fork** — L2 is the decision point: close with findings, or escalate with context.
5. **Carver gets uninterrupted focus** — don't pull L3 into L1 work. Protect investigation and hunting time.
6. **Hunt findings feed Herc** — every confirmed threat pattern becomes a detection rule candidate.
7. **Cutty automates the repeatable** — if a human does it three times, build a playbook.
8. **Lester feeds everyone** — threat intel is a shared resource. Intel flows to hunting, detection, and incident response.
9. **Bunny Colvin owns the big picture** — SOC Manager has final say on priority, staffing, and resource allocation.
10. **Cross-domain = Bunny Colvin coordinates** — any incident or initiative spanning multiple domains starts with SOC Manager.
