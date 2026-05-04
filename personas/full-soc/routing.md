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
| Auto-triage | Bodie (L1) | Informational alert auto-close, evidence-based assignment, L1 escalation decisions |
| Medium-severity investigation | Poot (L2) | Suspicious sign-in patterns, lateral movement signals, data exfiltration indicators |
| Entity enrichment | Poot (L2) | IP reputation, user risk assessment, host timeline, geo-anomaly checks |
| eDiscovery / evidence preservation | Poot (L2) | Legal hold placement, custodian management, review set creation, evidence export |
| Data classification assessment | Poot (L2) | Purview sensitivity labels, DLP policy violations, data exposure scope |
| Advanced investigation | Carver (L3) | APT indicators, complex attack chains, cross-domain correlation |
| KQL query development | Carver (L3) | Custom hunting queries, cross-workspace joins, performance optimization |
| ADX historical hunting | Carver (L3) | Long-term retention queries, cross-cluster joins, ADX security data lake |
| Detection rule design | Herc (Det Eng) | New analytics rules, MITRE-mapped detections, NRT rules, scheduled rules |
| Detection tuning | Herc (Det Eng) | False positive reduction, threshold adjustment, entity mapping fixes, rule retirement |
| Detection deployment | Herc (Det Eng) | Sentinel API rule deployment, bulk rule management, watchlist-driven detections |
| Playbook development | Cutty (Automation) | Logic Apps playbooks, automated enrichment, response automation |
| Automation requests | Cutty (Automation) | SOAR integrations, automated triage, enrichment workflows |
| Compliance automation | Cutty (Automation) | Compliance gap analysis, evidence collection, audit report generation |
| Workbook deployment | Cutty (Automation) | Dashboard deployment, workbook lifecycle, metrics visualization |
| Threat intel feed management | Cutty (Automation) | TAXII/STIX ingestion, TI indicator lifecycle, feed scheduling |
| Threat hunting | McNulty (Hunt Lead) | Hypothesis-driven hunts, IOC sweeps, behavioral pattern searches |
| Hunt campaign management | McNulty (Hunt Lead) | Hunt planning, scope definition, findings triage |
| Cloud posture hunting | McNulty (Hunt Lead) | Defender for Cloud recommendations, secure score analysis, misconfiguration hunts |
| IOC research | Lester (Threat Intel) | Threat feed lookups, adversary attribution, campaign correlation |
| Threat intelligence briefing | Lester (Threat Intel) | Threat landscape updates, emerging TTPs, priority actor tracking |
| DLP pattern analysis | Lester (Threat Intel) | Data loss prevention intelligence, sensitive info type patterns, exfiltration TTP context |
| Compliance oversight | Bunny Colvin (SOC Manager) | Framework compliance reviews, regulatory posture, audit preparation |
| Stakeholder communication | Bunny Colvin (SOC Manager) | Executive briefings, metrics reporting, resource requests |
| SOC metrics dashboards | Bunny Colvin (SOC Manager) | Operational workbook deployment, SLA dashboards, executive reporting |
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
| Compliance check required | Bunny Colvin | Cutty (automation), Poot (evidence) | Bunny Colvin |
| Legal hold / eDiscovery | Poot (L2) | Cutty (automation) | Bunny Colvin |
| Data classification incident | Poot (L2) | Lester (DLP patterns) | Bunny Colvin |
| Post-incident dashboard | Cutty (build) | Bunny Colvin (review) | Bunny Colvin |
| Threat intel feed onboarding | Lester (requirements) | Cutty (ingestion automation) | Bunny Colvin |
| MCP server queries | Any agent | Sentinel/Defender MCP | Self-serve |

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
| Lester → Cutty | New threat feed requires ingestion automation |
| Poot → Cutty | Evidence preservation needs eDiscovery automation |
| Cutty → Bunny Colvin | Compliance gap analysis completed, needs management review |
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
11. **Compliance checks before incident closure** — Cutty runs compliance framework mapping on every High/Critical incident before Bunny Colvin signs off.
12. **Legal holds precede evidence collection** — Poot places eDiscovery legal holds before collecting mailbox or document evidence.
13. **Dashboards are automated** — Cutty deploys workbooks via workbook-automation, not manual ARM template editing.
14. **Threat intel feeds are automated** — Lester defines requirements, Cutty builds TAXII/STIX ingestion via threat-intel-ingest.
15. **MCP servers are self-serve** — any agent can query Sentinel or Defender data via MCP server skills without routing.
