# Work Routing

How incidents and tasks are routed across the SOC team, by severity and work type.

## Severity-Based Routing

| Severity | Route To | Action |
|----------|----------|--------|
| Informational | Bunk (L1) | Auto-triage: check against known-good baselines, close or flag for review |
| Low | Bunk (L1) | Template-driven triage: run standard playbook, enrich basic IOCs, close or escalate |
| Medium | Kima (L2) | Full investigation: entity enrichment, timeline reconstruction, correlation, decide escalate vs. close |
| High | Freamon (L3) | Deep investigation: cross-domain correlation, threat hunting, MITRE mapping, containment recommendations |
| Critical / Multi-domain | Daniels (Shift Lead) | Shift Lead coordinates: assembles responders, manages stakeholder comms, tracks containment |

## Work-Type Routing

| Work Type | Route To | Examples |
|-----------|----------|----------|
| Alert triage, false positive review | Bunk | New Sentinel alert, Defender alert classification, bulk alert closure |
| Phishing response | Bunk | Reported phishing email, email-based IOC lookup, mailbox remediation |
| Compromised account response | Bunk | Password spray detection, token theft initial response, MFA reset |
| Medium-severity investigation | Kima | Suspicious sign-in patterns, lateral movement signals, data exfiltration indicators |
| Sentinel analytics rule tuning | Kima | False positive reduction, threshold adjustment, entity mapping fixes |
| Entity enrichment requests | Kima | IP reputation, user risk assessment, host timeline, geo-anomaly checks |
| KQL query development | Freamon | Custom hunting queries, cross-workspace joins, ADX queries, performance optimization |
| Threat hunting | Freamon | Hypothesis-driven hunts, IOC sweeps, behavioral pattern searches, UEBA analysis |
| Cross-domain correlation | Freamon | Endpoint + identity + email correlation, multi-kill-chain analysis |
| Playbook / automation requests | Main Squad (Herc) | Logic Apps playbooks, automated enrichment, SOAR integrations — route to secops-squad main |
| Stakeholder communication | Daniels | Executive briefings, incident status updates, compliance notifications |
| Shift handoff | Daniels | End-of-shift briefing, incident queue transfer, context handover |
| Incident assignment | Daniels | Workload balancing, re-assignment, escalation overrides |
| SLA tracking / reporting | Daniels | SLA breach alerts, response time metrics, shift performance |

## Escalation Path

```
Bunk (L1) → Kima (L2) → Freamon (L3) → Daniels (Shift Lead) → External (on-call, CISO)
```

### Escalation Triggers

| From | To | When |
|------|----|------|
| Bunk → Kima | Alert doesn't match known playbook, multiple related alerts, needs entity enrichment |
| Kima → Freamon | Complex attack chain, APT indicators, cross-domain correlation needed, detection gap found |
| Freamon → Daniels | Major incident declaration, stakeholder notification required, resource coordination needed |
| Daniels → External | Critical business impact, regulatory reporting required, executive escalation |

## Rules

1. **Severity drives initial routing** — every alert enters through its severity tier.
2. **Escalate up, never down** — once escalated, the higher tier owns it. Lower tiers assist if asked.
3. **Bunk auto-closes informational** — known-good patterns don't need human eyes. Log and move on.
4. **Kima decides the fork** — L2 is the decision point: close with findings, or escalate with context.
5. **Freamon gets uninterrupted focus** — don't pull L3 into L1 work. Protect hunting time.
6. **Daniels owns the queue** — Shift Lead has final say on assignment and priority overrides.
7. **Cross-domain = Daniels coordinates** — any incident spanning endpoint + identity + email starts with Shift Lead.
8. **Automation requests go to main squad** — playbook and SOAR work routes to Herc in the secops-squad core team, not the SOC persona.
