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

## Tool-Chain Routing

How specific task types map to Phase 2-3 skills and tool chains.

| Task Type | Primary Tool Chain | Agent | Skill References |
|-----------|-------------------|-------|------------------|
| Threat hunting | KQL builder → Advanced Hunting API | Freamon | `skills/kql/query-builder.md` → `skills/detection/advanced-hunting-api.md` |
| Hunt query development | KQL builder (template + validate + optimize) | Freamon | `skills/kql/query-builder.md` |
| Investigation queries | Log Analytics API → Sentinel API | Kima / Freamon | `skills/log-analytics/api-wrapper.md` → `skills/powershell/sentinel-api-wrapper.md` |
| Cross-workspace hunting | Log Analytics query patterns → KQL builder | Freamon | `skills/log-analytics/query-patterns.md` → `skills/kql/query-builder.md` |
| Endpoint investigation | Defender API → Advanced Hunting | Kima / Freamon | `skills/powershell/defender-api-wrapper.md` → `skills/detection/advanced-hunting-api.md` |
| SOC dashboards | Workbook automation | Kima / Daniels | `skills/soar/workbook-automation.md` |
| Alert triage routing | `.secops/alerting/routing.yaml` rules | Bunk / Kima | `.secops/alerting/routing.yaml` → `skills/powershell/sentinel-api-wrapper.md` |
| Alert escalation | `.secops/alerting/escalation.yaml` rules | Daniels | `.secops/alerting/escalation.yaml` |
| Query optimization | KQL builder validation + optimization tiers | Freamon | `skills/kql/query-builder.md` (performance tier) |
| Incident enrichment | Copilot for Security → Sentinel/Defender APIs | Kima | `skills/msft-security/copilot-for-security.md` |
| API operations (all) | Rate limiting patterns (mandatory) | All | `skills/powershell/rate-limiting.md` |

### Threat Hunting Flow

```
Hypothesis → KQL builder (template) → query-builder validate → Advanced Hunting API execute → results → detection gap analysis
```

1. **Freamon** formulates hypothesis, selects or builds KQL template via `query-builder.md`
2. **KQL builder** validates query (syntax → schema → performance → injection), optimizes with filter-first patterns
3. **Advanced Hunting API** executes against MDE/XDR unified schema or Sentinel workspace
4. Results feed back into detection gap analysis and new analytics rule proposals

### Investigation Flow

```
Alert → Sentinel API (incident details) → Defender API (endpoint context) → Log Analytics (cross-source) → Copilot enrichment
```

1. **Bunk/Kima** retrieves incident via `sentinel-api-wrapper.md`
2. **Kima** pulls endpoint/identity context via `defender-api-wrapper.md`
3. **Freamon** runs cross-workspace queries via `log-analytics/api-wrapper.md` + `query-patterns.md`
4. **Copilot for Security** provides natural-language enrichment and threat context

### Dashboard Flow

```
Workbook template → workbook-automation deploy → Sentinel workspace → SOC operational view
```

1. **Kima/Daniels** selects workbook template from `workbook-automation.md`
2. **Workbook automation** deploys to target Sentinel workspace (respects `.secops/` workspace config)
3. Dashboards cover: detection coverage, alert volume trends, SLA tracking, shift performance

### Alert Triage Flow

```
New alert → .secops/alerting/routing.yaml (severity mapping) → agent assignment → playbook or investigation
```

1. Alert enters via Sentinel or Defender XDR
2. `.secops/alerting/routing.yaml` maps alert source + severity to agent tier
3. `.secops/alerting/escalation.yaml` defines escalation triggers and override rules
4. Agent executes assigned playbook or begins investigation per routing table above

## Rules

1. **Severity drives initial routing** — every alert enters through its severity tier.
2. **Escalate up, never down** — once escalated, the higher tier owns it. Lower tiers assist if asked.
3. **Bunk auto-closes informational** — known-good patterns don't need human eyes. Log and move on.
4. **Kima decides the fork** — L2 is the decision point: close with findings, or escalate with context.
5. **Freamon gets uninterrupted focus** — don't pull L3 into L1 work. Protect hunting time.
6. **Daniels owns the queue** — Shift Lead has final say on assignment and priority overrides.
7. **Cross-domain = Daniels coordinates** — any incident spanning endpoint + identity + email starts with Shift Lead.
8. **Automation requests go to main squad** — playbook and SOAR work routes to Herc in the secops-squad core team, not the SOC persona.
9. **All API calls use rate limiting** — every agent must follow `skills/powershell/rate-limiting.md` patterns for exponential backoff and quota management.
10. **`.secops/` before API calls** — agents check `.secops/alerting/routing.yaml` for alert routing and `.secops/` workspace config before API operations.
11. **KQL builder validates before execution** — all hunting queries pass through `query-builder.md` 4-tier validation before Advanced Hunting API submission.
