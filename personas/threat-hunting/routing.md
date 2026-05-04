# Work Routing

How hunt work routes across the team, by phase and request type.

## Phase-Based Routing

| Phase | Route To | Action |
|-------|----------|--------|
| Hypothesis development | Omar (Hunt Lead) | Develop hypothesis from intel, incidents, or gap analysis; define scope and success criteria |
| Intelligence gathering | Bubbles (OSINT Researcher) | Collect relevant IOCs, TTPs, threat actor profiles; identify data sources for hunt |
| Query authoring | Slim Charles (KQL Hunter) | Translate hypothesis into KQL queries; execute across Sentinel, Defender XDR, ADX |
| Evidence analysis | Slim Charles (KQL Hunter) + Omar (Hunt Lead) | Analyze query results, correlate findings, confirm or refute hypothesis |
| Findings documentation | Rhonda (Reporting Analyst) | Document findings, assemble evidence chain, write hunt report |
| Presentation / briefing | Rhonda (Reporting Analyst) | Prepare and deliver findings to stakeholders, detection team, or leadership |

## Request-Type Routing

| Request Type | Route To | Examples |
|-------------|----------|----------|
| New hunt request | Omar | Threat intel-driven hunt, incident follow-up hunt, MITRE gap hunt |
| IOC sweep | Slim Charles | Known-bad IP/hash/domain sweep across all log sources |
| Threat actor research | Bubbles | Profile a specific APT group, track emerging TTPs, assess relevance |
| KQL query review | Slim Charles | Hunt query optimization, cross-workspace query help, UEBA pattern review |
| Hunt report request | Rhonda | Post-hunt documentation, executive summary, quarterly hunt program report |
| Detection recommendation | Omar | Hunt finding that should become a detection rule — routes to detection-engineering persona |

## Hunt Workflow

```
Intel/Gap → Omar (hypothesis) → Bubbles (research) → Slim Charles (queries) → Omar (analysis) → Rhonda (report)
```

## Escalation Path

| From | To | When |
|------|----|------|
| Slim Charles → Omar | Query results show active threat, need scope expansion or containment recommendation |
| Bubbles → Omar | Intelligence indicates imminent or active threat requiring priority hunt |
| Omar → Incident Response | Hunt uncovers active compromise — route to incident-response persona |
| Omar → Detection Engineering | Hunt confirms detection gap — route to detection-engineering persona |

## API & Tool Routing

| Operation | Skill / Tool | Agent |
|-----------|-------------|-------|
| Execute hunt KQL queries via agent | `sentinel-mcp-server` (MCP) | Slim Charles |
| Cross-workspace hunt query execution | `log-analytics/api-wrapper` + `log-analytics/query-patterns` | Slim Charles |
| Build parameterized hunt queries | `kql/query-builder` | Slim Charles |
| Sentinel incident context retrieval | `sentinel-api-wrapper` (PowerShell) | Omar |
| Check table data tiers before hunting | `data-tiering-commands` | Omar |
| Create hunt findings workbooks | `workbook-automation` | Rhonda |
| REST API reference lookup | `sentinel-api-reference` | Any agent |

### Tool Selection Priority

1. **MCP-first** — agents use `sentinel-mcp-server` for interactive KQL execution during hunts
2. **PowerShell wrappers** — use `sentinel-api-wrapper` for incident context and bulk data retrieval
3. **REST direct** — fallback via `sentinel-api-reference` when MCP/PS unavailable

## Rules

1. **Omar owns every hunt** — no hunt starts without a documented hypothesis and Omar's go-ahead.
2. **Bubbles briefs before queries run** — OSINT context shapes the hunt; don't query blind.
3. **Slim Charles owns query quality** — all hunt KQL goes through Slim Charles, no exceptions.
4. **Every hunt gets a Rhonda report** — no hunt ends without documented findings, even if the hypothesis was refuted.
5. **Active threats escalate immediately** — if a hunt finds live attacker activity, Omar routes to incident response. Don't keep hunting during an active compromise.
6. **Findings feed detections** — confirmed threat patterns route to the detection-engineering persona for rule development.
7. **Hunt time is protected** — don't pull hunters into incident response triage. That's what the SOC persona is for.
8. **MCP for interactive hunts** — Slim Charles uses MCP for live query execution; batch sweeps use PowerShell wrappers.
9. **Check data tiers first** — Omar verifies table tiers via `data-tiering-commands` before scoping hunts to avoid querying Archive-tier tables.
