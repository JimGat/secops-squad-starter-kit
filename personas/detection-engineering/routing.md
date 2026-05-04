# Work Routing

How detection work routes across the team, by request type and lifecycle stage.

## Request-Type Routing

| Request Type | Route To | Action |
|-------------|----------|--------|
| New rule request | Daniels (Detection Engineer) | Design detection logic, define MITRE mapping, specify data sources and entity mappings |
| Threat model for new detection | Prop Joe (Threat Modeler) | Run threat model session, map adversary techniques, validate detection approach |
| KQL query authoring | Lester (KQL Author) | Write and optimize KQL, handle complex joins and correlations, tune performance |
| KQL code review | Lester (KQL Author) | Review query logic, performance, edge cases, and data source usage |
| Rule validation / QA | Landsman (QA Validator) | Test against sample data, measure false positive rate, verify entity mappings |
| Detection gap analysis | Prop Joe (Threat Modeler) | Map current coverage against MITRE ATT&CK, identify and prioritize gaps |
| Rule tuning request | Daniels (Detection Engineer) | Assess tuning need, update threshold or logic, send to QA for revalidation |
| Rule retirement | Daniels (Detection Engineer) | Evaluate rule value, document reason, disable with rollback plan |

## Lifecycle Routing

```
Hypothesis/Request → Daniels (design) → Prop Joe (threat model) → Lester (KQL) → Landsman (QA) → Production
```

| Stage | Owner | Gate |
|-------|-------|------|
| Detection hypothesis | Daniels | Hypothesis documented, data source confirmed available |
| Threat model | Prop Joe | Threat model session completed, adversary techniques mapped |
| KQL authoring | Lester | Query written, performance tested, edge cases handled |
| QA validation | Landsman | Syntax valid, FP rate acceptable, entity mappings correct, regression clean |
| Production deployment | Daniels | All gates passed, deployment plan documented |
| Post-production tuning | Daniels + Lester | Tuning request logged, change validated by Landsman |

## API & Tool Routing

| Operation | Skill / Tool | Agent |
|-----------|-------------|-------|
| Sentinel analytics rule CRUD (create, update, delete, list) | `sentinel-api-wrapper` (PowerShell) | Daniels |
| Sentinel incident management via API | `sentinel-api-wrapper` (PowerShell) | Daniels |
| Agent-driven Sentinel operations (KQL execution, incident triage) | `sentinel-mcp-server` (MCP) | Lester |
| Cross-workspace query execution | `log-analytics/api-wrapper` + `log-analytics/query-patterns` | Lester |
| KQL query construction and parameterization | `kql/query-builder` | Lester |
| Workbook creation, update, deployment | `workbook-automation` | Daniels |
| Table data tiering (Analytics/Basic/Archive) | `data-tiering-commands` | Daniels |
| REST API reference lookup | `sentinel-api-reference` | Any agent |

### Tool Selection Priority

1. **MCP-first** — agents use `sentinel-mcp-server` for interactive operations (query execution, incident triage)
2. **PowerShell wrappers** — pipelines and automation use `sentinel-api-wrapper` for bulk CRUD
3. **REST direct** — fallback when MCP unavailable or PS modules not installed; consult `sentinel-api-reference`

## Rules

1. **Every new detection starts with Daniels** — he owns the pipeline and the design decision.
2. **Threat model before KQL** — Prop Joe validates the approach before Lester writes a single line of KQL.
3. **Lester owns query quality** — all KQL goes through Lester for authoring or review. No self-reviewed queries.
4. **Nothing ships without Landsman** — QA validation is the final gate. No exceptions, no shortcuts.
5. **Tuning loops back through QA** — every change to a production rule gets revalidated.
6. **MITRE mapping is mandatory** — no rule enters production without at least one ATT&CK technique ID.
7. **Retirement is a decision, not neglect** — disabled rules get a documented reason and a rollback plan.
8. **MCP for agents, PowerShell for pipelines** — interactive agent work uses MCP; CI/CD and bulk operations use PowerShell wrappers.
9. **Data tiering changes require cost review** — tier changes affect retention and query cost; Daniels documents impact before applying.
