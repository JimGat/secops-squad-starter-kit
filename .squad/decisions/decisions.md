# SecOps Squad Decisions Log

Archive of all team decisions, proposals, and architectural choices.

---

## 2026-04-30

### Decision: PowerShell Skills Domain (`skills/powershell/`)

**By:** Freamon (KQL Engineer)
**Date:** 2026-04-30T17:08:05-05:00
**Status:** Proposed
**Requested by:** Jose

#### What

Created the `skills/powershell/` domain — 10 skill files defining patterns for a SecOps PowerShell module covering Microsoft Security APIs. These are knowledge documents that teach agents how to generate correct, production-grade PowerShell code.

#### Structure

- `README.md` — Domain overview, module architecture, agent usage guide
- `module-foundation.md` — PSDepend, .psd1 manifest, submodule loading, initialization
- `auth-patterns.md` — MSAL, service principal, managed identity, multi-tenant, government cloud
- `error-handling.md` — Structured results, retry/backoff, throttling, audit logging
- `sentinel-module.md` — Incident management, analytics rules, hunting queries, workbooks
- `defender-module.md` — MDE alerts, advanced hunting, device actions, MDC recommendations
- `entra-module.md` — Conditional Access, PIM, Identity Protection, sign-in analysis
- `azure-monitor-module.md` — Action Groups, Alert Rules, Diagnostic Settings
- `resource-graph-module.md` — Security-focused ARG queries, compliance posture
- `data-tiering-module.md` — Analytics/Basic/Auxiliary/Archive tiers, retention, summary rules

#### Key Design Decisions

1. **Skills, not executable code** — These teach agents patterns; they're not a shipped module
2. **SecOps.Tools module name** with `SecOps` noun prefix on all exported functions
3. **Structured result pattern** (`New-SecOpsResult`) aligns with team's ok/error convention
4. **Central REST wrapper** (`Invoke-SecOpsRestMethod`) with retry, throttle, and audit logging built in
5. **`.secops/` auto-loading** at module init — environment, tenants, data-source-map
6. **Cloud-aware endpoint resolution** — All URIs resolve from `.secops/environment.yaml` cloud type
7. **Government cloud support** — GCC, GCC-High, DoD endpoint mappings for Graph, MDE, ARM
8. **ShouldProcess on all write operations** — `-WhatIf` and `-Confirm` support throughout
9. **MITRE ATT&CK mapped** on every skill file per team convention

#### Impact

- **Kima:** Can reference Sentinel and Defender skills when building detection automation
- **Herc:** Azure Monitor skill aligns with SOAR playbook triggers and action group setup
- **Sydnor:** Module foundation pattern can inform CLI extension design
- **Carver:** Can validate agent-generated PowerShell against these skill patterns
- **All agents:** PowerShell code generation now has a reference framework

#### Why

16 critical gaps identified in platform coverage analysis. PowerShell is the primary automation language for SOC engineers, yet the project had zero PowerShell skills. These 10 files close the gap for module structure, authentication, error handling, and 6 Microsoft Security API surfaces.

---

### Decision: Log Analytics API Skill — `.secops/` Integration as First-Class Pattern

**Date:** 2026-04-30
**By:** Freamon (KQL Engineer)
**Status:** Proposed

#### What

The two new Log Analytics skills (`api-wrapper.md`, `query-patterns.md`) establish a pattern where every API call and query construction starts by reading `.secops/` configuration files. This is not optional guidance — it is woven into every code example.

Specific integrations:
1. **Query API** reads workspace IDs from `.secops/workspaces/*.yaml` — never hardcoded
2. **Query patterns** check `.secops/data-sources/data-source-map.yaml` for table locations and tiers before building queries
3. **Alert rules** reference `.secops/alerting/routing.yaml` for action group binding and severity mapping
4. **DCR ingestion** reads DCE endpoints from workspace config's `custom_tables` section
5. **Migration-aware queries** consult `migrations.yaml` to union both old and new workspace locations

#### Why

Skills that hardcode workspace IDs or assume table locations break when deployed to customer environments. The `.secops/` framework exists to bridge this gap. By making config-driven patterns the default in all examples, agents that learn from these skills will produce environment-aware output automatically.

#### Impact

- **All agents:** Code examples in these skills model the correct `.secops/`-first pattern. Agents generating query or API code should follow the same approach.
- **Sydnor:** `ConvertFrom-Yaml` is used extensively in PowerShell examples — confirms `js-yaml` dependency alignment for Node.js, but PowerShell users need `powershell-yaml` module noted in prerequisites.
- **Kima:** Detection rules using cross-workspace queries should follow the union pattern shown in `query-patterns.md` for migration safety.

---

### Decision: Sentinel MCP Server Skill Architecture

**Date:** 2026-04-30
**Author:** Kima (SecOps Engineer)
**Status:** Proposed
**Requested by:** Jose

#### What

Created two new skills for Sentinel MCP Server integration and REST API reference:

1. **`skills/msft-security/sentinel-mcp-server.md`** — Comprehensive guide for configuring and using Azure MCP Server with Sentinel workspaces. Covers 8 sections: architecture overview, configuration/setup (multi-client, multi-workspace, gov cloud), resource listing patterns, CRUD operations via MCP tools, safe query execution, rate limiting/throttling, agent integration patterns, and 4 practical workflow examples.

2. **`skills/msft-security/sentinel-api-reference.md`** — Field reference for direct REST API usage covering incidents, analytics rules, data connectors, watchlists, threat intelligence, automation rules, bookmarks, and Log Analytics queries. Includes RBAC matrix, API versioning, PowerShell cmdlet mapping, and error handling.

#### Key Design Decisions

1. **MCP-first, REST-fallback** — Skills establish MCP as the preferred path for agent operations, with REST as graceful degradation. This aligns with the platform gap analysis identifying MCP integration as critical.

2. **`.secops/` integration** — MCP configuration links to workspace discovery via `.secops/workspaces/*.yaml`. Agents read workspace context before configuring MCP connections.

3. **Permission tiering** — Recommends `Sentinel Responder` as default agent role (incident management without rule modification risk). `Contributor` requires explicit elevation for rule CRUD.

4. **Multi-workspace via separate MCP instances** — Each workspace gets its own MCP server config block. Simpler than multiplexing and matches MSSP/multi-tenant patterns in `.secops/`.

5. **Structured comment protocol for multi-agent coordination** — JSON-formatted incident comments prevent duplicate agent actions on shared incidents.

#### Impact

- **All agents:** Now have MCP integration guidance for Sentinel operations
- **Kima:** Owns these skills; detection/incident workflows reference MCP as primary tooling
- **Sydnor:** May need to extend `.copilot/mcp-config.json` scaffolding in CLI based on patterns documented here
- **Freamon:** KQL query execution via MCP documented; complements existing KQL skills
- **Herc:** Automation rules API documented; SOAR workflows can reference for API integration

#### Open Questions

- Should `skills/mcp/` be a separate top-level category (per gap analysis) or keep MCP skills in `msft-security/`?
- Should the CLI auto-generate MCP config from `.secops/workspaces/*.yaml`?

---

### Decision: Defender MCP Server Skill Architecture

**Date:** 2026-04-30
**By:** Kima (SecOps Engineer)
**Status:** Proposed
**Requested by:** Jose

#### What

Created two new skills in `skills/msft-security/`:

1. **`defender-mcp-server.md`** — Comprehensive Defender MCP server integration skill covering the full API landscape, MCP configuration, product-specific operations via REST, rate limiting, caching strategies, and 5 end-to-end agent workflows (triage, hunting, posture, IR, vuln prioritization).

2. **`defender-api-permissions.md`** — Complete permissions reference for all Defender APIs with least-privilege patterns per SOC workflow, tiered app registration strategy, auth method comparison, multi-tenant/MSSP patterns, government cloud considerations, and credential governance.

#### Key Design Choices

1. **Complement, don't duplicate** — Existing skills (defender-for-endpoint.md, defender-xdr-configuration.md, microsoft-graph-security.md) cover portal configuration, onboarding, and Graph auth basics. These new skills focus on programmatic MCP/API access patterns that complement them.

2. **Tiered app registration** — Three-tier model (ReadOnly → Triage → Response) maps to SOC role tiers. Prevents junior analysts from holding incident response permissions they don't need.

3. **Graph-first, product-API-fallback** — Use Graph Security API wherever possible (alerts, incidents, hunting). Fall back to MDE API only for machine actions, Live Response, TVM, and custom indicators. This aligns with Microsoft's API convergence direction.

4. **Structured result pattern** — All API wrapper examples return `{ok, data}` / `{ok: false, error}` consistent with team decision on structured results.

5. **Government cloud awareness** — Every API section references `.secops/environment.yaml` cloud type check. Different endpoints for commercial vs. GCC vs. GCC High vs. DoD.

#### Impact

- **All agents:** Can now programmatically interact with Defender products via MCP patterns
- **Kima:** Owns these skills; will update as Microsoft migrates MDE actions to Graph
- **Herc:** SOAR playbooks can reference permission patterns for service principal setup
- **Sydnor:** MCP server configuration pattern established for future MCP integrations
- **Carver:** Can validate that API calls follow least-privilege and rate-limiting patterns

#### Open Questions

- Should we build an actual MCP server wrapper library in `lib/defender-mcp/` or keep this as a knowledge skill only?
- MDCA API token management (portal-generated, not Graph) needs a secure storage pattern — Key Vault integration?

---

### Decision: Sentinel API Wrapper — Dual-Approach Pattern (REST + Cmdlet)

**Date:** 2026-04-30T17:08:00-05:00
**By:** Freamon (KQL Engineer)
**Status:** Proposed
**Scope:** `skills/powershell/sentinel-api-wrapper.md`

#### Decision

The Sentinel API wrapper skill uses direct REST API calls (via `Invoke-SentinelApi` → `Invoke-SecOpsRestMethod`) as the primary approach, with `Az.SecurityInsights` cmdlet examples shown as alternatives where applicable.

#### Rationale

1. **REST-first gives full API surface coverage** — `Az.SecurityInsights` cmdlets lag behind the REST API by 3-6 months. NRT rules, TI bulk import, watchlist item CRUD, and connector health are REST-only.
2. **Consistent error handling** — REST calls flow through `Invoke-SecOpsRestMethod` which enforces the team's `SecOps.Result` pattern. Cmdlets throw exceptions that require separate try/catch wiring.
3. **Government cloud portability** — `Get-SentinelBaseUri` resolves the correct ARM endpoint from `.secops/` config. Cmdlets use `Get-AzContext` which may not reflect `.secops/` cloud preferences.
4. **Cmdlets shown for simplicity** — Simple read operations (list incidents, list rules) are shown with cmdlet alternatives for SOC engineers who prefer them.

#### Impact

- **All agents:** When generating Sentinel PowerShell, prefer the REST wrapper functions from this skill. Use cmdlets only for ad-hoc interactive use.
- **Kima:** Detection rule deployment should use `New-SecOpsAnalyticsRule` / `New-SentinelNrtRule`, not raw `New-AzSentinelAlertRule`.
- **Herc:** SOAR playbooks calling Sentinel APIs should use the shared helpers for consistent audit logging.

---

### Decision: Defender API Wrapper Skill Architecture

**Date:** 2026-04-30T17:08:05-05:00
**Author:** Kima (SecOps Engineer)
**Status:** Implemented
**Requested by:** Jose

#### What

Created `skills/powershell/defender-api-wrapper.md` — a comprehensive PowerShell skill covering 20+ production-ready REST API wrappers across four Defender products (MDE, Defender for Cloud, XDR, MDI).

#### Key Design Decisions

1. **Complement, don't duplicate** — defender-module.md has the base functions (Get-SecOpsAlert, Invoke-SecOpsAdvancedHunting, Set-SecOpsDeviceIsolation). This skill extends with MDE-specific wrappers (Live Response, TVM, custom detections), Defender for Cloud, XDR, and MDI coverage.

2. **Shared pagination helper** — `Invoke-SecOpsPaginatedRequest` is a reusable function for all Defender APIs that return `@odata.nextLink`. Safety-capped at 50 pages to prevent runaway queries.

3. **MDE-direct vs Graph split** — MDE-specific operations (machine actions, Live Response, TVM) use `api.securitycenter.microsoft.com` directly. Cross-product operations (incidents, XDR hunting, MDI health) use `graph.microsoft.com/v1.0/security`. This matches the actual API surface — Graph is the convergence target but MDE endpoints aren't fully migrated.

4. **Graph SDK alternative** — Included `Get-XdrIncidentSdk` as an example of the Microsoft.Graph.Security SDK approach with a decision matrix for when to use SDK vs REST. SDK is better for interactive SOC; REST is better for automation/Functions.

5. **MDI via XDR hunting** — MDI doesn't have its own REST API surface for suspicious activities. Used `Invoke-XdrAdvancedHunting` with `ServiceSource == "Microsoft Defender for Identity"` filter for the `Get-MdiSuspiciousActivity` function. Health issues use the Graph Security identities endpoint.

#### Impact

- **All agents:** New PowerShell wrappers available for Defender API tasks
- **Freamon:** KQL queries in kql/defender-xdr-hunting.md can be passed directly to Run-MdeAdvancedHunting or Invoke-XdrAdvancedHunting
- **Herc:** SOAR playbooks can call these wrappers as building blocks
- **Carver:** Should validate wrapper functions return SecOps.Result pattern consistently

---

### Decision: Unified API Rate Limiting Architecture

**Date:** 2026-04-30T17:08:05-05:00
**By:** Freamon (KQL Engineer)
**Status:** Proposed
**Requested by:** Jose

#### What

Created two cross-cutting PowerShell skills that define the project's API rate limiting and common API patterns:

1. **`skills/powershell/rate-limiting.md`** — Unified rate limit reference, exponential backoff, priority queuing, quota pooling, circuit breaker, monitoring, and cross-API coordination
2. **`skills/powershell/api-patterns.md`** — Pagination, batching, long-running operations, idempotency, correlation IDs, pipeline streaming

#### Key Design Choices

1. **3-tier priority model (Critical 60% / Normal 30% / Low 10%)** — Incident response API calls must pre-empt reporting and batch work. Token bucket implementation enforces this at the function level.

2. **File-based quota pooling with named mutexes** — For single-machine deployments (most SOC teams), a shared JSON file with `Global\` mutexes coordinates across processes. Redis option available for distributed environments.

3. **Per-provider backoff tuning** — ARM, Graph, MDE, Log Analytics, and MDCA each get different default retry parameters (base delay, max retries, default Retry-After). A single `Invoke-WithRetry` function handles all providers.

4. **Circuit breaker as module-scoped registry** — Circuit breakers persist across calls within a PowerShell session via `$script:CircuitBreakers` hashtable. Each API surface gets its own breaker. Recovery is automatic via half-open probes.

5. **Streaming pagination via PowerShell pipeline** — `Get-SecOpsStream` yields items one at a time from paginated APIs, enabling `Where-Object | Select-Object -First 10` patterns without loading all pages.

#### Impact

- **All agents:** These patterns are cross-cutting — every API wrapper skill should reference them
- **Kima:** Defender and Sentinel module skills should delegate retry/backoff to `Invoke-WithRetry` rather than reimplementing
- **Herc:** SOAR playbooks calling multiple APIs should use `New-SecOpsApiCoordinator` for budget sharing
- **Carver:** Test scenarios included for each major pattern — can integrate into CI validation

#### Open Questions

1. Should quota pooling default to file-based or Redis-based? Current default is file-based (simpler). Redis requires infrastructure.
2. Should circuit breaker state persist across PowerShell sessions (via file) or reset on session start? Currently resets.
3. The priority model budget split (60/30/10) is a starting point — should this be configurable via `.secops/` config?

---

### Decision: Data Tiering Commands Skill Architecture

**Date:** 2026-04-30
**By:** Freamon (KQL Engineer)
**Status:** Implemented

#### What

Created `skills/powershell/data-tiering-commands.md` (~500 lines) — production-ready PowerShell commands for the full data tiering lifecycle: tier management, retention policies, summary rules, purge operations, and migration workflows.

#### Key Design Decisions

1. **Complement, don't duplicate** — The existing `data-tiering-module.md` provides `Get-SecOpsTableInventory`, `Set-SecOpsTableTier`, `Set-SecOpsRetentionPolicy`, and `New-SecOpsSummaryRule`. The new skill adds *additional* functions and deeper workflows (tier recommendations, cost calculators, compliance auditing, purge/migration orchestration) without re-implementing the base functions.

2. **Pre-flight safety checks on tier changes** — `Set-LogAnalyticsTablePlan` blocks downgrades if:
   - Active Sentinel analytics rules reference the table
   - Active migrations exist in `migrations.yaml`
   - No summary rule exists (warns, doesn't block)
   This prevents accidental detection blindness from tier downgrades.

3. **Compliance as hard constraint** — `Set-LogAnalyticsRetention` validates against `.secops/compliance/requirements.yaml` before applying. The `-AutoComply` switch auto-raises values to the minimum; without it, sub-minimum values error out. Compliance is never optional.

4. **Cost impact before commitment** — `Get-TierCostImpact` and `Get-TierRecommendation` must be run before any tier change. The cost calculator uses `.secops/data-source-map.yaml` daily volumes as the default data source, reducing the need for live queries.

5. **Purge operations are audited** — `Submit-DataPurge` requires a `-Reason` parameter (ticket ID or justification), logs the operator identity, and returns a purge ID for tracking. This creates an audit trail for GDPR/privacy compliance.

6. **Migration orchestration is plan-first** — `Start-DataMigration` outputs a step-by-step plan and the YAML entry to add to `migrations.yaml`, but does NOT auto-modify the file. Human review of migration plans is required.

#### Impact

- **All agents:** New tier/retention commands integrate with `.secops/` context — agents must consult data-source-map.yaml before making tier recommendations
- **Kima:** Detection rule dependency checks prevent silent rule breakage from tier downgrades
- **Herc:** Migration workflows complement SOAR automation patterns for data movement
- **Carver:** Summary rule validation (`Test-SummaryRule`) can be added to CI for KQL correctness

#### Functions Added

| Function | Purpose |
|---|---|
| `Get-LogAnalyticsTablePlan` | Audit current tiers with .secops/ enrichment |
| `Set-LogAnalyticsTablePlan` | Tier change with safety checks |
| `Get-TierRecommendation` | Query-pattern-based tier recommendation |
| `Get-TierCostImpact` | Cost calculator for tier changes |
| `Get-LogAnalyticsRetention` | Retention audit with compliance status |
| `Set-LogAnalyticsRetention` | Retention change with compliance enforcement |
| `Test-RetentionCompliance` | Bulk compliance audit |
| `Set-BulkRetentionPolicy` | Apply retention to multiple tables |
| `New-SummaryRule` | Create aggregation rules |
| `Get-SummaryRule` | List summary rules |
| `Test-SummaryRule` | Validate summary rule KQL |
| `Submit-DataPurge` | GDPR data purge with audit trail |
| `Get-PurgeStatus` | Track purge operations |
| `Start-DataMigration` | Orchestrate ADX↔Sentinel, workspace consolidation |
| `Get-MigrationStatus` | Track active migrations |
