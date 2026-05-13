# Microsoft Security Platform Coverage Gap Analysis & Customer Knowledge Framework

> **Author:** McNulty (Lead) | **Date:** 2026-04-30 | **Requested by:** Jose Paid
>
> Audit of secops-squad repo against what a SOC team actually needs, plus a framework for customer-specific environment knowledge.

---

## Resolution Status

> **Status: ✅ All 56 gaps addressed** | **Updated:** 2026-05-04

All 56 platform coverage gaps identified in this analysis have been resolved across Phases 1–6:

| Phase | Focus | Gaps Addressed |
|-------|-------|---------------|
| **Phase 1** | Foundation (KQL, SOAR, Detection, ADX) | Initial 52 skills covering core domains |
| **Phase 2** | Log Analytics & Microsoft Security Products | 10 Log Analytics skills, 8 additional MSFT Security skills |
| **Phase 3** | PowerShell API Wrappers & Modules | 15 PowerShell skills for API patterns, modules, rate limiting |
| **Phase 4** | SOAR Expansion & Compliance | Additional SOAR skills (data exfil, malware, compliance mappings) |
| **Phase 5** | Platform & Cross-Cloud | Multi-tenant, cross-cloud connectors, gov cloud, MCP servers |
| **Phase 6** | Orchestration & Integration Testing | Cross-skill orchestration, MSSP workflows, Copilot for Security, integration tests |

The `.secops/` customer knowledge framework (Part 2 of this document) was implemented in Phase 2 and refined through Phase 6. See [ARCHITECTURE.md](ARCHITECTURE.md) for the current architecture and [SECOPS_SCHEMA.md](SECOPS_SCHEMA.md) for the complete schema reference.

---

## PART 1: Platform Coverage Gap Analysis

### What We HAVE (Current Inventory)

| Domain | Files | Key Coverage |
|--------|-------|-------------|
| **ADX** | 8 skills | Cluster architecture, data modeling, ingestion, retention, ML anomaly, dashboards, cross-cluster, migration |
| **Detection** | 8 skills | Scheduled/NRT rules, fusion, watchlists, MITRE mapping, lifecycle, custom functions, threat models |
| **KQL** | 10 skills | Hunting foundations, UEBA, incident investigation, Entra sign-in, cloud posture, XDR hunting, cross-workspace, ADX integration, analytics rules, detection tuning |
| **Log Analytics** | 8 skills | Workspace architecture, RBAC, retention/archive, diagnostic settings, data connectors, custom tables/DCR, cost optimization, purge/export |
| **MSFT Security** | 8 skills | Defender for Endpoint, Identity, Cloud policies, XDR config, Entra ID Protection, Graph Security API, Purview DLP, Sentinel setup |
| **SOAR** | 10 skills | Phishing response, malware containment, compromised account, data exfil, auto-triage, enrichment (IP/user), Teams alerts, ticket creation, threat intel ingest |
| **Bicep Templates** | 11 templates | ADX cluster/database/tables/ingestion, SOAR playbooks (5) |
| **Lib** | graph-security (9 files), kql-validator, azure-auth, mitre-mapping | Graph Security API client, offline KQL validation |
| **Docs** | 6 docs | Getting started, personas guide, skills catalog, MITRE coverage, Graph Security API, ADX setup |

**Total: 52 skills, 11 Bicep templates, 4 libraries, 6 docs**

---

### Gap Analysis by Microsoft Platform Area

---

#### 1. Microsoft Graph Security API

**Current Coverage:** `skills/msft-security/microsoft-graph-security.md` + `lib/graph-security/` (alerts, incidents, threat-intelligence, secure-score)

| Capability | Status | Gap Level |
|------------|--------|-----------|
| Alerts (list, get, update) | ✅ Have | — |
| Incidents (list, get, update) | ✅ Have | — |
| Threat Intelligence indicators | ✅ Have | — |
| Secure Score | ✅ Have | — |
| eDiscovery cases/custodians/review sets | ❌ Missing | 🟡 Important |
| Attack Simulation Training API | ❌ Missing | 🟢 Nice-to-have |
| Hunting API (run advanced hunting via Graph) | ❌ Missing | 🟡 Important |
| Security Actions (block IP, isolate device) | ❌ Missing | 🟡 Important |
| Compliance/DLP alerts via Graph | ❌ Missing | 🟡 Important |
| Webhook subscriptions for security events | ❌ Missing | 🔴 Critical |

**Verdict:** We have the four main modules. Missing webhook subscriptions is critical — SOC teams need real-time push notifications for alerts, not just polling. eDiscovery and hunting-via-Graph are important for IR teams.

---

#### 2. PowerShell Modules

**Current Coverage:** Skills reference PowerShell commands but we have NO dedicated PowerShell skill domain and NO PowerShell module reference guide.

| Module | Status | Gap Level | Why |
|--------|--------|-----------|-----|
| **Az.SecurityInsights** | ❌ No skill | 🔴 Critical | Primary module for Sentinel automation — rule deployment, incident management, watchlists, data connectors, all via PowerShell |
| **Az.OperationalInsights** | ❌ No skill | 🔴 Critical | Workspace creation, table management, saved searches, data export — the workhorse for Log Analytics IaC |
| **Microsoft.Graph.Security** | ❌ No skill | 🟡 Important | PowerShell alternative to our JS Graph Security client — many SOC teams are PS-first |
| **ExchangeOnlineManagement** | ❌ No skill | 🟡 Important | Email investigation, mailbox audit, message trace — Kima's phishing response needs this |
| **AzureADPreview / Microsoft.Graph.Identity** | ❌ No skill | 🟡 Important | PIM, Conditional Access policies as code, access reviews — critical for identity security |
| **Az.Monitor** | ❌ No skill | 🟡 Important | Alert rules, action groups, diagnostic settings automation |
| **Az.Kusto (ADX)** | ❌ No skill | 🟡 Important | ADX cluster and database management — complements our Bicep templates |
| **Az.DataExplorer** | ❌ No skill | 🟢 Nice-to-have | Newer module, overlaps with Az.Kusto |

**Verdict:** This is a significant gap. We're a SecOps framework with zero PowerShell module skills. Most SOC engineers live in PowerShell. Need at minimum `Az.SecurityInsights` and `Az.OperationalInsights` skills.

---

#### 3. Sentinel MCP Server

**Current Coverage:** `.copilot/mcp-config.json` has an EXAMPLE GitHub MCP server. No Sentinel MCP.

| Capability | Status | Gap Level |
|------------|--------|-----------|
| MCP server for KQL execution against live workspace | ❌ Missing | 🔴 Critical |
| MCP server for Sentinel incident management | ❌ Missing | 🔴 Critical |
| MCP server for rule deployment/management | ❌ Missing | 🟡 Important |
| Skill teaching agents how to use Sentinel MCP | ❌ Missing | 🔴 Critical |

**Verdict:** This is arguably the biggest gap. A Sentinel MCP would let agents actually _run_ KQL against live workspaces, manage incidents, and deploy rules — turning our skills from reference docs into executable capabilities. Microsoft has released Azure MCP Server tooling; we should build a skill around configuring and using it, even if we don't ship our own MCP server.

**Recommendation:** Create `skills/mcp/sentinel-mcp-setup.md` covering:
- Azure MCP Server configuration for Sentinel workspaces
- Authentication patterns (managed identity, service principal)
- Safe query execution (read-only vs. write operations)
- Rate limiting and cost awareness for agent-driven queries

---

#### 4. Sentinel Unified Data Platform / Data Lake

**Current Coverage:** `skills/log-analytics/cost-optimization.md` mentions Analytics vs. Basic Logs. `skills/log-analytics/retention-archive.md` covers archive tier. `skills/adx/migration-from-sentinel.md` covers ADX migration.

| Capability | Status | Gap Level |
|------------|--------|-----------|
| Basic Logs tier selection and query patterns | ⚠️ Partial (mentioned in cost-optimization) | 🔴 Critical |
| Analytics Logs vs. Basic Logs decision framework | ⚠️ Partial | 🔴 Critical |
| Sentinel data lake (low-cost retention tier) | ❌ Missing | 🟡 Important |
| Summary Rules (scheduled aggregation) | ❌ Missing | 🔴 Critical |
| Data tiering strategy (Analytics → Basic → Sentinel data lake → Archive) | ❌ Missing | 🔴 Critical |
| Ingestion-time transformations (workspace transforms) | ⚠️ Partial (in custom-tables-dcr) | 🟡 Important |
| Long-term data search (restored logs) | ⚠️ Partial (in retention-archive) | 🟡 Important |

**Verdict:** Microsoft's unified data platform is the future of Sentinel data management. SOC teams are making daily decisions about which tier each table belongs to. Summary Rules are critical for cost — they pre-aggregate verbose data. We need a dedicated `skills/log-analytics/data-tiering-strategy.md` and `skills/log-analytics/summary-rules.md`.

---

#### 5. Log Analytics REST API

**Current Coverage:** `skills/log-analytics/custom-tables-dcr.md` covers DCR patterns. `skills/log-analytics/data-connectors-setup.md` mentions Logs Ingestion API.

| Capability | Status | Gap Level |
|------------|--------|-----------|
| Log Analytics Query API (programmatic KQL execution) | ❌ No dedicated skill | 🔴 Critical |
| Logs Ingestion API (Custom Logs v2) | ⚠️ Partial | 🟡 Important |
| Data Collection Endpoints (DCE) | ❌ Missing | 🟡 Important |
| DCR/DCE deployment patterns (Bicep) | ❌ No Bicep template | 🟡 Important |
| Tables API (create/update custom tables) | ⚠️ Partial | 🟢 Nice-to-have |
| Saved Searches API | ❌ Missing | 🟢 Nice-to-have |
| Query packs | ❌ Missing | 🟢 Nice-to-have |

**Verdict:** The Query API gap is critical — agents need to know how to execute KQL programmatically (not just write it). This connects directly to the Sentinel MCP gap.

---

#### 6. Azure Monitor

**Current Coverage:** `skills/log-analytics/diagnostic-settings.md` covers diagnostic settings.

| Capability | Status | Gap Level |
|------------|--------|-----------|
| Diagnostic Settings | ✅ Have | — |
| Action Groups (routing, webhooks, Logic Apps) | ❌ Missing | 🔴 Critical |
| Alert Rules (metric, log, activity log) | ❌ Missing | 🔴 Critical |
| Workbooks (SOC dashboards as code) | ❌ Missing | 🟡 Important |
| Azure Dashboards | ❌ Missing | 🟢 Nice-to-have |
| Application Insights (for monitoring security tooling) | ❌ Missing | 🟢 Nice-to-have |
| Autoscale (for ADX/SOAR infrastructure) | ❌ Missing | 🟢 Nice-to-have |

**Verdict:** Action Groups and Alert Rules are the backbone of operational alerting. SOC teams configure these daily. Workbooks are how most Sentinel users build dashboards. All three need skills.

---

#### 7. Microsoft Defender APIs

**Current Coverage:** `skills/msft-security/defender-for-endpoint.md` (MDE), `defender-for-identity.md` (MDI), `defender-for-cloud-policies.md` (MDC), `defender-xdr-configuration.md` (XDR)

| Capability | Status | Gap Level |
|------------|--------|-----------|
| MDE: Device management, indicators, onboarding | ✅ Have | — |
| MDE: Live Response API (remote shell) | ⚠️ Mentioned, no API skill | 🔴 Critical |
| MDE: Advanced Hunting API (programmatic) | ❌ Missing | 🔴 Critical |
| MDE: Custom Detection Rules API | ❌ Missing | 🟡 Important |
| MDE: Machine Actions API (isolate, scan, collect) | ⚠️ In SOAR playbook, not standalone | 🟡 Important |
| MDI: Sensor management API | ❌ Missing | 🟢 Nice-to-have |
| MDI: Health alerts API | ❌ Missing | 🟢 Nice-to-have |
| Defender for Cloud Apps: Activity/file/alert APIs | ❌ Missing | 🟡 Important |
| Defender for Cloud Apps: App discovery, governance | ❌ Missing | 🟡 Important |
| Defender for Cloud: Recommendations API | ⚠️ Partial | 🟡 Important |
| Defender for Cloud: Regulatory Compliance API | ❌ Missing | 🟡 Important |

**Verdict:** MDE Live Response API and Advanced Hunting API are daily-use for IR teams. Defender for Cloud Apps is a blind spot — we reference it in fusion rules but have no standalone skill.

---

#### 8. Microsoft Purview

**Current Coverage:** `skills/msft-security/purview-dlp-patterns.md` covers DLP + sensitivity labels.

| Capability | Status | Gap Level |
|------------|--------|-----------|
| DLP policies and rules | ✅ Have | — |
| Sensitivity labels | ✅ Have | — |
| Insider Risk Management | ❌ Missing | 🟡 Important |
| eDiscovery (Premium) | ❌ Missing | 🟡 Important |
| Communication Compliance | ❌ Missing | 🟢 Nice-to-have |
| Information Barriers | ❌ Missing | 🟢 Nice-to-have |
| Records Management / Retention | ❌ Missing | 🟢 Nice-to-have |
| Compliance Manager API | ❌ Missing | 🟢 Nice-to-have |
| Audit (Premium) log access | ❌ Missing | 🟡 Important |

**Verdict:** Insider Risk and eDiscovery are the big misses. Both are increasingly SOC-adjacent and part of Defender XDR integration.

---

#### 9. Entra ID (Beyond Identity Protection)

**Current Coverage:** `skills/msft-security/entra-id-protection.md`, `skills/kql/entra-signin-analysis.md`

| Capability | Status | Gap Level |
|------------|--------|-----------|
| Identity Protection (risk policies, alerts) | ✅ Have | — |
| Sign-in log analysis | ✅ Have | — |
| Conditional Access as code (templates, Bicep) | ❌ Missing | 🔴 Critical |
| PIM (Privileged Identity Management) API | ❌ Missing | 🔴 Critical |
| Access Reviews (create, manage, remediate) | ❌ Missing | 🟡 Important |
| Identity Governance (entitlement, lifecycle) | ❌ Missing | 🟡 Important |
| Named Locations management | ❌ Missing | 🟡 Important |
| Authentication Methods API | ❌ Missing | 🟡 Important |
| Service Principal risk detection | ❌ Missing | 🟡 Important |
| Cross-tenant access settings | ❌ Missing | 🟢 Nice-to-have |

**Verdict:** Conditional Access as code and PIM are critical. Every SOC team manages these. CA policies should be version-controlled and deployed via pipeline — this is exactly the kind of pattern our framework should teach.

---

#### 10. Azure Resource Graph

**Current Coverage:** `skills/kql/cloud-security-posture.md` references Resource Graph queries.

| Capability | Status | Gap Level |
|------------|--------|-----------|
| Security posture queries (exposed resources, public endpoints) | ⚠️ Partial reference | 🔴 Critical |
| Resource inventory for SOC (what's deployed where) | ❌ Missing | 🔴 Critical |
| Change tracking (resource mutations) | ❌ Missing | 🟡 Important |
| Cross-subscription resource discovery | ❌ Missing | 🟡 Important |
| Policy compliance state queries | ❌ Missing | 🟡 Important |
| Advisor recommendations via ARG | ❌ Missing | 🟢 Nice-to-have |

**Verdict:** Resource Graph is how SOC teams understand their attack surface. A dedicated `skills/kql/resource-graph-hunting.md` is critical. Should include query patterns for: "show me all public IPs," "find unencrypted storage," "list VMs without endpoint protection."

---

#### 11. Copilot for Security

**Current Coverage:** None.

| Capability | Status | Gap Level |
|------------|--------|-----------|
| Custom plugin development | ❌ Missing | 🟡 Important |
| Custom skills authoring | ❌ Missing | 🟡 Important |
| Promptbook creation and management | ❌ Missing | 🟡 Important |
| Integration with our skills framework | ❌ Missing | 🟡 Important |
| KQL plugin for Copilot for Security | ❌ Missing | 🟡 Important |

**Verdict:** This is a strategic gap. As Copilot for Security matures, customers will want to build custom plugins. Our framework could become a development environment for Copilot for Security plugins. Not critical for v1, but important for positioning.

---

#### 12. Threat Intelligence

**Current Coverage:** `skills/soar/threat-intel-ingest.md` (TAXII/STIX ingest), `lib/graph-security/threat-intelligence.js` (Graph TI API), `skills/soar/sentinel-enrichment-ip.md` (MDTI enrichment)

| Capability | Status | Gap Level |
|------------|--------|-----------|
| STIX/TAXII feed ingestion | ✅ Have | — |
| Graph TI indicator CRUD | ✅ Have | — |
| MDTI enrichment (IP) | ✅ Have | — |
| MDTI API (full — articles, intel profiles, reputation) | ❌ Missing | 🟡 Important |
| TI matching rules (detect-on-ingest) | ❌ Missing | 🟡 Important |
| TI lifecycle management (aging, expiration, confidence) | ⚠️ Partial | 🟢 Nice-to-have |
| Threat Intelligence Blade management | ❌ Missing | 🟢 Nice-to-have |
| Custom TI platform integration (MISP, OpenCTI) | ❌ Missing | 🟢 Nice-to-have |

**Verdict:** Good foundation. MDTI full API skill is the main gap — Microsoft's threat intel is increasingly rich and SOC teams should query it directly.

---

### Gap Priority Summary

#### 🔴 Critical Gaps (16 items — SOC teams need these daily)

| # | Gap | Proposed Skill/Artifact |
|---|-----|------------------------|
| 1 | Sentinel MCP Server integration | `skills/mcp/sentinel-mcp-setup.md` |
| 2 | PowerShell: Az.SecurityInsights | `skills/powershell/az-security-insights.md` |
| 3 | PowerShell: Az.OperationalInsights | `skills/powershell/az-operational-insights.md` |
| 4 | Graph Security webhook subscriptions | Update `skills/msft-security/microsoft-graph-security.md` |
| 5 | Data tiering strategy (unified data platform) | `skills/log-analytics/data-tiering-strategy.md` |
| 6 | Summary Rules | `skills/log-analytics/summary-rules.md` |
| 7 | Log Analytics Query API | `skills/log-analytics/query-api.md` |
| 8 | Azure Monitor: Action Groups | `skills/azure-monitor/action-groups.md` |
| 9 | Azure Monitor: Alert Rules | `skills/azure-monitor/alert-rules.md` |
| 10 | MDE Advanced Hunting API | `skills/msft-security/mde-advanced-hunting-api.md` |
| 11 | MDE Live Response API | `skills/msft-security/mde-live-response-api.md` |
| 12 | Conditional Access as code | `skills/entra-id/conditional-access-as-code.md` |
| 13 | PIM API | `skills/entra-id/pim-automation.md` |
| 14 | Resource Graph security queries | `skills/kql/resource-graph-hunting.md` |
| 15 | Resource inventory for SOC | `skills/kql/resource-graph-hunting.md` (same file) |
| 16 | Basic Logs vs. Analytics Logs decision | `skills/log-analytics/data-tiering-strategy.md` (same file) |

#### 🟡 Important Gaps (25 items — should be in v1)

eDiscovery, Hunting via Graph, Security Actions, Graph DLP alerts, Microsoft.Graph.Security PS, ExchangeOnlineManagement, Graph.Identity PS, Az.Monitor PS, Az.Kusto PS, Sentinel data lake, Ingestion-time transforms detail, Logs Ingestion API detail, DCE patterns, DCR/DCE Bicep, Workbooks, MDE Custom Detection Rules API, MDE Machine Actions standalone, Defender for Cloud Apps, Defender for Cloud Regulatory Compliance, Insider Risk, eDiscovery Premium, Purview Audit Premium, Access Reviews, Identity Governance, Named Locations, Authentication Methods, Service Principal risk, ARG change tracking, ARG cross-subscription, ARG policy compliance, MDTI full API, TI matching rules, Copilot for Security plugin dev (5 items)

#### 🟢 Nice-to-have Gaps (15 items — can wait for later phases)

Attack Simulation, Az.DataExplorer, Saved Searches, Query Packs, Azure Dashboards, App Insights, Autoscale, MDI sensor/health APIs, Communication Compliance, Information Barriers, Records Management, Compliance Manager API, Cross-tenant access, Advisor via ARG, TI lifecycle detail, TI blade mgmt, MISP/OpenCTI integration

---

### New Skill Domains Needed

The current 6 skill domains (`adx`, `detection`, `kql`, `log-analytics`, `msft-security`, `soar`) need expansion:

| New Domain | Why | Priority |
|------------|-----|----------|
| `skills/powershell/` | Most SOC engineers are PS-first. No coverage today. | 🔴 Critical |
| `skills/mcp/` | Agent-executable security operations. Game changer. | 🔴 Critical |
| `skills/azure-monitor/` | Alert rules, action groups, workbooks. Currently orphaned under log-analytics. | 🔴 Critical |
| `skills/entra-id/` | CA-as-code, PIM, governance. Broader than just identity protection. | 🔴 Critical |
| `skills/resource-graph/` | Attack surface visibility. Could live under `kql/` since it's KQL-based. | 🟡 Important |
| `skills/copilot-for-security/` | Plugin development, promptbooks. Strategic positioning. | 🟡 Important |

---

## PART 2: Customer Knowledge Framework Design

### The Problem

Our skills are generic. They teach agents _how_ to do things but not _where_ to do them in a specific customer's environment. An agent writing a KQL query needs to know:
- Is `SecurityEvent` in Sentinel or ADX?
- What's the workspace ID? Is there more than one?
- What tier is `NetFlowLogs` in — Analytics, Basic, or Sentinel data lake?
- Are they migrating anything right now?

### Proposed Framework: `.secops/` Directory

#### Why `.secops/` (not `.squad/customer/` or other locations)

- `.squad/` is framework internals — agent configs, casting, routing
- `.secops/` is the customer's security environment — their data
- Keeps concerns separated: framework config vs. environment knowledge
- Matches the `.env` / `.config` pattern developers expect
- `.secops/` should be gitignored by default (contains environment-specific data)

#### Directory Structure

```
.secops/
├── environment.yaml          # Primary environment descriptor
├── workspaces/
│   ├── prod-sentinel.yaml    # Per-workspace details
│   ├── dev-sentinel.yaml
│   └── soc-adx.yaml
├── data-sources/
│   ├── data-source-map.yaml  # What data lives where
│   └── migrations.yaml       # Active/planned migrations
├── identity/
│   ├── tenants.yaml          # Multi-tenant topology
│   └── rbac-conventions.yaml # Naming conventions, role assignments
├── alerting/
│   ├── routing.yaml          # Alert → team/channel/ticket mapping
│   └── escalation.yaml       # Escalation procedures
├── compliance/
│   └── requirements.yaml     # Regulatory constraints, data residency
└── discovery-log.yaml        # Agent-discovered facts (auto-updated)
```

#### Schema Design

##### `.secops/environment.yaml` — Primary Environment Descriptor

```yaml
# .secops/environment.yaml
# Customer environment knowledge for secops-squad agents
# Updated: 2026-04-30
# Source: manual + agent-discovered

schema_version: "1.0"

organization:
  name: "Contoso Corp"
  cloud: "azure-commercial"   # azure-commercial | azure-government | azure-china | azure-stack
  primary_region: "eastus2"
  data_residency: "us"        # Constrains where agents look for data

tenants:
  - id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    name: "Contoso Production"
    type: "primary"            # primary | managed | lighthouse-delegated | csp
  - id: "ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj"
    name: "Contoso Dev/Test"
    type: "secondary"

subscriptions:
  - id: "11111111-2222-3333-4444-555555555555"
    name: "SOC-Production"
    tenant: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    purpose: "sentinel, soar-playbooks"
  - id: "66666666-7777-8888-9999-000000000000"
    name: "SOC-ADX"
    tenant: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    purpose: "adx-cluster, long-term-retention"

default_workspace: "prod-sentinel"  # References .secops/workspaces/<name>.yaml
```

##### `.secops/workspaces/prod-sentinel.yaml`

```yaml
# Workspace: Production Sentinel
name: "soc-sentinel-prod"
workspace_id: "aabbccdd-1234-5678-abcd-ef0123456789"
resource_group: "rg-soc-prod"
subscription: "11111111-2222-3333-4444-555555555555"
region: "eastus2"

sentinel_enabled: true
tier: "PerGB2018"              # PerGB2018 | CapacityReservation
commitment_tier_gb: 500        # null if PerGB2018

retention:
  default_days: 90
  interactive_days: 90
  archive_days: 730

custom_tables:
  - name: "NetFlowLogs_CL"
    tier: "Basic"              # Analytics | Basic | Sentinel data lake
    daily_gb: 45
    notes: "High-volume network flow data, search-only queries"
  - name: "CustomThreatIntel_CL"
    tier: "Analytics"
    daily_gb: 0.5
    dcr_id: "dcr-xxxxxxxx"
    dce_endpoint: "https://dce-contoso.eastus2.ingest.monitor.azure.com"

data_connectors:
  - name: "Microsoft Defender for Endpoint"
    status: "connected"
    tables: ["DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents"]
  - name: "Azure Active Directory"
    status: "connected"
    tables: ["SigninLogs", "AuditLogs", "AADNonInteractiveUserSignInLogs"]
  - name: "CEF via AMA"
    status: "connected"
    tables: ["CommonSecurityLog"]
    notes: "Palo Alto, Fortinet firewalls"

naming_conventions:
  analytics_rules: "{severity}-{mitre_tactic}-{description}"
  watchlists: "wl-{purpose}-{source}"
  workbooks: "wb-{domain}-{description}"
```

##### `.secops/data-sources/data-source-map.yaml`

```yaml
# Where does each data source live?
# This is the KEY file agents consult before writing queries.

sources:
  SecurityEvent:
    location: "sentinel"
    workspace: "prod-sentinel"
    tier: "Analytics"
    daily_gb: 12
    notes: "Windows Security Events via AMA"

  SigninLogs:
    location: "sentinel"
    workspace: "prod-sentinel"
    tier: "Analytics"
    daily_gb: 3

  NetFlowLogs:
    location: "adx"
    cluster: "soc-adx-prod"
    database: "SecurityLake"
    daily_gb: 200
    notes: "Migrated from Sentinel 2025-11 for cost savings"

  AWSCloudTrail:
    location: "sentinel"
    workspace: "prod-sentinel"
    tier: "Basic"
    daily_gb: 15
    notes: "Ingested via S3 → Event Hub → DCR pipeline"

  HistoricalFirewallLogs:
    location: "adx"
    cluster: "soc-adx-prod"
    database: "Archive"
    notes: "Pre-2025 firewall data, cold storage, external table over blob"
```

##### `.secops/data-sources/migrations.yaml`

```yaml
# Active and planned data migrations
# Agents MUST check this before recommending data source changes

migrations:
  - id: "mig-001"
    status: "in-progress"       # planned | in-progress | completed | cancelled
    description: "Moving NetFlowLogs from ADX to Sentinel data lake"
    source:
      location: "adx"
      cluster: "soc-adx-prod"
      database: "SecurityLake"
      table: "NetFlowLogs"
    target:
      location: "sentinel"
      workspace: "prod-sentinel"
      table: "NetFlowLogs_CL"
      tier: "Sentinel data lake"
    started: "2026-03-15"
    estimated_completion: "2026-06-01"
    owner: "jospaid"
    notes: "Sentinel data lake now cheaper than ADX for this volume. Running parallel until validated."

  - id: "mig-002"
    status: "planned"
    description: "Consolidate dev Sentinel workspace into prod"
    source:
      location: "sentinel"
      workspace: "dev-sentinel"
    target:
      location: "sentinel"
      workspace: "prod-sentinel"
    planned_start: "2026-Q3"
    notes: "Waiting for cross-workspace RBAC improvements"
```

##### `.secops/alerting/routing.yaml`

```yaml
# Alert routing: which alerts go where?

default_channel: "teams://soc-general"
default_severity_threshold: "Medium"

routes:
  - match:
      severity: ["High", "Critical"]
      product: ["Defender for Endpoint"]
    destination:
      type: "teams"
      channel: "soc-endpoint-alerts"
      mention: "@oncall-endpoint"
    sla_minutes: 15

  - match:
      severity: ["High", "Critical"]
      product: ["Entra ID Protection"]
    destination:
      type: "teams"
      channel: "soc-identity-alerts"
      mention: "@oncall-identity"
    sla_minutes: 30

  - match:
      mitre_tactic: ["Exfiltration"]
    destination:
      type: "pagerduty"
      service_id: "PXXXXXX"
    sla_minutes: 5

  - match:
      severity: ["Informational", "Low"]
    destination:
      type: "ticket"
      system: "servicenow"
      assignment_group: "SOC-L1"
    sla_minutes: 480
```

##### `.secops/discovery-log.yaml`

```yaml
# Agent-discovered facts
# Agents append here when they find environment data during investigations
# Format: timestamped, sourced, confidence-rated

discoveries:
  - timestamp: "2026-04-30T15:05:00-05:00"
    agent: "freamon"
    confidence: "high"          # high | medium | low
    fact: "SecurityEvent table exists in workspace soc-sentinel-prod"
    source: "KQL query against workspace"
    data_source: "SecurityEvent"
    location: "sentinel"
    workspace: "prod-sentinel"

  - timestamp: "2026-04-30T15:06:00-05:00"
    agent: "kima"
    confidence: "medium"
    fact: "NetFlowLogs found in ADX cluster soc-adx-prod, database SecurityLake"
    source: "Cross-cluster query during investigation"
    data_source: "NetFlowLogs"
    location: "adx"
    cluster: "soc-adx-prod"
    database: "SecurityLake"

  - timestamp: "2026-04-30T15:07:00-05:00"
    agent: "freamon"
    confidence: "high"
    fact: "Workspace uses Basic Logs tier for NetFlowLogs_CL (confirmed via table plan query)"
    source: ".show table NetFlowLogs_CL policy"
    notes: "High volume table, search-only access is sufficient"
```

---

### How Agents Discover and Use This Knowledge

#### Discovery Flow

```
Agent receives task
    │
    ├─ 1. Check .secops/environment.yaml → know the tenant/subscription context
    ├─ 2. Check .secops/data-sources/data-source-map.yaml → know WHERE data lives
    ├─ 3. Check .secops/data-sources/migrations.yaml → know what's MOVING
    ├─ 4. Check .secops/workspaces/<name>.yaml → know workspace specifics
    │
    ├─ 5. Execute task with environment-aware decisions
    │
    └─ 6. If discovered new fact → append to .secops/discovery-log.yaml
```

#### Agent Integration Points

1. **Skill files reference `.secops/` schema** — skills include a section like:
   ```markdown
   ## Environment Context
   Before executing, check `.secops/data-sources/data-source-map.yaml` for
   the location of tables referenced in this skill.
   ```

2. **Config schema extended** — `secops-squad.config.schema.json` gets a new `environment` field pointing to the `.secops/` directory.

3. **Agent routing aware** — `.squad/routing.md` updated so agents consult `.secops/` before making data source assumptions.

---

### Auto-Discovery Scenarios

#### Scenario 1: "SecurityEvent in ADX, SigninLogs in Sentinel"

```
Freamon is running a cross-platform hunt.
1. Queries workspace for SecurityEvent → fails (table not found)
2. Queries ADX cluster from .secops/environment.yaml → finds SecurityEvent
3. Appends to .secops/discovery-log.yaml:
   - fact: "SecurityEvent in ADX cluster soc-adx-prod, not in Sentinel workspace"
   - confidence: high
4. Queries workspace for SigninLogs → succeeds
5. Appends: "SigninLogs confirmed in prod-sentinel workspace"
6. Adjusts KQL to use adx() proxy for SecurityEvent, direct query for SigninLogs
7. Flags for human review: "data-source-map.yaml may need updating"
```

**Update to data-source-map.yaml:**
```yaml
SecurityEvent:
  location: "adx"              # Changed from sentinel
  cluster: "soc-adx-prod"
  database: "SecurityLake"
  discovered_by: "freamon"
  discovered_at: "2026-04-30"
  confidence: "high"
```

#### Scenario 2: "Basic Logs tier for NetFlow data"

```
Kima is investigating a network anomaly.
1. Queries NetFlowLogs_CL with summarize/join → gets error (Basic Logs restrictions)
2. Checks .secops/workspaces/prod-sentinel.yaml → confirms Basic tier
3. Rewrites query using search-compatible operators only
4. Logs discovery: "NetFlowLogs_CL in Basic tier confirmed via query error"
5. Notes in discovery-log: "Consider moving to Sentinel data lake if search pattern sufficient"
```

#### Scenario 3: "3 workspaces in different regions"

```
Herc is deploying a new SOAR playbook.
1. Reads .secops/environment.yaml → finds 3 subscriptions
2. Discovers workspaces in eastus2, westeurope, and australiaeast
3. Creates workspace YAML files for each
4. Updates environment.yaml with multi-region topology
5. Playbook deployment targets all 3 workspaces
6. Flags: "Alert routing may need region-aware rules"
```

---

### Scenarios Jose May Have Neglected

#### 1. Multi-Tenant / MSSP Patterns

```yaml
# .secops/environment.yaml for MSSPs
organization:
  type: "mssp"
  management_tenant: "mssp-tenant-id"

managed_customers:
  - name: "Customer A"
    tenant_id: "cust-a-tenant-id"
    access_type: "lighthouse"
    delegated_subscriptions:
      - id: "sub-1"
        delegated_rg: ["rg-soc-*"]
    sentinel_workspace: "cust-a-sentinel"

  - name: "Customer B"
    tenant_id: "cust-b-tenant-id"
    access_type: "guest-account"
    notes: "B2B guest, limited to specific workspace"
```

**Impact on agents:** Every KQL query, every API call, every SOAR deployment needs to know _which tenant_ and _which access model_. Lighthouse-delegated access has different permission scoping than guest access.

#### 2. Lighthouse-Delegated Environments

**What agents need to know:**
- Which resource groups are delegated (not entire subscriptions)
- Which roles are delegated (Reader? Contributor? Sentinel Responder?)
- Limitations: can't access Entra ID in customer tenant, can't manage users
- Cross-workspace queries work differently in Lighthouse context
- SOAR playbooks need managed identity in _customer_ tenant, not MSSP tenant

**Schema addition needed:**
```yaml
lighthouse:
  delegations:
    - customer_tenant: "cust-tenant-id"
      delegated_roles:
        - "Microsoft Sentinel Contributor"
        - "Log Analytics Reader"
      delegated_scopes:
        - "/subscriptions/xxx/resourceGroups/rg-soc"
      limitations:
        - "No Entra ID access"
        - "No key vault access"
        - "Playbooks require customer-side managed identity"
```

#### 3. Air-Gapped / Government Cloud Differences

**Schema supports:** `cloud: "azure-government"` in environment.yaml.

**What changes:**
- API endpoints differ (`management.usgovcloudapi.net` vs `management.azure.com`)
- Sentinel feature availability lags commercial by 3-6 months
- Some data connectors unavailable (e.g., M365 connectors in IL5)
- MDTI API not available in government
- Copilot for Security not available in government (as of 2026)
- FedRAMP/IL4/IL5 compliance constraints on data movement

**Agent behavior:** Skills should check `cloud` field and adjust API endpoints, warn about unavailable features, and enforce compliance boundaries.

#### 4. Data Residency Constraints

```yaml
# .secops/compliance/requirements.yaml
data_residency:
  primary_region: "westeurope"
  allowed_regions: ["westeurope", "northeurope"]
  prohibited_regions: ["eastus", "eastus2", "westus"]
  reason: "GDPR - EU data must stay in EU"

  constraints:
    - "No data export to non-EU regions"
    - "ADX cluster must be in EU regions"
    - "Playbook execution must be in EU regions"
    - "Threat intel enrichment: only EU endpoints for MDTI"

regulatory_frameworks:
  - name: "GDPR"
    impact: ["data-retention", "purge-on-request", "region-lock"]
  - name: "NIS2"
    impact: ["incident-reporting-24h", "supply-chain-monitoring"]
  - name: "DORA"
    impact: ["ict-risk-management", "resilience-testing"]
```

#### 5. Cross-Cloud (Azure + AWS + GCP)

```yaml
# .secops/data-sources/data-source-map.yaml extended
sources:
  AWSCloudTrail:
    location: "sentinel"
    workspace: "prod-sentinel"
    ingestion_method: "s3-to-eventhub-to-dcr"
    source_cloud: "aws"
    aws_account: "123456789012"
    aws_region: "us-east-1"

  GCPAuditLog:
    location: "sentinel"
    workspace: "prod-sentinel"
    ingestion_method: "pub-sub-to-sentinel-connector"
    source_cloud: "gcp"
    gcp_project: "security-logging-prod"

  # Cross-cloud correlation needs
  cross_cloud_identity_mapping:
    method: "email-based"       # email-based | custom-table | none
    mapping_table: "CrossCloudIdentityMap_CL"
    notes: "Maps AWS IAM users to Entra ID UPNs for correlation"
```

**Impact:** Agents doing incident investigation need to know that a user's identity may span Azure (Entra UPN), AWS (IAM ARN), and GCP (Google identity). The mapping method matters for KQL joins.

#### 6. Custom Connector / Data Source Mapping

```yaml
# .secops/data-sources/custom-connectors.yaml
custom_connectors:
  - name: "Palo Alto Panorama"
    type: "cef-via-ama"
    log_forwarder: "syslog-vm-01.internal"
    facility: "local4"
    sentinel_table: "CommonSecurityLog"
    parser_function: "PaloAltoParser"
    notes: "Custom KQL parser deployed as workspace function"

  - name: "CrowdStrike Falcon"
    type: "rest-api-poller"
    logic_app: "la-crowdstrike-ingest"
    sentinel_table: "CrowdStrikeFalcon_CL"
    dcr_id: "dcr-crowdstrike-xxxxx"
    polling_interval: "5m"
    notes: "Custom DCR with transformation to normalize to ASIM"

  - name: "ServiceNow ITSM"
    type: "bidirectional-sync"
    logic_app: "la-snow-sync"
    direction: "both"
    sentinel_table: "ServiceNowIncidents_CL"
    notes: "Bi-directional incident sync, SOAR playbooks reference this"
```

#### 7. Retention Policy Awareness

```yaml
# .secops/compliance/retention.yaml
retention_policies:
  default:
    interactive_days: 90
    archive_days: 730
    total_days: 820

  overrides:
    - table: "SecurityEvent"
      interactive_days: 365
      archive_days: 2555       # 7 years for PCI-DSS
      reason: "PCI-DSS Requirement 10.7"

    - table: "SigninLogs"
      interactive_days: 180
      archive_days: 730
      reason: "Identity forensics need 6 months interactive"

    - table: "NetFlowLogs_CL"
      interactive_days: 30
      archive_days: 90
      tier: "Basic"
      reason: "High volume, short retention sufficient"

  # Agents MUST check retention before writing queries spanning long time ranges
  # A query over 365 days on SecurityEvent will work interactively
  # A query over 365 days on NetFlowLogs_CL requires archive restore
  agent_guidance:
    - "Check retention before timespan > 90 days"
    - "Archive restore takes 1-5 minutes, factor into investigation time"
    - "Basic tier tables cannot use join/summarize — use search instead"
    - "ADX tables have unlimited retention but different query syntax via adx() proxy"
```

---

### Implementation Roadmap

#### Phase 1: Foundation (Now → Next Sprint)
1. Create `.secops/` directory structure with empty templates
2. Add `environment.yaml` schema to `secops-squad.config.schema.json`
3. Create `skills/customer-knowledge/environment-setup.md` teaching agents the framework
4. Add `.secops/` to `.gitignore` by default (environment-specific data)
5. Provide `secops-squad env init` CLI command to scaffold `.secops/`

#### Phase 2: Agent Integration (Sprint +1)
1. Update routing to check `.secops/` before query execution
2. Implement discovery-log append in agent workflows
3. Build `secops-squad env discover` command to auto-populate from live workspace
4. Add validation for `.secops/` YAML files

#### Phase 3: Auto-Discovery (Sprint +2)
1. Agent-driven discovery during normal operations
2. Conflict detection (discovery-log vs. data-source-map mismatch)
3. Human review workflow for discovered facts
4. Periodic re-validation of stored knowledge

---

### File Format Decision: YAML

**Why YAML over JSON:**
- Human-readable and editable (SOC engineers will hand-edit these)
- Supports comments (critical for documenting "why")
- Multi-line strings for notes
- Anchors/aliases for DRY patterns (e.g., shared tenant IDs)

**Why YAML over Markdown:**
- Machine-parseable (agents need to query this programmatically)
- Schema-validatable
- Structured data with reliable field access
- Markdown is for skills/docs, YAML is for configuration/knowledge

**Why not both?**
- `environment.yaml` is the source of truth
- A generated `environment-summary.md` could be created for human reference
- But the YAML is what agents read

---

## Appendix: Config Schema Extension

Add to `secops-squad.config.schema.json`:

```json
"environment": {
  "type": "object",
  "description": "Customer environment knowledge directory",
  "properties": {
    "path": {
      "type": "string",
      "default": ".secops",
      "description": "Path to environment knowledge directory"
    },
    "autoDiscover": {
      "type": "boolean",
      "default": true,
      "description": "Allow agents to auto-discover and log environment facts"
    },
    "requireReview": {
      "type": "boolean",
      "default": true,
      "description": "Require human review before promoting discovered facts to data-source-map"
    }
  }
}
```
