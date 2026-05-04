# SecOps Squad Starter Kit — Architecture Guide

> **Version:** 1.0 | **Last Updated:** 2026-05-04 | **Audience:** SecOps engineers, platform architects

---

## 1. Overview

The **SecOps Squad Starter Kit** is an AI-assisted security operations framework built on GitHub Copilot CLI. It turns conversational AI into a full SOC team — KQL hunting, SOAR automation, detection engineering, threat modeling, and cross-cloud security operations — all through natural language.

**Who it's for:**

| Role | Value |
|------|-------|
| **SOC Analysts** | Triage, investigate, and respond to incidents with AI-guided KQL and SOAR |
| **Detection Engineers** | Author MITRE-mapped detection rules with lifecycle management |
| **Threat Hunters** | Hypothesis-driven hunts across Sentinel, Defender XDR, and ADX |
| **Security Architects** | Multi-tenant, cross-cloud, and compliance-aware platform design |
| **MSSPs** | Scalable multi-customer security operations via Lighthouse |

**Design principles:**

1. **Skills as knowledge, not code** — Markdown files with YAML frontmatter, framework-agnostic
2. **Environment-aware** — `.secops/` framework provides customer context to every agent decision
3. **No heavy dependencies** — Only `js-yaml` in production; portable to restricted environments
4. **Read-first, write-never** — Agents read from your Sentinel workspace but never write unless explicitly told to

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     User / GitHub Copilot CLI                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                 CLI Layer  (cli/index.js)                        │
│   init │ doctor │ env │ skill │ persona │ workspace │ kql       │
└─────────────────────────────────────────────────────────────────┘
                              │
           ┌──────────────────┼──────────────────┐
           ▼                  ▼                  ▼
     ┌───────────┐     ┌───────────┐     ┌────────────────┐
     │ Personas  │     │  Skills   │     │   .secops/     │
     │ (6 roles) │     │ (90+ docs)│     │  Environment   │
     └───────────┘     └───────────┘     │  Knowledge     │
                                         └────────────────┘
           │                │                    │
           └────────────────┼────────────────────┘
                            ▼
          ┌──────────────────────────────────┐
          │       Agent Team (.squad/)       │
          │  McNulty · Kima · Freamon · Herc │
          │  Each agent has assigned skills  │
          └──────────────────────────────────┘
                            │
           ┌────────────────┼────────────────┐
           ▼                ▼                ▼
     ┌──────────┐    ┌──────────┐    ┌──────────────┐
     │   KQL    │    │   SOAR   │    │  Detection   │
     │ Queries  │    │ Playbooks│    │  Patterns    │
     └──────────┘    └──────────┘    └──────────────┘
           │                │                │
           └────────────────┼────────────────┘
                            ▼
          ┌──────────────────────────────────┐
          │   Microsoft Security Products    │
          │ Sentinel│Defender│Graph│ADX│Entra │
          └──────────────────────────────────┘
```

---

## 3. Skills Architecture

Skills are **markdown knowledge documents** that teach AI agents how to perform specific SecOps tasks. They are not executable code — they are reference material that agents consume and apply.

### 3.1 Skill File Structure

Every skill is a `.md` file with YAML frontmatter:

```yaml
---
title: Threat Hunting Foundations
category: kql
difficulty: beginner          # beginner | intermediate | advanced
author: Freamon
version: 1.0.0
last_updated: 2026-05-04
mitre_attack:                 # MITRE ATT&CK technique IDs
  - T1059.001
  - T1078
products:                     # Microsoft products covered
  - Microsoft Sentinel
  - Microsoft Defender XDR
---
```

The markdown body contains:
- **Overview** — What the skill teaches and when to use it
- **Environment Context** — Which `.secops/` files to consult first
- **Step-by-step procedures** — KQL queries, PowerShell scripts, API calls
- **Real-world examples** — Copy-paste-ready, not theoretical
- **Cross-references** — Links to related skills

### 3.2 Agent Routing

Agents receive skills through a two-layer assignment:

1. **Shared skills** — Every agent on the team gets these (core KQL, environment context)
2. **Per-agent skills** — Role-specific skills assigned to individual agents

The `personas/<persona>/skills.json` file controls this:

```json
{
  "persona": "soc-analyst",
  "version": "2.0.0",
  "skills": {
    "shared": [
      { "path": "kql/query-builder.md" },
      { "path": "kql/incident-investigation.md" }
    ],
    "per_agent": {
      "freamon": [
        { "path": "kql/threat-hunting-foundations.md" }
      ],
      "herc": [
        { "path": "soar/phishing-response.md" }
      ]
    }
  }
}
```

---

## 4. Domain Map

The starter kit organizes knowledge across **10 skill domains** and **3 platform layers**:

```
┌─────────────────────────────────────────────────────────────┐
│                    SKILL DOMAINS (90+ skills)                │
├──────────────┬──────────────┬───────────────┬───────────────┤
│  kql (11)    │ detection(9) │ soar (12)     │ adx (8)       │
│  • Hunting   │ • Rules      │ • Playbooks   │ • Clusters    │
│  • UEBA      │ • Lifecycle  │ • Enrichment  │ • Ingestion   │
│  • Analytics │ • MITRE      │ • Triage      │ • ML/Anomaly  │
├──────────────┼──────────────┼───────────────┼───────────────┤
│log-analytics │msft-security │ orchestration │ platform (3)  │
│   (10)       │   (16)       │    (4)        │ • Multi-tenant│
│  • RBAC      │ • Defender   │ • Workflows   │ • Cross-cloud │
│  • Retention │ • Purview    │ • MSSP        │ • Gov cloud   │
│  • DCR/DCE   │ • Sentinel   │ • Copilot     │               │
├──────────────┼──────────────┼───────────────┴───────────────┤
│ powershell   │ testing (2)  │                               │
│   (15)       │ • Integ.     │  Templates: Bicep, KQL,       │
│  • Modules   │   tests      │  Threat Models (10 tactics)   │
│  • API wraps │              │                               │
└──────────────┴──────────────┴───────────────────────────────┘
```

### Domain Relationships

```
                    ┌──────────────────┐
                    │   orchestration  │ ← Composes all domains
                    └────────┬─────────┘
                             │
          ┌──────────┬───────┼───────┬──────────┐
          ▼          ▼       ▼       ▼          ▼
     ┌────────┐ ┌────────┐ ┌────┐ ┌──────┐ ┌────────┐
     │  kql   │ │  soar  │ │ ps │ │ msft │ │  det   │
     └───┬────┘ └───┬────┘ └──┬─┘ └──┬───┘ └───┬────┘
         │          │         │      │          │
         ▼          ▼         ▼      ▼          ▼
     ┌────────────────────────────────────────────────┐
     │      log-analytics / adx  (data layer)         │
     └────────────────────────────────────────────────┘
         │                                        │
         ▼                                        ▼
     ┌────────────┐                        ┌────────────┐
     │  platform  │                        │  testing   │
     │ (infra)    │                        │ (quality)  │
     └────────────┘                        └────────────┘
```

---

## 5. `.secops/` Customer Knowledge Framework

The `.secops/` directory is the **single source of truth** for the customer's environment. Every agent reads it before performing operations.

### 5.1 Directory Structure

```
.secops/
├── environment.yaml            # Root config: org, tenants, subscriptions
├── discovery-log.yaml          # Append-only agent discovery log
├── workspaces/
│   └── <name>.yaml             # One file per Log Analytics workspace
├── data-sources/
│   ├── data-source-map.yaml    # Table → location mapping (THE key file)
│   └── migrations.yaml         # Active/planned data migrations
├── identity/
│   ├── tenants.yaml            # Multi-tenant topology
│   └── rbac-conventions.yaml   # RBAC role patterns
├── alerting/
│   ├── routing.yaml            # Alert routing rules (first-match)
│   └── escalation.yaml         # Escalation procedures
└── compliance/
    └── requirements.yaml       # Data residency, regulatory constraints
```

All files use `schema_version: "1.0"` for forward compatibility.

### 5.2 Discovery Flow

Agents discover environment facts during operations and follow this flow:

```
┌──────────┐    ┌──────────────┐    ┌──────────────┐    ┌───────────────┐
│  Agent   │───►│  Check       │───►│  Fact not     │───►│  Append to    │
│ operates │    │ .secops/     │    │  found?       │    │ discovery-    │
│          │    │ data-source- │    │  Query live   │    │ log.yaml      │
│          │    │ map.yaml     │    │  environment  │    │ (append-only) │
└──────────┘    └──────────────┘    └──────────────┘    └───────┬───────┘
                                                                │
                                                                ▼
                                                        ┌───────────────┐
                                                        │ Human reviews │
                                                        │ → promotes to │
                                                        │ authoritative │
                                                        │ YAML file     │
                                                        └───────────────┘
```

Each discovery entry includes: `timestamp`, `agent`, `confidence` (high/medium/low), `fact`, `source`, and optional structured fields (`data_source`, `location`, `workspace`, `tier`).

### 5.3 Auto-Discovery Pattern

When an agent encounters an unknown table:

1. Check `data-source-map.yaml` — if found, use mapped location
2. If not found, query the default workspace
3. If found, append to `discovery-log.yaml` with `confidence: high`
4. Human reviews and promotes to `data-source-map.yaml`
5. If not found anywhere, append with `confidence: low` and suggest investigation

See [SECOPS_SCHEMA.md](SECOPS_SCHEMA.md) for complete field-level documentation.

---

## 6. API Integration Layer

### 6.1 REST-First Approach

All Azure/Microsoft API integrations follow a consistent pattern:

```
┌──────────────┐     ┌───────────────┐     ┌──────────────────┐
│ PowerShell   │────►│  Auth Layer   │────►│  Microsoft API   │
│ Wrapper      │     │  (MSAL/Az)    │     │  (Graph, ARM,    │
│ Module       │     │               │     │   Sentinel REST) │
└──────────────┘     └───────────────┘     └──────────────────┘
```

Key libraries in `lib/`:
- **graph-security/** — Alerts, incidents, threat intel, secure score
- **kql-validator/** — Offline KQL syntax validation
- **mitre-mapping/** — MITRE ATT&CK technique resolution

### 6.2 PowerShell Wrappers

The `skills/powershell/` domain provides 15 module patterns:
- `auth-patterns.md` — MSAL, certificate, managed identity auth
- `sentinel-api-wrapper.md` — Sentinel REST API operations
- `defender-api-wrapper.md` — Defender XDR API operations
- `rate-limiting.md` — Token bucket, retry-after, exponential backoff
- `error-handling.md` — Structured error handling across all modules

### 6.3 MCP Servers

Model Context Protocol servers extend agent capabilities:

```json
// .copilot/mcp-config.json
{
  "mcpServers": {
    "sentinel": { "command": "npx", "args": ["sentinel-mcp-server"] },
    "defender": { "command": "npx", "args": ["defender-mcp-server"] }
  }
}
```

Skills `msft-security/sentinel-mcp-server.md` and `msft-security/defender-mcp-server.md` document configuration and usage patterns.

---

## 7. Multi-Tenant Architecture

### 7.1 Tenant Topology

Defined in `.secops/environment.yaml` and `.secops/identity/tenants.yaml`:

| Tenant Type | Access Model | Use Case |
|-------------|-------------|----------|
| `primary` | Full admin | Main organizational tenant |
| `secondary` | Full admin | Dev/test, subsidiary, M&A |
| `managed` | Full admin (delegated) | MSSP-managed customer |
| `lighthouse-delegated` | Scoped roles | Azure Lighthouse |
| `csp` | Partner relationship | Cloud Solution Provider |

### 7.2 MSSP Patterns

For `org_type: "mssp"` in `environment.yaml`:

```
┌──────────────────────────────────┐
│      Managing Tenant (MSSP)      │
│  ┌────────┐  ┌───────────────┐   │
│  │ SOC    │  │ Lighthouse    │   │
│  │ Team   │  │ Delegations   │   │
│  └────────┘  └──────┬────────┘   │
└─────────────────────┼────────────┘
                      │ Scoped access
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │Customer A│  │Customer B│  │Customer C│
  │ Sentinel │  │ Sentinel │  │ Sentinel │
  │ Defender │  │ Defender │  │ Defender │
  └──────────┘  └──────────┘  └──────────┘
```

**Isolation rules:**
- Every API call carries explicit tenant context
- Data never crosses tenant boundaries unless aggregated in the managing tenant
- Separate auth token per tenant
- Lighthouse delegations define scoped roles and resource groups

### 7.3 Lighthouse Integration

Configured in `.secops/environment.yaml` under `lighthouse.delegations[]`:

```yaml
lighthouse:
  delegations:
    - customer_tenant: "cust-tenant-id"
      customer_name: "Customer A"
      delegated_roles:
        - "Microsoft Sentinel Contributor"
        - "Log Analytics Reader"
      delegated_scopes:
        - "/subscriptions/xxx/resourceGroups/rg-soc"
      limitations:
        - "No Entra ID access in customer tenant"
        - "Playbooks require customer-side managed identity"
```

---

## 8. Cross-Cloud Integration

### 8.1 Supported Connectors

| Cloud | Data Source | Connector Type | Sentinel Table |
|-------|-----------|---------------|---------------|
| **AWS** | CloudTrail | S3 → Event Hub → DCR | `AWSCloudTrail` |
| **AWS** | GuardDuty | CCP (native) | `AWSGuardDuty` |
| **AWS** | VPC Flow Logs | S3 → Event Hub | `AWSVPCFlow_CL` |
| **GCP** | Cloud Audit | Pub/Sub → DCR | `GCPAuditLogs_CL` |
| **GCP** | Security Command Center | REST API | `GCPSCC_CL` |

### 8.2 ASIM Normalization

Cross-cloud correlation uses [ASIM](https://learn.microsoft.com/azure/sentinel/normalization) (Advanced Security Information Model) parsers to normalize disparate log formats:

```
AWS CloudTrail ──┐
Azure SigninLogs ─┤──► ASIM Authentication Parser ──► Unified query
GCP Audit Logs ──┘
```

### 8.3 Multi-SIEM Migration

The `skills/platform/cross-cloud-connectors.md` skill covers migration from:
- **Splunk** → Sentinel (SPL to KQL translation, data onboarding)
- **QRadar** → Sentinel (LEEF/CEF to ASIM mapping)
- **Elastic** → Sentinel (ECS to ASIM normalization)

Migration state is tracked in `.secops/data-sources/migrations.yaml`.

---

## 9. Persona System

### 9.1 How Personas Work

A persona is a **curated skill set and team composition** for a specific SOC role:

```
personas/
└── soc-analyst/
    ├── README.md         # Persona overview
    ├── skills.json       # Shared + per-agent skill assignments
    ├── team.md           # Agent roster and expertise
    ├── routing.md        # How work is distributed
    └── ceremonies.md     # Team rituals (standup, retro, etc.)
```

### 9.2 Available Personas

| Persona | Focus | Core Domains |
|---------|-------|-------------|
| **soc-analyst** | Triage, investigation, response | kql, soar, msft-security |
| **detection-engineering** | Rule authoring, MITRE mapping | detection, kql, testing |
| **threat-hunting** | Proactive hunting, hypothesis-driven | kql, adx, detection |
| **cloud-security** | Cloud posture, Defender for Cloud | msft-security, platform |
| **incident-response** | IR procedures, forensics, containment | soar, kql, powershell |
| **full-soc** | All skills combined | All domains |

### 9.3 Persona Composition

When a persona is selected during `secops init`:

1. `personas/<name>/skills.json` is read
2. Shared skills are loaded for all agents
3. Per-agent skills are assigned to specific team members
4. `.squad/team.md` and `.squad/routing.md` are configured
5. Agent charters in `.squad/agents/<name>/charter.md` define expertise

---

## 10. Orchestration Patterns

The `skills/orchestration/` domain defines **5 workflow patterns** for composing multi-skill operations:

### Pattern 1: Sequential Pipeline

Linear chain of steps, each feeding the next:

```
[Sentinel Alert] → [KQL Enrichment] → [Defender Lookup] → [SOAR Response]
```

**Use case:** Incident auto-triage, phishing response, compromised account containment.

### Pattern 2: Fan-Out / Fan-In

Parallel execution with result aggregation:

```
                ┌─► [Sentinel Query]    ─┐
[Trigger] ──────┼─► [Defender Query]    ─┼──► [Aggregate] → [Report]
                └─► [Graph API Query]   ─┘
```

**Use case:** Cross-product investigation, multi-workspace hunting.

### Pattern 3: Event-Driven

Reactive workflows triggered by external events:

```
[Webhook/Alert] → [Evaluate Routing Rules] → [Dispatch to Handler]
```

**Use case:** Real-time alert routing, SLA enforcement, escalation.

### Pattern 4: Saga (Long-Running with Compensation)

Multi-step operations with rollback on failure:

```
[Start] → [Step 1 ✓] → [Step 2 ✓] → [Step 3 ✗] → [Compensate 2] → [Compensate 1]
```

**Use case:** Multi-tenant deployments, data migrations, compliance exports.

### Pattern 5: Human-in-the-Loop

Automated analysis with human decision gates:

```
[Auto-Analysis] → [Present Findings] → [Human Decision] → [Execute Action]
```

**Use case:** Threat hunting review, detection rule approval, IR escalation.

### Cross-Skill Coordination

All orchestration patterns require:

1. **Load `.secops/` context** — Environment, data sources, compliance constraints
2. **Check `data-source-map.yaml`** — Know where each table lives before querying
3. **Respect `compliance/requirements.yaml`** — Data residency, retention rules
4. **Follow `alerting/routing.yaml`** — Route outputs to correct channels
5. **Log to `discovery-log.yaml`** — Record any new environment facts found

---

## 11. Validation and Quality

| Layer | Tool | What It Checks |
|-------|------|---------------|
| **KQL Syntax** | `lib/kql-validator/` | Offline syntax validation, no Azure required |
| **Config Schema** | `secops-squad.config.schema.json` | Customer configuration validity |
| **`.secops/` Files** | `cli/commands/env.js` | YAML structure, required fields |
| **Detection Lifecycle** | `skills/detection/detection-lifecycle.md` | Phase 1-4 quality gates |
| **Threat Models** | `templates/threat-models/` | Review gate before rule deployment |

Run locally:

```bash
npm test              # KQL validator + Graph Security client tests
npm run lint          # ESLint on cli/ and lib/
npm run validate:kql  # KQL validation on skill markdown blocks
```

---

## 12. File Structure Reference

```
secops-squad-starter-kit/
├── cli/                    # CLI commands (init, doctor, env, etc.)
├── lib/                    # Libraries (kql-validator, graph-security, mitre-mapping)
├── skills/                 # 90+ markdown knowledge packs across 10 domains
├── personas/               # 6 pre-built team compositions
├── .secops/                # Customer environment knowledge (template)
├── .squad/                 # Agent team configuration (instance)
├── .copilot/               # MCP server configuration
├── templates/              # Bicep, KQL, and threat model templates
├── samples/                # Example configurations (secops-contoso)
├── docs/                   # Project documentation
├── package.json            # Node.js project metadata
└── secops-squad.config.schema.json  # Configuration validation schema
```

---

## Related Documentation

- [Getting Started](getting-started.md) — Installation and first hunt
- [Integration Guide](INTEGRATION.md) — Connect to real environments
- [`.secops/` Schema Reference](SECOPS_SCHEMA.md) — Complete field-level docs
- [Skills Catalog](skills-catalog.md) — Full inventory with MITRE mappings
- [Personas Guide](personas-guide.md) — All 6 personas in detail
- [Platform Coverage](platform-coverage-gap-analysis.md) — Gap analysis and resolution
