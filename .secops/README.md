# `.secops/` — Customer Environment Knowledge Framework

> **Schema Version:** 1.0 | **Framework:** secops-squad | **Status:** Template

## What Is This?

`.secops/` is the customer-specific environment knowledge directory for secops-squad agents. While skills teach agents **how** to do things, `.secops/` tells them **where** — which tenants, workspaces, data sources, and policies exist in a specific environment.

**Without `.secops/`:** Agents guess where data lives, assume single-tenant, and can't respect compliance boundaries.

**With `.secops/`:** Agents know that `SecurityEvent` is in ADX (not Sentinel), that the customer is GDPR-bound to EU regions, and that `NetFlowLogs` is mid-migration.

## Directory Structure

```
.secops/
├── README.md                     # This file
├── environment.yaml              # Primary environment descriptor
├── workspaces/
│   ├── README.md                 # Workspace schema docs
│   └── example-workspace.yaml    # Example workspace config
├── data-sources/
│   ├── README.md                 # Data source mapping docs
│   ├── data-source-map.yaml      # What data lives where
│   └── migrations.yaml           # Active/planned data migrations
├── identity/
│   ├── README.md                 # Identity/tenant topology docs
│   ├── tenants.yaml              # Multi-tenant topology
│   └── rbac-conventions.yaml     # Naming conventions, role assignments
├── alerting/
│   ├── README.md                 # Alert routing docs
│   ├── routing.yaml              # Alert → team/channel/ticket mapping
│   └── escalation.yaml           # Escalation procedures
├── compliance/
│   ├── README.md                 # Compliance docs
│   └── requirements.yaml         # Regulatory constraints, data residency
└── discovery-log.yaml            # Agent-discovered facts
```

## How Agents Use This (Discovery Flow)

```
Agent receives task
    │
    ├─ 1. Read .secops/environment.yaml        → tenant/subscription context
    ├─ 2. Read .secops/data-sources/data-source-map.yaml → WHERE data lives
    ├─ 3. Read .secops/data-sources/migrations.yaml      → what's MOVING
    ├─ 4. Read .secops/workspaces/<name>.yaml   → workspace specifics
    ├─ 5. Read .secops/compliance/requirements.yaml      → constraints
    │
    ├─ 6. Execute task with environment-aware decisions
    │
    └─ 7. If discovered new fact → append to .secops/discovery-log.yaml
```

**Key rule:** Agents MUST check `data-source-map.yaml` before writing any KQL query that references a table. The table may not be where they assume.

## Schema Version & Compatibility

- **Current version:** `1.0`
- All YAML files include a `schema_version` field
- Schema changes follow semver: minor versions add optional fields, major versions may break consumers
- Unknown fields MUST be preserved (not rejected) — this allows forward-compatible extensions
- Agents should check `schema_version` and warn (not fail) on unknown versions

## Initializing for a New Environment

### Option 1: Manual Setup
1. Copy the template files from this directory
2. Replace `Contoso Corp` example values with your environment data
3. Start with `environment.yaml` — it's the root of all references
4. Add workspace files as you discover/document them
5. Leave `discovery-log.yaml` empty — agents populate it

### Option 2: CLI Scaffolding (Future)
```bash
secops-squad env init          # Interactive setup wizard
secops-squad env discover      # Auto-populate from live Azure workspace
secops-squad env validate      # Validate all .secops/ YAML files
```

## The Auto-Discovery Pattern

Agents discover environment facts during normal operations. The flow is:

1. **Agent discovers** a fact (e.g., finds a table in ADX during a hunt)
2. **Agent appends** to `discovery-log.yaml` with timestamp, confidence, and source
3. **Human reviews** discovery-log entries periodically
4. **Human promotes** confirmed facts to the authoritative YAML files (e.g., `data-source-map.yaml`)

This pattern ensures:
- Agents never silently assume — they log what they find
- Humans remain in control of authoritative environment data
- Knowledge accumulates over time without manual auditing

## Subdirectory Reference

| Directory | Purpose | Key File |
|-----------|---------|----------|
| `workspaces/` | Per-workspace configuration (Sentinel, ADX) | One YAML per workspace |
| `data-sources/` | Where data lives, what's migrating | `data-source-map.yaml` |
| `identity/` | Tenant topology, RBAC patterns | `tenants.yaml` |
| `alerting/` | Alert routing and escalation | `routing.yaml` |
| `compliance/` | Regulatory and residency constraints | `requirements.yaml` |

## Notes

- **This directory should be `.gitignored`** — it contains environment-specific data, not framework code. Template files live in the repo; populated files do not.
- **Every file is standalone** — agents can use any single file without the others existing. Missing files mean "unknown," not "error."
- **YAML is the format** — human-editable, supports comments, machine-parseable. See the gap analysis for the rationale.
- **Extensibility** — add custom YAML files to any subdirectory. Agents will ignore files they don't recognize, and unknown fields in known files are preserved.
