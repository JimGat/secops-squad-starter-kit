# SecOps Squad — Tool-Agnostic Architecture

## What Changed

SecOps Squad was originally built for Microsoft Sentinel + GitHub Copilot CLI.
This fork makes it **tool-agnostic**: the same agent team, skills, and personas
work regardless of which SIEM, SOAR, or agent runtime your SOC runs.

### Three abstractions make this work:

1. **Intents** — Universal SOC actions (hunt, detect, triage, respond) defined
   in `toolkit/intents/`. Each intent is SIEM-agnostic — it describes WHAT to do,
   not HOW to do it.

2. **Adapters** — Platform-specific implementations in `toolkit/adapters/`.
   Each adapter (sentinel, splunk, elastic, qradar) maps intents to concrete
   query languages (KQL, SPL, EQL, AQL) and API patterns.

3. **Runtime** — The agent framework that runs the team. Originally Copilot CLI;
   now also supports Hermes Agent via `toolkit/adapters/hermes/`.

## Quick Start (Tool-Agnostic)

### 1. Configure your stack

Edit `.secops/environment.yaml`:

```yaml
toolkit:
  primary_adapter: splunk    # YOUR SIEM: sentinel, splunk, elastic, qradar
  query_language: SPL         # YOUR QUERY LANGUAGE
  soar_platform: splunk-soar  # YOUR SOAR: sentinel-playbooks, splunk-soar, elastic-case

siem:
  platform: splunk            # sentinel, splunk, elastic, qradar, other
  instances:
    - name: primary
      adapter: splunk
      workspace: "prod-splunk"
```

### 2. Run with your preferred agent runtime

**Hermes Agent:**
```bash
cd /your/secops-project
hermes -s secops-squad
```

**GitHub Copilot CLI (original):**
```bash
cd /your/secops-project
copilot --agent secops-squad --yolo
```

### 3. Use intents instead of product names

Instead of: "Write a KQL query for brute-force detection"
Say: "Detect brute-force attacks" (intent: `detect.brute-force`)

The adapter resolves the intent to the right query language and skill file
automatically based on your `.secops/environment.yaml` configuration.

## Supported Adapters

| Adapter | SIEM | Query Language | SOAR Platform | Status |
|---|---|---|---|---|
| `sentinel` | Microsoft Sentinel | KQL | Sentinel Playbooks | Stable (original) |
| `splunk` | Splunk Enterprise/Cloud | SPL | Splunk SOAR | New (this fork) |
| `elastic` | Elastic Security | EQL/KQL | Elastic Case Management | Planned |
| `qradar` | IBM QRadar | AQL | QRadar SOAR | Planned |
| `generic` | Any | N/A (technique-only) | N/A | Available |

## Supported Runtimes

| Runtime | Status | How to Use |
|---|---|---|
| GitHub Copilot CLI | Stable (original) | `copilot --agent secops-squad` |
| Hermes Agent | New (this fork) | `hermes -s secops-squad` |
| Claude Code | Planned | Via Claude Code skill |
| OpenAI Codex | Planned | Via Codex skill |

## Directory Structure (New Additions)

```
toolkit/
  intents/                    # Universal SOC intent definitions
    identity/                 # Authentication, identity, RBAC
      hunt-suspicious-signins.yaml
      detect-brute-force.yaml
      detect-credential-stuffing.yaml
      respond-compromised-account.yaml
    endpoint/                 # EDR, process, file, registry
      hunt-lateral-movement.yaml
      detect-process-injection.yaml
      respond-malware-containment.yaml
  adapters/                   # Platform-specific implementations
    sentinel/                 # Original (KQL + ARM API)
      adapter.yaml
      skills/
    splunk/                   # NEW (SPL + REST API)
      adapter.yaml
      skills/
        hunt-suspicious-signins.md
        detect-brute-force.md
        respond-compromised-account.md
    elastic/                  # Planned
    qradar/                   # Planned
    generic/                  # Technique-only (no query language)
    hermes/                   # NEW (runtime adapter)
      RUNTIME_ADAPTER.md
  SECOPS_SCHEMA_V2.md         # Updated .secops/ schema (multi-SIEM)
  README.md                   # This file
```

## How Adapter Resolution Works

```
Agent receives task: "Hunt for suspicious sign-ins"
    │
    ▼
Agent reads intent: hunt.suspicious-signins
    │
    ▼
Check .secops/environment.yaml → toolkit.primary_adapter = splunk
    │
    ▼
Load toolkit/adapters/splunk/adapter.yaml
    │
    ▼
Resolve intent_map → hunt.suspicious-signins → adapters/splunk/skills/hunt-suspicious-signins.md
    │
    ▼
Agent loads the Splunk skill file with SPL query templates
    │
    ▼
Agent executes hunt using Splunk-appropriate queries and API patterns
```

## Adding a New Adapter

1. Create `toolkit/adapters/{name}/adapter.yaml` with your SIEM details
2. Map intents to your query language in the `intent_map` section
3. Create skill files in `toolkit/adapters/{name}/skills/` for each intent
4. Add the adapter to `.secops/environment.yaml` `toolkit.primary_adapter`
5. Test by running a hunt or detection intent through the new adapter

See `toolkit/adapters/splunk/` as a reference implementation.

## Migration Path (From Sentinel-Only)

The migration is **additive** — nothing breaks:

1. **Phase 1 (Done):** Toolkit abstraction layer + Splunk adapter + Hermes runtime
2. **Phase 2:** Elastic and QRadar adapters
3. **Phase 3:** Refactor core skills to reference intents; existing KQL skills become the `sentinel` adapter
4. **Phase 4:** Update all personas to use `skills.v3.json` format with `adapter_overrides`
5. **Phase 5:** CLI support for `secops-squad toolkit list/adapters/intents`

At every phase, the Sentinel adapter continues to work exactly as before.
The original skills ARE the Sentinel adapter.
