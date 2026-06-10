---
schema_version: "1.0.0"
description: |
  Tool-agnostic abstraction layer for SecOps Squad.
  Each "intent" describes WHAT a SOC analyst does (hunt, detect, triage, enrich, respond).
  Each "adapter" maps that intent to a concrete tool implementation (Sentinel/KQL, Splunk/SPL, Elastic/EQL, etc.).
  Skills reference intents instead of hard-coding product-specific logic.
---

# Toolkit Abstraction Layer

## Core Concept

SecOps workflows are the same regardless of which SIEM or SOAR platform you run:
- **Hunt** -- query logs for suspicious patterns
- **Detect** -- write rules that fire alerts
- **Enrich** -- add context to IOCs and entities
- **Triage** -- assess alert severity and scope
- **Respond** -- take containment/remediation action
- **Report** -- document findings and hand off

The **toolkit** layer separates these universal SOC intents from the
tool-specific implementations. A skill says "hunt for suspicious sign-ins"
and the adapter translates that into KQL, SPL, EQL, or Lucene depending on
what SIEM the SOC actually runs.

## Intent Schema

Each intent is a YAML/JSON document:

```yaml
intent: hunt.suspicious-signins          # unique dot-notation ID
domain: identity                          # detection, identity, endpoint, cloud, network, data
description: >
  Hunt for suspicious authentication activity including impossible travel,
  unfamiliar properties, brute-force patterns, and credential stuffing.
mitre_attack:
  - T1110      # Brute Force
  - T1110.001  # Password Guessing
  - T1110.003  # Password Spraying
  - T1078      # Valid Accounts
required_data:
  - authentication_logs
  - identity_provider_events
outputs:
  - suspicious_signin_events
  - risk_scored_entities
references:
  - skill: skills/kql/entra-signin-analysis.md
    adapter: sentinel
  - skill: community/threat-hunting/detecting-privilege-escalation-attempts.md
    adapter: generic
```

## Adapter Schema

Each adapter declares which SIEM/SOAR platform it targets and maps intents
to concrete implementations:

```yaml
adapter: sentinel
display_name: Microsoft Sentinel
query_language: KQL
soar_platform: Sentinel Playbooks / Logic Apps
api_style: REST (Azure Resource Manager)
products:
  - Microsoft Sentinel
  - Microsoft Defender XDR
  - Microsoft Entra ID
  - Azure Monitor / Log Analytics
intent_map:
  hunt.suspicious-signins:
    skill: skills/kql/entra-signin-analysis.md
    query_template: |
      SigninLogs
      | where TimeGenerated > ago({lookback})
      | where ResultType != 0
      | summarize ...
  detect.brute-force:
    skill: skills/detection/nrt-rule-pattern.md
    query_template: |
      let threshold = {threshold};
      SigninLogs
      | where TimeGenerated > ago(5m)
      | where ResultType == 50126
      | summarize ...
```

```yaml
adapter: splunk
display_name: Splunk Enterprise / Splunk Cloud
query_language: SPL
soar_platform: Splunk SOAR (Phantom)
api_style: REST (Splunk REST API)
products:
  - Splunk Enterprise
  - Splunk Cloud
  - Splunk SOAR
intent_map:
  hunt.suspicious-signins:
    skill: adapters/splunk/skills/hunt-suspicious-signins.md
    query_template: |
      index=azureAD sourcetype=azure:aad:signin
      (status!=0 OR riskState="atRisk")
      | stats count as failures by user, src_ip, app
      | where failures > {threshold}
  detect.brute-force:
    skill: adapters/splunk/skills/detect-brute-force.md
    query_template: |
      index=auth action=failure
      | bucket _time span=5m
      | stats count as failures by src_ip, user
      | where failures > {threshold}
```

## Directory Structure

```
toolkit/
  intents/                    # Universal SOC intent definitions
    identity/                 #   Authentication, identity, RBAC
      hunt-suspicious-signins.yaml
      detect-brute-force.yaml
      detect-credential-stuffing.yaml
      respond-compromised-account.yaml
    endpoint/                 #   EDR, process, file, registry
      hunt-lateral-movement.yaml
      detect-process-injection.yaml
      respond-malware-containment.yaml
    cloud/                    #   Cloud posture, IAM, compute
      detect-cloud-misconfig.yaml
      hunt-privilege-escalation.yaml
    network/                  #   NetFlow, proxy, DNS, firewall
      hunt-beaconing.yaml
      detect-dns-tunneling.yaml
    data/                     #   DLP, exfiltration, data handling
      detect-data-exfiltration.yaml
    detection/                #   Rule authoring, tuning, lifecycle
      author-nrt-rule.yaml
      tune-false-positives.yaml
  adapters/                   # Platform-specific implementations
    sentinel/                 #   Microsoft Sentinel (KQL + ARM API)
      adapter.yaml            #     Adapter metadata + intent map
      skills/                 #     Sentinel-specific skill overrides
    splunk/                   #   Splunk Enterprise/Cloud (SPL + REST)
      adapter.yaml
      skills/
    elastic/                  #   Elastic Security (EQL/KQL + ES API)
      adapter.yaml
      skills/
    qradar/                   #   IBM QRadar (AQL + QRadar API)
      adapter.yaml
      skills/
    generic/                  #   Product-agnostic technique skills
      adapter.yaml            #     Maps to community/ skills
  schema/                     # JSON/YAML schemas for validation
    intent.schema.yaml
    adapter.schema.yaml
```

## How Skills Use the Toolkit

Skills reference intents instead of hard-coding product queries:

```markdown
## Detection Logic

This skill implements intent `detect.brute-force`.

| Adapter | Implementation |
|---------|---------------|
| Sentinel (KQL) | `skills/kql/entra-signin-analysis.md` |
| Splunk (SPL) | `adapters/splunk/skills/detect-brute-force.md` |
| Elastic (EQL) | `adapters/elastic/skills/detect-brute-force.md` |
| Generic | `community/threat-hunting/detecting-privilege-escalation-attempts.md` |

Agent routing: when the SOC environment configures `adapter: splunk`,
the coordinator loads the Splunk adapter's intent map and resolves
skill references accordingly.
```

## Environment Configuration (.secops/)

The `.secops/` framework now includes a `toolkit` section:

```yaml
# .secops/environment.yaml
toolkit:
  primary_adapter: splunk        # Which adapter to use by default
  secondary_adapter: sentinel    # Fallback / parallel SIEM
  query_language: SPL            # Primary query language
  soar_platform: splunk-soar     # SOAR/automation platform
  siem_version: "9.2"            # SIEM version for API compatibility
```

This replaces the previous Azure-only assumptions. When an agent reads
`.secops/environment.yaml`, it knows which adapter to load and therefore
which skill implementations and query templates to use.

## Migration Path

Existing Microsoft-locked skills remain functional. The migration is additive:

1. **Phase 1** -- Create toolkit/ directory with intent definitions and
   Splunk adapter (this proves the pattern works end-to-end)
2. **Phase 2** -- Add Elastic and QRadar adapters
3. **Phase 3** -- Refactor core skills to reference intents instead of
   hard-coded KQL; existing KQL skills become the `sentinel` adapter
4. **Phase 4** -- Update personas and routing to use toolkit resolution
5. **Phase 5** -- Update CLI to support `secops-squad toolkit list/adapters`

At no point does Phase N break Phase N-1. The Sentinel adapter always
works because the original skills ARE the Sentinel adapter.
