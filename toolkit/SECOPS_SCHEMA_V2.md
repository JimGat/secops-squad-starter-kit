# .secops/ Environment Configuration (Tool-Agnostic)

## Overview

The `.secops/` directory tells agents **where** they are operating — which
SIEM, SOAR, identity provider, and data sources exist in your specific SOC
environment. It is tool-agnostic: the same schema works whether you run
Sentinel, Splunk, Elastic, QRadar, or any combination.

## Schema Reference

### environment.yaml

```yaml
# Organization identity
organization:
  name: "Example Corp"
  industry: "technology"           # technology, finance, healthcare, government, etc.
  size: "enterprise"               # small, medium, enterprise
  regions: ["us-east", "us-west"]  # Data residency regions

# Toolkit configuration (NEW - tool-agnostic abstraction)
toolkit:
  primary_adapter: sentinel        # Which SIEM adapter to use by default
  secondary_adapter: null          # Fallback / parallel SIEM
  query_language: KQL              # Primary query language
  soar_platform: sentinel-playbooks # SOAR/automation platform
  siem_version: null               # SIEM version for API compatibility
  # Supported adapters: sentinel, splunk, elastic, qradar, generic

# SIEM configuration
siem:
  platform: sentinel               # sentinel, splunk, elastic, qradar, other
  version: null                    # Platform version
  instances:                       # Multiple SIEM deployments if applicable
    - name: primary
      adapter: sentinel
      workspace: "prod-sentinel"
      retention_days: 90
    - name: archive
      adapter: adx
      workspace: "long-term"
      retention_days: 365

# Identity providers
identity:
  primary: entra_id                # entra_id, okta, ping, onelogin, adfs, other
  secondary: null
  mfa_enforced: true
  conditional_access: true
  providers:
    - name: entra_id
      type: cloud
      domains: ["example.com"]
      features: [identity_protection, conditional_access, pim]

# Data sources (tool-agnostic classification)
data_sources:
  - name: authentication
    sourcetypes: [azure:aad:signin, wineventlog:security]
    tables: [SigninLogs, SecurityEvent]
    retention_days: 30
    daily_volume_gb: 5
  - name: endpoint
    sourcetypes: [sysmon, microsoft:defender:endpoint]
    tables: [DeviceEvents, DeviceProcessEvents]
    retention_days: 90
    daily_volume_gb: 50
  - name: cloud_audit
    sourcetypes: [azure:activity, aws:cloudtrail, gcp:audit]
    tables: [AzureActivity, AWSCloudTrail]
    retention_days: 90
    daily_volume_gb: 2
  - name: network
    sourcetypes: [cisco:asa, paloalto:firewall, zeek]
    tables: [CommonSecurityLog, NetworkEvents]
    retention_days: 30
    daily_volume_gb: 100
  - name: email
    sourcetypes: [o365:management:activity, microsoft:defender:email]
    tables: [EmailEvents, EmailUrlInfo]
    retention_days: 30
    daily_volume_gb: 1

# SOAR / Automation
automation:
  platform: sentinel-playbooks     # sentinel-playbooks, splunk-soar, elastic-case, swimlane, other
  playbooks_path: null             # Path to local playbook definitions
  auto_remediate: false            # Enable automatic remediation without human approval
  approval_required_for:          # Actions that always require human approval
    - account_disable
    - endpoint_isolate
    - data_purge

# Compliance boundaries
compliance:
  frameworks: [NIST-800-53, PCI-DSS]  # NIST, PCI-DSS, SOC2, GDPR, HIPAA, etc.
  data_residency: us                 # us, eu, apac, global
  retention_minimum_days: 365

# Notification channels
alerting:
  channels:
    - type: teams
      webhook: null                   # Set at deploy time
    - type: email
      distribution_list: "soc@example.com"
    - type: slack
      webhook: null

# Discovery log (agent-populated, gitignored)
discovery_log: .secops/discovery-log.yaml
```

## Migration from Microsoft-Only .secops/

The original `.secops/` schema assumed Azure/Microsoft everywhere. Key changes:

| Original Field | New Field | Change |
|---|---|---|
| `tenant_id` | `identity.providers[].domains` | Now supports non-Azure IdP |
| `subscription_id` | `siem.instances[]` | Supports multiple SIEM deployments |
| `workspace_id` | `siem.instances[].workspace` | Instance-scoped, not global |
| (implicit KQL) | `toolkit.query_language` | Explicit query language declaration |
| (implicit Sentinel) | `toolkit.primary_adapter` | Explicit adapter selection |
| (Azure-only data sources) | `data_sources[].sourcetypes` | Maps to Splunk sourcetypes, ES indices, etc. |

## Adapter Resolution

When an agent reads `.secops/environment.yaml`:

1. Check `toolkit.primary_adapter` to determine which adapter to load
2. Load `toolkit/adapters/{primary_adapter}/adapter.yaml`
3. When a skill references an intent, resolve via the adapter's `intent_map`
4. If no mapping exists, fall back to `generic` adapter skills
5. If `toolkit.secondary_adapter` is set, also load its adapter for cross-SIEM queries
