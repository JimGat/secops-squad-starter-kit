# Alerting

Alert routing rules and escalation procedures. Defines how alerts flow from detection to human response.

## Files

| File | Purpose |
|------|---------|
| `routing.yaml` | Alert → team/channel/ticket routing rules with SLA |
| `escalation.yaml` | Escalation tiers, timeouts, and contact information |

## How Routing Works

Alerts are matched against `routing.yaml` rules in order. The first matching rule determines the destination. Rules can match on:
- **Severity:** Informational, Low, Medium, High, Critical
- **Product:** Defender for Endpoint, Entra ID Protection, etc.
- **MITRE Tactic:** Exfiltration, Lateral Movement, etc.
- **Custom tags:** Any key-value pair

If no rule matches, the alert goes to `default_channel` with `default_severity_threshold` applied.

## Agent Behavior

- **SOAR playbooks:** Reference `routing.yaml` to determine notification channels
- **Detection rules:** Check `routing.yaml` to understand SLA expectations for the severity level
- **Escalation:** Reference `escalation.yaml` for timeout-based escalation paths
