# Work Routing

How cloud security work routes across the team, by domain and request type.

## Domain-Based Routing

| Domain | Route To | Action |
|--------|----------|--------|
| Policy creation / assignment | Stringer (Policy Analyst) | Design policy, map to compliance requirement, test in audit mode, assign |
| Policy exemption request | Stringer (Policy Analyst) | Assess exemption justification, document risk acceptance, configure exemption |
| Posture assessment | D'Angelo (Posture Reviewer) | Run CSPM assessment, analyze Secure Score, identify and prioritize findings |
| Misconfiguration finding | D'Angelo (Posture Reviewer) | Investigate finding, assess risk, create remediation ticket for Avon |
| Remediation execution | Avon (Cloud Security Engineer) | Implement fix, verify remediation, update posture status |
| Defender for Cloud configuration | Avon (Cloud Security Engineer) | Enable/configure Defender plans, set up integrations, manage alert rules |
| Workspace RBAC change | Avon (Cloud Security Engineer) | Review access request, implement RBAC change, verify least-privilege |
| Diagnostic settings | Avon (Cloud Security Engineer) | Configure log collection, verify data flowing to workspace, troubleshoot gaps |
| Compliance report | Stringer (Policy Analyst) + D'Angelo (Posture Reviewer) | Generate compliance report, map findings to framework controls, document gaps |

## Workflow Routing

```
D'Angelo (assess) → Stringer (policy check) → Avon (remediate) → D'Angelo (verify)
```

| Stage | Owner | Gate |
|-------|-------|------|
| Assessment | D'Angelo | CSPM scan completed, findings prioritized by risk |
| Policy alignment | Stringer | Finding mapped to policy, compliance impact assessed |
| Remediation | Avon | Fix implemented, change documented, no new violations introduced |
| Verification | D'Angelo | Post-remediation scan confirms finding resolved, Secure Score updated |

## Escalation Path

| From | To | When |
|------|----|------|
| D'Angelo → Stringer | Finding requires new policy or policy gap identified |
| D'Angelo → Avon | High-risk misconfiguration needs immediate remediation |
| Stringer → Avon | Policy violation requires technical remediation |
| Avon → SOC (soc-analyst persona) | Remediation uncovers active exploitation — route to incident response |

## API & Tool Routing

| Operation | Skill / Tool | Agent |
|-----------|-------------|-------|
| Defender XDR incident management | `defender-api-wrapper` (PowerShell) | Avon |
| MDE machine actions (isolate, scan, Live Response) | `defender-api-wrapper` (PowerShell) | Avon |
| Advanced Hunting query execution | `advanced-hunting-api` | Avon |
| Agent-driven Defender operations | `defender-mcp-server` (MCP) | Avon |
| Copilot for Security promptbooks | `copilot-for-security` | Avon, D'Angelo |
| Defender for Cloud Apps policy management | `defender-cloud-apps` | Stringer |
| OAuth app governance and audit | `defender-cloud-apps` | Stringer |
| Permission review and app registration | `defender-api-permissions` | Avon |
| Secure Score and compliance APIs | `defender-api-wrapper` (PowerShell) | D'Angelo |

### Tool Selection Priority

1. **MCP-first** — agents use `defender-mcp-server` for interactive Defender operations
2. **PowerShell wrappers** — pipelines and automation use `defender-api-wrapper` for bulk operations and machine actions
3. **Copilot for Security** — use for incident summarization, TI enrichment, and guided investigation
4. **REST direct** — fallback when MCP unavailable; consult `defender-api-permissions` for required scopes

## Rules

1. **D'Angelo assesses first** — no remediation without a prioritized finding and risk assessment.
2. **Stringer owns the policy layer** — all policy changes, exemptions, and compliance mapping go through Stringer.
3. **Avon fixes, D'Angelo verifies** — remediation and verification are separate roles. No self-verified fixes.
4. **Exemptions require documentation** — every policy exemption has a documented justification and expiration date.
5. **Defender for Cloud changes go through Avon** — plan enablement, alert configuration, and integration changes are Avon's domain.
6. **Active exploitation escalates** — if posture review or remediation uncovers active threat activity, route to SOC immediately.
7. **Compliance reports need both** — Stringer provides the framework mapping, D'Angelo provides the posture data.
8. **MCP for agents, PowerShell for pipelines** — interactive agent work uses MCP; CI/CD and bulk operations use PowerShell wrappers.
9. **Least-privilege by default** — consult `defender-api-permissions` before creating app registrations; use tiered app strategy.
10. **MDCA changes go through Stringer** — Cloud App policy, OAuth governance, and session control changes are Stringer's domain.
