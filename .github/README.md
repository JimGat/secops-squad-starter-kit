# .github/ — GitHub Repository Configuration

Agent definitions, CI/CD workflows, policies, and automation for the secops-squad repository.

## Directory Structure

```
.github/
├── agents/                      — GitHub Copilot agent definitions
│   ├── secops-squad.agent.md    — Security-specialized coordinator
│   └── squad.agent.md           — General-purpose coordinator
├── workflows/                   — GitHub Actions CI/CD
│   ├── kql-validate.yml         — KQL syntax validation on PRs
│   ├── squad-heartbeat.yml      — Squad health monitoring
│   ├── squad-issue-assign.yml   — Auto-assign issues via squad: labels
│   ├── squad-triage.yml         — Automatic issue triage
│   └── sync-squad-labels.yml    — Sync squad member labels
├── ISSUE_TEMPLATE/              — Issue templates (bug reports, feature requests)
├── acl/                         — Access control lists
├── compliance/                  — Compliance policies and checks
└── policies/                    — Repository policies
```

## Agent Definitions

Both agents use the Squad SDK v0.9.4 coordinator pattern:

| Agent | File | Use Case |
|-------|------|----------|
| SecOps Squad | `secops-squad.agent.md` | Security-specialized — detection, response, hunting, SOAR |
| Squad | `squad.agent.md` | General-purpose — framework development, docs, tooling |

## Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `kql-validate.yml` | PR | Validates KQL syntax using `lib/kql-validator/` |
| `squad-heartbeat.yml` | Schedule | Monitors squad health and activity |
| `squad-issue-assign.yml` | Issue labeled | Routes issues to agents based on `squad:{name}` labels |
| `squad-triage.yml` | Issue opened | Auto-triages new issues |
| `sync-squad-labels.yml` | Manual/schedule | Syncs squad member labels |

## Related

- [`.copilot/`](../.copilot/) — Copilot CLI configuration and skills
- [`.squad/`](../.squad/) — Squad runtime state and agent configuration
