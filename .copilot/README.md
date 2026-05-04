# .copilot/ — GitHub Copilot CLI Configuration

Configures GitHub Copilot CLI behavior and agent skills for this repository.

## Directory Structure

```
.copilot/
├── mcp-config.json                    — MCP server configuration
└── skills/                            — Copilot agent skill modules (9 skills)
    ├── secops-environment-context.md  — .secops/ discovery and usage patterns
    ├── agent-collaboration/           — Multi-agent handoff and coordination
    ├── error-recovery/                — Error handling and recovery strategies
    ├── git-workflow/                  — Git branching, commit, and PR conventions
    ├── reviewer-protocol/             — Code review gates and approval workflows
    ├── secret-handling/               — Secret detection and safe handling
    ├── session-recovery/              — Session state recovery after interruptions
    ├── squad-conventions/             — Squad naming, file, and communication conventions
    └── test-discipline/               — Testing standards and quality gates
```

## Skills

| Skill | Purpose |
|-------|---------|
| `secops-environment-context.md` | **Most important** — teaches agents to read `.secops/` before any environment-aware task |
| `agent-collaboration/` | How agents hand off work and coordinate across specializations |
| `error-recovery/` | Strategies for handling and recovering from errors |
| `git-workflow/` | Branching, commit message, and PR conventions |
| `reviewer-protocol/` | Code review gates and approval workflows |
| `secret-handling/` | Detecting secrets and handling them safely |
| `session-recovery/` | Recovering session state after interruptions |
| `squad-conventions/` | Squad naming, file structure, and communication patterns |
| `test-discipline/` | Testing standards and quality gates |

> These are **operational** skills (how agents work). Security detection and response skills live in the top-level `skills/` directory.

## MCP Configuration

`mcp-config.json` configures [Model Context Protocol](https://modelcontextprotocol.io/) server integration. Currently contains a GitHub MCP server entry.

## Related

- [`.github/agents/`](../.github/agents/) — Agent definition files that reference these skills
- [`skills/`](../skills/) — Security-domain skill modules (detection, response, hunting, etc.)
