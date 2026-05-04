# cli/ — CLI Reference

The `secops-squad` command-line interface. Main entry point for all operations.

## Files

| File | Purpose |
|------|---------|
| `index.js` | Command router, banner, help |
| `secops-config.js` | `.secops/` YAML parser — `loadEnvironment()`, `listWorkspaces()`, `loadDataSourceMap()`, `validateAll()` |
| `secops-init.js` | Interactive `.secops/` directory scaffolding |
| `commands/init.js` | Project initialization with persona selection |
| `commands/doctor.js` | Environment health check |
| `commands/env.js` | Show/validate `.secops/` configuration |
| `commands/persona.js` | Switch or inspect active persona |
| `commands/skill.js` | List and add skills |
| `commands/kql-validate.js` | KQL syntax validation |
| `commands/playbook.js` | SOAR playbook deployment |
| `commands/plugin.js` | Plugin management |

## Usage

```bash
secops-squad <command> [options]
```

## Commands

| Command | Description | Status |
|---------|-------------|--------|
| `init` | Set up a new secops-squad project | ✅ Implemented |
| `init --secops` | Scaffold `.secops/` directory interactively | ✅ Implemented |
| `doctor` | Check environment prerequisites | ✅ Implemented |
| `env [validate\|workspaces\|data-sources]` | Show/validate `.secops/` config | ✅ Implemented |
| `skill [list\|add <name>]` | List and add skills | ✅ Implemented |
| `persona [list\|switch <name>]` | Switch or inspect persona | ✅ Implemented |
| `kql validate <file\|glob>` | KQL syntax validation | ✅ Implemented |
| `playbook [list\|deploy <name>]` | SOAR playbook management | ✅ Implemented |
| `plugin [install\|list\|remove]` | Plugin management | ✅ Implemented |
| `workspace [connect\|status\|disconnect]` | Sentinel workspace connection | 🔜 Planned |
| `status` | Show current config, persona, skills | 🔜 Planned |

## Global Flags

| Flag | Description |
|------|-------------|
| `--help` | Show help for any command |
| `--version` | Show version |

## Related

- [lib/README.md](../lib/README.md) — Shared libraries used by the CLI
- [lib/kql-validator/](../lib/kql-validator/) — KQL validation engine
- [lib/plugins/](../lib/plugins/) — Plugin system
