# Workspaces

Per-workspace configuration files for Log Analytics workspaces and ADX clusters.

## Schema

Each workspace file is a standalone YAML document describing one workspace or cluster. File naming convention: `<workspace-short-name>.yaml` (e.g., `prod-sentinel.yaml`, `dev-sentinel.yaml`, `soc-adx.yaml`).

The `default_workspace` field in `environment.yaml` references the filename (without `.yaml`) of the primary workspace.

## Key Fields

| Field | Description |
|-------|-------------|
| `name` | Azure resource name of the workspace |
| `workspace_id` | Log Analytics workspace GUID |
| `sentinel_enabled` | Whether Microsoft Sentinel is enabled |
| `tier` | Pricing tier (PerGB2018, CapacityReservation) |
| `retention` | Default, interactive, and archive retention days |
| `custom_tables[]` | Tables with non-default tiers (Basic, Auxiliary) |
| `data_connectors[]` | Connected data sources and their status |
| `naming_conventions` | Patterns for analytics rules, watchlists, etc. |

## Usage by Agents

- **Before querying:** Check `custom_tables[]` for tier restrictions (Basic tier = no join/summarize)
- **Before deploying:** Check `region` for compliance with data residency
- **Before creating rules:** Follow `naming_conventions` patterns

See `example-workspace.yaml` for the full schema with comments.
