# Data Sources

Maps data tables to their physical locations across Sentinel workspaces, ADX clusters, and external systems. This is the **most critical directory** for agent operations — agents consult `data-source-map.yaml` before writing any query.

## Files

| File | Purpose |
|------|---------|
| `data-source-map.yaml` | Where each data table lives (Sentinel, ADX, external) |
| `migrations.yaml` | Active and planned data migrations between platforms |

## Why This Matters

An agent writing a KQL query for `SecurityEvent` needs to know:
- Is it in Sentinel or ADX?
- What workspace/cluster/database?
- What tier (Analytics, Basic, Auxiliary)?
- Is it currently being migrated?

Without this mapping, agents assume everything is in Sentinel, which breaks in real environments.

## Agent Behavior

1. **Before any query:** Check `data-source-map.yaml` for the table's location
2. **Before recommending changes:** Check `migrations.yaml` for in-flight migrations
3. **When a table is missing:** Query live workspace, then append finding to `discovery-log.yaml`
4. **Cross-cloud data:** Check `source_cloud` field for AWS/GCP origin context

## Discovery Fields

Entries may include `discovered_by`, `discovered_at`, and `confidence` fields when populated by agent auto-discovery. These mark entries that haven't been human-verified yet.
