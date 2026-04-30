# History

<!-- Populated automatically during squad sessions. -->

## Learnings

<!-- Append new learnings below. Each entry is something lasting about the project. -->

### 2026-04-30: Platform Coverage Gap Analysis

- **52 skills across 6 domains** is the current inventory. Good breadth but significant depth gaps.
- **Biggest blind spot: PowerShell modules.** Zero dedicated PS skills despite SOC engineers being PS-first. `Az.SecurityInsights` and `Az.OperationalInsights` are the most critical gaps.
- **Sentinel MCP integration is the game-changer.** Without it, agents write KQL but can't execute it. Azure MCP Server exists; we need a skill for configuring and using it.
- **Unified Data Platform (Basic/Auxiliary/Summary Rules)** is where Microsoft is pushing Sentinel. Our data tiering coverage is fragmented across cost-optimization and retention-archive. Needs a dedicated skill.
- **16 critical gaps, 25 important, 15 nice-to-have** identified across 12 Microsoft platform areas.
- **4 new skill domains proposed:** `powershell/`, `mcp/`, `azure-monitor/`, `entra-id/` — all critical.
- **Customer Knowledge Framework:** Proposed `.secops/` directory structure with YAML files for environment-specific knowledge (workspaces, data sources, migrations, routing, compliance). YAML chosen over JSON/markdown for human-editability + machine-parseability.
- **Key design decision:** `.secops/` is gitignored by default (environment-specific data) and separate from `.squad/` (framework internals). Agents consult `.secops/data-sources/data-source-map.yaml` before writing queries.
- **Auto-discovery pattern:** Agents append to `.secops/discovery-log.yaml` when they find environment facts. Human review required before promoting to data-source-map.
- **Scenarios customers neglect:** Multi-tenant MSSP, Lighthouse delegation limitations, government cloud feature gaps, cross-cloud identity mapping, retention-aware queries, data residency constraints.
- **Key file:** `docs/platform-coverage-gap-analysis.md` — full analysis document.
