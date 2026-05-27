

# Squad Decisions

## Active Decisions

### 2026-05-08T16:09:41.073-05:00: Workspace Connect — Azure Auto-Discovery



**By:** Sydnor (Platform Dev)



**Status:** Implemented



**What:** Rewrote `cli/commands/workspace.js` `connect()` to auto-discover Microsoft Sentinel workspaces from Azure instead of manually prompting for workspace name, resource group, and subscription ID.



**New flow:**

1. Verify `az` CLI installed, auto-run `az login` if not authenticated (uses `stdio: 'inherit'` for browser flow)

2. List enabled subscriptions, present numbered picker if multiple

3. Discover all Log Analytics workspaces via `az monitor log-analytics workspace list`

4. Check Sentinel on each workspace via `az rest` against `SecurityInsights({name})` solution endpoint

5. Present Sentinel-enabled workspaces (or all workspaces if none have Sentinel) as numbered list

6. Write `.secops/workspaces/<name>.yaml` with auto-populated fields matching schema v1.0

7. Update `.secops/environment.yaml` default_workspace



**Key design choices:**

- `execAz()` helper with configurable timeout (30s default, 120s for login), `inherit` stdio, and `allowFail` options — replaces single-purpose `execSafe()`

- Resource group parsed from ARM resource ID regex, not from a separate API call

- Sentinel detection via `Microsoft.OperationsManagement/solutions` REST API (simpler than querying alert rules)

- Graceful fallback: if no Sentinel workspaces found, show all LA workspaces with warning



**Impact:**

- All agents: `workspace connect` now produces richer YAML (includes `workspace_id`, `region`, `sentinel_enabled`, `tier`)

- Kima/Freamon: Can rely on `sentinel_enabled: true` in workspace config for conditional logic

- Users: Zero manual typing of GUIDs or resource group names



# Decision: GitHub CLI promoted to required dependency

**Date:** 2026-05-08T16:21:48.253-05:00
**By:** Sydnor (Platform Dev)
**Status:** Accepted

## What

GitHub CLI (`gh`) is now a **required** dependency in `install.ps1`, upgraded from optional. The install script will auto-install it via `winget install GitHub.cli` if missing.

Additionally, the GitHub Copilot CLI extension (`gh extension install github/gh-copilot`) is now installed as part of the bootstrap.

## Why

- `gh` is required for squad issue mode (Ralph's issue routing, label-based work assignment).
- The `copilot --agent secops-squad` launch command depends on the `gh-copilot` extension.
- The primary workflow (`copilot --agent secops-squad`) cannot function without both `gh` and the copilot extension.

## Impact

- **All agents:** The `copilot` command is now the documented entry point. References to `node cli/index.js` are removed from README.
- **Users:** Fresh installs get `gh` and `gh-copilot` automatically. Users still need to run `gh auth login` manually (cannot be automated in a non-interactive script).
- **install.ps1:** Fails if `gh` cannot be installed (same as Git and Node.js).

# Decision: gh CLI and az CLI are optional — connected during agent session

**Date:** 2026-05-08T16:41:19.514-05:00
**By:** Sydnor (Platform Dev)
**Status:** Implemented

## What

GitHub CLI (`gh`) and Azure CLI (`az`) are no longer install-time prerequisites for secops-squad.
They are optional tools that users connect interactively during a Copilot session when they first need them.

## Why

Most users don't have `gh` or `az` configured before starting. Requiring them upfront creates friction
and failed installs for users who just want to try the tool. The agent can guide interactive auth
far more gracefully than a shell script can.

## Changes

- `install.ps1`: `gh` demoted from required (`$true`) to optional (`$false`). `Ensure-GhCopilotExtension` removed entirely.
- `install.sh`: no change needed (gh was already optional).
- `README.md`: prerequisites table updated; `--yolo` promoted as primary launch command.
- `cli/commands/doctor.js`: `checkCopilotCli()` added as required check; gh/az remain optional warnings.

## Impact

- **All agents:** Users may not have `gh` or `az` connected on first run — agents should check and offer to help connect them.
- **McNulty:** Issue mode requires gh; should detect and prompt before attempting gh operations.
- **Herc/Kima:** Azure operations require az login; should detect and prompt before az calls.

# Decision: First-Run Onboarding Skill Design

**Date:** 2026-05-08T16:48:55-05:00
**By:** Kima (SecOps Engineer)
**Status:** Implemented

## What

Created `.copilot/skills/first-run-onboarding/SKILL.md` — a copilot-level skill that teaches the agent to proactively detect first-run state and guide new users through environment setup.

## Key Design Choices

1. **Progressive disclosure over prerequisite dumps.** The skill guides one step at a time: Azure CLI → Workspace discovery → .secops/ init → GitHub CLI (optional). No walls of text listing everything the user needs.

2. **Detection-first, not prompt-first.** The agent runs 5 silent checks at session start (`.secops/` exists, `az account show`, workspace count, `gh auth status`, template defaults) and uses a decision matrix to determine which step to start at. Users don't need to ask for help.

3. **Re-entry without restart.** When a user returns to a partially-configured environment, the agent picks up at the first incomplete step. Token-expired sessions get a targeted `az login`, not a full re-onboarding.

4. **Azure before GitHub.** Azure is required for all security work; GitHub is optional for PR workflows. The skill enforces this ordering and frames GitHub as "one more optional step."

5. **Delegates deep setup.** Basic onboarding gets users to one working Sentinel workspace. Product-by-product connectivity (Defender XDR, MDI, MDE, etc.) is deferred to `skills/msft-security/connectivity-setup.md`. No duplication.

6. **Leverages existing CLI.** The skill references `secops-squad workspace connect` (Sydnor's auto-discovery flow) and `secops-squad init --secops` rather than reimplementing workspace discovery. Falls back to manual guidance if CLI commands fail.

## Impact

- **All agents:** Should check first-run signals at session start. If signals detected, invoke this skill before doing security work.
- **Sydnor:** The skill depends on `workspace connect` and `init --secops` CLI commands — changes to those commands should update this skill.
- **Freamon/Herc:** Can assume `.secops/` exists after onboarding. No need to add their own first-run detection.
- **Users:** New users get guided setup instead of "run these 5 commands first."

### 2026-05-13T07:58:33-05:00: User directive

**By:** John Spaid (via Copilot)
**Status:** Accepted

**What:** Ground all agent personas on modern SecOps approaches. Specifically: use "Sentinel data lake" instead of "Auxiliary Logs" or "Aux Logs." ADX should only be recommended when there's a justifiable requirement. The modern default for long-term/low-cost data retention in Sentinel is the Sentinel data lake, not Aux Logs, not standalone ADX. All charters, skills, docs, and templates should reflect current Microsoft SecOps terminology and patterns.

**Why:** User request — captured for team memory

### 2026-05-13: Sentinel Data Lake Terminology Modernization

**Date:** 2026-05-13
**Author:** Freamon (KQL Engineer)
**Status:** Accepted

**Context:** Microsoft rebranded "Auxiliary Logs" to **Sentinel data lake** as the modern low-cost retention tier in Microsoft Sentinel. The secops-squad-starter-kit skills documentation used the legacy "Auxiliary Logs" terminology and positioned Azure Data Explorer (ADX) as the default recommendation for long-term retention.

**Decision:**
1. **Replace "Auxiliary Logs"/"Aux Logs" with "Sentinel data lake"** in all skills prose and documentation.
2. **Keep `'Auxiliary'` in PowerShell `ValidateSet` parameters and API calls** — this is the Azure Log Analytics Tables API parameter value. Annotate with `# Auxiliary = Sentinel data lake` comments.
3. **Reposition ADX as a specialized option**, not the default for long-term retention. Sentinel data lake is the modern default for most organizations.
4. **Standard data tiering order:** Analytics → Basic → Sentinel data lake → Archive.
5. **Standardize pricing at ~$0.75/GB ingestion** for the Sentinel data lake tier.

**Scope:** 14 files updated across log-analytics, adx, kql, platform, and powershell skill domains.

**Impact:** All squad members creating or updating skills that reference data tiers, retention strategies, or ADX migration should use "Sentinel data lake" in prose and follow the API-vs-product naming convention established here.

### 2026-05-13T07:58:33-05:00: Modern SecOps Terminology Standards

**By:** Kima (SecOps Engineer)
**Status:** Accepted

**What:** Standardized terminology across all `skills/msft-security/` and `skills/detection/` files to reflect Microsoft's modern SecOps platform:
1. **"Sentinel data lake"** is the modern low-cost retention tier (replaces "Basic Logs" / "Auxiliary Logs" as the primary term in tiering discussions). "Basic Logs" remains valid as a Log Analytics concept but Sentinel-facing docs should lead with "Sentinel data lake."
2. **Unified SOC platform** at security.microsoft.com — Sentinel + Defender XDR share a single portal experience. References to "the Sentinel portal" now acknowledge this unified option.
3. **ADX repositioned** — Azure Data Explorer is a specialized option (custom ML, cross-org federation, massive scale). Sentinel data lake is the default for long-term retention within Sentinel.
4. **Content Hub** — Portal references updated to use Content Hub as the modern deployment path for Sentinel solutions.
5. **Summary rules** — Added as a modern cost-optimization pattern (aggregate Sentinel data lake tables into compact Analytics-tier tables).

**Why:** John directed that all content reflect modern Microsoft SecOps approaches. The platform has evolved significantly — the unified SOC portal, Sentinel data lake tier, and summary rules are all GA features that should be the default guidance.

**Impact:**
- **All agents:** When referencing Sentinel portal, include the unified SOC platform at security.microsoft.com. When discussing data tiers, lead with Sentinel data lake as the modern low-cost tier.
- **Freamon:** PowerShell scripts referencing Sentinel should note the unified portal URL.
- **log-analytics skills:** Already correctly reference both "Basic Logs" and "Sentinel data lake" — no changes needed there.
- **Future skills:** Should follow these terminology standards from the start.

### 2026-05-13T07:58:33-05:00: Technology Grounding Sections in All Agent Charters

**By:** McNulty (Lead)
**Status:** Implemented

**What:** Added a `## Technology Grounding` section to all 6 agent charters (McNulty, Kima, Freamon, Herc, Sydnor, Carver) with agent-specific guidance on modern Microsoft Sentinel and SecOps patterns. Updated `team.md` project context to reflect the modern platform.

**Why:** An agent used "Aux Logs" and "ADX" as default long-term retention guidance. The modern (2025-2026) approach is **Sentinel data lake** — a low-cost, long-term retention tier within Sentinel itself. ADX remains valid but is an advanced option, not the default. The unified SOC platform (security.microsoft.com) is now the converged operational surface.

**Key Terminology Changes:**
- "Aux Logs" / "Auxiliary Logs" → **Sentinel data lake**
- ADX → advanced option requiring justification (custom ML, cross-org federation, existing investments)
- Standalone Sentinel portal → **unified SOC platform** (security.microsoft.com)

**Impact:**
- **All agents:** Must use modern terminology and default to Sentinel data lake for long-term retention guidance.
- **McNulty:** Reviews PRs for modern pattern compliance — rejects "Aux Logs" references and unjustified ADX usage.
- **Kima:** References Content Hub, unified SOC platform, Microsoft Security Exposure Management.
- **Freamon:** Aware of query differences across Analytics/Basic/Sentinel data lake tiers; uses Summary Rules for aggregation.
- **Herc:** Targets unified SOC platform APIs; playbooks query Sentinel data lake, not ADX, by default.
- **Sydnor:** IaC templates provision Sentinel data lake tables by default, ADX as optional add-on.
- **Carver:** Validates queries target correct data tier; flags tier mismatches in test coverage.

**Convention:** When the platform evolves again, apply the same pattern: update all charters' Technology Grounding sections, not just the one that triggered the issue.

### 2026-05-27T09:06:17.460-05:00: Skill Relevance Analysis — Anthropic-Cybersecurity-Skills

**By:** Kima (SecOps Engineer)
**Status:** Proposed

**What:** Comprehensive analysis of 754 external skills from mukul975/Anthropic-Cybersecurity-Skills across 26 domains. Categorized domains as HIGH (8 domains, 311 skills), MEDIUM (11 domains, 225 skills), and LOW (7 domains, 177 skills) relevance. Identified ~74–102 likely duplicates with our existing 92 curated skills.

**Key Framework Findings:**
- **MITRE ATT&CK:** HIGH — adopt for expanded technique coverage
- **D3FEND:** HIGH — fills our defensive vocabulary gap (we have no D3FEND coverage)
- **NIST CSF:** HIGH — maps to our IR lifecycle
- **ATLAS:** MEDIUM — selective import for AI/ML-assisted workflows
- **AI RMF:** LOW — governance-level, not actionable for SOC operations

**Recommended Import Priority:** HIGH domains first (Threat Hunting, Threat Intelligence) → D3FEND vocabulary → NIST CSF alignment → ATLAS for targeted AI workflows.

**Impact:**
- **All agents:** Community skill imports will bring structured hypothesis frameworks, MISP integration patterns, cloud forensics procedures, SOC metrics frameworks, PAM patterns, and D3FEND defensive countermeasure vocabulary.
- **McNulty:** Use this analysis to guide deduplication review and feature gate decisions.
- **Carver:** Validate D3FEND mapping skill for coverage completeness; vet Threat Hunting skills for KQL accuracy before import.
- **Freamon:** KQL accuracy review for Threat Hunting domain skills.

### 2026-05-27T09:06:17.460-05:00: External Skill Assimilation Strategy — Anthropic-Cybersecurity-Skills

**By:** McNulty (Lead)
**Status:** Proposed — Awaiting team adoption

**What:** Defined comprehensive strategy for importing ~390 skills from 14 Microsoft-adjacent domains of mukul975/Anthropic-Cybersecurity-Skills. Created hybrid frontmatter schema preserving framework metadata (NIST CSF, MITRE ATT&CK, CIS Controls, etc.). Established `skills/community/` directory structure, deduplication rules, and vendor-at-commit maintenance model.

**Key Decisions:**
1. **Scope:** Import 14 curated domains (~390 skills); skip 12 red-team/adversary/non-Microsoft domains (~364 skills)
2. **Format:** Hybrid frontmatter extending our current schema with `mitre_attack`, `nist_csf`, `nist_800_53`, `cis_controls`, `author`, `source_repo`, `license` fields
3. **Directory:** New `skills/community/` isolation; curated skills remain unchanged and take precedence
4. **Deduplication:** Add `superseded_by:` references to community skills overlapping curated content; never delete
5. **Attribution:** Preserve `author:` fields (Apache-2.0 requirement); create `skills/community/NOTICE.md` with source commit SHA
6. **Maintenance:** Vendor (copy in) at pinned commit; periodic sync script, not submodule

**Recommended Implementation:**
- Sydnor: Write import script (Node.js or PowerShell) with frontmatter transformation
- Carver: Generate deduplication report (fuzzy title/tag overlap against curated skills)
- Kima: Spot-check 10–15 skills across domains for quality
- McNulty: Gate PR on deduplication report and format compliance

**Impact:**
- **All agents:** Will have access to 390+ new skills with rich framework mappings, enabling better technique coverage and compliance alignment
- **Curated domains:** Unchanged; community skills provide supplementary reference material
- **Framework coverage:** Gains D3FEND vocabulary, expanded MITRE ATT&CK technique mappings, NIST CSF alignment
- **Scope isolation:** Clear provenance boundary between curated and community content

### 2026-05-27T09:32:50.930-05:00: User directive — Import ALL skills

**By:** User (via Copilot)
**Status:** Accepted

**What:** User directive explicitly overrides McNulty's 14-domain filter recommendation. Import ALL 754 skills from all 26 domains in mukul975/Anthropic-Cybersecurity-Skills with no exclusions.

**Why:** User request — captured for team memory. Overrides the earlier domain filtering strategy.

**Impact:**
- **Sydnor:** Import scope now includes all 754 upstream skills; excluded domains (red-team, pentesting, malware analysis, etc.) are now included
- **Carver:** Deduplication and validation apply across all imported subdomains, not just Microsoft-adjacent ones
- **McNulty:** Previous filtered-domain list is superseded; review gates now apply to the full catalog
- **Kima/Freamon/Herc:** Community skill discovery surfaces broader defensive and adjacent reference material; curated skills remain the quality bar
- **All agents:** Greater breadth of defensive context available, though some imported skills may fall outside primary SOC operational scope

### 2026-05-27T09:32:50.930-05:00: Community Skill Import Scope Override

**By:** Sydnor (Platform Dev)
**Status:** Implemented

**What:** Executed full import of all 754 skills from mukul975/Anthropic-Cybersecurity-Skills into `skills/community/` tree across all 26 subdomains. Preserved McNulty's community-skill architecture (hybrid frontmatter, vendor model, attribution, NOTICE.md) while widening scope to entire upstream catalog per user directive.

**Key Actions:**
1. Wrote `scripts/import-community-skills.js` to fetch, filter, flatten, and transform upstream skills into hybrid frontmatter format
2. Imported all 754 skills into `skills/community/{subdomain}/{name}.md`
3. Generated `skills/community/NOTICE.md` with pinned upstream commit SHA and attribution roster
4. Preserved all framework metadata (MITRE ATT&CK, NIST CSF, D3FEND, ATLAS, etc.) in frontmatter
5. Created cross-references for skills overlapping curated content using `superseded_by:` field
6. Committed as commit f43f848

**Impact:**
- **Squad members:** 754 community skills now discoverable across 45 subdomains (expanded from original 26 due to granular categorization)
- **McNulty:** Future review applies to full import; filtered-domain strategy superseded
- **Carver:** Deduplication report now maps all community skills against 102 curated skills for overlap detection
- **Kima/Freamon/Herc:** Broader skill discovery available; agent logic can weight curated vs. community appropriately
- **Users:** Expanded defensive reference library available during agent sessions
- **Maintenance:** `scripts/import-community-skills.js` is the canonical sync path; future imports require new commit SHA and explicit timestamp

### 2026-05-13T07:58:33-05:00: Terminology Modernization — Auxiliary Logs → Sentinel data lake

**By:** Sydnor (Platform Dev)
**Status:** Implemented

**What:** Updated all documentation, templates, samples, and skill files to use modern Microsoft SecOps terminology:
- **"Auxiliary Logs" / "Aux Logs" → "Sentinel data lake"** across 30+ files
- **Data tiering order** standardized to: Analytics Logs → Basic Logs → Sentinel data lake → Archive
- **ADX positioning** changed from default long-term retention to specialized option (extreme volume, full KQL on historical data, cross-team sharing)

**Key Design Choice:** PowerShell `ValidateSet` parameters and Azure API calls retain `'Auxiliary'` as the enum value (that's what the Azure REST API expects). Inline comments annotate the modern name. Display-facing strings (CLI badges, docs, YAML comments) use "Sentinel data lake".

**Impact:**
- **All agents:** Use "Sentinel data lake" in all output and recommendations. Never say "Auxiliary Logs" or "Aux Logs" in user-facing content.
- **Freamon:** PowerShell data-tiering functions keep `'Auxiliary'` in `ValidateSet` — don't change the API enum, only the comments and prose.
- **Kima/Herc:** Skills and charters already updated by McNulty's modernization pass. This completes the platform layer.
- **Templates/Samples:** `.secops/` YAML files now reference "Sentinel data lake" in tier values and comments. Contoso sample fully aligned.
