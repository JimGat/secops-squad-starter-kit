# Squad Decisions

## Active Decisions

### 2026-04-28T09:16:43-05:00: Team composition and role assignments

**By:** Sydnor (on behalf of the squad)

**What:** The secops-squad team is composed of 8 members from The Wire universe, each with distinct SecOps responsibilities:
- **McNulty** (Lead) — architecture, scope, code review
- **Kima** (SecOps Engineer) — Microsoft Security products, threat hunting, detection engineering
- **Freamon** (KQL Engineer) — KQL queries, Log Analytics, Azure Data Explorer
- **Herc** (Automation/SOAR) — Logic Apps, Azure Functions, SOAR workflows
- **Sydnor** (Platform Dev) — templates, CLI, framework, CI/CD
- **Carver** (Tester/QA) — validation, testing, quality gates
- **Scribe** (Session Logger) — logging, decisions, memory management
- **Ralph** (Work Monitor) — work tracking, circuit breaking

**Why:** Clear role separation ensures each domain has a dedicated specialist. SecOps work spans detection engineering, query authoring, automation, and platform tooling — each requires distinct expertise. Reviewer authority is shared between McNulty (architecture) and Carver (quality).

### 2026-04-28T09:16:43-05:00: secops-squad Framework Architecture

**By:** McNulty (Lead)

**Decision:** The core product is a skills-first architecture modeled after bradygaster/squad, specialized for Microsoft Security products, KQL engineering, Logic Apps automation, Log Analytics workspace management, and Azure Data Explorer integration.

**Key Architectural Choices:**
1. **Skills-First Architecture** — Markdown skill files categorized by domain (`skills/kql/`, `skills/soar/`, `skills/detection/`, `skills/log-analytics/`, `skills/adx/`, `skills/msft-security/`)
2. **Persona-Driven Onboarding** — Pre-built team configurations installable via `secops-squad init` (initial set: `soc-analyst`, `detection-engineering`, `threat-hunting`, `cloud-security`, `incident-response`, `full-soc`)
3. **KQL Files Are CI-Validated** — Every `.kql` file syntax-validated on PR. Carver owns the quality gate.
4. **Every SOAR Skill Requires a Rollback Plan** — No Logic Apps playbook ships without `destroy.ps1` and documented undo procedure
5. **CLI Extends Squad** — `secops-squad` CLI wraps `@bradygaster/squad-cli`; security-specific commands are additive
6. **Azure Discovery Is Non-Blocking** — Init completes with placeholder config if discovery fails; users can connect later
7. **Threat Model Required for Every Detection** — `detection-engineering` persona enforces threat-model-session ceremony; McNulty gates review
8. **MITRE ATT&CK Tagging Mandatory** — Every detection/KQL skill maps to ATT&CK technique IDs (machine-readable YAML frontmatter)

**Owners of Key Areas:**
- KQL skills + ADX skills: Freamon
- SOAR skills + Bicep templates: Herc
- Detection skills + Microsoft Security skills: Kima
- Log Analytics skills: Freamon + Kima
- CLI + install script: Sydnor
- KQL validation harness + testing: Carver
- Architecture + persona design: McNulty
- Session logging + decisions: Scribe

**Phase 1 Exit Criteria:** Working init wizard, `soc-analyst` persona, 3 KQL skills, 3 SOAR skills, KQL validation CI, getting-started docs. Target: New user → working SecOps team with KQL hunting and phishing response in ≤ 15 minutes.

### 2026-04-28T12:01:11-05:00: KQL Validator Library Design

**By:** Freamon (KQL Engineer)

**Status:** Implemented

**What:** Built `lib/kql-validator/` — offline KQL syntax validation with 4 modules (index, parser, reporter, operators). ~60 operators, 250+ functions, ~50 Sentinel/Defender tables. 56/57 tests passing.

**Key Choices:**
- Offline-only (no Azure workspace connectivity)
- Error vs Warning distinction (= in where clause is error; project * is warning)
- Where-clause scoping prevents false positives on join patterns
- Markdown extraction supports both ````kql` and ````kusto` blocks
- CommonJS modules, zero dependencies

**Why:** CI pipeline requires KQL validation on every PR. CLI command `secops-squad kql validate` needs a library to call.

### 2026-04-28T14:08:04-05:00: ADX Table Schemas Use Staging + Update Policy Pattern

**By:** Herc (Automation/SOAR)

**What:** All ADX security tables use two-table ingestion: `*_Raw` staging table receives raw JSON, update policy transforms to structured target table.

**Impact:**
- Freamon: ADX skills and queries target structured tables (SecurityEvents, NetworkTraffic, etc.), not `*_Raw`
- Kima: Detection rules via `adx()` proxy use structured table names
- All: Adding new columns requires updating KQL scripts in `templates/bicep/adx/scripts/`

**Why:** Allows schema evolution without breaking ingestion pipelines. New columns can be added to transform query without re-creating data connections.

### 2026-04-28T12:34:12-05:00: Persona Template Architecture and Character Assignments

**By:** McNulty (Lead)

**Status:** Active

**What:** All 6 personas are self-contained, installable team configurations with no cross-persona dependencies. Each uses unique Wire characters with thematic alignment:
- soc-analyst: Bunk, Kima, Freamon, Daniels
- detection-engineering: Daniels, Lester, Prop Joe, Landsman
- threat-hunting: Omar, Slim Charles, Bubbles, Rhonda
- cloud-security: Avon, Stringer, D'Angelo
- incident-response: Rawls, Sydnor, Beadie, Prez
- full-soc: Bunny Colvin, Bodie, Poot, Carver, Herc, Cutty, McNulty, Lester

**Key Choices:**
1. Self-contained — each installs complete working team with no external dependencies
2. Consistent format — all follow 5-file structure from soc-analyst
3. Skill references forward-compatible — reference Phase 2 skills to be created
4. Full-SOC is additive — shows integration, not concatenation
5. Ceremonies domain-specific

**Why:** Users pick any persona and get working team immediately.

### 2026-04-28T14:08:04-05:00: Structured Result Objects for API Libraries

**By:** Sydnor (Platform Dev)

**Status:** Proposed

**What:** All API-wrapping libraries return structured result objects instead of throwing exceptions:
```javascript
// Success: { ok: true, data: ..., nextLink?: string }
// Failure: { ok: false, error: string, status?: number, code?: string }
```

**Why:** SOC automation runs unattended in Logic Apps and Functions. Thrown exceptions cause silent failures. Structured results force explicit error handling, make context available, compose cleanly in async pipelines.

**Scope:**
- Applies to all `lib/*/` API wrapper modules
- Does NOT apply to CLI commands (use `fatal()`)
- `createClient()` may throw for invalid config (programmer error)

**Established in:** `lib/graph-security/` (Carver's test suite validates pattern)

## Governance

- All meaningful changes require team consensus
- Document architectural decisions here
- Keep history focused on work, decisions focused on direction
