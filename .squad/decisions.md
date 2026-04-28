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

## Governance

- All meaningful changes require team consensus
- Document architectural decisions here
- Keep history focused on work, decisions focused on direction
