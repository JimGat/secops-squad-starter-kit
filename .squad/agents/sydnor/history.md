# Project Context

- **Owner:** John Spaid
- **Project:** secops-squad — SecOps framework for Microsoft Security products (Sentinel, Defender, Entra ID Protection), KQL, Logic Apps, Log Analytics, Azure Data Explorer
- **Stack:** KQL, Logic Apps, Azure Functions, Bicep, PowerShell, Node.js/TypeScript
- **Created:** 2026-04-28

## Learnings

<!-- Append new learnings below. Each entry is something lasting about the project. -->

📌 Team initialized on 2026-04-28 — full squad scaffolded with SecOps-focused roles and routing.

📌 **Phase 1: Framework Architecture Finalized** (2026-04-28)
- Skills-first architecture: markdown skills by domain (kql/, soar/, detection/, log-analytics/, adx/, msft-security/)
- Persona-driven onboarding: init wizard with Azure discovery, personas include soc-analyst, detection-engineering, threat-hunting, cloud-security, incident-response, full-soc
- Quality gates: KQL CI validation (Carver), SOAR rollback plans mandatory (Herc), threat model ceremony for detection (McNulty)
- Coverage analysis: MITRE ATT&CK tagging required for all detection/KQL skills
- CLI strategy: secops-squad wraps @bradygaster/squad-cli, additive security commands
- Phase 1 exit: init wizard, soc-analyst persona, 3 KQL skills, 3 SOAR skills, KQL CI, getting-started docs
- Target: new user → working SecOps team with KQL hunting + phishing response in ≤ 15 minutes

🔷 **Sydnor Phase 1 Contribution** (2026-04-28, ~180s)
- Scaffolded 24 directories and root-level project files
- Generated `package.json`, `README.md`, `CONTRIBUTING.md`, CLI structure
- Built GitHub Actions workflows for CI/CD and orchestration
- Created getting-started documentation and initial setup scripts
- Established project foundation for team collaboration

🔷 **CLI Init Wizard + Squad Doctor** (2026-04-28T12:01:11-05:00)
- Built `cli/commands/init.js` — interactive wizard with persona discovery, Azure CLI auto-detection, config generation, persona file installation. Supports `--no-interactive --persona <name>` for CI/scripted use. Uses readline (no deps). Detects existing config (idempotent). Validates against schema.
- Built `cli/commands/doctor.js` — 8-point environment health check: Node version, Git, config validation, team roster parsing, Azure CLI, GitHub CLI, skills.json cross-reference, KQL template syntax. ✅/⚠️/❌ output with actionable messages. Exit code 1 on failure.
- Updated `cli/index.js` — wired init and doctor to real modules, kept other stubs. Version now reads from package.json. Main function is async to support readline prompts. Errors caught with clean messages.
- Added `secops-squad.config.json` to `.gitignore` — it's user-generated per-machine config.
- Only `soc-analyst` persona has full files — other 5 are scaffolds. Init handles this gracefully with a warning.
- Zero external dependencies — readline, fs, path, child_process only. Cross-platform (path.join everywhere).
