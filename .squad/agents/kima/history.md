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

🟩 **Kima Phase 1 Contribution** (2026-04-28, ~154s)
- Established SOC Analyst persona with team structure and routing logic
- Created persona onboarding template and skill discovery architecture
- Defined team ceremonies, threat modeling, and skill routing framework
- Built foundation for persona-driven security operations workflows
- Set up initial team configuration and role-based skill access

📌 **Detection Engineering Skills Library Created** (2026-04-28)
- Wrote 8 detection engineering skills in `skills/detection/`:
  1. `mitre-attack-mapping.md` — ATT&CK mapping methodology, coverage gap analysis, Navigator layer export
  2. `scheduled-rule-pattern.md` — Full ARM template, frequency/lookback guidance, entity mapping patterns, brute force example
  3. `nrt-rule-pattern.md` — NRT vs scheduled decision framework, limitations, IOC match patterns
  4. `detection-lifecycle.md` — 4-phase lifecycle (Research → Develop → Deploy → Tune) with quality gates and metrics
  5. `custom-kql-function.md` — Saved function authoring, parameterization, ARM/Bicep deployment, versioning
  6. `watchlist-driven-detection.md` — Watchlist patterns (VIP monitoring, blocklists, allowlists), update automation
  7. `fusion-rule-context.md` — Fusion ML interpretation, blind spot analysis, supplementary detection patterns
  8. `threat-model-template.md` — Full fillable template, review workflow, phishing credential theft example
- All skills enforce team decisions #7 (threat model mandatory) and #8 (MITRE tagging mandatory)
- Every skill cross-references related KQL and SOAR skills
- Format follows the established pattern from `skills/kql/threat-hunting-foundations.md`
