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
📌 **Phase 1 Documentation Polished** (2026-04-28)
- README.md updated with badges, "What's in the Box" inventory, Phase 1 vs Phase 2 clarity, skill summaries, and correct persona status (SOC Analyst live; others Phase 2)
- Getting-started.md rewritten as a 15-minute walkthrough with real workflows: init → doctor → skill browse → first hunt → first automation
- Skills Catalog created: 6 shipped skills with difficulty, MITRE tags, products, use cases, and contributor info
- Personas Guide created: explains persona model, SOC Analyst config, custom persona creation, and Phase 2 roadmap
- All docs link to actual skill files in repo, no placeholders or broken references
- Tone: professional, accurate, action-oriented — designed for first impression with real value in ≤ 15 minutes
📌 **Phase 2: All 5 Persona Templates Built** (2026-04-28)
- Created detection-engineering, threat-hunting, cloud-security, incident-response, and full-soc personas (25 files total)
- Each persona has 5 files: team.md, routing.md, skills.json, ceremonies.md, README.md — matching soc-analyst format exactly
- Wire character assignments: no overlap between personas or with the core project team (McNulty, Kima, Freamon, Herc, Sydnor, Carver, Scribe, Ralph)
- Skill references aligned with Phase 2 skill names: mitre-attack-mapping, detection-lifecycle, scheduled-rule-pattern, nrt-rule-pattern, detection-tuning, entra-signin-analysis, cloud-security-posture, defender-for-cloud-policies, defender-xdr-configuration, workspace-rbac, diagnostic-settings, malware-containment, data-exfiltration-response, microsoft-graph-security
- Full-SOC persona (8 agents) demonstrates cross-functional flow: intel → hunting → detection → triage → automation → lessons learned
- Ceremonies are domain-specific and practical: detection review, threat model session, hunt kickoff/debrief, posture review, policy review, IR kickoff, containment review, lessons learned, daily standup, shift handoff, weekly retro
- Architecture decision: personas are self-contained and installable — no cross-persona dependencies required
