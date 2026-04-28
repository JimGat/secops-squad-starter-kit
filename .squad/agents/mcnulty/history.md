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

📌 **Phase 2: Documentation Updated — Skills Catalog, README, Personas Guide** (2026-04-28)
- Skills Catalog (docs/skills-catalog.md) updated with all 28 Phase 2 skills: 10 KQL, 10 SOAR, 8 Detection Engineering
- Each skill documented with: Name, Difficulty, MITRE ATT&CK tags, Products, Brief Description, File Link
- Organized by category with summary table showing Phase status (Active, Coming Soon, Phase 3)
- Learning paths added: New to Threat Hunting, New to SOAR, Building a Detection Rule, New to Detection Engineering
- README.md updated: Phase badge changed to "Phase 2 Active", skills count (6→28), personas count (1→6)
- "What's in the Box" section rewritten with full inventory reflecting all 6 personas and skill counts
- Project Status section updated: Phase 1 ✅ SHIPPED, Phase 2 ✅ ACTIVE (with completed items checked), Phase 3 planned
- Personas Guide (docs/personas-guide.md) completely rewritten with all 6 personas documented
- Each persona includes: Status, Best For, Team Composition (with agent names, roles, focus), Key Skills, Typical Workflow, When to Use, How to Load
- Personas documented: SOC Analyst, Detection Engineering, Threat Hunting, Cloud Security, Incident Response, Full SOC
- All documentation: accurate (only reference things that exist), professional tone, GFM markdown, no broken references
- Critical: All persona agents use actual Wire character names (Bunk, Kima, Freamon, Daniels, Omar, etc.); no duplicates across personas

📌 **Phase 3 Round 1: ADX Skills, Threat Models, Graph Security API, ADX Bicep Templates** (2026-04-28)
- Added 8 ADX skills: cluster-architecture, security-data-modeling, data-ingestion, long-term-retention, cross-cluster-queries, migration-from-sentinel, adx-ml-anomaly, adx-dashboards
- Added 10 threat model templates aligned with MITRE ATT&CK tactics: Initial Access, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Lateral Movement, Exfiltration, Impact, blank template, README
- Graph Security API library deployed: 7 zero-dependency modules (index.js, auth.js, alerts.js, incidents.js, threat-intelligence.js, secure-score.js, constants) with 3 auth flows (client credentials, managed identity, device code)
- ADX Bicep templates: main.bicep + cluster.bicep, database.bicep, tables.bicep, ingestion.bicep; 5 KQL scripts (security-events, network-traffic, threat-intelligence, identity-events, cloud-audit); dev/standard/production tier support with auto-scale, VNet, PE, CMK, diagnostic logging

📌 **Phase 3 Round 1: Documentation Updated** (2026-04-28)
- README.md: Phase badge updated to "Phase 3 Active", repo URL references prepared for x3nc0n/secops-squad, skills count updated to 36 (28 Phase 2 + 8 ADX), added ADX skills section with descriptions, added threat model templates section (10 templates, 8 MITRE tactics), added Graph Security API library section, added ADX Bicep templates section with reference to README, added Installation section with install.sh/install.ps1 pointer, updated Project Status to Phase 3 ACTIVE with all Phase 3 deliverables checked
- Skills Catalog: Total updated to 36 skills, ADX skills section added (8 skills with full descriptions, difficulty, products, authors), summary table updated showing ADX as Phase 3 Active
- Personas Guide: Full SOC persona updated to load all 36 Phase 3 skills, Threat Hunting persona updated with ADX skills (cluster-architecture, security-data-modeling), Detection Engineering persona updated with threat model template integration notes + links to threat model templates
- Created docs/adx-setup.md: Quick comparison table (ADX vs Log Analytics), deployment guide for 3 tiers (dev/standard/production) with Bicep commands, post-deployment verification, data ingestion options (Sentinel export, batch, diagnostic settings), cross-resource querying from Sentinel, ADX skill loading in personas, use cases (multi-month hunts, forensics, anomaly detection), troubleshooting
- Created docs/graph-security-api.md: Setup guide (app registration, permissions, credentials), 4 auth methods (client credentials, managed identity, device code, token), 4 modules (alerts, incidents, threat-intelligence, secure-score) with examples, error handling (structured results, status codes, auto-retry), integration examples (Logic Apps auto-triage, bulk IOC import, incident forensics), API reference, troubleshooting
- All docs: practical, code examples included, linked to repo files (no placeholders), MITRE ATT&CK references accurate, tone actionable for first-time users

Key architectural decisions locked in for Phase 3:
- **Threat Models as Shared Templates:** All personas can reference threat models; Detection Engineering treats them as ceremony gates; Incident Response uses them for forensic correlation
- **ADX as Optional Data Lake:** Not required for Phase 1–2 personas; Threat Hunting and Full SOC benefit most; optional load in others via skills.json
- **Graph Security API as Automation Bridge:** Zero dependencies means deployment in Azure Functions/Logic Apps with minimal overhead; 3 auth flows cover all deployment contexts
- **Bicep Templates as Infrastructure Code:** Production-grade, tiered approach (dev/standard/prod) allows cost-appropriate deployments; pre-built tables reduce schema definition burden
