# History

<!-- Populated automatically during squad sessions. -->

## Learnings

<!-- Append new learnings below. Each entry is something lasting about the project. -->
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

📌 **Microsoft Security Product Skills Library Created** (2026-04-28)
- Wrote 8 Microsoft Security product skills in `skills/msft-security/`:
  1. `sentinel-workspace-setup.md` — Workspace provisioning via Bicep, Content Hub installation, data connector priority, UEBA/Entity Analytics/Anomalies, Lighthouse MSSP config, cost estimation
  2. `defender-xdr-configuration.md` — Unified portal config, alert suppression rules, custom detection rules from Advanced Hunting, auto-investigation levels, Safe Attachments/Links/Anti-phish, cross-product correlation
  3. `defender-for-cloud-policies.md` — Policy assignments at subscription/MG level, regulatory compliance (NIST/CIS/PCI-DSS/ISO 27001), Defender plans Bicep (Servers/Storage/SQL/AppService/KeyVault/ARM/DNS/Containers), CSPM vs CWP, workflow automation, secure score methodology
  4. `defender-for-identity.md` — DC sensor prerequisites/sizing/installation, coverage planning by org size, alert tuning for service accounts, lateral movement path detection, XDR integration; MITRE: T1078, T1087, T1003, T1558
  5. `defender-for-endpoint.md` — Onboarding via Intune/GPO/SCCM/local script, ASR rules with phased rollout, custom indicators (hash/IP/URL/cert), Live Response commands, device groups and RBAC, auto-investigation levels; MITRE: T1059, T1203, T1053
  6. `entra-id-protection.md` — User/sign-in risk policies via Graph, risk detection types mapped to severity, SSPR config, Conditional Access Zero Trust policy set (10 policies), gap analysis methodology with What-If; MITRE: T1078, T1110, T1556
  7. `microsoft-graph-security.md` — Security API endpoints (alerts_v2, incidents, TI, secureScores), app-only vs delegated auth, batch operations and pagination, webhook subscriptions with handler example, PowerShell and Python SDK examples
  8. `purview-dlp-patterns.md` — DLP policy creation across Exchange/SPO/OD/Teams/Endpoints, sensitivity label taxonomy, custom SITs, endpoint DLP with blocked apps/domains, alert investigation workflow, Sentinel KQL for exfiltration detection; MITRE: T1567, T1048, T1537
- All skills include: YAML frontmatter, Bicep/ARM snippets, PowerShell/CLI commands, KQL queries, MITRE ATT&CK references, cross-references to related skills across all categories
- Total library: ~109 KB across 8 production-ready skill files

📌 **Phase 3: Threat Model Template Library Created** (2026-04-28)
- Built comprehensive threat model template library in `templates/threat-models/` — 10 files, ~155 KB total
- Covers 8 MITRE ATT&CK tactics: Credential Access (TA0006), Initial Access (TA0001), Lateral Movement (TA0008), Persistence (TA0003), Privilege Escalation (TA0004), Exfiltration (TA0010), Defense Evasion (TA0005), Impact (TA0040)
- Each tactic template includes: YAML frontmatter, per-technique Mermaid attack flow diagrams, specific Microsoft log table data sources, KQL detection query stubs, false positive scenarios with tuning guidance, Microsoft product coverage mapping, detection gap analysis with compensating controls, cross-references to existing detection and msft-security skills
- Created README.md with workflow diagram connecting threat models to detection engineering skills
- Created template-blank.md as reusable starting point for any new tactic
- Enforces team decision #7 (threat model required before detection rules merge) and #8 (MITRE ATT&CK tagging mandatory)
- Total techniques covered: ~35 unique techniques/sub-techniques with attack flows and detection guidance
- Every template links back to relevant skills in `skills/detection/` and `skills/msft-security/`
- Key insight: Exfiltration tactic has 0 techniques at "Full" coverage — behavioral detection against legitimate data sharing patterns remains the hardest detection challenge in the Microsoft stack

📌 **MITRE ATT&CK Coverage Map Created** (2026-04-28)
- Built `docs/mitre-coverage.md` — comprehensive coverage mapping of all 52 skills to MITRE ATT&CK Enterprise v15
- Created `lib/mitre-mapping/index.js` — zero-dependency Node.js utility (scanSkills, buildCoverageMap, findGaps, generateReport) with built-in YAML frontmatter parser
- Updated 11 skill frontmatter files to sync `mitre_attack` field with techniques referenced in body text (detection/*, kql/incident-investigation, msft-security/*)
- Coverage stats: 48 unique techniques across 14 tactics, 20% overall Enterprise ATT&CK coverage
- Strongest areas: Initial Access (80%), Credential Access (59%), Persistence (50%)
- Weakest areas: Reconnaissance (0%), Resource Development (0%), Discovery (9%), Impact (14%)
- T1078 (Valid Accounts) referenced by 29 skills — most cross-cutting technique
- Identified 13 missing top-20 techniques; T1055 (Process Injection), T1036 (Masquerading), T1204 (User Execution) are highest priority gaps
- Key insight: log-analytics and adx categories are infrastructure-focused with minimal direct ATT&CK mapping — this is expected and correct
- Key insight: T1086 appears in mitre-attack-mapping.md body but is deprecated (replaced by T1059.001) — intentionally excluded from frontmatter

## Learnings

- YAML frontmatter parsing needs only handle strings and arrays for skill files — keep it simple
- Sub-techniques (T####.###) should be listed alongside parent techniques in frontmatter for complete machine-readable coverage
- Coverage percentage is misleading for pre-compromise tactics (Reconnaissance, Resource Development) — Microsoft's detection surface starts at Initial Access
- The 52 skills naturally divide into "detection-relevant" (36 skills with MITRE mappings) and "infrastructure" (16 skills without) — both are essential but serve different purposes
- When building coverage maps, always scan both frontmatter AND body text — 11 of 52 skills had techniques in body that weren't in frontmatter

📌 **Defender MCP Server & API Permissions Skills Created** (2026-04-30)
- Created `skills/msft-security/defender-mcp-server.md` (~490 lines) — comprehensive MCP integration skill covering full Defender API landscape, MCP configuration, per-product operations (MDE, XDR, Defender for Cloud, MDI, MDCA), rate limiting, caching, priority queues, and 5 end-to-end agent workflows
- Created `skills/msft-security/defender-api-permissions.md` (~370 lines) — complete permissions reference covering Graph Security, MDE, Entra ID Protection, and ARM permissions matrices; least-privilege patterns per workflow; tiered app registration strategy; certificate/secret/managed identity auth; multi-tenant MSSP patterns; government cloud considerations; credential expiry monitoring
- Key design: Complements existing defender-for-endpoint.md, defender-xdr-configuration.md, and microsoft-graph-security.md without duplicating — each skill file cross-references the others
- API landscape insight: Graph Security API is the convergence target but MDE-specific operations (machine actions, Live Response, TVM, custom indicators) still require direct REST to api.securitycenter.microsoft.com
- Tiered app strategy: ReadOnly → Triage → Response with escalating permissions — matches SOC role tiers
- Government cloud: Different API endpoints per cloud type (.us for GCC/GCCHigh), some features unavailable in DoD/China — agents must check .secops/environment.yaml cloud field first

📌 **Cross-Team Context: ADX Staging + Update Policy Pattern** (2026-04-28)
- Herc decision: All ADX security tables use two-table ingestion (Raw staging → structured table via update policy)
- Impact on Kima: All detection rules querying ADX via `adx()` proxy should use structured table names (SecurityEvents, NetworkTraffic, ThreatIntelligence, IdentityEvents, CloudAudit)
- Do NOT query `*_Raw` staging tables directly
- Pattern rationale: Allows schema evolution without breaking detection rules; new columns added to update policy transformation
- Related: Freamon's ADX skills query structured tables; Herc's Bicep templates in `templates/bicep/adx/` implement this architecture

📌 **Cross-Team Context: Persona Template Architecture** (2026-04-28)
- McNulty decision: All 6 personas are self-contained, installable team configurations with no cross-persona dependencies
- Each persona uses unique Wire characters (Kima only in soc-analyst persona)
- Personas: soc-analyst, detection-engineering, threat-hunting, cloud-security, incident-response, full-soc
- Implication: Kima as character only appears in soc-analyst; other personas have different team rosters
- Personas reference Kima's skills (detection-engineering, threat-hunting personas) but don't depend on soc-analyst persona configuration
- Related: McNulty's personas-guide with full team rosters and skill routing

📌 **Cross-Team Context: Structured Result Pattern** (2026-04-28)
- Sydnor decision: All API-wrapping libraries return structured results (ok/error), never throw exceptions
- Pattern: Success = `{ ok: true, data: ..., nextLink?: string }` | Failure = `{ ok: false, error: string, status?: number, code?: string }`
- Carver validation: Graph Security API test suite validates this pattern for all libraries
- Implication: Kima's detection skills and Microsoft Security skills won't call APIs that throw; all error handling is explicit

📌 **Westlake Customer Documentation: Sentinel & XDR Role Assignments** (2026-04-30)
- Created `docs/westlake-sentinel-xdr-roles.md` — comprehensive customer-facing RBAC guide (~36 KB, 15 sections)
- Three-group model: Infrastructure Engineers, CyberSec Analysts, CyberSec Administrators (subset of Analysts)
- Role mapping approach: Entra ID directory roles → implicit XDR URBAC derivation, no separate URBAC assignments needed in current design
- Custom role: "Westlake Policy Operator" (Resource Policy Contributor minus deletes, plus remediation) — JSON definition included
- PIM configuration: 5 eligible roles with tiered activation (4h approval-required for Owner/SecAdmin, 8h self-service for operational roles)
- Citation format: Every role assignment cites specific Microsoft Learn URL; 9 unique references consolidated in References section
- Key documentation patterns learned:
  - Effective permissions matrix (✅/🔑/❌) is the most scannable format for customer stakeholders
  - Separation of duties notes with compensating controls table addresses audit concerns preemptively
  - Playbook automation identity section is often missed — managed identities need their own RBAC, separate from user groups
  - Future considerations with 📌 prefix flags optimization opportunities without scope-creeping the initial deployment

📌 **Sentinel MCP Server & API Reference Skills Created** (2026-04-30)
- Wrote 2 new skills in `skills/msft-security/`:
  1. `sentinel-mcp-server.md` (~500 lines) — Azure MCP Server integration for Sentinel: architecture, config (multi-client JSON), auth (DefaultAzureCredential chain), multi-workspace/gov cloud setup, resource listing patterns, incident/rule/watchlist/TI CRUD via MCP tools, safe query execution, rate limiting with priority queues, agent integration patterns with graceful REST degradation, 4 end-to-end workflow examples (triage, rule deploy, TI enrichment, health check)
  2. `sentinel-api-reference.md` (~450 lines) — REST API quick reference: SecurityInsights resource provider endpoints, full RBAC permissions matrix (Reader/Responder/Contributor/Automation Contributor), API version tracking with breaking change notes, curl + PowerShell examples for incidents/rules/connectors/watchlists/TI/automation/bookmarks, pagination, error handling patterns, Az.SecurityInsights cmdlet mapping
- Both skills cross-reference each other and existing Sentinel/Graph/detection skills
- MCP skill connects to `.secops/` workspace discovery flow — agents auto-discover workspace config before MCP calls
- API reference includes government cloud endpoints and auth scope differences (ARM vs Log Analytics)
- Key insight: MCP vs REST vs PowerShell decision matrix depends on WHO is performing the operation (agent → MCP, pipeline → REST, human → PowerShell)
- Key insight: Sentinel Responder role is the sweet spot for agent triage — enough to manage incidents without rule modification risk

📌 **Defender REST API Wrapper Skill Created** (2026-04-30)
- Created `skills/powershell/defender-api-wrapper.md` (~500 lines) — production-ready PowerShell wrappers for full Defender REST API surface
- **MDE wrappers:** Run-MdeAdvancedHunting (KQL with quota tracking), Invoke-MdeMachineAction (isolate/restrict/scan/collect/offboard), Start-MdeLiveResponse (session commands/scripts), Get-MdeAlert/Update-MdeAlert (with pagination + classification filter), Get-MdeSoftwareInventory, Get-MdeVulnerability, Get-MdeCustomDetection/New-MdeCustomDetection (CRUD)
- **Defender for Cloud wrappers:** Get-DefenderSecureScore, Get-DefenderCloudAlert (cross-subscription), Get-ComplianceAssessment (regulatory frameworks with per-control drill-down), Request-JitVmAccess (time-bounded port access)
- **XDR wrappers:** Get-XdrIncident/Update-XdrIncident (unified incidents with comment support), Invoke-XdrAdvancedHunting (cross-product KQL), Get-XdrInvestigation, Get-XdrAttackDisruption
- **MDI wrappers:** Get-MdiHealthIssue (sensor monitoring), Get-MdiSecurityAssessment (identity posture), Get-MdiSuspiciousActivity (via XDR hunting), Get-MdiEntityProfile (user/device context)
- Shared pagination helper (Invoke-SecOpsPaginatedRequest) drains all @odata.nextLink pages with safety limit
- Graph SDK alternative section with decision matrix (SDK vs REST by use case)
- Pre-flight connectivity check (Test-DefenderPreFlight) validates MDE + Graph access
- Complements defender-module.md (base functions), defender-mcp-server.md (MCP patterns), defender-api-permissions.md (permissions matrices) — no duplication
- All wrappers use ShouldProcess for destructive actions, .secops/ context for cloud endpoints, structured SecOps.Result return pattern
- 10 MITRE ATT&CK techniques mapped across all sections
