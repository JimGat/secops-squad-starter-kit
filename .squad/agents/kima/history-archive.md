# History Archive

## Archived Learnings (Phase 1-6)

📌 **Kima Domain Summary** (2026-04-30)
- **Core expertise:** Detection engineering, Sentinel operations, Defender integration, threat modeling
- **Total contribution:** 20 skills across Microsoft Security, Detection Engineering, and Threat Models
- **Phase 1:** Established SOC Analyst persona and team structure
- **Phase 2-3:** Built 8 detection engineering skills + 8 Microsoft Security product skills
- **Phase 3:** Created comprehensive threat model library (10 files covering 8 MITRE tactics)
- **Phase 4:** Developed Sentinel MCP server integration and API reference, Defender MCP/permissions architecture
- **Phase 6 (2026-04-30):** Completed Defender API wrapper, Westlake customer documentation

📌 **Key Architectural Patterns Established by Kima**
- **Persona-driven architecture:** Self-contained, installable team configurations (soc-analyst, detection-engineering, threat-hunting, cloud-security, incident-response, full-soc)
- **Threat model as mandatory gate:** All detection rules require threat model review before merge (team decision #7)
- **MITRE ATT&CK coverage mapping:** Built lib/mitre-mapping/ utility + docs/mitre-coverage.md to track 52 skills across 48 unique techniques
- **Detection lifecycle quality gates:** Research → Develop → Deploy → Tune with metrics at each gate
- **Structured comment protocol:** JSON-formatted incident comments for multi-agent coordination in Sentinel
- **MCP-first pattern:** MCP established as primary agent pathway, REST as graceful degradation
- **Tiered permissions model:** ReadOnly → Triage → Response app registrations matching SOC analyst role progression

📌 **Phase 1-3 Contributions**
- **Detection Engineering Library (8 skills):** mitre-attack-mapping, scheduled-rule-pattern, nrt-rule-pattern, detection-lifecycle, custom-kql-function, watchlist-driven-detection, fusion-rule-context, threat-model-template
- **Microsoft Security Library (8 skills):** sentinel-workspace-setup, defender-xdr-configuration, defender-for-cloud-policies, defender-for-identity, defender-for-endpoint, entra-id-protection, microsoft-graph-security, purview-dlp-patterns
- **Threat Model Library (10 files):** Comprehensive coverage of Credential Access, Initial Access, Lateral Movement, Persistence, Privilege Escalation, Exfiltration, Defense Evasion, Impact tactics with detection guidance
- **MITRE Coverage Map:** lib/mitre-mapping/ scanner + 52-skill coverage report identifying 13 missing top-20 techniques

📌 **Phase 4 Sentinel Integration (2026-04-30)**
- **sentinel-mcp-server.md (~500 lines):** Azure MCP Server integration covering architecture, multi-client/multi-workspace/gov cloud config, CRUD via MCP tools, safe query execution, rate limiting, agent integration patterns with REST fallback
- **sentinel-api-reference.md (~450 lines):** REST API quick reference with RBAC matrix, API versioning, curl/PowerShell examples, error patterns, cmdlet mapping
- **Key insight:** Sentinel Responder role is the sweet spot for agent operations (manages incidents without rule modification risk)
- **Key insight:** MCP vs REST vs PowerShell decision depends on WHO operates (agent → MCP, pipeline → REST, human → PowerShell)
- **Key integration:** MCP config links to .secops/workspaces/*.yaml for workspace discovery

📌 **Phase 4 Defender Integration (2026-04-30)**
- **defender-mcp-server.md (~490 lines):** Full Defender API landscape with MCP configuration, per-product operations (MDE, XDR, Defender for Cloud, MDI, MDCA), rate limiting, caching, 5 end-to-end agent workflows
- **defender-api-permissions.md (~370 lines):** Permissions reference (Graph, MDE, Entra, ARM) with least-privilege patterns per workflow; tiered app strategy; multi-tenant/MSSP patterns; government cloud considerations
- **defender-api-wrapper.md (~500 lines):** 20+ production PowerShell wrappers covering MDE (hunting, machine actions, Live Response, TVM, custom detections), Defender for Cloud (secure score, alerts, compliance, JIT access), XDR (incidents, advanced hunting, investigations), MDI (health, assessments, suspicious activities, entity profiles)
- **Key insight:** Graph Security API is convergence target but MDE-specific ops still require direct api.securitycenter.microsoft.com REST
- **Key insight:** Complements existing skills (defender-for-endpoint.md, defender-xdr-configuration.md, microsoft-graph-security.md) without duplication

📌 **Phase 6 Customer Documentation**
- **westlake-sentinel-xdr-roles.md (~36 KB):** Comprehensive RBAC guide for Sentinel + XDR role assignments
- **Three-group model:** Infrastructure Engineers, CyberSec Analysts, CyberSec Administrators (Analyst subset)
- **PIM configuration:** 5 eligible roles with tiered activation (4h approval for Owner/SecAdmin, 8h self-service for operational)
- **Custom role creation:** "Westlake Policy Operator" with Resource Policy Contributor permissions minus deletes, plus remediation capability
- **Key lesson learned:** Managed identities need separate RBAC (often missed in automation identity section)

📌 **Phase 6 eDiscovery & Purview API Skills (2026-04-30)**
- **ediscovery-api-wrapper.md (~490 lines):** Full Graph eDiscovery API wrapper — case management, custodians, legal hold, KQL content search across Exchange/SharePoint/OneDrive/Teams, review sets, export (PST/MSG/native), 3 production wrapper functions (New-SecOpsEdiscoveryCase, Search-SecOpsMailboxes, Export-SecOpsReviewSet), 3 end-to-end agent workflows (phishing response, insider threat, regulator request), Sentinel monitoring KQL, rate limits, troubleshooting
- **purview-api-wrapper.md (~630 lines):** Comprehensive Purview API surface — sensitivity labels (list/evaluate/auto-label), DLP alerts via Graph + policy management via PowerShell, data classification (SITs, trainable classifiers, EDM), records management (retention labels/policies), insider risk alert correlation, Unified Audit Log (PowerShell + Management API + Graph preview), Compliance Manager (score, assessments, improvement actions), 3 production wrapper functions (Get-SecOpsDlpAlerts, Get-SecOpsAuditLog, Get-SecOpsComplianceScore), 3 agent workflows (classify→label→protect→audit, incident data investigation, compliance posture monitoring)
- **Key design:** Complements purview-dlp-patterns.md (policy design) with API integration; all wrappers follow structured result pattern {ok/error}
- **Key insight:** Purview API surface is fragmented — Graph for labels/alerts/classification, IPPSSession for DLP policies, EXO for audit log, Management API for streaming events; agents must handle multiple auth contexts

📌 **Phase 2-3 Persona Updates (2026-05-04)**
- **detection-engineering:** Updated skills.json (v2.0.0) with 8 new skills across shared+per-agent: sentinel-api-wrapper, sentinel-mcp-server, sentinel-api-reference (shared), data-tiering-commands, workbook-automation (Daniels), log-analytics/api-wrapper, log-analytics/query-patterns, kql/query-builder (Lester). Updated routing.md with API & Tool Routing table + tool selection priority. Updated README.md with Phase 2-3 capabilities table.
- **threat-hunting:** Updated skills.json (v2.0.0) with 8 new skills: sentinel-api-wrapper, sentinel-mcp-server, sentinel-api-reference (shared), data-tiering-commands (Omar), log-analytics/api-wrapper, log-analytics/query-patterns, kql/query-builder (Slim Charles), workbook-automation (Rhonda). Updated routing.md with API & Tool Routing table. Updated README.md with Phase 2-3 capabilities.
- **cloud-security:** Updated skills.json (v2.0.0) with 6 new skills: defender-api-wrapper, defender-mcp-server, defender-api-permissions (shared), advanced-hunting-api, copilot-for-security (Avon), defender-cloud-apps (Stringer), copilot-for-security (D'Angelo). Updated routing.md with API & Tool Routing table + 3 new rules. Updated README.md with Phase 2-3 capabilities.
- **Key pattern:** All three personas follow MCP-first → PowerShell → REST fallback tool selection hierarchy
- **Key pattern:** Routing files now include API & Tool Routing tables mapping operations to specific skills and agents

📌 **Phase 6 Copilot for Security + Defender for Cloud Apps Skills (2026-04-30)**
- **copilot-for-security.md (~376 lines):** Comprehensive Copilot for Security integration — SCU capacity planning/provisioning (Bicep), built-in plugin matrix (9 plugins), custom plugin development (manifest + OpenAPI), promptbook creation/execution, REST API patterns (session management, prompt evaluation, plugin management), 4 agent integration patterns (incident summarization, TI enrichment, script analysis, guided investigation), rate limits, MITRE ATT&CK coverage across 8 tactics
- **defender-cloud-apps.md (~454 lines):** Full MDCA CASB coverage — Cloud Discovery (4 data sources), app risk scoring, OAuth app governance with audit workflow, 6 policy types (activity, file, session, anomaly, discovery, OAuth), complete REST API reference (/api/v1/ — activities, alerts, files, discovery, entities), Conditional Access App Control (reverse proxy session controls), Sentinel SIEM integration (3 tables + 2 KQL queries), 3 agent workflows (Shadow IT assessment, OAuth audit, incident correlation), rate limit handler
- **Key decisions:** Copilot API uses session-based context preservation (reuse sessions to save SCU); MDCA uses portal-generated API tokens (not OAuth); structured result pattern applied to both API wrappers
- **MITRE coverage added:** T1071, T1199, T1537, T1550, T1567 (new techniques not previously covered in skill library)
- **.secops/ integration:** Both skills define environment.yaml configuration blocks for agent consumption

📌 **ADX Staging Pattern & Impact**
- **Herc decision:** All ADX security tables use two-table ingestion (Raw staging → structured table via update policy)
- **Kima implication:** All detection rules querying ADX via dx() proxy must use structured table names (SecurityEvents, NetworkTraffic, IdentityEvents, CloudAudit)
- **Rationale:** Schema evolution without breaking rules; new columns added to update policy

📌 **Structured Result Pattern**
- **Sydnor decision:** All API-wrapping libraries return structured results {ok/error}, never throw exceptions
- **Kima usage:** Detection skills won't call APIs that throw; all error handling explicit
- **Validation:** Carver's test suite validates this pattern for all libraries
