# History

<!-- Populated automatically during squad sessions. -->

## Learnings

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
- **MITRE ATT&CK coverage mapping:** Built `lib/mitre-mapping/` utility + `docs/mitre-coverage.md` to track 52 skills across 48 unique techniques
- **Detection lifecycle quality gates:** Research → Develop → Deploy → Tune with metrics at each gate
- **Structured comment protocol:** JSON-formatted incident comments for multi-agent coordination in Sentinel
- **MCP-first pattern:** MCP established as primary agent pathway, REST as graceful degradation
- **Tiered permissions model:** ReadOnly → Triage → Response app registrations matching SOC analyst role progression

📌 **Phase 1-3 Contributions**
- **Detection Engineering Library (8 skills):** mitre-attack-mapping, scheduled-rule-pattern, nrt-rule-pattern, detection-lifecycle, custom-kql-function, watchlist-driven-detection, fusion-rule-context, threat-model-template
- **Microsoft Security Library (8 skills):** sentinel-workspace-setup, defender-xdr-configuration, defender-for-cloud-policies, defender-for-identity, defender-for-endpoint, entra-id-protection, microsoft-graph-security, purview-dlp-patterns
- **Threat Model Library (10 files):** Comprehensive coverage of Credential Access, Initial Access, Lateral Movement, Persistence, Privilege Escalation, Exfiltration, Defense Evasion, Impact tactics with detection guidance
- **MITRE Coverage Map:** `lib/mitre-mapping/` scanner + 52-skill coverage report identifying 13 missing top-20 techniques

📌 **Phase 4 Sentinel Integration (2026-04-30)**
- **sentinel-mcp-server.md (~500 lines):** Azure MCP Server integration covering architecture, multi-client/multi-workspace/gov cloud config, CRUD via MCP tools, safe query execution, rate limiting, agent integration patterns with REST fallback
- **sentinel-api-reference.md (~450 lines):** REST API quick reference with RBAC matrix, API versioning, curl/PowerShell examples, error patterns, cmdlet mapping
- **Key insight:** Sentinel Responder role is the sweet spot for agent operations (manages incidents without rule modification risk)
- **Key insight:** MCP vs REST vs PowerShell decision depends on WHO operates (agent → MCP, pipeline → REST, human → PowerShell)
- **Key integration:** MCP config links to `.secops/workspaces/*.yaml` for workspace discovery

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

📌 **Cross-Team Context Dependencies**
- **Freamon integration:** Can reference Sentinel/Defender skills when generating PowerShell; relies on PowerShell/rate-limiting patterns for API calls
- **Herc integration:** SOAR playbooks can reference Defender/Sentinel API permission patterns for service principal setup; Automation Rules API documented
- **Carver integration:** Can validate that detection rules follow least-privilege and rate-limiting patterns
- **Westlake customer:** Role assignments follow documented three-tier model for analyst progression

📌 **ADX Staging Pattern & Impact**
- **Herc decision:** All ADX security tables use two-table ingestion (Raw staging → structured table via update policy)
- **Kima implication:** All detection rules querying ADX via `adx()` proxy must use structured table names (SecurityEvents, NetworkTraffic, IdentityEvents, CloudAudit)
- **Rationale:** Schema evolution without breaking rules; new columns added to update policy

📌 **Structured Result Pattern**
- **Sydnor decision:** All API-wrapping libraries return structured results {ok/error}, never throw exceptions
- **Kima usage:** Detection skills won't call APIs that throw; all error handling explicit
- **Validation:** Carver's test suite validates this pattern for all libraries
