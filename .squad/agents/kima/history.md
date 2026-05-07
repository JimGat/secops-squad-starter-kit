# History

<!-- Populated automatically during squad sessions. -->

## Learnings

📌 **Phase 8 Connectivity Setup Skill (2026-05-04)**
- **connectivity-setup.md (~700 lines):** Definitive connectivity guide for all 6 Microsoft Security products — Microsoft Sentinel, Defender XDR, Defender for Cloud, Defender for Identity, Defender for Endpoint, Entra ID Protection.
- **Quick Connectivity Test:** Single PowerShell block runs all 6 product checks in sequence and prints a color-coded summary. Acts as a "doctor command" for the entire security product stack.
- **Key connectivity pattern:** Products on management.azure.com (Sentinel, Defender for Cloud) use Azure RBAC — no app registration needed for human users. Products on Graph and pi.securitycenter.microsoft.com require app registration with admin-consented application permissions for agent/service use.
- **Per-product structure:** Each section has Required Roles/Permissions table → Setup Steps → Verification Commands → Common Issues & Fixes table → cross-references to existing skills.
- **Troubleshooting Matrix:** 20 error messages mapped to root causes and fixes, covering token expiry, license gaps, missing consent, wrong tenant, provider registration, and endpoint selection.
- **Authentication Summary table:** Maps each product to its API target, auth method, and token resource — agents can use this to determine which auth context to use before calling any product.
- **Cross-references:** Deliberately references defender-api-permissions.md for full permissions detail rather than duplicating the matrix; references gov-cloud-support.md for endpoint overrides; references each product's dedicated skill for deep configuration.
- **Key insight:** MDE permissions are on the WindowsDefenderATP resource (not Graph); this is the most common agent confusion point and is called out explicitly in both setup steps and the troubleshooting matrix.

📌 **Phase 7 Gov Cloud + Copilot Workflow Skills (2026-05-04)**
- **gov-cloud-support.md (~640 lines):** Comprehensive sovereign cloud support — 6 cloud environments (Commercial, GCC, GCC High, DoD, Azure Gov, China), full endpoint matrices for identity/Graph/ARM/Sentinel/Defender/Log Analytics per cloud, auth flow differences with certificate-based auth for GCC High/DoD, .secops/ integration with cloud_type field driving automatic endpoint resolution, feature availability matrices (Sentinel, Defender, Copilot, Purview) per cloud, 4 production PowerShell functions (Get-SecOpsCloudEndpoints, Connect-SecOpsEnvironment, Test-SecOpsCloudFeature, Export-SecOpsCloudConfig), compliance constraints for IL2/IL4/IL5, agent decision flow for sovereign operations
- **copilot-security-workflows.md (~780 lines):** Copilot for Security enriched workflow patterns — 5 enrichment patterns (incident summarization, TI enrichment, script deobfuscation, KQL assistance, vulnerability assessment), 3 full workflow templates with ASCII diagrams and production PowerShell (AI-Assisted Incident Triage, Threat Hunt with AI, Automated Reporting), SCU cost management (budget thresholds, per-workflow limits, fallback logic), response caching for TI enrichment, graceful degradation matrix for all Copilot-dependent features, cloud availability guard function
- **Key design:** Both skills integrate with .secops/environment.yaml cloud_type field; gov-cloud-support drives endpoint resolution, copilot-security-workflows provides fallback paths when Copilot unavailable
- **Key insight:** GCC High/DoD have no Copilot for Security (planned); workflows must always include non-AI fallback paths
- **Cross-references:** gov-cloud-support.md ↔ copilot-security-workflows.md ↔ copilot-for-security.md ↔ cross-skill-orchestration.md

📌 **Cross-Team Context Dependencies**
- **Freamon integration:** Can reference Sentinel/Defender skills when generating PowerShell; relies on PowerShell/rate-limiting patterns for API calls
- **Herc integration:** SOAR playbooks can reference Defender/Sentinel API permission patterns for service principal setup; Automation Rules API documented
- **Carver integration:** Can validate that detection rules follow least-privilege and rate-limiting patterns
- **Westlake customer:** Role assignments follow documented three-tier model for analyst progression

📌 **Phase 7 Attack Simulation & Cloud App Discovery API Skills (2026-05-04)**
- **attack-simulation-api.md (~620 lines):** Complete Attack Simulation Training API coverage — Graph API endpoints (/security/attackSimulation/), 5 simulation types (credential harvest, attachment, drive-by URL, link-in-attachment, OAuth consent grant), payload management (list/create custom payloads), campaign management (create/schedule/automate simulations), full reporting (compromise rates, report rates, training completion, per-user breakdown), trend analysis across campaigns, 5 production PowerShell functions (Get-SecOpsSimulationPayloads, New-SecOpsPayload, New-SecOpsAttackSimulation, New-SecOpsSimulationAutomation, Get-SecOpsSimulationReport, Get-SecOpsSimulationTrends, Get-SecOpsSimulationDetectionGaps), 4 Sentinel KQL queries for detection correlation and gap analysis, .secops/ integration (simulation config, campaign schedules, baseline metrics tracking)
- **cloud-app-discovery-api.md (~680 lines):** Comprehensive MDCA Discovery API — authentication with portal-generated tokens, cloud discovery log upload (6 firewall/proxy formats), discovered app enumeration with risk filtering, app governance (sanction/unsanction), OAuth app management (list/approve/ban/revoke), activity log queries, alert management, file monitoring with DLP integration, 10+ production PowerShell functions (Import-SecOpsDiscoveryLog, Get-SecOpsDiscoveredApps, Set-SecOpsAppSanctionStatus, Get-SecOpsOAuthApps, Set-SecOpsOAuthAppStatus, Get-SecOpsMdcaActivities, Get-SecOpsMdcaAlerts, Get-SecOpsMdcaFiles), 3 Sentinel KQL queries (shadow IT detection, OAuth risk, cross-product alert correlation), .secops/ integration (discovery config, sanctioned app list, risk thresholds)
- **Key design:** Both skills complement existing defender-cloud-apps.md (CASB fundamentals) without duplication; attack-simulation-api.md fills detection validation gap; cloud-app-discovery-api.md provides API-level automation for shadow IT workflows
- **Key insight:** Attack simulation results should correlate with Sentinel detections to measure detection pipeline effectiveness; gap reports identify techniques with no corresponding alerts
- **All wrappers:** Follow structured result pattern {ok/error} per team decision
