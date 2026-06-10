# 📚 SecOps Squad — Skills Catalog

> **Last updated:** 2026-06-10 | **Total skills:** 847 (92 core + 755 community) | **Core domains:** 11 | **Community sub-domains:** 45

Complete inventory of all skills in the SecOps Squad Starter Kit. Each skill is a Markdown knowledge file that teaches Copilot CLI agents how to perform specific security operations tasks.

## Summary

| Domain | Count | Description |
|--------|-------|-------------|
| [**ADX (Azure Data Explorer)**](#adx-azure-data-explorer) | 8 | Security data lake, long-term retention, ML anomaly detection, dashboards |
| [**Detection Engineering**](#detection-engineering) | 10 | Rule authoring, MITRE ATT&CK mapping, detection lifecycle, NRT/scheduled rules |
| [**KQL**](#kql) | 11 | Threat hunting, Sentinel analytics, UEBA, cross-workspace queries |
| [**Log Analytics**](#log-analytics) | 10 | Workspace architecture, data connectors, retention, cost optimization |
| [**Microsoft Security**](#microsoft-security) | 19 | Defender XDR, Sentinel, Entra ID, Purview, Graph Security API, MCP servers |
| [**Orchestration**](#orchestration) | 3 | Cross-skill workflows, Copilot for Security integration, MSSP patterns |
| [**Platform**](#platform) | 4 | Multi-tenant, sovereign cloud (GCC/GCC-H/DoD), cross-cloud, performance tuning |
| [**PowerShell**](#powershell) | 14 | Module foundation, API wrappers, auth patterns, rate limiting |
| [**SOAR/Automation**](#soarautomation) | 12 | Phishing response, auto-triage, compromised account, threat intel ingest |
| [**Testing**](#testing) | 1 | Integration test suites for SecOps workflows |
| [**Copilot Skills**](#copilot-skills) | 10 | Agent collaboration, git workflow, error recovery, squad conventions, onboarding |
| [**Community Skills**](#community-skills) | 755 | 45 sub-domains covering threat hunting, cloud security, network security, malware analysis, digital forensics, and more |
| **Total** | **847** | |

---

## ADX (Azure Data Explorer)

Skills for building and operating a security data lake on Azure Data Explorer.

| # | Skill | Path | Description |
|---|-------|------|-------------|
| 1 | ADX Dashboards | `skills/adx/adx-dashboards.md` | Building security dashboards with ADX native visualization |
| 2 | ADX ML & Anomaly Detection | `skills/adx/adx-ml-anomaly.md` | Machine learning and anomaly detection for security data |
| 3 | Cluster Architecture | `skills/adx/cluster-architecture.md` | ADX cluster sizing, configuration, and architecture patterns |
| 4 | Cross-Cluster Queries | `skills/adx/cross-cluster-queries.md` | Querying across multiple ADX clusters for federated security data |
| 5 | Data Ingestion | `skills/adx/data-ingestion.md` | Ingesting security data into ADX from various sources |
| 6 | Long-Term Retention | `skills/adx/long-term-retention.md` | Cost-effective long-term security data retention strategies |
| 7 | Migration from Sentinel | `skills/adx/migration-from-sentinel.md` | Migrating security data from Sentinel to ADX |
| 8 | Security Data Modeling | `skills/adx/security-data-modeling.md` | Designing security-optimized data models in ADX |

## Detection Engineering

Skills for building, testing, deploying, and tuning security detections.

| # | Skill | Path | Description |
|---|-------|------|-------------|
| 1 | Advanced Hunting API & Live Response | `skills/detection/advanced-hunting-api.md` | Using the Advanced Hunting API and Live Response capabilities |
| 2 | Custom KQL Function Authoring | `skills/detection/custom-kql-function.md` | Writing reusable KQL functions for detections |
| 3 | Detection Lifecycle | `skills/detection/detection-lifecycle.md` | End-to-end detection lifecycle: design → test → deploy → tune |
| 4 | Fusion Rule Context | `skills/detection/fusion-rule-context.md` | Understanding ML-based multi-stage attack detection (Fusion rules) |
| 5 | MITRE ATT&CK Mapping | `skills/detection/mitre-attack-mapping.md` | Mapping detections to MITRE ATT&CK techniques and tactics |
| 6 | Near-Real-Time (NRT) Rule Pattern | `skills/detection/nrt-rule-pattern.md` | Authoring NRT analytics rules for low-latency detection |
| 7 | Scheduled Analytics Rule Pattern | `skills/detection/scheduled-rule-pattern.md` | Authoring scheduled analytics rules with proper patterns |
| 8 | Threat Intel Enrichment | `skills/detection/threat-intel-enrichment.md` | External threat intelligence enrichment for detections |
| 9 | Threat Model Template | `skills/detection/threat-model-template.md` | Threat model templates for detection engineering |
| 10 | Watchlist-Driven Detection | `skills/detection/watchlist-driven-detection.md` | Using Sentinel watchlists to drive adaptive detections |

## KQL

Skills for writing, optimizing, and deploying Kusto Query Language queries.

| # | Skill | Path | Description |
|---|-------|------|-------------|
| 1 | ADX Integration | `skills/kql/adx-integration.md` | KQL patterns for ADX-specific security queries |
| 2 | Cloud Security Posture | `skills/kql/cloud-security-posture.md` | KQL queries for cloud security posture assessment |
| 3 | Cross-Workspace Queries | `skills/kql/cross-workspace-queries.md` | Querying across multiple Log Analytics workspaces |
| 4 | Defender XDR Advanced Hunting | `skills/kql/defender-xdr-hunting.md` | KQL hunting queries for Defender XDR tables |
| 5 | Detection Tuning | `skills/kql/detection-tuning.md` | Tuning detection rules to reduce false positives |
| 6 | Entra Sign-In Analysis | `skills/kql/entra-signin-analysis.md` | Analyzing Entra ID sign-in logs for anomalies |
| 7 | Incident Investigation | `skills/kql/incident-investigation.md` | KQL patterns for structured incident investigations |
| 8 | KQL Query Builder | `skills/kql/query-builder.md` | Templates, validation, and optimization for KQL queries |
| 9 | Sentinel Analytics Rules | `skills/kql/sentinel-analytics-rules.md` | Writing KQL for Sentinel analytics rule logic |
| 10 | Threat Hunting Foundations | `skills/kql/threat-hunting-foundations.md` | Foundational KQL patterns for hypothesis-driven hunting |
| 11 | UEBA Patterns | `skills/kql/ueba-patterns.md` | User and Entity Behavior Analytics query patterns |

## Log Analytics

Skills for managing Azure Monitor Log Analytics workspaces and data pipelines.

| # | Skill | Path | Description |
|---|-------|------|-------------|
| 1 | Log Analytics API Wrapper | `skills/log-analytics/api-wrapper.md` | REST API wrapper for Log Analytics query and management |
| 2 | Cost Optimization | `skills/log-analytics/cost-optimization.md` | Strategies for reducing Log Analytics costs |
| 3 | Custom Tables & DCR | `skills/log-analytics/custom-tables-dcr.md` | Creating custom tables with Data Collection Rules |
| 4 | Data Connectors Setup | `skills/log-analytics/data-connectors-setup.md` | Configuring data connectors for security data ingestion |
| 5 | Diagnostic Settings | `skills/log-analytics/diagnostic-settings.md` | Azure diagnostic settings for security log routing |
| 6 | Purge & Export | `skills/log-analytics/purge-and-export.md` | Data purge operations and export configurations |
| 7 | Advanced Query Patterns | `skills/log-analytics/query-patterns.md` | Advanced Log Analytics query patterns and optimization |
| 8 | Retention & Archive | `skills/log-analytics/retention-archive.md` | Configuring retention and archive policies |
| 9 | Workspace Architecture | `skills/log-analytics/workspace-architecture.md` | Designing multi-workspace architectures for security |
| 10 | Workspace RBAC | `skills/log-analytics/workspace-rbac.md` | Role-based access control for Log Analytics workspaces |

## Microsoft Security

Skills for the Microsoft Security product suite — Defender, Sentinel, Entra, Purview, and Graph.

| # | Skill | Path | Description |
|---|-------|------|-------------|
| 1 | Attack Simulation Training API | `skills/msft-security/attack-simulation-api.md` | Attack simulation training via API |
| 2 | Cloud App Discovery API | `skills/msft-security/cloud-app-discovery-api.md` | Defender for Cloud Apps Discovery API integration |
| 3 | Connectivity Setup | `skills/msft-security/connectivity-setup.md` | Microsoft Security connectivity setup and prerequisites |
| 4 | Microsoft Copilot for Security | `skills/msft-security/copilot-for-security.md` | Integrating with Microsoft Copilot for Security |
| 5 | Defender API Permissions Reference | `skills/msft-security/defender-api-permissions.md` | Required API permissions for Defender operations |
| 6 | Defender for Cloud Apps (MDCA) | `skills/msft-security/defender-cloud-apps.md` | Microsoft Defender for Cloud Apps configuration and queries |
| 7 | Defender for Cloud Policies | `skills/msft-security/defender-for-cloud-policies.md` | Managing Defender for Cloud security policies |
| 8 | Defender for Endpoint | `skills/msft-security/defender-for-endpoint.md` | Defender for Endpoint integration and hunting |
| 9 | Defender for Identity | `skills/msft-security/defender-for-identity.md` | Defender for Identity configuration and detection |
| 10 | Defender MCP Server | `skills/msft-security/defender-mcp-server.md` | MCP server integration for Defender XDR |
| 11 | Defender XDR Configuration | `skills/msft-security/defender-xdr-configuration.md` | Configuring Defender XDR unified security operations |
| 12 | eDiscovery API Wrapper | `skills/msft-security/ediscovery-api-wrapper.md` | REST API wrapper for eDiscovery operations |
| 13 | Entra ID Protection | `skills/msft-security/entra-id-protection.md` | Entra ID Protection risk policies and investigation |
| 14 | Microsoft Graph Security API | `skills/msft-security/microsoft-graph-security.md` | Graph Security API for alerts, incidents, and threat intel |
| 15 | Purview API Wrapper | `skills/msft-security/purview-api-wrapper.md` | REST API wrapper for Microsoft Purview |
| 16 | Purview DLP Patterns | `skills/msft-security/purview-dlp-patterns.md` | Data Loss Prevention patterns with Microsoft Purview |
| 17 | Sentinel REST API Reference | `skills/msft-security/sentinel-api-reference.md` | Quick reference for the Sentinel REST API |
| 18 | Sentinel MCP Server | `skills/msft-security/sentinel-mcp-server.md` | MCP server integration for Microsoft Sentinel |
| 19 | Sentinel Workspace Setup | `skills/msft-security/sentinel-workspace-setup.md` | Sentinel workspace provisioning and configuration |

## Orchestration

Skills for composing multi-step security workflows across domains.

| # | Skill | Path | Description |
|---|-------|------|-------------|
| 1 | Copilot for Security Enriched Workflows | `skills/orchestration/copilot-security-workflows.md` | Workflows enriched by Microsoft Copilot for Security |
| 2 | Cross-Skill Workflow Orchestration | `skills/orchestration/cross-skill-orchestration.md` | Orchestrating workflows across multiple skill domains |
| 3 | MSSP SecOps Workflows | `skills/orchestration/mssp-workflows.md` | Multi-customer MSSP workflow orchestration |

## Platform

Skills for multi-tenant, sovereign cloud, and cross-cloud security operations.

| # | Skill | Path | Description |
|---|-------|------|-------------|
| 1 | Cross-Cloud Security Data Connectors | `skills/platform/cross-cloud-connectors.md` | Connecting AWS, GCP, and multi-cloud data to Sentinel |
| 2 | Sovereign Cloud Support (GCC/GCC-H/DoD) | `skills/platform/gov-cloud-support.md` | Operating in Azure Government and sovereign cloud environments |
| 3 | Multi-Tenant SecOps Operations | `skills/platform/multi-tenant-support.md` | Managing security operations across multiple Azure AD tenants |
| 4 | Performance Tuning & Optimization | `skills/platform/performance-tuning.md` | Performance tuning and optimization for security workloads |

## PowerShell

Skills for building production PowerShell modules, API wrappers, and automation.

| # | Skill | Path | Description |
|---|-------|------|-------------|
| 1 | Common API Patterns | `skills/powershell/api-patterns.md` | Reusable patterns for calling REST APIs from PowerShell |
| 2 | Authentication Patterns | `skills/powershell/auth-patterns.md` | Azure AD / Entra authentication flows for PowerShell |
| 3 | Azure Monitor Submodule | `skills/powershell/azure-monitor-module.md` | PowerShell submodule for Azure Monitor operations |
| 4 | Data Tiering Commands | `skills/powershell/data-tiering-commands.md` | Commands for managing data tiering (hot/warm/cold) |
| 5 | Data Tiering Submodule | `skills/powershell/data-tiering-module.md` | PowerShell submodule for data tiering automation |
| 6 | Defender REST API Wrapper | `skills/powershell/defender-api-wrapper.md` | PowerShell wrapper for Defender REST APIs |
| 7 | Defender Submodule | `skills/powershell/defender-module.md` | PowerShell submodule for Defender operations |
| 8 | Entra ID Submodule | `skills/powershell/entra-module.md` | PowerShell submodule for Entra ID management |
| 9 | Error Handling Patterns | `skills/powershell/error-handling.md` | Structured error handling for PowerShell modules |
| 10 | Module Foundation | `skills/powershell/module-foundation.md` | Base patterns for building PowerShell security modules |
| 11 | Unified API Rate Limiting | `skills/powershell/rate-limiting.md` | Rate limiting and throttling for API-heavy automation |
| 12 | Resource Graph Submodule | `skills/powershell/resource-graph-module.md` | PowerShell submodule for Azure Resource Graph queries |
| 13 | Sentinel REST API Wrapper | `skills/powershell/sentinel-api-wrapper.md` | Production PowerShell functions for the Sentinel REST API |
| 14 | Sentinel Submodule | `skills/powershell/sentinel-module.md` | PowerShell submodule for Sentinel operations |

## SOAR/Automation

Skills for Security Orchestration, Automation, and Response playbooks.

| # | Skill | Path | Description |
|---|-------|------|-------------|
| 1 | L1 Auto-Triage | `skills/soar/auto-triage.md` | Evidence-based incident routing and initial triage automation |
| 2 | Compliance Framework Mappings | `skills/soar/compliance-framework-mappings.md` | Automated posture assessment against compliance frameworks |
| 3 | Compromised Account Auto-Response | `skills/soar/compromised-account.md` | Automated response for compromised account incidents |
| 4 | Data Exfiltration Response | `skills/soar/data-exfiltration-response.md` | DLP alert enrichment and data exfiltration blocking |
| 5 | Malware Containment | `skills/soar/malware-containment.md` | Malware containment and evidence collection playbooks |
| 6 | Phishing Response | `skills/soar/phishing-response.md` | Phishing incident auto-triage and remediation |
| 7 | IP Threat Intelligence Enrichment | `skills/soar/sentinel-enrichment-ip.md` | IP address threat intelligence enrichment for Sentinel |
| 8 | User Account Context Enrichment | `skills/soar/sentinel-enrichment-user.md` | User account context enrichment for Sentinel incidents |
| 9 | Teams Notification (Adaptive Card) | `skills/soar/teams-notification.md` | Sentinel incident notification via Teams Adaptive Cards |
| 10 | Threat Intelligence Ingest | `skills/soar/threat-intel-ingest.md` | TAXII/STIX to Sentinel threat intelligence ingestion |
| 11 | ITSM Ticket Creation | `skills/soar/ticket-create.md` | ServiceNow / JIRA bi-directional incident ticket sync |
| 12 | Workbook Automation | `skills/soar/workbook-automation.md` | Programmatic Sentinel workbook/dashboard management |

## Testing

Skills for testing and validating SecOps workflows and detections.

| # | Skill | Path | Description |
|---|-------|------|-------------|
| 1 | Integration Test Suite | `skills/testing/integration-test-suite.md` | Integration test patterns for SecOps workflows |

## Copilot Skills

Agent-level skills that govern how Copilot CLI agents collaborate, recover, and follow conventions.

| # | Skill | Path | Description |
|---|-------|------|-------------|
| 1 | Agent Collaboration | `.copilot/skills/agent-collaboration/SKILL.md` | Standard collaboration patterns — worktree awareness, cross-agent communication |
| 2 | Error Recovery Patterns | `.copilot/skills/error-recovery/SKILL.md` | Recovery patterns for agent failures — adapt, don't just report |
| 3 | First-Run Onboarding | `.copilot/skills/first-run-onboarding/SKILL.md` | Detects first-run state and guides new users through environment setup |
| 4 | Git Workflow | `.copilot/skills/git-workflow/SKILL.md` | Squad branching model: dev-first workflow with insiders preview |
| 5 | Reviewer Protocol | `.copilot/skills/reviewer-protocol/SKILL.md` | Reviewer rejection workflow and strict lockout semantics |
| 6 | SecOps Environment Context | `.copilot/skills/secops-environment-context.md` | Environment-aware context for SecOps operations |
| 7 | Secret Handling | `.copilot/skills/secret-handling/SKILL.md` | Never read .env files or write secrets to committed files |
| 8 | Session Recovery | `.copilot/skills/session-recovery/SKILL.md` | Find and resume interrupted Copilot CLI sessions |
| 9 | Squad Conventions | `.copilot/skills/squad-conventions/SKILL.md` | Core conventions and patterns used in the Squad codebase |
| 10 | Test Discipline | `.copilot/skills/test-discipline/SKILL.md` | Update tests when changing APIs — no exceptions |

---

## Community Skills

Community-contributed skills spanning 45 security sub-domains with 755 total skills. These cover extended security operations beyond the core Microsoft Security stack.

| # | Sub-Domain | Count | Coverage |
|---|-----------|-------|----------|
| 1 | Threat Hunting | 56 | Advanced persistent threat detection, hypothesis-driven hunting, behavioral analysis |
| 2 | Threat Intelligence | 50 | TI platforms, indicator management, attribution, dark web monitoring |
| 3 | Cloud Security | 63 | Multi-cloud posture, CSPM, workload protection, cloud-native security |
| 4 | Network Security | 43 | Network monitoring, IDS/IPS, traffic analysis, firewall management |
| 5 | Web Application Security | 42 | OWASP, WAF, API security, secure development practices |
| 6 | Malware Analysis | 39 | Static/dynamic analysis, reverse engineering, sandbox techniques |
| 7 | Digital Forensics | 37 | Disk forensics, memory analysis, timeline reconstruction, evidence handling |
| 8 | Identity & Access Management | 33 | IAM policies, privilege management, federation, MFA |
| 9 | SOC Operations | 33 | SOC maturity, shift handoff, metrics, analyst workflows |
| 10 | Container Security | 29 | Kubernetes security, image scanning, runtime protection |
| 11 | API Security | 28 | API gateway protection, OAuth security, rate limiting |
| 12 | OT/ICS Security | 28 | Industrial control systems, SCADA, operational technology |
| 13 | Security Operations | 28 | Operational procedures, playbooks, escalation frameworks |
| 14 | Incident Response | 26 | IR procedures, containment, eradication, recovery |
| 15 | Vulnerability Management | 25 | Scanning, prioritization, patching, risk scoring |
| 16 | Red Teaming | 24 | Adversary simulation, assumed breach, purple team |
| 17 | Penetration Testing | 20 | Methodology, tools, reporting, remediation validation |
| 18 | DevSecOps | 17 | CI/CD security, SAST/DAST, shift-left practices |
| 19 | Endpoint Security | 17 | EDR, host hardening, endpoint detection |
| 20 | Zero Trust Architecture | 17 | Zero trust principles, microsegmentation, continuous verification |
| 21 | Cryptography | 15 | Key management, PKI, encryption standards |
| 22 | Phishing Defense | 15 | Anti-phishing, awareness, simulation, response |
| 23 | Ransomware Defense | 13 | Prevention, detection, recovery, negotiation frameworks |
| 24 | Mobile Security | 13 | MDM, mobile threat defense, app security |
| 25 | Threat Detection | 7 | Detection methodologies, alert correlation, enrichment |
| 26 | Application Security | 4 | Secure SDLC, code review, dependency management |
| 27 | Compliance & Governance | 4 | Regulatory frameworks, audit preparation, policy management |
| 28 | Deception Technology | 3 | Honeypots, honeytokens, deception platforms |
| 29 | Supply Chain Security | 3 | Software supply chain, SBOM, vendor risk |
| 30 | AI Security | 2 | AI/ML model security, adversarial attacks, LLM safety |
| 31 | Identity & Access (Legacy) | 2 | Legacy IAM patterns and migration paths |
| 32 | Offensive Security | 2 | Offensive security methodology and tooling |
| 33 | Privacy Compliance | 2 | GDPR, CCPA, privacy engineering |
| 34 | Red Team | 2 | Red team operations and campaign planning |
| 35 | Wireless Security | 2 | WiFi security, Bluetooth, RF analysis |
| 36 | Blockchain Security | 1 | Smart contract security, DeFi risks |
| 37 | Data Protection | 1 | Data classification, DLP, encryption at rest |
| 38 | Firmware Analysis | 1 | Firmware extraction and vulnerability analysis |
| 39 | Firmware Security | 1 | Secure boot, firmware integrity |
| 40 | Governance, Risk & Compliance | 1 | GRC frameworks and integration |
| 41 | Identity Security | 1 | Identity threat detection and response |
| 42 | OT Security | 1 | Operational technology fundamentals |
| 43 | Purple Team | 1 | Purple team exercises and collaboration |
| 44 | Social Engineering Defense | 1 | Social engineering awareness and countermeasures |
| 45 | Zero Trust | 1 | Zero trust implementation basics |

---

## Category READMEs

These files provide domain-level overviews and are not individual skills:

| File | Domain |
|------|--------|
| `skills/orchestration/README.md` | Orchestration Skills Domain overview |
| `skills/platform/README.md` | Platform Skills Domain overview |
| `skills/powershell/README.md` | PowerShell Skills Domain overview |
| `skills/testing/README.md` | Testing Skills overview |
