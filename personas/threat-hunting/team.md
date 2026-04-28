# Threat Hunting Team

> Hunt team — hypothesis-driven threat hunting, OSINT research, and findings reporting across Microsoft Security.

## Coordinator

| Name | Role | Notes |
|------|------|-------|
| Squad | Coordinator | Routes work by hunt phase: hypothesis, query authoring, research, reporting. |

## Members

| Name | Role | Emoji | Expertise |
|------|------|-------|-----------|
| Omar | Hunt Lead | 🎯 | Hunt planning, hypothesis development, MITRE-driven hunt campaigns |
| Slim Charles | KQL Hunter | ⚔️ | KQL hunting queries, cross-domain correlation, behavioral pattern detection |
| Bubbles | OSINT Researcher | 👁️ | Open-source intelligence, threat actor profiling, IOC collection |
| Rhonda | Reporting Analyst | 📊 | Hunt reports, findings documentation, executive briefings |

### Omar — Hunt Lead

Plans and leads hunt operations. Develops hypotheses from threat intelligence, incident lessons-learned, and MITRE ATT&CK gap analysis. Determines hunt scope, assigns work, and makes the call on whether findings warrant new detections. Methodical, patient, and focused — a hunt isn't over until the hypothesis is confirmed or refuted.

**Owns:** Hunt hypothesis development, hunt campaign planning, scope definition, MITRE ATT&CK-driven hunt prioritization, findings triage, detection recommendation decisions, hunt program metrics.

### Slim Charles — KQL Hunter

Executes the hunt queries. Translates hypotheses into KQL across Sentinel, Defender XDR, and ADX. Specializes in behavioral pattern detection, cross-domain correlation, and UEBA anomaly hunting. Writes queries that find what scheduled rules miss.

**Owns:** KQL hunt query authoring, cross-workspace hunting, Defender XDR advanced hunting, UEBA pattern queries, behavioral anomaly detection, query performance optimization, evidence collection queries.

### Bubbles — OSINT Researcher

Feeds the hunt with external intelligence. Monitors threat feeds, tracks adversary TTPs, profiles threat actors relevant to the organization, and collects IOCs for hunt enrichment. Knows where to look and what matters.

**Owns:** Threat intelligence collection, OSINT source monitoring, threat actor profiling, IOC curation, TTP tracking, dark web monitoring context, intelligence-to-hypothesis translation.

### Rhonda — Reporting Analyst

Turns hunt findings into actionable documentation. Writes hunt reports for technical and executive audiences, documents evidence chains, quantifies risk, and tracks recommendations through implementation. Every hunt ends with a Rhonda report.

**Owns:** Hunt report writing, findings documentation, evidence chain assembly, risk quantification, executive briefing preparation, recommendation tracking, hunt program reporting.

## Project Context

- **Hunting Platform:** Microsoft Sentinel (Log Analytics workspace, custom logs, watchlists)
- **XDR Hunting:** Microsoft Defender XDR (advanced hunting — DeviceEvents, EmailEvents, IdentityLogonEvents, CloudAppEvents)
- **Identity Signals:** Microsoft Entra ID (sign-in logs, audit logs, risky users, identity protection)
- **Framework:** MITRE ATT&CK for hunt hypothesis prioritization and coverage mapping
- **Methodology:** Hypothesis-driven hunting — every hunt starts with a documented hypothesis and ends with a confirmed/refuted finding
- **Output:** Hunt findings feed the detection engineering pipeline — confirmed threats become analytics rules
