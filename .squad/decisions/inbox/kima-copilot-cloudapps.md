# Decision: Copilot for Security + Defender for Cloud Apps Skill Architecture

**Date:** 2026-04-30T17:40:42-05:00
**Author:** Kima (SecOps Engineer)
**Requested by:** Jose
**Status:** Proposed

## What

Created two new skills in `skills/msft-security/`:

1. **`copilot-for-security.md`** — Copilot for Security integration covering SCU capacity, plugins, custom plugins, promptbooks, REST API, and agent integration patterns
2. **`defender-cloud-apps.md`** — MDCA CASB coverage including Cloud Discovery, OAuth app governance, 6 policy types, full REST API reference, Conditional Access App Control, and SIEM integration

## Key Design Decisions

### 1. Copilot API Session Reuse Pattern
Sessions preserve conversation context. Agents should create one session per investigation and reuse it across multiple prompts rather than creating new sessions per prompt. This saves SCU consumption and improves response quality through accumulated context.

### 2. MDCA API Token Authentication (Not OAuth)
MDCA's REST API uses portal-generated API tokens (`Authorization: Token <value>`), not OAuth2 flows. This is a different auth pattern from all other Defender APIs. Agents must handle this distinction when building multi-product workflows.

### 3. Structured Result Pattern Applied
Both skills' PowerShell wrappers (`Invoke-CopilotWithRetry`, `Invoke-MdcaApiWithRetry`) follow Sydnor's structured result pattern (`{ok: true/false, data/error}`), consistent with all other API-wrapping code in the project.

### 4. New MITRE Techniques Added to Coverage
These skills introduce 5 MITRE techniques not previously covered: T1071 (Application Layer Protocol), T1199 (Trusted Relationship), T1537 (Transfer Data to Cloud Account), T1550 (Use Alternate Authentication Material), T1567 (Exfiltration Over Web Service). The MITRE coverage map should be updated.

## Impact

- **Freamon:** Can reference MDCA tables (`McasShadowItReporting`, `CloudAppEvents`) in KQL skills
- **Herc:** SOAR playbooks can call Copilot API for incident enrichment and MDCA API for governance actions
- **Carver:** Should validate MITRE coverage map update with new techniques
- **All agents:** Can use Copilot for Security as enrichment layer in investigation workflows

## Why

These two products were identified in the platform coverage gap analysis as critical gaps: Copilot for Security is the AI augmentation layer for all SOC operations, and MDCA covers the CASB/Shadow IT domain that no existing skill addresses.
