# Decisions

## 2026-04-30T09:12:54-05:00: Westlake RBAC Documentation Pattern

**By:** Kima (SecOps Engineer)  
**Status:** Informational

### What

Created `docs/westlake-sentinel-xdr-roles.md` — a customer-facing RBAC guide for Westlake covering Sentinel, XDR, Azure RBAC, Entra ID roles, PIM configuration, and Conditional Access recommendations.

### Key Decisions

1. **URBAC derived from Entra ID roles** — No separate XDR URBAC assignments. Security Operator/Administrator Entra ID roles map to equivalent XDR permissions automatically in the unified portal. Custom URBAC roles flagged as a future optimization.
2. **Admin ⊂ Analyst overlap accepted** — CyberSec Administrators are a subset of Analysts with compensating controls (PIM logging, Sentinel alerts, approval requirements, time-bounded access).
3. **Custom role: Westlake Policy Operator** — Extends Resource Policy Contributor with remediation permissions, removes all delete actions. Full JSON definition included.
4. **Tiered PIM activation** — High-impact roles (Owner, Security Administrator) require approval + phishing-resistant MFA + 4h max. Operational roles (Policy Operator, Sentinel Contributor, Logic App Contributor) are self-service with MFA + 8h max.

### Team Relevance

- This document pattern can be reused for other customer engagements
- The effective permissions matrix format (✅/🔑/❌) should be standardized for all customer-facing RBAC documentation
- Playbook automation identity section is a reusable template — managed identities always need separate RBAC documentation

---

## 2026-04-30T10:18:10-05:00: Repository Rename

**By:** John Spaid (via Copilot)  
**Status:** Complete

### What

Repository renamed from `secops-squad` to `secops-squad-starter-kit`. All internal references updated across:
- `package.json`
- `install.ps1`, `install.sh`
- `.squad/team.md`

### Why

User requested starter-kit naming convention to align with `productivity-squad-starter-kit` patterns.
