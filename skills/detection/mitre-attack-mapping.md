---
title: MITRE ATT&CK Mapping for Detections
category: detection
difficulty: intermediate
mitre_attack:
  - T1110  # Brute Force
  - T1110.003  # Password Spraying
  - T1078  # Valid Accounts
  - T1566  # Phishing
  - T1566.001  # Spearphishing Attachment
  - T1003  # OS Credential Dumping
  - T1021  # Remote Services
  - T1059.001  # PowerShell
products:
  - Microsoft Sentinel
  - Microsoft Defender for Endpoint
  - Microsoft Defender for Identity
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# MITRE ATT&CK Mapping for Detections

## Overview

Every detection rule in this framework maps to one or more MITRE ATT&CK techniques. This isn't paperwork — it's how you find the gaps that attackers exploit. If you can't map a detection to a technique, either the detection is too vague or you're solving a problem that doesn't exist.

This skill covers how to identify the right technique and sub-technique for a detection, run a coverage gap analysis across your analytics rules, and maintain a living map that stays useful as your detection library grows.

Use this skill when:
- Building a new detection and need to assign the correct ATT&CK technique
- Running a quarterly coverage gap analysis
- Presenting detection posture to leadership
- Prioritizing which detections to build next based on coverage gaps
- Reviewing a detection for team approval (MITRE tagging is mandatory per team decision #8)

## Prerequisites

| Requirement | Detail |
|---|---|
| **MITRE ATT&CK** | Familiarity with the Enterprise ATT&CK matrix (v14+) |
| **Sentinel** | Access to the Analytics blade in your Sentinel workspace |
| **ATT&CK Navigator** | Browser access to [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator) |
| **Threat model** | Completed threat model for the detection (team decision #7 — mandatory) |

## Methodology

### Step 1 — Identify the Behavior, Not the Tool

Map to what the adversary is *doing*, not what tool they use. A PowerShell-based credential dump maps to **T1003 (OS Credential Dumping)**, not to a hypothetical "PowerShell Abuse" technique.

**Decision framework:**

1. What is the adversary's *objective* in this step? → This determines the **Tactic** (column in the matrix).
2. What *method* are they using to achieve it? → This determines the **Technique**.
3. Is there a more specific variant? → This determines the **Sub-technique**.

### Step 2 — Select the Right Granularity

| Scenario | Map to |
|---|---|
| Detection catches a broad behavior (e.g., any failed auth spike) | Technique level (e.g., T1110 — Brute Force) |
| Detection targets a specific method (e.g., password spray) | Sub-technique level (e.g., T1110.003 — Password Spraying) |
| Detection covers multiple techniques (e.g., timeline correlation) | All applicable techniques — list each one |

### Step 3 — Assign a Confidence Level

Not every detection covers a technique equally. Tag each mapping with a confidence level:

| Level | Definition | Example |
|---|---|---|
| **High** | Detection directly targets this technique with low false-positive rate | Password spray rule triggering on 10+ failed logins to distinct accounts from one IP |
| **Medium** | Detection catches this technique among other behaviors; some noise expected | Anomalous sign-in rule that also catches brute force among other patterns |
| **Low** | Detection provides indirect signal; useful for correlation, not standalone alerting | Rare process execution that *could* indicate credential dumping |

### Step 4 — Coverage Gap Analysis

Run this quarterly or after any major detection library change.

**Manual process:**

1. Export your Sentinel analytics rules to a spreadsheet (or query the `SentinelAnalyticsRules` table if available).
2. List the ATT&CK techniques each rule maps to (from YAML frontmatter or Sentinel's built-in MITRE mapping field).
3. Load the Enterprise ATT&CK matrix in the ATT&CK Navigator.
4. Color-code by coverage: Green (high), Yellow (medium), Red (low), White (none).
5. Identify white-space clusters — adjacent uncovered techniques often represent entire attack phases you're blind to.

**KQL-assisted inventory:**

```kql
// List all analytics rules and their MITRE ATT&CK mappings from Sentinel
SentinelHealth
| where TimeGenerated > ago(1d)
| where SentinelResourceType == "Analytic rule"
| distinct SentinelResourceName
| join kind=leftouter (
    _GetWatchlist('DetectionMITREMapping')
    | project RuleName = SearchKey, Techniques = Techniques
) on $left.SentinelResourceName == $right.RuleName
| project SentinelResourceName, Techniques
| order by SentinelResourceName asc
```

> **Note:** This query assumes you maintain a `DetectionMITREMapping` watchlist. If you use Sentinel's built-in MITRE mapping on analytics rules, you can also review coverage directly in the **MITRE ATT&CK** blade in the unified SOC platform at [security.microsoft.com](https://security.microsoft.com) or in the Sentinel section of the Azure portal.

### Step 5 — Navigator Layer Export

Create a reusable ATT&CK Navigator layer file for your detection coverage:

```json
{
  "name": "Contoso Detection Coverage - Q2 2026",
  "versions": {
    "attack": "14",
    "navigator": "4.9",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "description": "Current detection coverage across Sentinel analytics rules",
  "techniques": [
    {
      "techniqueID": "T1110",
      "tactic": "credential-access",
      "color": "#00ff00",
      "comment": "Brute force detection — scheduled rule, high confidence",
      "score": 3
    },
    {
      "techniqueID": "T1110.003",
      "tactic": "credential-access",
      "color": "#00ff00",
      "comment": "Password spray detection — scheduled rule, high confidence",
      "score": 3
    },
    {
      "techniqueID": "T1566.001",
      "tactic": "initial-access",
      "color": "#ffff00",
      "comment": "Phishing link detection — MDO integration, medium confidence",
      "score": 2
    }
  ],
  "gradient": {
    "colors": ["#ff0000", "#ffff00", "#00ff00"],
    "minValue": 1,
    "maxValue": 3
  }
}
```

**Score mapping:** 1 = Low, 2 = Medium, 3 = High confidence coverage.

## Example: Mapping a Brute Force Detection to T1110

### The Detection

A Sentinel scheduled rule that fires when a single IP address produces 50+ failed sign-in attempts against 5+ distinct accounts within 10 minutes.

### The Mapping

| Field | Value |
|---|---|
| **Tactic** | Credential Access |
| **Technique** | T1110 — Brute Force |
| **Sub-technique** | T1110.003 — Password Spraying (multiple accounts from one source) |
| **Confidence** | High — direct behavioral match, low FP rate after tuning |
| **Data source** | `SignInLogs` (Azure AD), `SecurityEvent` 4625 (on-prem AD) |
| **Detection rule** | `BruteForce-PasswordSpray-Scheduled` |

### Documentation Template

Use this YAML block in every detection skill's frontmatter:

```yaml
mitre_attack:
  - T1110       # Brute Force (parent)
  - T1110.003   # Password Spraying (specific sub-technique)
mitre_confidence:
  T1110: high
  T1110.003: high
mitre_data_sources:
  - Azure AD Sign-in Logs
  - Windows Security Events (4625)
```

## Best Practices

1. **Map before you build.** Identify the ATT&CK technique *first*, then design the detection. This prevents building detections that don't map to real adversary behavior.
2. **One detection can map to multiple techniques.** A lateral movement detection might map to both T1021 (Remote Services) and T1078 (Valid Accounts).
3. **Don't force-map.** If a detection doesn't cleanly map to a technique, it may be a policy compliance rule, not a threat detection. That's fine — just label it clearly.
4. **Re-map annually.** ATT&CK updates techniques. What was T1086 (PowerShell) is now T1059.001. Keep your mappings current.
5. **Use the MITRE ATT&CK blade in Sentinel.** It shows your coverage automatically for rules that have MITRE mappings configured in the `tactics` and `techniques` fields.

## Related Skills

- **[Scheduled Rule Pattern](scheduled-rule-pattern.md)** — Build the detection rule once you've identified the technique.
- **[Detection Lifecycle](detection-lifecycle.md)** — MITRE mapping is a Phase 1 activity in the lifecycle.
- **[Threat Model Template](threat-model-template.md)** — The threat model links directly to ATT&CK technique selection.
- **[Threat Hunting Foundations](../kql/threat-hunting-foundations.md)** — Hunt for techniques before you build automated detections.
