---
title: Cloud Security Posture
category: kql
difficulty: intermediate
mitre_attack:
  - T1078  # Valid Accounts
  - T1190  # Exploit Public-Facing Application
  - T1530  # Data from Cloud Storage Object
  - T1562  # Impair Defenses
products:
  - Microsoft Defender for Cloud
  - Microsoft Sentinel
  - Azure Resource Graph
author: Freamon
version: 1.0.0
last_updated: 2026-04-28
---

# Cloud Security Posture

## Overview

Microsoft Defender for Cloud generates security recommendations, secure score assessments, and compliance data that flow into Log Analytics and Azure Resource Graph. This skill covers KQL patterns for querying cloud security posture data — tracking secure score over time, monitoring recommendation compliance, detecting configuration drift, and surfacing resource health issues.

Use this skill when:
- Tracking your organization's secure score trends and regression
- Auditing compliance against regulatory frameworks (CIS, NIST, PCI-DSS)
- Detecting misconfigurations that create attack surface (open storage, exposed management ports)
- Building executive dashboards for cloud security posture
- Hunting for configuration drift that may indicate attacker persistence

## Prerequisites

| Requirement | Detail |
|---|---|
| **Tables** | `SecurityRecommendation`, `SecureScoreControls`, `SecureScores`, `SecurityAlert`, `AzureActivity` |
| **Resource Graph** | `SecurityResources`, `Resources`, `ResourceContainers` |
| **Workspace** | Sentinel-connected workspace with Defender for Cloud connector enabled |
| **Permissions** | `Security Reader` on subscriptions; `Microsoft Sentinel Reader` on workspace |
| **Data connectors** | Microsoft Defender for Cloud connector, Azure Activity connector |

## Core Patterns

### Pattern 1 — Secure Score Trending Over Time

Track how your organization's secure score changes over time to detect regressions and measure improvement campaigns.

```kql
// Track daily secure score trends across subscriptions.
// SecureScores table captures score snapshots periodically.
let LookbackPeriod = 90d;
SecureScores
| where TimeGenerated > ago(LookbackPeriod)
| extend
    CurrentScore = toreal(Properties.score.current),
    MaxScore = toreal(Properties.score.max),
    PercentageScore = toreal(Properties.score.percentage) * 100,
    SubscriptionId = tostring(Properties.subscriptionId)
| summarize
    AvgScore = avg(PercentageScore),
    MinScore = min(PercentageScore),
    MaxScorePercent = max(PercentageScore)
    by bin(TimeGenerated, 1d), SubscriptionId
| order by SubscriptionId asc, TimeGenerated asc
| extend
    PrevDayScore = prev(AvgScore),
    PrevSub = prev(SubscriptionId),
    ScoreDelta = iff(SubscriptionId == prev(SubscriptionId), round(AvgScore - prev(AvgScore), 2), real(null))
| where isnotempty(ScoreDelta)
| project
    Date = TimeGenerated,
    SubscriptionId,
    Score = round(AvgScore, 2),
    ScoreDelta,
    Trend = iff(ScoreDelta > 0, "📈 Improving", iff(ScoreDelta < 0, "📉 Regressing", "➡️ Stable"))
```

**Parameters to customize:**
- `LookbackPeriod` — 90 days for quarterly review; extend to 365d for annual reporting.
- `bin(TimeGenerated, 1d)` — Change to `7d` for weekly trends in executive dashboards.

**Performance notes:**
- `SecureScores` table is relatively small (one row per subscription per assessment). Even 365-day queries are fast.
- Use `prev()` for delta calculation — requires the data to be sorted by subscription and date.

---

### Pattern 2 — Unhealthy Resource Recommendations

Surface resources with unhealthy security recommendations, prioritized by severity and resource criticality.

```kql
// Find all unhealthy recommendations grouped by severity and resource type.
let LookbackPeriod = 1d;
SecurityRecommendation
| where TimeGenerated > ago(LookbackPeriod)
| where RecommendationState == "Unhealthy"
| extend
    Severity = tostring(Properties.metadata.severity),
    Category = tostring(Properties.metadata.category),
    ResourceType = tostring(Properties.resourceDetails.ResourceType),
    ResourceName = tostring(Properties.resourceDetails.ResourceName),
    RecommendationName = tostring(Properties.displayName)
| summarize
    UnhealthyCount = count(),
    AffectedResources = dcount(ResourceName),
    SampleResources = make_set(ResourceName, 10)
    by RecommendationName, Severity, Category, ResourceType
| order by
    case(Severity == "High", 1, Severity == "Medium", 2, Severity == "Low", 3, 4) asc,
    UnhealthyCount desc
```

```kql
// Track recommendation status changes — detect when a resource goes from healthy to unhealthy.
// This catches configuration drift or tampering.
let CurrentWindow = 1d;
let PreviousWindow = 2d;
let CurrentState = (SecurityRecommendation
    | where TimeGenerated > ago(CurrentWindow)
    | where RecommendationState == "Unhealthy"
    | extend ResourceId = tostring(Properties.resourceDetails.ResourceId)
    | distinct ResourceId, RecommendationName = tostring(Properties.displayName));
let PreviousState = (SecurityRecommendation
    | where TimeGenerated between (ago(PreviousWindow) .. ago(CurrentWindow))
    | where RecommendationState == "Healthy"
    | extend ResourceId = tostring(Properties.resourceDetails.ResourceId)
    | distinct ResourceId, RecommendationName = tostring(Properties.displayName));
// Resources that were healthy before but are now unhealthy
CurrentState
| join kind=inner PreviousState on ResourceId, RecommendationName
| project ResourceId, RecommendationName, DriftDetected = "Previously Healthy → Now Unhealthy"
| order by RecommendationName asc
```

**Parameters to customize:**
- `CurrentWindow` / `PreviousWindow` — Adjust based on how frequently Defender for Cloud reassesses (typically every 12-24 hours).
- `Severity` — Filter to `"High"` only for critical-path dashboards.

**Performance notes:**
- `SecurityRecommendation` is a snapshot table — each assessment cycle produces a full set of rows. Query the latest window only for current state.
- The drift detection query compares two time windows — keep them tight to avoid false positives from natural reassessment cycles.

---

### Pattern 3 — Compliance Assessment by Framework

Query compliance status against specific regulatory frameworks to prepare for audits and track remediation progress.

```kql
// Compliance posture against a specific regulatory standard.
// Run in Azure Resource Graph Explorer for cross-subscription visibility.
securityresources
| where type == "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols/regulatorycomplianceassessments"
| extend
    Standard = extract(@"/regulatoryComplianceStandards/([^/]+)/", 1, id),
    Control = extract(@"/regulatoryComplianceControls/([^/]+)/", 1, id),
    Assessment = name,
    State = tostring(properties.state),
    PassedResources = toint(properties.passedResources),
    FailedResources = toint(properties.failedResources),
    SkippedResources = toint(properties.skippedResources)
// Filter to your target standard (e.g., CIS, NIST 800-53, PCI DSS)
| where Standard contains "CIS"
| summarize
    TotalPassed = sum(PassedResources),
    TotalFailed = sum(FailedResources),
    TotalSkipped = sum(SkippedResources),
    FailedControls = countif(State == "Failed"),
    PassedControls = countif(State == "Passed")
    by Standard, Control
| extend CompliancePercent = round(todouble(TotalPassed) / todouble(TotalPassed + TotalFailed) * 100, 2)
| order by CompliancePercent asc  // Show least compliant first
```

**Parameters to customize:**
- `Standard contains "CIS"` — Replace with `"NIST"`, `"PCI"`, `"SOC"`, or your target framework.
- Scope to specific subscriptions by adding `| where subscriptionId == "YOUR_SUB_ID"`.

**Performance notes:**
- Azure Resource Graph queries are free and fast. Use them for compliance reporting rather than Log Analytics.
- Resource Graph returns a maximum of 1,000 rows per page; use pagination for large estates.

---

### Pattern 4 — Critical Misconfiguration Detection

Proactively detect the most dangerous cloud misconfigurations — exposed storage, open management ports, and disabled security features.

```kql
// Detect Azure resources with critical misconfigurations using Resource Graph.
// Pattern: storage accounts with public blob access enabled.
resources
| where type == "microsoft.storage/storageaccounts"
| where properties.allowBlobPublicAccess == true
    or properties.publicNetworkAccess == "Enabled"
| project
    ResourceName = name,
    ResourceGroup = resourceGroup,
    SubscriptionId = subscriptionId,
    Location = location,
    PublicBlobAccess = tostring(properties.allowBlobPublicAccess),
    PublicNetworkAccess = tostring(properties.publicNetworkAccess),
    HttpsOnly = tostring(properties.supportsHttpsTrafficOnly),
    MinTlsVersion = tostring(properties.minimumTlsVersion)
| order by ResourceName asc
```

```kql
// Detect VMs with management ports (RDP/SSH) exposed to the internet.
// Uses SecurityRecommendation in Log Analytics.
let LookbackPeriod = 1d;
SecurityRecommendation
| where TimeGenerated > ago(LookbackPeriod)
| where RecommendationState == "Unhealthy"
| where Properties has "management ports" or Properties has "JIT" or Properties has "SSH" or Properties has "RDP"
| extend
    ResourceId = tostring(Properties.resourceDetails.ResourceId),
    RecommendationName = tostring(Properties.displayName),
    Severity = tostring(Properties.metadata.severity),
    RemediationSteps = tostring(Properties.metadata.remediationDescription)
| project
    TimeGenerated,
    ResourceId,
    RecommendationName,
    Severity,
    RemediationSteps
| order by Severity asc
```

**Parameters to customize:**
- Storage account query — Add checks for `properties.encryption.requireInfrastructureEncryption` for double encryption compliance.
- Management port query — Extend `Properties has` filters for your specific compliance requirements.

**Performance notes:**
- Resource Graph queries reflect the current state of Azure resources — no historical data. Combine with `AzureActivity` for change tracking.
- `SecurityRecommendation` queries show the latest assessment state — query within the latest assessment window.

---

### Pattern 5 — Security Alert Correlation with Configuration Changes

Detect when security alerts coincide with configuration changes — a pattern that may indicate an attacker disabling defenses or expanding access.

```kql
// Correlate Defender for Cloud alerts with Azure Activity log changes.
// Catches: attacker disables NSG → alert fires → attacker exploits exposure.
let LookbackPeriod = 7d;
let CorrelationWindowMinutes = 60;
// Security alerts from Defender for Cloud
let Alerts = (SecurityAlert
    | where TimeGenerated > ago(LookbackPeriod)
    | where ProviderName == "Azure Security Center"
    | where AlertSeverity in ("High", "Medium")
    | extend ResourceId = tostring(parse_json(ExtendedProperties).resourceIdentifiers)
    | project
        AlertTime = TimeGenerated,
        AlertName,
        AlertSeverity,
        Description,
        ResourceId,
        CompromisedEntity);
// Configuration changes from Azure Activity
let Changes = (AzureActivity
    | where TimeGenerated > ago(LookbackPeriod)
    | where OperationNameValue has_any ("write", "delete", "action")
    | where ActivityStatusValue == "Success"
    | where CategoryValue == "Administrative"
    | project
        ChangeTime = TimeGenerated,
        Operation = OperationNameValue,
        ResourceId = _ResourceId,
        Caller,
        CallerIpAddress);
// Correlate: changes within 60 minutes before an alert on the same resource
Alerts
| join kind=inner Changes on ResourceId
| where ChangeTime between (ago(LookbackPeriod) .. AlertTime)
| where datetime_diff('minute', AlertTime, ChangeTime) <= CorrelationWindowMinutes
| project
    AlertTime,
    AlertName,
    AlertSeverity,
    ChangeTime,
    Operation,
    Caller,
    CallerIpAddress,
    TimeBetween = datetime_diff('minute', AlertTime, ChangeTime),
    ResourceId
| order by AlertTime desc
```

**Parameters to customize:**
- `CorrelationWindowMinutes` — 60 minutes captures most attack sequences. Extend for slow-and-low activity.
- `AlertSeverity` — Include `"Low"` for comprehensive correlation; restrict to `"High"` for critical triage.

**Performance notes:**
- The join on `ResourceId` can produce large result sets if many changes and alerts share resources. Pre-filter both sides aggressively.
- `AzureActivity` is high-volume — always filter by `CategoryValue` and `ActivityStatusValue` early.

## MITRE ATT&CK Context

| Technique | ID | How This Skill Helps |
|---|---|---|
| Valid Accounts | T1078 | Configuration drift detection (Pattern 2) catches unauthorized permission changes that enable account abuse. |
| Exploit Public-Facing Application | T1190 | Management port exposure detection (Pattern 4) finds VMs vulnerable to exploitation. |
| Data from Cloud Storage Object | T1530 | Public storage detection (Pattern 4) identifies blob containers exposed to data theft. |
| Impair Defenses | T1562 | Alert-change correlation (Pattern 5) detects attackers disabling security controls before exploitation. |

## False Positive Guidance

| Pattern | Common False Positives | Tuning Advice |
|---|---|---|
| Secure score regression | Planned maintenance, resource scaling operations | Correlate with change management tickets; exclude known maintenance windows. |
| Configuration drift | Terraform/Bicep deployments creating temporary unhealthy states | Allow a grace period (2-4 hours) for infrastructure-as-code deployments to converge. |
| Public storage accounts | Intentionally public static website hosting | Tag intentionally public resources; exclude tagged resources from alerts. |
| Alert-change correlation | Normal admin operations (NSG rule updates) that coincidentally precede alerts | Focus on changes by non-admin accounts or from unusual IP addresses. |

## Tuning Guide

### Severity Prioritization Matrix

| Severity | Response SLA | Examples |
|---|---|---|
| High | Investigate within 4 hours | Public storage with sensitive data, exposed RDP, disabled encryption |
| Medium | Investigate within 24 hours | Missing MFA on admin accounts, outdated TLS versions |
| Low | Review in weekly posture meeting | Missing tags, non-optimal SKUs |

### Performance Optimization Checklist

- [ ] Resource Graph queries used for current-state posture (free, fast)
- [ ] Log Analytics queries used for historical trending and correlation
- [ ] `SecurityRecommendation` filtered to latest assessment window
- [ ] `AzureActivity` filtered by `CategoryValue` and `ActivityStatusValue` before joins
- [ ] Compliance queries scoped to target regulatory standard before aggregation
- [ ] Executive dashboards use `bin()` for time-series aggregation to control data points

## Related Skills

- **[Sentinel Analytics Rules](sentinel-analytics-rules.md)** — Promote posture drift detections into automated analytics rules.
- **[Incident Investigation](incident-investigation.md)** — Investigate alerts generated from posture detections.
- **[Detection Tuning](detection-tuning.md)** — Reduce false positives in cloud posture alerting.
- **[Cross-Workspace Queries](cross-workspace-queries.md)** — Query posture data across multiple subscriptions and workspaces.
