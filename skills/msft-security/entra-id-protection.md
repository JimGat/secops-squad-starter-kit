---
title: Entra ID Protection
category: msft-security
difficulty: intermediate
mitre_attack:
  - T1078  # Valid Accounts
  - T1110  # Brute Force
  - T1556  # Modify Authentication Process
  - T1539  # Steal Web Session Cookie
products:
  - Microsoft Entra ID Protection
  - Microsoft Entra ID
  - Microsoft Entra Conditional Access
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# Entra ID Protection

## Overview

Microsoft Entra ID Protection uses machine learning to detect identity-based risks in real time — impossible travel, leaked credentials, password spray, anomalous token activity — and enforces automated remediation through risk-based Conditional Access policies. This skill covers user risk policies, sign-in risk policies, Conditional Access design patterns, and gap analysis methodology.

Use this skill when:
- Configuring user risk and sign-in risk policies
- Designing Conditional Access policies for Zero Trust
- Mapping risk detection types to response actions
- Running Conditional Access gap analysis
- Integrating identity protection with Defender XDR and Sentinel

## Prerequisites

| Requirement | Detail |
|---|---|
| **Licensing** | Microsoft Entra ID P2 (included in M365 E5) |
| **Permissions** | `Security Administrator` or `Conditional Access Administrator` |
| **MFA** | Users must be registered for MFA before risk policies enforce MFA challenges |
| **SSPR** | Self-Service Password Reset must be enabled before user risk policies enforce password reset |

## Configuration Patterns

### User Risk Policy Configuration

User risk represents the probability that a user's identity has been compromised.

```powershell
# Configure user risk policy via Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess", "Policy.Read.All"

# Create Conditional Access policy for user risk
$params = @{
    displayName = "CA-201: Require password change for high-risk users"
    state = "enabledForReportingButNotEnforced"  # Start in report-only
    conditions = @{
        users = @{
            includeUsers = @("All")
            excludeUsers = @("<break-glass-account-id>")  # Always exclude emergency access
        }
        userRiskLevels = @("high")
        applications = @{
            includeApplications = @("All")
        }
    }
    grantControls = @{
        operator = "AND"
        builtInControls = @("passwordChange", "mfa")
    }
    sessionControls = @{
        signInFrequency = @{
            value = 0
            type = "everyTime"
            isEnabled = $true
        }
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $params
```

**User Risk Response Matrix:**

| Risk Level | Recommended Action | Rationale |
|---|---|---|
| **High** | Block + Force password reset + MFA | Strong evidence of compromise; credential likely leaked |
| **Medium** | Force password reset + MFA | Moderate confidence; remediate proactively |
| **Low** | MFA challenge | Low confidence but worth verifying identity |
| **None** | No action | Normal behavior |

### Sign-In Risk Policy Configuration

Sign-in risk represents the probability that a specific authentication request is not authorized by the identity owner.

```powershell
# Sign-in risk policy
$signInRiskPolicy = @{
    displayName = "CA-202: Require MFA for medium+ risk sign-ins"
    state = "enabledForReportingButNotEnforced"
    conditions = @{
        users = @{
            includeUsers = @("All")
            excludeUsers = @("<break-glass-account-id>")
        }
        signInRiskLevels = @("medium", "high")
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("browser", "mobileAppsAndDesktopClients")
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
    sessionControls = @{
        signInFrequency = @{
            value = 1
            type = "hours"
            isEnabled = $true
        }
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $signInRiskPolicy

# Block high-risk sign-ins outright
$blockHighRisk = @{
    displayName = "CA-203: Block high-risk sign-ins"
    state = "enabledForReportingButNotEnforced"
    conditions = @{
        users = @{
            includeUsers = @("All")
            excludeUsers = @("<break-glass-account-id>")
        }
        signInRiskLevels = @("high")
        applications = @{
            includeApplications = @("All")
        }
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("block")
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $blockHighRisk
```

### Risk Detection Types and Severity Mapping

| Detection | Risk Type | Severity | MITRE | Description |
|---|---|---|---|---|
| **Leaked credentials** | User | High | T1078 | Credentials found in dark web dumps |
| **Password spray** | Sign-in | High | T1110.003 | Multiple accounts targeted with common passwords |
| **Impossible travel** | Sign-in | Medium | T1078 | Logins from geographically distant locations |
| **Anomalous token** | Sign-in | High | T1539 | Token with unusual characteristics |
| **Unfamiliar sign-in properties** | Sign-in | Medium | T1078 | New device/location/IP combination |
| **Malicious IP address** | Sign-in | Medium | T1078 | Sign-in from known malicious IP |
| **Suspicious inbox forwarding** | User | Medium | T1114.003 | Email rules forwarding to external addresses |
| **Atypical travel** | Sign-in | Low | T1078 | Travel pattern inconsistent with history |
| **Anonymous IP address** | Sign-in | Low | T1090 | Sign-in from VPN/Tor/proxy |
| **Token issuer anomaly** | Sign-in | High | T1556 | Unusual token issuer detected |

### Self-Service Password Reset (SSPR) Configuration

SSPR must be enabled before user risk policies can enforce password reset.

```powershell
# Configure SSPR via Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.AuthenticationMethod"

# Enable SSPR for all users
$sspr = @{
    isEnabled = $true
    isSelfServicePasswordResetEnabledForAll = $true
    authenticationMethodsRequired = 2  # Require 2 methods
    allowedMethods = @(
        "mobilePhone",
        "email",
        "microsoftAuthenticator",
        "securityQuestion"
    )
    numberOfQuestionsRequired = 3
    registrationRequiredOnSignin = $true
    registrationReconfirmationPeriod = 180  # Days
}

# Verify SSPR readiness
Get-MgReportAuthenticationMethodUserRegistrationDetail -Top 100 |
    Where-Object { $_.IsSsprRegistered -eq $false } |
    Select-Object UserPrincipalName, IsSsprRegistered, IsMfaRegistered |
    Export-Csv "sspr-gaps.csv" -NoTypeInformation
```

### Conditional Access Policy Design Patterns

**Zero Trust Foundation — Recommended Policy Set:**

| Policy ID | Name | Conditions | Grant/Session | Priority |
|---|---|---|---|---|
| CA-001 | Require MFA for all users | All users, All apps | Require MFA | Foundation |
| CA-002 | Block legacy authentication | All users, All apps, Legacy clients | Block | Foundation |
| CA-003 | Require compliant device for Office 365 | All users, Office 365 apps | Require compliant device | Data protection |
| CA-100 | Require MFA for admins | Directory roles (GA, PA, etc.) | Require MFA, Compliant device | Admin protection |
| CA-101 | Block admin access from untrusted locations | Admin roles, Exclude named locations | Block | Admin protection |
| CA-201 | Password change for high-risk users | All users, High user risk | Password change + MFA | Risk-based |
| CA-202 | MFA for risky sign-ins | All users, Medium+ sign-in risk | Require MFA | Risk-based |
| CA-203 | Block high-risk sign-ins | All users, High sign-in risk | Block | Risk-based |
| CA-300 | App protection for mobile | All users, Office 365, iOS/Android | Require app protection policy | Mobile |
| CA-900 | Emergency access exclusion | Break-glass accounts | Exclude from all policies | Safety |

```powershell
# Named locations — define trusted corporate networks
$namedLocation = @{
    "@odata.type" = "#microsoft.graph.ipNamedLocation"
    displayName = "Corporate Network"
    isTrusted = $true
    ipRanges = @(
        @{
            "@odata.type" = "#microsoft.graph.iPv4CidrRange"
            cidrAddress = "203.0.113.0/24"
        },
        @{
            "@odata.type" = "#microsoft.graph.iPv4CidrRange"
            cidrAddress = "198.51.100.0/24"
        }
    )
}

New-MgIdentityConditionalAccessNamedLocation -BodyParameter $namedLocation

# Country-based named location
$countryLocation = @{
    "@odata.type" = "#microsoft.graph.countryNamedLocation"
    displayName = "Blocked Countries"
    countriesAndRegions = @("KP", "IR", "RU", "CN")  # Adjust per risk profile
    includeUnknownCountriesAndRegions = $false
}

New-MgIdentityConditionalAccessNamedLocation -BodyParameter $countryLocation
```

### Conditional Access Gap Analysis Methodology

**Step 1: Export current policies**

```powershell
# Export all Conditional Access policies
$policies = Get-MgIdentityConditionalAccessPolicy -All
$policies | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.DisplayName
        State = $_.State
        Users = ($_.Conditions.Users.IncludeUsers -join ', ')
        Apps = ($_.Conditions.Applications.IncludeApplications -join ', ')
        Grant = ($_.GrantControls.BuiltInControls -join ', ')
        SignInRisk = ($_.Conditions.SignInRiskLevels -join ', ')
        UserRisk = ($_.Conditions.UserRiskLevels -join ', ')
        Platforms = ($_.Conditions.Platforms.IncludePlatforms -join ', ')
        Locations = ($_.Conditions.Locations.IncludeLocations -join ', ')
    }
} | Export-Csv "ca-policy-inventory.csv" -NoTypeInformation
```

**Step 2: Gap analysis checklist**

| Check | Question | Gap If Missing |
|---|---|---|
| **MFA coverage** | Do all users have MFA enforced? | Credential theft risk (T1078) |
| **Legacy auth block** | Is legacy authentication blocked? | Password spray bypass (T1110) |
| **Admin protection** | Do admins have stricter policies? | Privileged account compromise |
| **Risk-based policies** | Are sign-in and user risk policies active? | No automated response to detected risks |
| **Device compliance** | Is device compliance required for sensitive apps? | Unmanaged device data leakage |
| **Break-glass accounts** | Are emergency access accounts excluded? | Lockout risk during outage |
| **Named locations** | Are trusted networks defined? | Can't differentiate corporate vs external access |
| **Session controls** | Are sign-in frequency and persistent browser configured? | Excessive token lifetimes |

**Step 3: Validate with What-If**

```powershell
# Use the What-If tool to test policy evaluation
# Portal: Entra admin center > Protection > Conditional Access > What If

# Test scenario: External user, unknown device, risky sign-in
# Expected: MFA required + session limited to 1 hour
# If result shows "No policies applied" → gap identified
```

## Integration Points

- **Defender XDR** — Risk detections appear as alerts in the unified portal
- **Microsoft Sentinel** — Sign-in and audit logs with risk data flow via connector
- **Defender for Identity** — On-prem identity compromise feeds into cloud risk scores
- **Defender for Cloud Apps** — Session controls enforce real-time access decisions
- **Microsoft Purview** — Identity risk correlates with data access patterns

## Operational Procedures

### Daily Risk Monitoring KQL

```kql
// High-risk users in the last 24 hours
AADUserRiskEvents
| where TimeGenerated > ago(24h)
| where RiskLevel in ("high", "medium")
| summarize
    RiskEvents = count(),
    RiskTypes = make_set(RiskEventType),
    LatestRisk = max(TimeGenerated)
    by UserPrincipalName, RiskLevel, RiskState
| sort by RiskLevel, RiskEvents desc
```

```kql
// Conditional Access policy failures — users being blocked
SigninLogs
| where TimeGenerated > ago(24h)
| where ConditionalAccessStatus == "failure"
| summarize
    BlockCount = count(),
    Policies = make_set(ConditionalAccessPolicies[0].displayName)
    by UserPrincipalName, IPAddress, AppDisplayName
| sort by BlockCount desc
| take 20
```

```kql
// Users with risky sign-ins who weren't challenged with MFA
SigninLogs
| where TimeGenerated > ago(24h)
| where RiskLevelDuringSignIn in ("medium", "high")
| where MfaDetail.authMethod == ""
| project TimeGenerated, UserPrincipalName, IPAddress, RiskLevelDuringSignIn, 
    AppDisplayName, ConditionalAccessStatus
| sort by TimeGenerated desc
```

### Weekly Risk Review

1. Review and remediate high-risk users (confirm or dismiss risks)
2. Analyze Conditional Access report-only policies — move to enabled if no false positives
3. Check MFA registration gaps — users not registered can't be challenged
4. Review named location definitions — update corporate IP ranges if changed

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| Risk policy not triggering | Policy in report-only mode | Move to enabled after validation period |
| Users can't reset password | SSPR not enabled or not registered | Enable SSPR; require registration at next sign-in |
| MFA prompt not appearing for risky sign-in | Policy conditions don't match | Check client app type, user scope, and risk level in policy |
| False positive impossible travel | VPN or corporate proxy | Add VPN egress IPs to named locations as trusted |
| Break-glass account locked out | Emergency account not excluded | Add break-glass to exclusion group in all policies |
| Conditional Access "Not applied" | Policy disabled or conditions not met | Use What-If tool to diagnose; check policy state |

## Related Skills

- **[Defender for Identity](defender-for-identity.md)** — On-prem identity threats feed into Entra risk scores
- **[Defender XDR Configuration](defender-xdr-configuration.md)** — Identity risk in the unified portal
- **[Sentinel Workspace Setup](sentinel-workspace-setup.md)** — Identity logs in Sentinel
- **[Microsoft Graph Security](microsoft-graph-security.md)** — API access to risk detections and policies
- **[Scheduled Rule Pattern](../detection/scheduled-rule-pattern.md)** — Custom Sentinel rules for identity events
- **[MITRE ATT&CK Mapping](../detection/mitre-attack-mapping.md)** — Map identity attack techniques
