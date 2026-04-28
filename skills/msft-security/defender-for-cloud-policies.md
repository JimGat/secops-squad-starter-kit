---
title: Defender for Cloud Policies
category: msft-security
difficulty: intermediate
mitre_attack:
  - T1530  # Data from Cloud Storage
  - T1078  # Valid Accounts
  - T1190  # Exploit Public-Facing Application
  - T1525  # Implant Internal Image
products:
  - Microsoft Defender for Cloud
  - Azure Policy
  - Microsoft Sentinel
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# Defender for Cloud Policies

## Overview

Microsoft Defender for Cloud provides Cloud Security Posture Management (CSPM) and Cloud Workload Protection (CWP) across Azure, AWS, and GCP. This skill covers security policy assignments, regulatory compliance dashboards, Defender plan enablement, workflow automation, and secure score methodology.

Use this skill when:
- Assigning security policies at subscription or management group level
- Configuring regulatory compliance dashboards (NIST, CIS, PCI-DSS, ISO 27001)
- Enabling Defender plans for specific workload types
- Building workflow automation for security recommendations
- Improving secure score systematically

## Prerequisites

| Requirement | Detail |
|---|---|
| **Permissions** | `Security Admin` or `Subscription Contributor` |
| **Licensing** | Foundational CSPM is free; enhanced CSPM and Defender plans require P2/paid plans |
| **Azure Policy** | Subscription must allow policy assignments |
| **Log Analytics** | Workspace for Defender for Cloud data export to Sentinel |

## Configuration Patterns

### Security Policy Assignments

```bicep
@description('Assign CIS Microsoft Azure Foundations Benchmark at management group level')
param managementGroupId string
param policySetDefinitionId string = '/providers/Microsoft.Authorization/policySetDefinitions/1a5bb27d-173f-493e-9568-eb56638dde4d' // CIS v2.0

resource policyAssignment 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'cis-azure-benchmark'
  properties: {
    displayName: 'CIS Microsoft Azure Foundations Benchmark v2.0'
    description: 'Assigns the CIS benchmark to evaluate Azure resource compliance'
    policyDefinitionId: policySetDefinitionId
    enforcementMode: 'Default'
    parameters: {}
    nonComplianceMessages: [
      {
        message: 'This resource does not comply with CIS Microsoft Azure Foundations Benchmark v2.0. Review the recommendation in Defender for Cloud.'
      }
    ]
  }
}
```

```powershell
# Assign policies at subscription level
$subscriptionId = '<subscription-id>'

# Enable Microsoft Cloud Security Benchmark (MCSB) — the default initiative
$policySetId = "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8"

New-AzPolicyAssignment -Name "mcsb-assignment" `
    -DisplayName "Microsoft Cloud Security Benchmark" `
    -PolicySetDefinition (Get-AzPolicySetDefinition -Id $policySetId) `
    -Scope "/subscriptions/$subscriptionId" `
    -EnforcementMode "Default"

# Assign additional regulatory compliance standards
$standards = @{
    'NIST SP 800-53 Rev. 5' = 'nist-sp-800-53-r5'
    'PCI DSS v4.0'          = 'pci-dss-v4'
    'ISO 27001:2013'        = 'iso-27001-2013'
    'CIS v2.0'              = 'cis-azure-2.0'
}

foreach ($standard in $standards.GetEnumerator()) {
    Write-Host "Assigning: $($standard.Key)" -ForegroundColor Cyan
    # Assign via Portal: Defender for Cloud > Environment settings > Security policies > Add standard
}
```

### Regulatory Compliance Dashboard Configuration

| Standard | Policy Set ID | Focus Areas |
|---|---|---|
| **Microsoft Cloud Security Benchmark** | `1f3afdf9-d0c9-4c3d-847f-89da613e70a8` | General cloud security baseline |
| **NIST SP 800-53 Rev. 5** | `179d1daa-458f-4e47-8086-2a68d0d6c38f` | Federal/government compliance |
| **PCI DSS v4.0** | Azure-specific | Payment card data environments |
| **ISO 27001:2013** | `89c6cddc-1c73-4ac1-b19c-54d1a15a42f2` | Information security management |
| **CIS Azure Foundations v2.0** | `1a5bb27d-173f-493e-9568-eb56638dde4d` | Infrastructure hardening |
| **SOC 2 Type 2** | Azure-specific | Service organization controls |

### Defender Plans Enablement

```bicep
@description('Enable Defender plans for a subscription')
param location string = 'global'

// Defender for Servers Plan 2
resource defenderServers 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'VirtualMachines'
  properties: {
    pricingTier: 'Standard'
    subPlan: 'P2'
    extensions: [
      {
        name: 'MdeDesignatedSubscription'
        isEnabled: 'True'
      }
      {
        name: 'AgentlessVmScanning'
        isEnabled: 'True'
      }
    ]
  }
}

// Defender for Storage
resource defenderStorage 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'StorageAccounts'
  properties: {
    pricingTier: 'Standard'
    subPlan: 'DefenderForStorageV2'
    extensions: [
      {
        name: 'OnUploadMalwareScanning'
        isEnabled: 'True'
        additionalExtensionProperties: {
          CapGBPerMonthPerStorageAccount: '5000'
        }
      }
      {
        name: 'SensitiveDataDiscovery'
        isEnabled: 'True'
      }
    ]
  }
}

// Defender for SQL
resource defenderSql 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'SqlServers'
  properties: {
    pricingTier: 'Standard'
  }
}

// Defender for App Service
resource defenderAppService 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'AppServices'
  properties: {
    pricingTier: 'Standard'
  }
}

// Defender for Key Vault
resource defenderKeyVault 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'KeyVaults'
  properties: {
    pricingTier: 'Standard'
  }
}

// Defender for ARM
resource defenderArm 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'Arm'
  properties: {
    pricingTier: 'Standard'
  }
}

// Defender for DNS
resource defenderDns 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'Dns'
  properties: {
    pricingTier: 'Standard'
  }
}

// Defender for Containers
resource defenderContainers 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'Containers'
  properties: {
    pricingTier: 'Standard'
    extensions: [
      {
        name: 'ContainerVulnerabilityAssessment'
        isEnabled: 'True'
      }
    ]
  }
}
```

```powershell
# Quick enable via PowerShell
$plans = @(
    'VirtualMachines', 'StorageAccounts', 'SqlServers',
    'AppServices', 'KeyVaults', 'Arm', 'Dns', 'Containers'
)

foreach ($plan in $plans) {
    Set-AzSecurityPricing -Name $plan -PricingTier "Standard"
    Write-Host "Enabled Defender for: $plan" -ForegroundColor Green
}
```

### CSPM vs Workload Protection (CWP)

| Capability | Foundational CSPM (Free) | Defender CSPM (Paid) | Workload Protection (CWP) |
|---|---|---|---|
| Secure score | ✅ | ✅ | — |
| Security recommendations | ✅ Basic | ✅ Enhanced | Per-workload |
| Asset inventory | ✅ | ✅ | — |
| Attack path analysis | — | ✅ | — |
| Agentless scanning | — | ✅ | — |
| Cloud security explorer | — | ✅ | — |
| Data-aware security posture | — | ✅ | — |
| Governance rules | — | ✅ | — |
| Threat detection | — | — | ✅ |
| Vulnerability assessment | — | ✅ Agentless | ✅ Agent-based |

### Workflow Automation for Recommendations

```bicep
@description('Workflow automation to notify on high-severity recommendations')
param logicAppResourceId string
param workspaceName string

resource automation 'Microsoft.Security/automations@2023-12-01-preview' = {
  name: 'auto-high-severity-recommendations'
  location: resourceGroup().location
  properties: {
    isEnabled: true
    description: 'Trigger Logic App when high-severity recommendation is created'
    scopes: [
      {
        description: 'Subscription scope'
        scopePath: subscription().id
      }
    ]
    sources: [
      {
        eventSource: 'Assessments'
        ruleSets: [
          {
            rules: [
              {
                propertyJPath: 'properties.status.code'
                propertyType: 'String'
                expectedValue: 'Unhealthy'
                operator: 'Equals'
              }
              {
                propertyJPath: 'properties.metadata.severity'
                propertyType: 'String'
                expectedValue: 'High'
                operator: 'Equals'
              }
            ]
          }
        ]
      }
    ]
    actions: [
      {
        actionType: 'LogicApp'
        logicAppResourceId: logicAppResourceId
        uri: 'https://placeholder-will-be-replaced.azurewebsites.net'
      }
    ]
  }
}
```

### Secure Score Improvement Methodology

**Phase 1: Quick Wins (Week 1)**
1. Enable MFA for all admin accounts (+10% score)
2. Enable Defender plans for critical workloads
3. Restrict management port access (JIT VM access)
4. Enable encryption at rest for storage accounts

**Phase 2: Infrastructure Hardening (Weeks 2–4)**
1. Apply NSG rules to all subnets
2. Enable diagnostic logging for all resources
3. Configure key rotation policies
4. Enable DDoS protection standard

**Phase 3: Advanced Posture (Months 2–3)**
1. Enable Defender CSPM for attack path analysis
2. Configure governance rules for recommendation tracking
3. Implement Azure Policy deny assignments for high-risk configurations
4. Set up continuous export to Sentinel for posture monitoring

```kql
// Track secure score over time
SecureScores
| where TimeGenerated > ago(90d)
| summarize Score = avg(PercentageScore) by bin(TimeGenerated, 1d)
| render timechart
```

## Integration Points

- **Microsoft Sentinel** — Continuous export of alerts and recommendations to Log Analytics
- **Azure Policy** — Compliance policies evaluated and reported in Defender for Cloud
- **Defender XDR** — Cloud workload alerts correlate with identity and endpoint signals
- **Azure Resource Graph** — Query security posture data programmatically
- **Logic Apps** — Automated remediation workflows triggered by recommendations

## Operational Procedures

### Weekly Posture Review KQL

```kql
// Defender for Cloud — recommendation compliance summary
SecureScoreControls
| where TimeGenerated > ago(1d)
| summarize
    HealthyResources = sum(HealthyResourceCount),
    UnhealthyResources = sum(UnhealthyResourceCount),
    NotApplicable = sum(NotApplicableResourceCount)
    by ControlName
| extend ComplianceRate = round(100.0 * HealthyResources / (HealthyResources + UnhealthyResources), 1)
| sort by ComplianceRate asc
| take 20
```

```kql
// Track Defender plan alerts over the last 30 days
SecurityAlert
| where TimeGenerated > ago(30d)
| where ProviderName == "Azure Security Center"
| summarize AlertCount = count() by AlertType, AlertSeverity
| sort by AlertCount desc
```

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| Secure score not updating | Assessment runs every 12 hours | Wait for next assessment cycle; force refresh via API |
| Policy shows "Not started" | Policy assignment not scoped correctly | Verify scope includes target subscription/management group |
| Defender plan not detecting threats | Agent not installed (Servers plan) | Deploy MDE agent via Defender for Cloud auto-provisioning |
| Compliance dashboard empty | Standard not assigned | Assign regulatory compliance standard in Environment settings |
| Workflow automation not triggering | Logic App trigger URL expired | Regenerate Logic App trigger URL; update automation |
| Recommendations not appearing | Resource type not covered by enabled plans | Enable the corresponding Defender plan |

## Related Skills

- **[Sentinel Workspace Setup](sentinel-workspace-setup.md)** — Export Defender alerts to Sentinel
- **[Defender XDR Configuration](defender-xdr-configuration.md)** — Correlate cloud alerts with XDR
- **[Defender for Endpoint](defender-for-endpoint.md)** — Server protection via Defender for Servers
- **[MITRE ATT&CK Mapping](../detection/mitre-attack-mapping.md)** — Map cloud attack techniques
- **[Purview DLP Patterns](purview-dlp-patterns.md)** — Data protection policies complement cloud posture
