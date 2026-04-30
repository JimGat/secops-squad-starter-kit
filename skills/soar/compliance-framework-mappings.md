---
title: "Compliance Framework Mappings — Automated Posture Assessment"
category: soar
difficulty: advanced
products:
  - Microsoft Defender for Cloud
  - Microsoft Sentinel
  - Microsoft Purview
  - Microsoft Secure Score
author: Herc
version: 1.0.0
last_updated: 2026-04-30
frameworks:
  - NIST-800-53-r5
  - CIS-Controls-v8
  - PCI-DSS-v4
  - HIPAA
  - SOC2
  - ISO-27001-2022
---

# Compliance Framework Mappings — Automated Posture Assessment

## Overview

Compliance mapping bridges the gap between what your security controls *do* and what regulations *require*. Without automation, compliance teams manually cross-reference hundreds of controls across frameworks — a process that's slow, error-prone, and stale by the time it's finished.

This skill automates **continuous compliance posture assessment** by mapping Microsoft security controls (Defender for Cloud, Secure Score, Sentinel analytics, Purview DLP) to six major regulatory frameworks. The result: real-time gap analysis, automated evidence collection, and audit-ready reports — all scriptable, all repeatable.

**What this skill covers:**
1. Control mapping across 6 frameworks to Microsoft's security stack
2. Automated compliance assessment pipelines (Logic Apps + Defender API)
3. Gap analysis automation — current state vs. required controls
4. Evidence collection for audit readiness
5. `.secops/compliance/requirements.yaml` integration for environment-aware assessments

## Environment Context

Before running compliance assessments, check `.secops/compliance/requirements.yaml` for:
- **Applicable frameworks** — only assess against frameworks your organization is subject to
- **Data residency constraints** — assessment data must stay in allowed regions
- **Retention requirements** — compliance evidence must meet minimum retention periods
- **Prohibited regions** — never deploy compliance resources outside allowed regions

```powershell
# Quick check: which frameworks apply?
$config = Get-Content ".secops/compliance/requirements.yaml" -Raw | ConvertFrom-Yaml
$config.regulatory_frameworks | ForEach-Object { $_.name }
```

---

## Supported Frameworks

### NIST 800-53 Rev 5

**18 Control Families:**

| Family | ID | Description | Microsoft Mapping |
|--------|----|-------------|-------------------|
| Access Control | AC | Account management, access enforcement, separation of duties | Entra ID Conditional Access, PIM, RBAC |
| Audit & Accountability | AU | Audit events, content, storage, review | Sentinel, Log Analytics, Purview Audit |
| Assessment & Authorization | CA | Security assessments, continuous monitoring | Defender for Cloud, Secure Score |
| Configuration Management | CM | Baseline configs, change control | Azure Policy, Defender CSPM |
| Contingency Planning | CP | Backup, recovery, system resilience | Azure Backup, ASR, availability zones |
| Identification & Authentication | IA | MFA, authenticator management | Entra ID, FIDO2, Authenticator |
| Incident Response | IR | Incident handling, monitoring, reporting | Sentinel, SOAR playbooks |
| Maintenance | MA | Controlled maintenance, remote access | Azure Update Manager, Bastion |
| Media Protection | MP | Media sanitization, transport | Azure Disk Encryption, Purview |
| Physical & Environmental | PE | Physical access, environmental controls | Azure datacenter (inherited) |
| Planning | PL | Security plans, rules of behavior | Governance policies |
| Program Management | PM | Risk management strategy | Defender for Cloud, Governance |
| Personnel Security | PS | Personnel screening, termination | Entra ID lifecycle, access reviews |
| Risk Assessment | RA | Vulnerability scanning, risk assessment | Defender Vulnerability Management |
| System & Services Acquisition | SA | SDLC, supply chain, testing | GitHub Advanced Security, Defender for DevOps |
| System & Comms Protection | SC | Boundary protection, cryptography | NSG, Azure Firewall, Key Vault, TLS |
| System & Information Integrity | SI | Flaw remediation, malware protection | Defender for Endpoint, Defender for Cloud |
| Supply Chain Risk Management | SR | Supply chain controls | Defender for DevOps, SBOM |

### CIS Controls v8

**18 Control Groups:**

| # | Control Group | Microsoft Products |
|---|--------------|-------------------|
| 1 | Inventory & Control of Enterprise Assets | Defender for Endpoint, Intune |
| 2 | Inventory & Control of Software Assets | Defender Vulnerability Management |
| 3 | Data Protection | Purview DLP, Information Protection |
| 4 | Secure Configuration of Assets | Azure Policy, Defender CSPM |
| 5 | Account Management | Entra ID, PIM, Access Reviews |
| 6 | Access Control Management | Conditional Access, RBAC |
| 7 | Continuous Vulnerability Management | Defender Vulnerability Management |
| 8 | Audit Log Management | Log Analytics, Sentinel |
| 9 | Email & Web Browser Protections | Defender for Office 365 |
| 10 | Malware Defenses | Defender for Endpoint, Defender AV |
| 11 | Data Recovery | Azure Backup, ASR |
| 12 | Network Infrastructure Management | Azure Firewall, NSG, Network Watcher |
| 13 | Network Monitoring & Defense | Sentinel, NDR, Azure Firewall |
| 14 | Security Awareness Training | Attack Simulation Training |
| 15 | Service Provider Management | Lighthouse, Defender for Cloud Apps |
| 16 | Application Software Security | Defender for DevOps, GitHub GHAS |
| 17 | Incident Response Management | Sentinel SOAR, playbooks |
| 18 | Penetration Testing | Defender EASM, red team tooling |

### PCI-DSS v4.0

**12 Requirements mapped:**

| Req | Title | Primary Microsoft Control |
|-----|-------|--------------------------|
| 1 | Install & maintain network security controls | Azure Firewall, NSG, Private Endpoints |
| 2 | Apply secure configurations | Azure Policy, Defender CSPM |
| 3 | Protect stored account data | Purview Information Protection, Azure Disk Encryption |
| 4 | Protect cardholder data with strong crypto in transit | Azure TLS 1.2+, Key Vault |
| 5 | Protect from malicious software | Defender for Endpoint, Defender AV |
| 6 | Develop & maintain secure systems | Defender for DevOps, GitHub GHAS |
| 7 | Restrict access by business need-to-know | Entra ID RBAC, PIM, Conditional Access |
| 8 | Identify users & authenticate access | Entra ID MFA, FIDO2, passwordless |
| 9 | Restrict physical access to cardholder data | Azure datacenter controls (inherited) |
| 10 | Log & monitor all access | Sentinel, Log Analytics, Purview Audit |
| 11 | Test security of systems & networks regularly | Defender Vulnerability Management, EASM |
| 12 | Support information security with policies & programs | Compliance Manager, Governance |

### HIPAA

| Safeguard Category | Key Requirements | Microsoft Controls |
|-------------------|-----------------|-------------------|
| **Administrative** | Risk analysis, workforce training, access management, contingency planning | Defender for Cloud risk assessments, Attack Simulation Training, Entra ID access reviews, Azure Backup |
| **Physical** | Facility access, workstation security, device controls | Intune MDM, Defender for Endpoint, Azure datacenter (inherited) |
| **Technical** | Access control, audit controls, integrity controls, transmission security | Conditional Access + MFA, Sentinel audit logging, Purview Information Protection, TLS + encryption |

### SOC 2 Trust Service Criteria

| Category | ID | Criteria | Microsoft Controls |
|----------|-----|---------|-------------------|
| Common Criteria | CC1-CC9 | Organization & management, communications, risk assessment, monitoring, logical access, system operations, change management | Entra ID, Defender for Cloud, Azure Policy, Azure Monitor |
| Availability | A1 | System availability commitments | Azure SLAs, availability zones, ASR |
| Processing Integrity | PI1 | Processing completeness, accuracy | Azure Monitor, Application Insights |
| Confidentiality | C1 | Confidential information protection | Purview, Azure Key Vault, encryption |
| Privacy | P1-P8 | Notice, consent, collection, use, retention, disclosure, quality, monitoring | Purview, Priva, data lifecycle management |

### ISO 27001:2022 (Annex A)

| Clause | Controls | Microsoft Mapping |
|--------|----------|-------------------|
| A.5 | Organizational (37 controls) | Azure Policy, Defender for Cloud, Governance |
| A.6 | People (8 controls) | Entra ID lifecycle, access reviews |
| A.7 | Physical (14 controls) | Azure datacenter (inherited), Intune |
| A.8 | Technological (34 controls) | Defender XDR, Sentinel, Purview, Key Vault, Conditional Access |

---

## Microsoft Control Mapping

### Defender for Cloud Regulatory Compliance

Defender for Cloud natively maps assessments to regulatory standards. Query these programmatically:

```powershell
# List all regulatory compliance standards enabled in subscription
$standards = Get-AzSecurityRegulatoryComplianceStandard
$standards | Select-Object Name, State, PassedControls, FailedControls, SkippedControls |
    Format-Table -AutoSize

# Get controls for a specific standard
$controls = Get-AzSecurityRegulatoryComplianceControl -StandardName "NIST-SP-800-53-R5"
$controls | Select-Object Name, State, PassedAssessments, FailedAssessments |
    Sort-Object State | Format-Table -AutoSize

# Get individual assessment results for a control
$assessments = Get-AzSecurityRegulatoryComplianceAssessment `
    -StandardName "NIST-SP-800-53-R5" `
    -ControlName "AC-2"
$assessments | Select-Object Name, State, Description | Format-Table -AutoSize
```

### Secure Score to Framework Requirements

```powershell
# Map Secure Score controls to framework requirements
$secureScore = Get-AzSecuritySecureScoreControl
foreach ($control in $secureScore) {
    [PSCustomObject]@{
        Control      = $control.DisplayName
        Score        = "$($control.CurrentScore)/$($control.MaxScore)"
        Weight       = $control.Weight
        # Cross-reference to compliance framework
        NIST_Mapping = Get-NISTMapping -ControlName $control.DisplayName
        CIS_Mapping  = Get-CISMapping -ControlName $control.DisplayName
    }
}

# Helper: Map Secure Score control names to NIST families
function Get-NISTMapping {
    param([string]$ControlName)
    $map = @{
        "Enable MFA"                        = "IA-2"
        "Manage access and permissions"     = "AC-2, AC-3, AC-6"
        "Apply system updates"              = "SI-2"
        "Remediate vulnerabilities"         = "RA-5, SI-2"
        "Enable endpoint protection"        = "SI-3"
        "Enable encryption at rest"         = "SC-28"
        "Enable encryption in transit"      = "SC-8"
        "Restrict unauthorized network access" = "SC-7, AC-4"
        "Enable auditing and logging"       = "AU-2, AU-3, AU-6"
    }
    return $map[$ControlName] ?? "Review manually"
}
```

### Sentinel Analytics Rules to Detection Requirements

```kql
// Query: Map analytics rules to frameworks they satisfy
SecurityIncident
| where TimeGenerated > ago(30d)
| extend RuleId = tostring(parse_json(tostring(AdditionalData)).alertProductNames)
| join kind=inner (
    _GetWatchlist('ComplianceDetectionMap')
    | project RuleId = SearchKey,
              Framework = Framework,
              ControlId = ControlId,
              Requirement = Requirement
) on RuleId
| summarize
    IncidentCount = count(),
    Frameworks = make_set(Framework),
    Controls = make_set(ControlId)
    by RuleName = Title
| sort by IncidentCount desc
```

### Purview DLP to Data Protection Requirements

```powershell
# Map DLP policies to framework data protection requirements
$dlpPolicies = Get-DlpCompliancePolicy

foreach ($policy in $dlpPolicies) {
    $rules = Get-DlpComplianceRule -Policy $policy.Name
    foreach ($rule in $rules) {
        [PSCustomObject]@{
            PolicyName      = $policy.Name
            RuleName        = $rule.Name
            SensitiveTypes  = ($rule.ContentContainsSensitiveInformation |
                              ForEach-Object { $_.Name }) -join ", "
            PCI_DSS         = if ($rule.ContentContainsSensitiveInformation.Name -match
                              "Credit Card") { "Req 3, Req 4" } else { "N/A" }
            HIPAA           = if ($rule.ContentContainsSensitiveInformation.Name -match
                              "Health|Medical") { "Technical Safeguards" } else { "N/A" }
            NIST            = "SC-28, MP-5"
        }
    }
}
```

---

## Automation Patterns

### Pattern 1: Automated Compliance Assessment Pipeline

This Logic App runs a full compliance assessment, queries Defender for Cloud, and generates a report.

```json
{
  "definition": {
    "triggers": {
      "Recurrence": {
        "type": "Recurrence",
        "recurrence": { "frequency": "Week", "interval": 1, "schedule": { "weekDays": ["Monday"] } }
      }
    },
    "actions": {
      "Get_Compliance_Standards": {
        "type": "Http",
        "inputs": {
          "method": "GET",
          "uri": "https://management.azure.com/subscriptions/@{parameters('subscriptionId')}/providers/Microsoft.Security/regulatoryComplianceStandards?api-version=2019-01-01-preview",
          "authentication": { "type": "ManagedServiceIdentity" }
        }
      },
      "For_Each_Standard": {
        "type": "Foreach",
        "foreach": "@body('Get_Compliance_Standards')?['value']",
        "actions": {
          "Get_Controls": {
            "type": "Http",
            "inputs": {
              "method": "GET",
              "uri": "https://management.azure.com@{items('For_Each_Standard')?['id']}/regulatoryComplianceControls?api-version=2019-01-01-preview",
              "authentication": { "type": "ManagedServiceIdentity" }
            }
          },
          "Calculate_Posture": {
            "type": "Compose",
            "inputs": {
              "standard": "@items('For_Each_Standard')?['name']",
              "passed": "@length(body('Get_Controls')?['value']?[?properties.state=='Passed'])",
              "failed": "@length(body('Get_Controls')?['value']?[?properties.state=='Failed'])",
              "timestamp": "@utcNow()"
            }
          }
        }
      },
      "Generate_Report": {
        "type": "Http",
        "inputs": {
          "method": "POST",
          "uri": "@parameters('reportEndpoint')",
          "body": {
            "assessmentDate": "@utcNow()",
            "results": "@variables('assessmentResults')",
            "overallScore": "@variables('overallScore')"
          }
        }
      },
      "Send_Report_Email": {
        "type": "ApiConnection",
        "inputs": {
          "host": { "connection": { "name": "@parameters('$connections')['office365']['connectionId']" } },
          "method": "post",
          "path": "/v2/Mail",
          "body": {
            "To": "@parameters('complianceTeamEmail')",
            "Subject": "Weekly Compliance Assessment — @{formatDateTime(utcNow(), 'yyyy-MM-dd')}",
            "Body": "<h2>Compliance Posture Report</h2>@{variables('reportHtml')}"
          }
        }
      }
    }
  }
}
```

### Pattern 2: Continuous Compliance Monitoring

```powershell
# Continuous compliance monitor — runs as Azure Function (Timer trigger)
function Invoke-ComplianceMonitor {
    param(
        [string]$SubscriptionId,
        [string[]]$Frameworks = @("NIST-SP-800-53-R5", "PCI-DSS-v4", "CIS-Microsoft-Azure-Foundations-v2")
    )

    $results = @()
    foreach ($framework in $Frameworks) {
        $standard = Get-AzSecurityRegulatoryComplianceStandard -Name $framework
        $controls = Get-AzSecurityRegulatoryComplianceControl -StandardName $framework

        $passed = ($controls | Where-Object { $_.State -eq "Passed" }).Count
        $failed = ($controls | Where-Object { $_.State -eq "Failed" }).Count
        $total  = $controls.Count

        $results += [PSCustomObject]@{
            Framework       = $framework
            PassedControls  = $passed
            FailedControls  = $failed
            TotalControls   = $total
            ComplianceRate  = [math]::Round(($passed / $total) * 100, 1)
            Timestamp       = (Get-Date).ToUniversalTime()
        }

        # Alert on compliance drift — if failed controls increased since last run
        $previousState = Get-CompliancePreviousState -Framework $framework
        if ($previousState -and $failed -gt $previousState.FailedControls) {
            $drift = $failed - $previousState.FailedControls
            Send-ComplianceDriftAlert -Framework $framework -NewFailures $drift
        }
    }

    # Store results for trend tracking
    $results | ConvertTo-Json | Out-File "compliance-state-$(Get-Date -Format 'yyyyMMdd').json"
    return $results
}
```

### Pattern 3: Gap Analysis Automation

```powershell
function Invoke-ComplianceGapAnalysis {
    param(
        [string]$FrameworkName,
        [string]$RequirementsFile = ".secops/compliance/requirements.yaml"
    )

    # Load required controls from .secops/
    $requirements = Get-Content $RequirementsFile -Raw | ConvertFrom-Yaml
    $requiredFrameworks = $requirements.regulatory_frameworks |
        Where-Object { $_.name -eq $FrameworkName }

    if (-not $requiredFrameworks) {
        Write-Warning "Framework '$FrameworkName' not found in $RequirementsFile"
        return
    }

    # Get current compliance state from Defender for Cloud
    $currentControls = Get-AzSecurityRegulatoryComplianceControl -StandardName $FrameworkName

    # Build gap report
    $gaps = @()
    foreach ($control in $currentControls) {
        if ($control.State -eq "Failed") {
            $assessments = Get-AzSecurityRegulatoryComplianceAssessment `
                -StandardName $FrameworkName `
                -ControlName $control.Name

            $failedAssessments = $assessments | Where-Object { $_.State -eq "Failed" }
            $gaps += [PSCustomObject]@{
                ControlId           = $control.Name
                Description         = $control.Description
                FailedAssessments   = $failedAssessments.Count
                TotalAssessments    = $assessments.Count
                RemediationPriority = switch ($failedAssessments.Count) {
                    { $_ -gt 10 } { "Critical" }
                    { $_ -gt 5 }  { "High" }
                    { $_ -gt 1 }  { "Medium" }
                    default       { "Low" }
                }
                Details             = $failedAssessments | Select-Object Name, Description
            }
        }
    }

    # Generate gap analysis report
    $report = @{
        Framework      = $FrameworkName
        AssessmentDate = (Get-Date).ToUniversalTime().ToString("o")
        TotalControls  = $currentControls.Count
        PassedControls = ($currentControls | Where-Object { $_.State -eq "Passed" }).Count
        FailedControls = $gaps.Count
        Gaps           = $gaps | Sort-Object RemediationPriority
        ComplianceRate = [math]::Round(
            (($currentControls | Where-Object { $_.State -eq "Passed" }).Count /
             $currentControls.Count) * 100, 1
        )
    }

    return $report
}
```

### Pattern 4: Evidence Collection Automation

```powershell
function Export-ComplianceEvidence {
    param(
        [string]$FrameworkName,
        [string]$ControlId,
        [string]$OutputPath = "./evidence"
    )

    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $evidenceDir = Join-Path $OutputPath "$FrameworkName-$ControlId-$timestamp"
    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null

    # Collect evidence based on control type
    switch -Regex ($ControlId) {
        "^AC-|^IA-" {
            # Access control / Identity evidence
            $caPolices = Get-MgIdentityConditionalAccessPolicy
            $caPolices | ConvertTo-Json -Depth 10 |
                Out-File "$evidenceDir/conditional-access-policies.json"

            $accessReviews = Get-MgIdentityGovernanceAccessReviewDefinition
            $accessReviews | ConvertTo-Json -Depth 5 |
                Out-File "$evidenceDir/access-reviews.json"

            $pimRoles = Get-MgRoleManagementDirectoryRoleAssignment
            $pimRoles | ConvertTo-Json -Depth 5 |
                Out-File "$evidenceDir/privileged-role-assignments.json"
        }
        "^AU-" {
            # Audit evidence
            $workspaces = Get-AzOperationalInsightsWorkspace
            $workspaces | ConvertTo-Json -Depth 5 |
                Out-File "$evidenceDir/log-analytics-workspaces.json"

            $diagnosticSettings = foreach ($ws in $workspaces) {
                Get-AzDiagnosticSetting -ResourceId $ws.ResourceId
            }
            $diagnosticSettings | ConvertTo-Json -Depth 5 |
                Out-File "$evidenceDir/diagnostic-settings.json"
        }
        "^SC-" {
            # System & comms protection evidence
            $nsgs = Get-AzNetworkSecurityGroup
            $nsgs | Select-Object Name, ResourceGroupName,
                @{N='Rules';E={$_.SecurityRules.Count}} |
                ConvertTo-Json | Out-File "$evidenceDir/nsg-summary.json"

            $kvaults = Get-AzKeyVault
            $kvaults | ConvertTo-Json -Depth 5 |
                Out-File "$evidenceDir/key-vault-inventory.json"
        }
        "^SI-" {
            # System integrity evidence
            $defenderStatus = Get-AzSecuritySetting
            $defenderStatus | ConvertTo-Json -Depth 5 |
                Out-File "$evidenceDir/defender-settings.json"

            $recommendations = Get-AzSecurityTask | Where-Object {
                $_.State -eq "Active"
            }
            $recommendations | ConvertTo-Json -Depth 5 |
                Out-File "$evidenceDir/active-recommendations.json"
        }
    }

    # Generate evidence manifest
    $files = Get-ChildItem $evidenceDir -File
    $manifest = @{
        Framework    = $FrameworkName
        ControlId    = $ControlId
        CollectedAt  = (Get-Date).ToUniversalTime().ToString("o")
        CollectedBy  = "Automated — Herc SOAR"
        Files        = $files | ForEach-Object {
            @{ Name = $_.Name; SizeKB = [math]::Round($_.Length / 1KB, 1) }
        }
    }
    $manifest | ConvertTo-Json -Depth 3 | Out-File "$evidenceDir/manifest.json"

    Write-Output "Evidence collected: $($files.Count) files in $evidenceDir"
    return $evidenceDir
}
```

---

## `.secops/compliance/requirements.yaml` Integration

### Defining Compliance Requirements

The `.secops/compliance/requirements.yaml` file is the single source of truth for which frameworks apply to your environment. All compliance automation reads this file first.

```yaml
# .secops/compliance/requirements.yaml — Production example
schema_version: "1.0"

data_residency:
  primary_region: "eastus2"
  allowed_regions: ["eastus2", "eastus", "centralus"]
  prohibited_regions: ["westeurope", "northeurope"]
  reason: "US-only data residency per corporate policy"

regulatory_frameworks:
  - name: "PCI-DSS"
    version: "4.0"
    description: "Payment Card Industry Data Security Standard"
    impact:
      - "data-retention"
      - "access-logging"
      - "quarterly-scanning"
      - "network-segmentation"
    defender_standard: "PCI-DSS-v4"
    assessment_frequency: "quarterly"

  - name: "NIST-800-53"
    version: "Rev 5"
    description: "NIST Special Publication 800-53 Revision 5"
    impact:
      - "continuous-monitoring"
      - "access-control"
      - "incident-response"
      - "audit-logging"
    defender_standard: "NIST-SP-800-53-R5"
    assessment_frequency: "monthly"

  - name: "SOC2"
    version: "Type II"
    description: "SOC 2 Trust Service Criteria"
    impact:
      - "availability"
      - "confidentiality"
      - "processing-integrity"
    defender_standard: "SOC-2"
    assessment_frequency: "continuous"

retention_requirements:
  default:
    interactive_days: 90
    archive_days: 730
    total_days: 820
  overrides:
    - table: "SecurityEvent"
      interactive_days: 365
      archive_days: 2555
      reason: "PCI-DSS Req 10.7 — 1 year online, 7 years total"
    - table: "SigninLogs"
      interactive_days: 180
      archive_days: 730
      reason: "Identity forensics — 6 months interactive"
```

### Mapping Frameworks to Microsoft Products

```powershell
# Load .secops/ requirements and run targeted assessments
function Invoke-SecOpsComplianceCheck {
    $requirements = Get-Content ".secops/compliance/requirements.yaml" -Raw |
        ConvertFrom-Yaml

    # Only assess frameworks defined in .secops/
    foreach ($fw in $requirements.regulatory_frameworks) {
        Write-Host "`n=== Assessing: $($fw.name) v$($fw.version) ===" -ForegroundColor Cyan

        # Map to Defender for Cloud standard name
        $defenderStandard = $fw.defender_standard
        if (-not $defenderStandard) {
            Write-Warning "No Defender mapping for $($fw.name) — skipping"
            continue
        }

        $result = Invoke-ComplianceGapAnalysis -FrameworkName $defenderStandard
        [PSCustomObject]@{
            Framework      = $fw.name
            Version        = $fw.version
            ComplianceRate = "$($result.ComplianceRate)%"
            Gaps           = $result.FailedControls
            NextAssessment = $fw.assessment_frequency
        }
    }
}
```

### Compliance Status Tracking

```powershell
# Generate compliance status for all configured frameworks
function Get-CompliancePosture {
    param([string]$SecOpsPath = ".secops")

    $requirements = Get-Content "$SecOpsPath/compliance/requirements.yaml" -Raw |
        ConvertFrom-Yaml
    $environment = Get-Content "$SecOpsPath/environment.yaml" -Raw | ConvertFrom-Yaml

    $posture = @{
        OrganizationName = $environment.organization.name
        AssessmentDate   = (Get-Date).ToUniversalTime().ToString("o")
        Frameworks       = @()
    }

    foreach ($fw in $requirements.regulatory_frameworks) {
        $standard = Get-AzSecurityRegulatoryComplianceStandard -Name $fw.defender_standard
        $posture.Frameworks += @{
            Name           = $fw.name
            Version        = $fw.version
            Passed         = $standard.PassedControls
            Failed         = $standard.FailedControls
            Skipped        = $standard.SkippedControls
            ComplianceRate = if ($standard.PassedControls + $standard.FailedControls -gt 0) {
                [math]::Round(
                    $standard.PassedControls /
                    ($standard.PassedControls + $standard.FailedControls) * 100, 1
                )
            } else { 0 }
        }
    }

    return $posture
}
```

---

## Report Templates

### Compliance Posture Report

```powershell
function Export-CompliancePostureReport {
    param(
        [string]$OutputPath = "./reports",
        [string]$Format = "HTML"
    )

    $posture = Get-CompliancePosture
    $date = Get-Date -Format "yyyy-MM-dd"

    $html = @"
<!DOCTYPE html>
<html>
<head><title>Compliance Posture — $date</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; margin: 2rem; }
  .pass { color: #107c10; } .fail { color: #d13438; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
  th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
  th { background: #0078d4; color: white; }
  .score { font-size: 2rem; font-weight: bold; }
</style></head>
<body>
<h1>Compliance Posture Report</h1>
<p><strong>Organization:</strong> $($posture.OrganizationName)</p>
<p><strong>Assessment Date:</strong> $($posture.AssessmentDate)</p>

<table>
<tr><th>Framework</th><th>Version</th><th>Passed</th><th>Failed</th>
    <th>Compliance Rate</th></tr>
$(foreach ($fw in $posture.Frameworks) {
"<tr><td>$($fw.Name)</td><td>$($fw.Version)</td>
<td class='pass'>$($fw.Passed)</td><td class='fail'>$($fw.Failed)</td>
<td><span class='score'>$($fw.ComplianceRate)%</span></td></tr>"
})
</table>

<p><em>Generated by secops-squad compliance automation (Herc SOAR)</em></p>
</body></html>
"@

    $outputFile = Join-Path $OutputPath "compliance-posture-$date.html"
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $html | Out-File $outputFile -Encoding UTF8
    Write-Output "Report: $outputFile"
}
```

### Gap Analysis Report

```powershell
function Export-GapAnalysisReport {
    param(
        [string]$FrameworkName,
        [string]$OutputPath = "./reports"
    )

    $gaps = Invoke-ComplianceGapAnalysis -FrameworkName $FrameworkName
    $date = Get-Date -Format "yyyy-MM-dd"

    $report = @{
        Title          = "Gap Analysis: $FrameworkName"
        Date           = $date
        ComplianceRate = "$($gaps.ComplianceRate)%"
        Summary        = @{
            TotalControls  = $gaps.TotalControls
            PassedControls = $gaps.PassedControls
            FailedControls = $gaps.FailedControls
        }
        Gaps           = $gaps.Gaps | ForEach-Object {
            @{
                ControlId   = $_.ControlId
                Description = $_.Description
                Priority    = $_.RemediationPriority
                FailedCount = $_.FailedAssessments
            }
        }
        Remediation    = $gaps.Gaps |
            Sort-Object RemediationPriority |
            Select-Object ControlId, RemediationPriority -First 10
    }

    $outputFile = Join-Path $OutputPath "gap-analysis-$FrameworkName-$date.json"
    $report | ConvertTo-Json -Depth 5 | Out-File $outputFile -Encoding UTF8
    Write-Output "Gap analysis: $outputFile"
}
```

### Audit Evidence Package

```powershell
function Export-AuditEvidencePackage {
    param(
        [string]$FrameworkName,
        [string]$OutputPath = "./evidence-packages"
    )

    $packageDir = Join-Path $OutputPath "$FrameworkName-$(Get-Date -Format 'yyyyMMdd')"
    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null

    # Collect evidence for all failed controls
    $gaps = Invoke-ComplianceGapAnalysis -FrameworkName $FrameworkName
    foreach ($gap in $gaps.Gaps) {
        Export-ComplianceEvidence `
            -FrameworkName $FrameworkName `
            -ControlId $gap.ControlId `
            -OutputPath $packageDir
    }

    # Generate posture report
    Export-CompliancePostureReport -OutputPath $packageDir

    # Create package manifest
    $manifest = @{
        Framework      = $FrameworkName
        PackageDate    = (Get-Date).ToUniversalTime().ToString("o")
        ComplianceRate = $gaps.ComplianceRate
        GapsAnalyzed   = $gaps.Gaps.Count
        EvidenceFiles  = (Get-ChildItem $packageDir -Recurse -File).Count
        GeneratedBy    = "secops-squad Herc SOAR"
    }
    $manifest | ConvertTo-Json | Out-File "$packageDir/package-manifest.json"

    # Compress for delivery
    $zipPath = "$packageDir.zip"
    Compress-Archive -Path $packageDir -DestinationPath $zipPath -Force
    Write-Output "Audit package: $zipPath"
}
```

---

## Cross-References

- **SOAR Playbooks:** All incident response playbooks in `skills/soar/` can reference compliance framework control IDs in incident comments for audit trails
- **Detection Rules:** Kima's detection skills in `skills/detection/` map to framework detection requirements
- **KQL Queries:** Freamon's `skills/kql/` hunting queries support compliance evidence gathering
- **Workbook Automation:** See `skills/soar/workbook-automation.md` for compliance dashboard deployment
- **`.secops/` Framework:** See `.secops/compliance/README.md` for schema documentation
