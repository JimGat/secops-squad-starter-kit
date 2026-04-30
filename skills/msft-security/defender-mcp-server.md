---
title: Defender MCP Server Integration
category: msft-security
difficulty: advanced
mitre_attack:
  - T1059   # Command and Scripting Interpreter
  - T1078   # Valid Accounts
  - T1110   # Brute Force
  - T1566   # Phishing
  - T1190   # Exploit Public-Facing Application
  - T1486   # Data Encrypted for Impact
  - T1003   # OS Credential Dumping
products:
  - Microsoft Defender XDR
  - Microsoft Defender for Endpoint
  - Microsoft Defender for Cloud
  - Microsoft Defender for Identity
  - Microsoft Defender for Cloud Apps
  - Microsoft Graph Security API
  - Azure MCP Server
author: Kima
version: 1.0.0
last_updated: 2026-04-30
---

# Defender MCP Server Integration

## Overview

This skill teaches agents how to interact with Microsoft Defender products programmatically through MCP (Model Context Protocol) server patterns. It covers the full Defender API landscape, MCP configuration, product-specific operations, rate limiting, and end-to-end agent workflows for security operations.

This skill **complements** — does not duplicate — existing skills:
- **[Defender for Endpoint](defender-for-endpoint.md)** — onboarding, ASR rules, Live Response commands, device groups
- **[Defender XDR Configuration](defender-xdr-configuration.md)** — portal settings, suppression rules, custom detections, email protection
- **[Microsoft Graph Security](microsoft-graph-security.md)** — Graph auth patterns, alerts_v2, incidents, TI, webhooks

Use this skill when:
- Connecting an MCP server to Defender APIs for agent-driven security operations
- Running Advanced Hunting queries programmatically via MCP
- Automating incident response actions (isolate, scan, investigate) through API
- Building multi-product workflows that span MDE, MDI, MDCA, and Defender for Cloud
- Understanding which API to call for which Defender operation

## Environment Context

Before using any Defender API, check `.secops/environment.yaml` for tenant and subscription context, and `.secops/identity/tenants.yaml` for cross-tenant access boundaries. Government cloud tenants use different API endpoints — see Section 2.

## Section 1: Defender API Landscape

### Product-to-API Mapping

| Defender Product | Primary API | Base URL | MCP Access |
|---|---|---|---|
| **Defender XDR** | Graph Security API v1.0 | `graph.microsoft.com/v1.0/security` | Azure MCP Server (Graph) |
| **Defender for Endpoint** | MDE API + Graph | `api.securitycenter.microsoft.com` | Direct REST (MDE-specific) |
| **Defender for Cloud** | Azure Resource Manager | `management.azure.com` | Azure MCP Server (ARM) |
| **Defender for Identity** | Graph Security API | `graph.microsoft.com/v1.0/security` | Azure MCP Server (Graph) |
| **Defender for Cloud Apps** | MDCA API | `<tenant>.portal.cloudappsecurity.com` | Direct REST |
| **Entra ID Protection** | Graph Identity API | `graph.microsoft.com/v1.0/identityProtection` | Azure MCP Server (Graph) |

### Graph Security API vs. Product-Specific APIs

```
┌─────────────────────────────────────────────────────────┐
│              Microsoft Graph Security API                │
│   (Unified: alerts_v2, incidents, secureScores, TI)     │
│   Endpoint: graph.microsoft.com/v1.0/security           │
├────────────┬────────────┬───────────┬───────────────────┤
│  XDR       │  MDE       │  MDI      │  MDCA (partial)   │
│  Alerts    │  Alerts    │  Alerts   │  Alerts           │
│  Incidents │  (mapped)  │  (mapped) │  (mapped)         │
└────────────┴────────────┴───────────┴───────────────────┘

┌─────────────────────────────────────────────────────────┐
│              Product-Specific APIs (Direct REST)         │
├──────────────────┬──────────────────────────────────────┤
│  MDE API         │  Machine actions, Live Response,     │
│  api.security    │  TVM, custom detections, indicators  │
│  center.ms.com   │  Advanced Hunting (MDE tables only)  │
├──────────────────┼──────────────────────────────────────┤
│  MDCA API        │  Cloud app discovery, policies,      │
│  *.cloudapp      │  files, activities, governance       │
│  security.com    │  actions, OAuth app management       │
├──────────────────┼──────────────────────────────────────┤
│  ARM REST API    │  Defender for Cloud plans, policies, │
│  management      │  recommendations, secure score,      │
│  .azure.com      │  JIT VM access, adaptive controls    │
└──────────────────┴──────────────────────────────────────┘
```

### What Azure MCP Server Covers vs. Direct REST

| Operation | Azure MCP Server | Direct REST Required |
|---|---|---|
| Read/update alerts & incidents | ✅ Graph Security | — |
| Advanced Hunting (XDR unified) | ✅ Graph `runHuntingQuery` | — |
| Secure scores & controls | ✅ Graph Security | — |
| Identity risk detections | ✅ Graph Identity Protection | — |
| Machine isolation/actions | ❌ | MDE API |
| Live Response sessions | ❌ | MDE API |
| Custom indicators (IOCs) | ❌ | MDE API |
| TVM software/vulns | ❌ | MDE API |
| Cloud app policies/governance | ❌ | MDCA API |
| Defender for Cloud plans/recs | ❌ | ARM REST API |
| JIT VM access | ❌ | ARM REST API |

### API Convergence Direction

Microsoft is converging Defender APIs into the Graph Security API. Current trajectory:
- **Already unified:** Alerts (alerts_v2), incidents, Advanced Hunting, secure scores, TI
- **In progress:** MDE machine actions moving to Graph (preview: `security/microsoft.graph.security`)
- **Future:** TVM, Live Response, MDCA operations expected in Graph
- **Design for:** Use Graph wherever available today; fall back to product APIs only when needed

## Section 2: MCP Configuration for Defender

### MCP Server Setup

```jsonc
// .mcp.json — MCP server configuration for Defender operations
{
  "mcpServers": {
    "azure-mcp": {
      "command": "npx",
      "args": ["-y", "@azure/mcp-server"],
      "env": {
        "AZURE_TENANT_ID": "${AZURE_TENANT_ID}",
        "AZURE_CLIENT_ID": "${AZURE_CLIENT_ID}",
        "AZURE_CLIENT_SECRET": "${AZURE_CLIENT_SECRET}"
      }
    },
    // For MDE-specific operations not in Graph
    "defender-endpoint": {
      "command": "node",
      "args": ["mcp-servers/defender-endpoint-server.js"],
      "env": {
        "MDE_TENANT_ID": "${AZURE_TENANT_ID}",
        "MDE_CLIENT_ID": "${MDE_CLIENT_ID}",
        "MDE_CLIENT_SECRET": "${MDE_CLIENT_SECRET}"
      }
    }
  }
}
```

### Authentication: App Registration

```powershell
# Register Entra ID app for Defender API access
$app = New-MgApplication -DisplayName "SecOps-Squad-MCP-Defender" `
    -SignInAudience "AzureADMyOrg" `
    -RequiredResourceAccess @(
        @{
            ResourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
            ResourceAccess = @(
                # See defender-api-permissions.md for full matrix
                @{ Id = "bf394140-e372-4bf9-a898-299cfc7564e5"; Type = "Role" }  # SecurityIncident.ReadWrite.All
                @{ Id = "472e4a4d-bb4a-4026-98d1-0571f1840dc8"; Type = "Role" }  # SecurityAlert.ReadWrite.All
                @{ Id = "dd98c7f5-2d42-42d8-a6d0-1e30e91de81e"; Type = "Role" }  # ThreatHunting.Read.All
            )
        },
        @{
            ResourceAppId = "fc780465-2017-40d4-a0c5-307022471b92"  # WindowsDefenderATP
            ResourceAccess = @(
                @{ Id = "93489bf5-0fbc-4f2d-b901-33f2fe08ff05"; Type = "Role" }  # Machine.ReadWrite.All
                @{ Id = "37f71c98-d198-41ae-964d-7e2e4a3bbd05"; Type = "Role" }  # Alert.ReadWrite.All
                @{ Id = "a0e06b5e-7e90-4e80-87d7-7c4e2a046891"; Type = "Role" }  # AdvancedQuery.Read.All
            )
        }
    )

# Grant admin consent (requires Global Admin or Privileged Role Admin)
# Navigate: Entra admin center > App registrations > API permissions > Grant admin consent
```

### Government Cloud Endpoints

```yaml
# .secops/ cloud-specific API endpoints
# Check .secops/environment.yaml → organization.cloud before making calls

azure-commercial:
  graph: "https://graph.microsoft.com"
  mde: "https://api.securitycenter.microsoft.com"
  arm: "https://management.azure.com"
  login: "https://login.microsoftonline.com"

azure-government:
  graph: "https://graph.microsoft.us"
  mde: "https://api-gcc.securitycenter.microsoft.us"
  arm: "https://management.usgovcloudapi.net"
  login: "https://login.microsoftonline.us"

azure-china:
  graph: "https://microsoftgraph.chinacloudapi.cn"
  mde: null  # MDE not available in China cloud
  arm: "https://management.chinacloudapi.cn"
  login: "https://login.chinacloudapi.cn"
```

## Section 3: Defender for Endpoint (MDE) via MCP

> Complements [Defender for Endpoint](defender-for-endpoint.md) — see that skill for onboarding, ASR rules, Live Response commands, and device groups.

### Advanced Hunting via API

```python
# Run KQL query against MDE Advanced Hunting
# Covers: DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents,
#          DeviceRegistryEvents, DeviceLogonEvents, DeviceEvents, DeviceInfo

import requests

MDE_BASE = "https://api.securitycenter.microsoft.com/api"

def run_mde_hunting(token, query):
    """Execute KQL against MDE tables. Returns structured result."""
    response = requests.post(
        f"{MDE_BASE}/advancedqueries/run",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"Query": query}
    )
    if response.status_code == 200:
        return {"ok": True, "data": response.json()}
    return {"ok": False, "error": response.text, "status": response.status_code}

# Example: Find suspicious PowerShell across fleet (T1059.001)
result = run_mde_hunting(token, """
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("DownloadString", "IEX", "EncodedCommand", "-enc")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| take 100
""")
```

### Machine Actions via API

```python
# Machine actions: isolate, unisolate, restrict, scan, investigate
# MITRE: Response actions for T1059, T1078, T1003

def isolate_machine(token, machine_id, comment, isolation_type="Full"):
    """Isolate a machine. Types: Full (no network except Defender), Selective."""
    response = requests.post(
        f"{MDE_BASE}/machines/{machine_id}/isolate",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"Comment": comment, "IsolationType": isolation_type}
    )
    return {"ok": response.status_code == 201, "data": response.json()}

def run_av_scan(token, machine_id, scan_type="Quick"):
    """Trigger AV scan. Types: Quick, Full."""
    response = requests.post(
        f"{MDE_BASE}/machines/{machine_id}/runAntiVirusScan",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"Comment": "Automated scan via MCP", "ScanType": scan_type}
    )
    return {"ok": response.status_code == 201, "data": response.json()}

def collect_investigation_package(token, machine_id):
    """Collect forensic investigation package from device."""
    response = requests.post(
        f"{MDE_BASE}/machines/{machine_id}/collectInvestigationPackage",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"Comment": "Investigation package collection via MCP"}
    )
    return {"ok": response.status_code == 201, "data": response.json()}

def restrict_code_execution(token, machine_id):
    """Restrict app execution to Microsoft-signed binaries only."""
    response = requests.post(
        f"{MDE_BASE}/machines/{machine_id}/restrictCodeExecution",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"Comment": "Code execution restricted during investigation"}
    )
    return {"ok": response.status_code == 201, "data": response.json()}
```

### Threat & Vulnerability Management (TVM)

```python
# Software inventory, vulnerabilities, and recommendations via MDE API

def get_software_inventory(token, top=100):
    """Get software inventory across all onboarded devices."""
    response = requests.get(
        f"{MDE_BASE}/Software?$top={top}&$orderby=activeAlertCount desc",
        headers={"Authorization": f"Bearer {token}"}
    )
    return response.json().get("value", [])

def get_vulnerabilities(token, severity="Critical"):
    """Get known vulnerabilities. Filter by severity: Critical, High, Medium, Low."""
    response = requests.get(
        f"{MDE_BASE}/vulnerabilities?$filter=severity eq '{severity}'&$top=50",
        headers={"Authorization": f"Bearer {token}"}
    )
    return response.json().get("value", [])

def get_recommendations(token, status="Active"):
    """Get security recommendations. Status: Active, Exception, InProgress."""
    response = requests.get(
        f"{MDE_BASE}/recommendations?$filter=status eq '{status}'&$top=50"
        "&$orderby=exposedMachinesCount desc",
        headers={"Authorization": f"Bearer {token}"}
    )
    return response.json().get("value", [])
```

### Custom Detection Rules via API

```python
# Create custom detection rule from KQL query
def create_custom_detection(token, rule):
    """Create a custom detection rule in MDE."""
    payload = {
        "queryText": rule["query"],
        "title": rule["title"],
        "description": rule["description"],
        "severity": rule["severity"],       # Informational, Low, Medium, High
        "category": rule["category"],       # MITRE tactic
        "mitreTechniques": rule.get("mitre", []),
        "period": rule.get("period", "1"),  # Hours between runs
        "impactedEntities": rule.get("entities", [
            {"entityType": "Machine", "column": "DeviceName"},
            {"entityType": "User", "column": "AccountName"}
        ]),
        "actions": rule.get("actions", [])  # AlertAndBlock, RunScript, etc.
    }
    response = requests.post(
        f"{MDE_BASE}/customDetections",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload
    )
    return {"ok": response.status_code == 201, "data": response.json()}
```

## Section 4: Defender XDR (Unified) via MCP

> Complements [Defender XDR Configuration](defender-xdr-configuration.md) — see that skill for portal settings, alert suppression, and email protection.

### Unified Incident Management via Graph

```python
# Incident operations via Graph Security API
GRAPH_BASE = "https://graph.microsoft.com/v1.0/security"

def get_active_incidents(token, severity=None, top=25):
    """Get active incidents from unified XDR queue."""
    url = f"{GRAPH_BASE}/incidents?$top={top}&$orderby=createdDateTime desc"
    url += "&$filter=status eq 'active'"
    if severity:
        url += f" and severity eq '{severity}'"
    response = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    return response.json().get("value", [])

def update_incident(token, incident_id, updates):
    """Update incident status, assignment, classification."""
    response = requests.patch(
        f"{GRAPH_BASE}/incidents/{incident_id}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=updates
    )
    return {"ok": response.status_code == 200}

# Assign and classify an incident
update_incident(token, "incident-id", {
    "status": "active",
    "assignedTo": "analyst@contoso.com",
    "classification": "truePositive",
    "determination": "malware",
    "customTags": ["mcp-triaged", "phishing-campaign-042"]
})
```

### Cross-Product Advanced Hunting (Unified Schema)

```python
# Unified Advanced Hunting spans ALL Defender products
# Tables: Device*, Email*, Identity*, CloudApp*, AADSignInEventsBeta, AlertInfo, AlertEvidence

def run_xdr_hunting(token, query):
    """Run Advanced Hunting across all XDR products via Graph."""
    response = requests.post(
        f"{GRAPH_BASE}/microsoft/graph/security/runHuntingQuery",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"Query": query}
    )
    return {"ok": response.status_code == 200, "data": response.json()}

# Cross-product query: phishing email → endpoint compromise (T1566 → T1059)
result = run_xdr_hunting(token, """
EmailEvents
| where Timestamp > ago(24h)
| where ThreatTypes has "Phish"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe")
) on $left.RecipientEmailAddress == $right.AccountUpn
| project EmailTimestamp=Timestamp, RecipientEmailAddress, Subject,
          DeviceName, FileName, ProcessCommandLine
""")
```

### Automated Investigation Status

```python
# Check auto-investigation status for an incident
def get_investigations(token, incident_id):
    """Get automated investigations linked to an incident."""
    response = requests.get(
        f"{GRAPH_BASE}/incidents/{incident_id}?$expand=alerts",
        headers={"Authorization": f"Bearer {token}"}
    )
    return response.json()
```

## Section 5: Defender for Cloud via MCP

### Security Recommendations & Secure Score

```python
# Defender for Cloud uses ARM REST API
ARM_BASE = "https://management.azure.com"

def get_secure_score(token, subscription_id):
    """Get Defender for Cloud secure score."""
    response = requests.get(
        f"{ARM_BASE}/subscriptions/{subscription_id}"
        "/providers/Microsoft.Security/secureScores/ascScore"
        "?api-version=2020-01-01",
        headers={"Authorization": f"Bearer {token}"}
    )
    data = response.json()
    props = data.get("properties", {})
    score = props.get("score", {})
    return {
        "current": score.get("current"),
        "max": score.get("max"),
        "percentage": score.get("percentage")
    }

def get_recommendations(token, subscription_id, status="Unhealthy"):
    """Get security recommendations. Status: Healthy, Unhealthy, NotApplicable."""
    response = requests.get(
        f"{ARM_BASE}/subscriptions/{subscription_id}"
        "/providers/Microsoft.Security/assessments"
        f"?api-version=2021-06-01&$filter=properties/status/code eq '{status}'",
        headers={"Authorization": f"Bearer {token}"}
    )
    return response.json().get("value", [])
```

### Regulatory Compliance

```python
def get_compliance_results(token, subscription_id, standard="Azure-CIS-1.3.0"):
    """Get regulatory compliance assessment results."""
    response = requests.get(
        f"{ARM_BASE}/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Security/regulatoryComplianceStandards/{standard}"
        "/regulatoryComplianceControls?api-version=2019-01-01-preview",
        headers={"Authorization": f"Bearer {token}"}
    )
    controls = response.json().get("value", [])
    return [{
        "id": c["name"],
        "state": c["properties"]["state"],
        "passed": c["properties"].get("passedAssessments", 0),
        "failed": c["properties"].get("failedAssessments", 0)
    } for c in controls]
```

### JIT VM Access

```python
# Request Just-In-Time VM access (T1190 mitigation)
def request_jit_access(token, subscription_id, rg, vm_name, ports=[22, 3389]):
    """Request JIT access to a VM — reduces attack surface for management ports."""
    from datetime import datetime, timedelta
    end_time = (datetime.utcnow() + timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    payload = {
        "virtualMachines": [{
            "id": f"/subscriptions/{subscription_id}/resourceGroups/{rg}"
                  f"/providers/Microsoft.Compute/virtualMachines/{vm_name}",
            "ports": [{"number": p, "duration": "PT3H",
                       "allowedSourceAddressPrefix": "*"} for p in ports]
        }],
        "justification": "Incident response investigation via MCP"
    }
    response = requests.post(
        f"{ARM_BASE}/subscriptions/{subscription_id}/resourceGroups/{rg}"
        f"/providers/Microsoft.Security/locations/centralus"
        f"/jitNetworkAccessPolicies/default/initiate"
        f"?api-version=2020-01-01",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload
    )
    return {"ok": response.status_code in [200, 202], "data": response.json()}
```

## Section 6: Defender for Identity (MDI) via MCP

> Complements [Defender for Identity](defender-for-identity.md) — see that skill for sensor deployment, alert tuning, and lateral movement paths.

### Identity Hunting via Advanced Hunting

```kql
// MDI data is available in XDR Advanced Hunting
// Tables: IdentityLogonEvents, IdentityQueryEvents, IdentityDirectoryEvents

// Detect lateral movement — pass-the-hash (T1550.002)
IdentityLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "RemoteInteractive"
| where Protocol == "NTLM"
| summarize TargetCount = dcount(TargetDeviceName) by AccountName, AccountDomain
| where TargetCount > 5
| sort by TargetCount desc

// Detect reconnaissance — LDAP enumeration (T1087.002)
IdentityQueryEvents
| where Timestamp > ago(24h)
| where ActionType == "LDAP query"
| where QueryTarget has_any ("Domain Admins", "Enterprise Admins", "Schema Admins")
| project Timestamp, AccountName, DeviceName, QueryType, QueryTarget
```

### Integration with Entra ID Protection

```python
# Correlate MDI alerts with Entra ID Protection risk detections
def get_risky_users_with_identity_alerts(token):
    """Cross-reference risky users with MDI detections."""
    # Get risky users from Entra ID Protection
    risky = requests.get(
        "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers"
        "?$filter=riskLevel eq 'high'&$top=20",
        headers={"Authorization": f"Bearer {token}"}
    ).json().get("value", [])

    # For each risky user, check for MDI alerts
    for user in risky:
        alerts = requests.get(
            f"https://graph.microsoft.com/v1.0/security/alerts_v2"
            f"?$filter=actorDisplayName eq '{user['userPrincipalName']}'&$top=10",
            headers={"Authorization": f"Bearer {token}"}
        ).json().get("value", [])
        user["mdi_alerts"] = alerts

    return risky
```

## Section 7: Rate Limiting & Operational Patterns

### Per-Product Rate Limits

| API | Rate Limit | Scope | Notes |
|---|---|---|---|
| **Graph Security** | 150 req/min per app | Per tenant | Standard Graph throttling, 429 with Retry-After |
| **MDE API** | 100 req/min most endpoints | Per app | Machine actions: 25/min; Live Response: 10/min |
| **MDE Advanced Hunting** | 45 req/hour | Per app | 10-minute query timeout, 100K rows max |
| **MDCA API** | 30 req/min | Per tenant | 500 req/hr for discovery endpoints |
| **ARM (Defender for Cloud)** | 250 read/min, 10 write/min | Per subscription | Standard ARM throttling |
| **Graph Batch** | 20 requests per batch | Per call | Use for bulk alert/incident reads |

### Priority Queue Pattern

```python
# Implement priority-based API call scheduling
from enum import IntEnum
import heapq, time

class Priority(IntEnum):
    INCIDENT_RESPONSE = 1   # Isolate, scan, investigate — immediate
    ACTIVE_TRIAGE = 2       # Alert enrichment, incident correlation
    HUNTING = 3             # Advanced hunting queries — can wait
    POSTURE = 4             # Secure score, recommendations — background
    REPORTING = 5           # Dashboards, metrics — lowest priority

class DefenderAPIQueue:
    def __init__(self, rate_limit_per_min=100):
        self.queue = []
        self.rate_limit = rate_limit_per_min
        self.calls_this_minute = 0
        self.minute_start = time.time()

    def enqueue(self, priority, func, *args):
        heapq.heappush(self.queue, (priority, time.time(), func, args))

    def process_next(self):
        now = time.time()
        if now - self.minute_start > 60:
            self.calls_this_minute = 0
            self.minute_start = now
        if self.calls_this_minute >= self.rate_limit:
            return None  # Wait for rate limit window
        priority, _, func, args = heapq.heappop(self.queue)
        self.calls_this_minute += 1
        return func(*args)
```

### Caching Strategy

| Data Type | Cache Duration | Reason |
|---|---|---|
| Software inventory (TVM) | 4 hours | Changes with software deployments, not per-minute |
| Security recommendations | 1 hour | Updated on assessment schedule |
| Secure score | 30 minutes | Score updates as controls are implemented |
| Device inventory | 15 minutes | Devices come/go, but not rapidly |
| Active alerts | No cache | Must be real-time for triage |
| Active incidents | No cache | Must be real-time for response |
| Risk detections | No cache | Real-time for identity threat response |

### Bulk Operations

```python
# Batch alert updates via Graph $batch endpoint
def batch_update_alerts(token, alert_updates):
    """Update multiple alerts in a single API call (max 20 per batch)."""
    requests_list = []
    for i, update in enumerate(alert_updates[:20]):
        requests_list.append({
            "id": str(i),
            "method": "PATCH",
            "url": f"/security/alerts_v2/{update['id']}",
            "body": {
                "status": update.get("status", "inProgress"),
                "assignedTo": update.get("assignedTo"),
                "classification": update.get("classification")
            },
            "headers": {"Content-Type": "application/json"}
        })
    response = requests.post(
        "https://graph.microsoft.com/v1.0/$batch",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"requests": requests_list}
    )
    return response.json()
```

## Section 8: Agent Workflow Examples

### Workflow 1: Automated Alert Triage

```
Alert fires → Enrich from MDE → Correlate in XDR → Auto-assign
MITRE: Response to any detection (T1059, T1078, T1566)
```

```python
def auto_triage_alert(token, alert_id):
    """Full triage workflow: enrich → correlate → assign."""
    # Step 1: Get alert details
    alert = requests.get(
        f"{GRAPH_BASE}/alerts_v2/{alert_id}",
        headers={"Authorization": f"Bearer {token}"}
    ).json()

    # Step 2: Enrich with device context from MDE
    device_name = next(
        (e["deviceDnsName"] for e in alert.get("evidence", [])
         if e.get("@odata.type") == "#microsoft.graph.security.deviceEvidence"),
        None
    )
    device_info = None
    if device_name:
        device_info = run_mde_hunting(token, f"""
            DeviceInfo | where DeviceName == '{device_name}'
            | summarize arg_max(Timestamp, *) by DeviceId
        """)

    # Step 3: Check for related incidents in XDR
    incidents = requests.get(
        f"{GRAPH_BASE}/incidents?$filter=status eq 'active'"
        f"&$top=5&$orderby=createdDateTime desc",
        headers={"Authorization": f"Bearer {token}"}
    ).json().get("value", [])

    # Step 4: Auto-assign based on severity
    assignee = {
        "high": "senior-analyst@contoso.com",
        "medium": "analyst@contoso.com",
        "low": "junior-analyst@contoso.com"
    }.get(alert.get("severity", "medium"), "analyst@contoso.com")

    # Step 5: Update alert
    update_result = requests.patch(
        f"{GRAPH_BASE}/alerts_v2/{alert_id}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"status": "inProgress", "assignedTo": assignee,
              "comment": f"Auto-triaged via MCP. Device: {device_name}"}
    )
    return {"alert": alert, "device": device_info, "assignee": assignee}
```

### Workflow 2: Threat Hunting

```
Hypothesis → Advanced Hunting → Bookmark findings → Create incident
MITRE: Proactive hunting for T1003 (Credential Dumping), T1110 (Brute Force)
```

```python
def hunting_workflow(token, hypothesis, query):
    """Execute a threat hunting hypothesis with bookmarking."""
    # Step 1: Run the hunting query
    results = run_xdr_hunting(token, query)
    if not results.get("ok") or not results["data"].get("results"):
        return {"ok": True, "findings": 0, "message": "No matches — hypothesis not confirmed"}

    # Step 2: If findings exist, create incident for investigation
    findings = results["data"]["results"]
    if len(findings) > 0:
        incident = requests.post(
            f"{GRAPH_BASE}/incidents",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={
                "displayName": f"Hunting: {hypothesis}",
                "severity": "medium",
                "status": "active",
                "customTags": ["threat-hunt", "mcp-generated"]
            }
        )
        return {"ok": True, "findings": len(findings), "incident": incident.json()}
    return {"ok": True, "findings": 0}
```

### Workflow 3: Posture Assessment

```
Secure score → Recommendations → Remediation plan
```

```powershell
# Full posture assessment via PowerShell
Connect-MgGraph -Scopes "SecurityEvents.Read.All"

# Get current secure score
$score = Get-MgSecuritySecureScore -Top 1 -OrderBy "createdDateTime desc"
$pct = [math]::Round($score[0].CurrentScore / $score[0].MaxScore * 100, 1)
Write-Host "Secure Score: $($score[0].CurrentScore)/$($score[0].MaxScore) ($pct%)"

# Get top unimplemented controls sorted by impact
$controls = Get-MgSecuritySecureScoreControlProfile -Top 100
$controls | Where-Object { $_.ImplementationStatus -ne "implemented" } |
    Sort-Object -Property MaxScore -Descending |
    Select-Object -First 10 Title, MaxScore, ImplementationStatus, UserImpact |
    Format-Table -AutoSize
```

### Workflow 4: Incident Response

```
Alert → Isolate device → Collect evidence → Build timeline → Report
MITRE: Full IR for T1486 (Ransomware), T1078 (Compromised Account)
```

```python
def incident_response_workflow(token, machine_id, incident_id):
    """Automated IR: isolate → collect → timeline → update incident."""
    results = {}

    # Step 1: Isolate the machine immediately
    results["isolate"] = isolate_machine(
        token, machine_id, f"IR for incident {incident_id}")

    # Step 2: Collect investigation package
    results["package"] = collect_investigation_package(token, machine_id)

    # Step 3: Run AV scan
    results["scan"] = run_av_scan(token, machine_id, "Full")

    # Step 4: Build timeline via hunting
    results["timeline"] = run_mde_hunting(token, f"""
        let target = '{machine_id}';
        union DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents
        | where DeviceId == target
        | where Timestamp > ago(48h)
        | project Timestamp, ActionType, FileName, ProcessCommandLine,
                  RemoteIP, RemoteUrl
        | sort by Timestamp asc
        | take 500
    """)

    # Step 5: Update incident with IR actions taken
    update_incident(token, incident_id, {
        "status": "active",
        "customTags": ["ir-in-progress", "device-isolated", "evidence-collected"]
    })
    return results
```

### Workflow 5: Vulnerability Prioritization

```
TVM scan → CVSS + exploitability → Remediation priority
MITRE: Proactive defense against T1190 (Exploit Public-Facing Application)
```

```python
def prioritize_vulnerabilities(token):
    """Prioritize vulnerabilities by exploitability and exposure."""
    vulns = get_vulnerabilities(token, severity="Critical")
    recommendations = get_recommendations(token)

    prioritized = []
    for vuln in vulns:
        prioritized.append({
            "cve": vuln.get("id"),
            "name": vuln.get("name"),
            "severity": vuln.get("severity"),
            "cvss": vuln.get("cvssV3"),
            "exploit_in_wild": vuln.get("exploitInKit", False),
            "exposed_machines": vuln.get("exposedMachines", 0),
            "priority": "P1" if vuln.get("exploitInKit") else
                       "P2" if vuln.get("cvssV3", 0) >= 9.0 else "P3"
        })

    # Sort: actively exploited first, then by CVSS, then by exposure count
    prioritized.sort(key=lambda v: (
        0 if v["exploit_in_wild"] else 1,
        -(v["cvss"] or 0),
        -v["exposed_machines"]
    ))
    return prioritized
```

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| MDE API returns 403 | App missing WindowsDefenderATP permissions | Add MDE permissions and grant admin consent |
| Graph hunting returns empty | No E5 license or products not onboarded | Verify licensing; check table has data in portal |
| MDCA API connection refused | Wrong tenant URL or IP restriction | Verify `<tenant>.portal.cloudappsecurity.com`; check IP allowlist |
| ARM throttled (429) | Exceeded subscription-level rate limits | Implement Retry-After header backoff |
| Gov cloud auth fails | Using commercial endpoints for gov tenant | Check `.secops/environment.yaml` cloud field; use `.us` endpoints |
| Machine action pending | Device offline or connectivity issue | Verify device is online in MDE portal; action queues until connected |

## Related Skills

- **[Defender for Endpoint](defender-for-endpoint.md)** — Onboarding, ASR rules, Live Response, device groups
- **[Defender XDR Configuration](defender-xdr-configuration.md)** — Portal settings, suppression, custom detections
- **[Microsoft Graph Security](microsoft-graph-security.md)** — Graph auth, alerts_v2, incidents, webhooks
- **[Defender for Cloud Policies](defender-for-cloud-policies.md)** — Cloud posture, compliance, Defender plans
- **[Defender for Identity](defender-for-identity.md)** — Sensor deployment, lateral movement detection
- **[Entra ID Protection](entra-id-protection.md)** — Risk policies and Conditional Access
- **[Defender API Permissions](defender-api-permissions.md)** — Complete permissions reference
