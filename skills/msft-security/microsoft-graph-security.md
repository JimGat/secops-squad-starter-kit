---
title: Microsoft Graph Security API
category: msft-security
difficulty: intermediate
mitre_attack:
  - T1059  # Command and Scripting Interpreter (automation context)
  - T1078  # Valid Accounts (auth patterns)
products:
  - Microsoft Graph
  - Microsoft Defender XDR
  - Microsoft Sentinel
  - Microsoft Entra ID
author: Kima
version: 1.0.0
last_updated: 2026-04-28
---

# Microsoft Graph Security API

## Overview

The Microsoft Graph Security API provides a unified programmatic interface to security data across Microsoft's security products — alerts, incidents, threat intelligence, secure scores, and more. This skill covers the key security API endpoints, authentication patterns, batch operations, webhooks, and SDK examples in PowerShell and Python.

Use this skill when:
- Building custom security dashboards or reporting
- Automating incident response workflows
- Integrating Microsoft security data with third-party tools
- Subscribing to real-time security notifications via webhooks
- Querying threat intelligence programmatically

## Prerequisites

| Requirement | Detail |
|---|---|
| **App Registration** | Entra ID app with appropriate Graph permissions |
| **Permissions** | See per-endpoint permission table below |
| **SDK** | Microsoft Graph SDK for PowerShell or Python |
| **Authentication** | MSAL library for token acquisition |

## Configuration Patterns

### Security API Endpoints

| Endpoint | Purpose | Permission (Application) | Permission (Delegated) |
|---|---|---|---|
| `/security/alerts_v2` | Unified alerts from all Defender products | `SecurityAlert.ReadWrite.All` | `SecurityAlert.ReadWrite.All` |
| `/security/incidents` | Correlated incidents (multi-alert) | `SecurityIncident.ReadWrite.All` | `SecurityIncident.ReadWrite.All` |
| `/security/threatIntelligence` | TI indicators, articles, host data | `ThreatIntelligence.Read.All` | `ThreatIntelligence.Read.All` |
| `/security/secureScores` | Tenant security posture scores | `SecurityEvents.Read.All` | `SecurityEvents.Read.All` |
| `/security/secureScoreControlProfiles` | Score improvement actions | `SecurityEvents.Read.All` | `SecurityEvents.Read.All` |
| `/security/attackSimulation` | Attack simulation training data | `AttackSimulation.Read.All` | `AttackSimulation.Read.All` |
| `/security/cases/ediscoveryCases` | eDiscovery case management | `eDiscovery.ReadWrite.All` | `eDiscovery.ReadWrite.All` |
| `/identityProtection/riskDetections` | Identity risk events | `IdentityRiskEvent.Read.All` | `IdentityRiskEvent.Read.All` |
| `/identityProtection/riskyUsers` | Users flagged as risky | `IdentityRiskyUser.ReadWrite.All` | `IdentityRiskyUser.ReadWrite.All` |

### Authentication Patterns

**App-Only (Daemon/Service) — for automation and background jobs:**

```python
# Python — MSAL app-only authentication
from msal import ConfidentialClientApplication
import requests

TENANT_ID = "<tenant-id>"
CLIENT_ID = "<client-id>"
CLIENT_SECRET = "<client-secret>"  # Use cert-based auth in production
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["https://graph.microsoft.com/.default"]

app = ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET
)

token = app.acquire_token_for_client(scopes=SCOPES)

headers = {
    "Authorization": f"Bearer {token['access_token']}",
    "Content-Type": "application/json"
}

# Query security alerts
response = requests.get(
    "https://graph.microsoft.com/v1.0/security/alerts_v2"
    "?$top=10&$orderby=createdDateTime desc"
    "&$filter=severity eq 'high'",
    headers=headers
)

alerts = response.json().get("value", [])
for alert in alerts:
    print(f"[{alert['severity']}] {alert['title']} — {alert['createdDateTime']}")
```

```powershell
# PowerShell — App-only with certificate
$params = @{
    TenantId = "<tenant-id>"
    ClientId = "<client-id>"
    CertificateThumbprint = "<cert-thumbprint>"
}
Connect-MgGraph @params

# Query security alerts
$alerts = Get-MgSecurityAlert -Top 10 -OrderBy "createdDateTime desc" `
    -Filter "severity eq 'high'"

$alerts | Select-Object Title, Severity, Status, CreatedDateTime,
    @{N='Products';E={$_.ProductName}} | Format-Table
```

**Delegated (Interactive) — for user-facing apps and investigation tools:**

```powershell
# PowerShell — Delegated authentication
Connect-MgGraph -Scopes "SecurityAlert.ReadWrite.All", "SecurityIncident.ReadWrite.All"

# Interactive user consents to permissions
$incidents = Get-MgSecurityIncident -Top 5 -OrderBy "createdDateTime desc"
$incidents | Select-Object DisplayName, Severity, Status, CreatedDateTime
```

```python
# Python — Delegated with device code flow
from msal import PublicClientApplication

app = PublicClientApplication(CLIENT_ID, authority=AUTHORITY)

flow = app.initiate_device_flow(
    scopes=["SecurityAlert.ReadWrite.All", "SecurityIncident.ReadWrite.All"]
)
print(flow["message"])  # User completes auth in browser

token = app.acquire_token_by_device_flow(flow)
```

### Working with Alerts (v2)

```python
# List high-severity alerts from the last 24 hours
from datetime import datetime, timedelta

since = (datetime.utcnow() - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")

response = requests.get(
    f"https://graph.microsoft.com/v1.0/security/alerts_v2"
    f"?$filter=createdDateTime ge {since} and severity eq 'high'"
    f"&$top=50"
    f"&$orderby=createdDateTime desc",
    headers=headers
)

alerts = response.json().get("value", [])
for alert in alerts:
    print(f"ID: {alert['id']}")
    print(f"Title: {alert['title']}")
    print(f"Severity: {alert['severity']}")
    print(f"Status: {alert['status']}")
    print(f"Product: {alert.get('productName', 'N/A')}")
    print(f"MITRE: {[t.get('techniqueId') for t in alert.get('mitreTechniques', [])]}")
    print("---")
```

```powershell
# Update alert status
Update-MgSecurityAlert -AlertId "<alert-id>" -BodyParameter @{
    status = "inProgress"
    assignedTo = "analyst@contoso.com"
    classification = "truePositive"
    determination = "malware"
    comment = "Investigating — SOAR playbook triggered"
}
```

### Working with Incidents

```powershell
# Get incident with related alerts
$incident = Get-MgSecurityIncident -IncidentId "<incident-id>"
$incident | Select-Object DisplayName, Severity, Status, 
    @{N='AlertCount';E={$_.Alerts.Count}},
    @{N='Entities';E={($_.Tags -join ', ')}}

# Update incident
Update-MgSecurityIncident -IncidentId "<incident-id>" -BodyParameter @{
    status = "active"
    assignedTo = "analyst@contoso.com"
    classification = "truePositive"
    determination = "compromisedUser"
    customTags = @("phishing-campaign-2026-04", "priority-investigation")
}
```

### Threat Intelligence API

```python
# Query threat intelligence indicators
response = requests.get(
    "https://graph.microsoft.com/v1.0/security/threatIntelligence/hosts"
    "?$top=10",
    headers=headers
)

# Look up a specific host
host_response = requests.get(
    "https://graph.microsoft.com/v1.0/security/threatIntelligence/hosts/contoso.com",
    headers=headers
)
host = host_response.json()
print(f"Host: {host.get('id')}")
print(f"First Seen: {host.get('firstSeenDateTime')}")
print(f"Last Seen: {host.get('lastSeenDateTime')}")

# Get threat intelligence articles
articles = requests.get(
    "https://graph.microsoft.com/v1.0/security/threatIntelligence/articles"
    "?$top=5&$orderby=createdDateTime desc",
    headers=headers
).json().get("value", [])

for article in articles:
    print(f"[{article.get('createdDateTime')}] {article.get('title')}")
```

### Secure Score API

```powershell
# Get current secure score
$scores = Get-MgSecuritySecureScore -Top 1 -OrderBy "createdDateTime desc"
$score = $scores[0]

Write-Host "Current Score: $($score.CurrentScore) / $($score.MaxScore)"
Write-Host "Percentage: $([math]::Round($score.CurrentScore / $score.MaxScore * 100, 1))%"

# Get score control profiles (improvement actions)
$controls = Get-MgSecuritySecureScoreControlProfile -Top 50
$controls | Where-Object { $_.ImplementationStatus -ne "implemented" } |
    Sort-Object -Property MaxScore -Descending |
    Select-Object Title, MaxScore, ImplementationStatus, UserImpact |
    Format-Table -AutoSize
```

### Batch Operations and Pagination

```python
# Batch request — multiple queries in a single call
batch_payload = {
    "requests": [
        {
            "id": "1",
            "method": "GET",
            "url": "/security/alerts_v2?$top=5&$filter=severity eq 'high'"
        },
        {
            "id": "2",
            "method": "GET",
            "url": "/security/incidents?$top=5&$filter=status eq 'active'"
        },
        {
            "id": "3",
            "method": "GET",
            "url": "/security/secureScores?$top=1&$orderby=createdDateTime desc"
        }
    ]
}

batch_response = requests.post(
    "https://graph.microsoft.com/v1.0/$batch",
    headers=headers,
    json=batch_payload
)

for resp in batch_response.json()["responses"]:
    print(f"Request {resp['id']}: Status {resp['status']}")
    if resp["status"] == 200:
        print(f"  Results: {len(resp['body'].get('value', []))}")
```

```python
# Pagination — handle large result sets
def get_all_alerts(headers, filter_query=""):
    url = f"https://graph.microsoft.com/v1.0/security/alerts_v2?$top=100"
    if filter_query:
        url += f"&$filter={filter_query}"
    
    all_alerts = []
    while url:
        response = requests.get(url, headers=headers)
        data = response.json()
        all_alerts.extend(data.get("value", []))
        url = data.get("@odata.nextLink")  # None when no more pages
    
    return all_alerts

alerts = get_all_alerts(headers, "severity eq 'high'")
print(f"Total high-severity alerts: {len(alerts)}")
```

### Webhook Subscriptions for Real-Time Notifications

```python
# Create a webhook subscription for new security alerts
subscription = {
    "changeType": "created,updated",
    "notificationUrl": "https://your-app.azurewebsites.net/api/security-webhook",
    "resource": "/security/alerts_v2",
    "expirationDateTime": "2026-05-28T00:00:00Z",  # Max 43200 minutes
    "clientState": "secretClientState-for-validation"
}

response = requests.post(
    "https://graph.microsoft.com/v1.0/subscriptions",
    headers=headers,
    json=subscription
)

sub = response.json()
print(f"Subscription ID: {sub['id']}")
print(f"Expires: {sub['expirationDateTime']}")
```

```python
# Webhook handler (Azure Function / Flask endpoint)
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/security-webhook", methods=["POST"])
def handle_webhook():
    # Validation handshake
    if "validationToken" in request.args:
        return request.args["validationToken"], 200, {"Content-Type": "text/plain"}
    
    # Process notification
    data = request.json
    for notification in data.get("value", []):
        resource = notification.get("resource")
        change_type = notification.get("changeType")
        client_state = notification.get("clientState")
        
        # Verify client state
        if client_state != "secretClientState-for-validation":
            return "Unauthorized", 403
        
        # Process the alert
        print(f"Alert {change_type}: {resource}")
        # Trigger SOAR playbook, send Teams notification, etc.
    
    return "", 202
```

```powershell
# Renew subscription before expiration
$newExpiration = (Get-Date).AddDays(29).ToString("yyyy-MM-ddTHH:mm:ssZ")
Update-MgSubscription -SubscriptionId "<subscription-id>" -BodyParameter @{
    expirationDateTime = $newExpiration
}
```

## Integration Points

- **Microsoft Sentinel** — Graph API data enriches Sentinel incidents via Logic Apps
- **Defender XDR** — Alerts and incidents accessible via unified Graph endpoint
- **Azure Functions** — Serverless webhook handlers for real-time processing
- **Logic Apps** — Low-code connectors for Graph Security API
- **Power Automate** — Citizen-developer friendly security automation
- **Power BI** — Security dashboards from Graph API data

## Operational Procedures

### API Health Check Script

```powershell
# Verify Graph Security API connectivity and data freshness
Connect-MgGraph -Scopes "SecurityAlert.Read.All", "SecurityEvents.Read.All"

# Check alerts endpoint
$alerts = Get-MgSecurityAlert -Top 1 -OrderBy "createdDateTime desc"
Write-Host "Latest alert: $($alerts[0].CreatedDateTime) — $($alerts[0].Title)"

# Check secure score
$score = Get-MgSecuritySecureScore -Top 1 -OrderBy "createdDateTime desc"
Write-Host "Secure score: $($score[0].CurrentScore)/$($score[0].MaxScore)"

# Check subscriptions
$subs = Get-MgSubscription | Where-Object { $_.Resource -like "*security*" }
foreach ($sub in $subs) {
    $daysLeft = ((Get-Date $sub.ExpirationDateTime) - (Get-Date)).Days
    Write-Host "Subscription: $($sub.Resource) — Expires in $daysLeft days"
    if ($daysLeft -lt 3) {
        Write-Warning "Subscription expiring soon — renew immediately"
    }
}
```

### Rate Limiting and Throttling

| Endpoint | Limit | Strategy |
|---|---|---|
| `/security/alerts_v2` | 150 requests/min per app | Use `$top` and `$filter` to reduce calls |
| `/security/incidents` | 150 requests/min per app | Cache results; use delta queries |
| `$batch` | 20 requests per batch | Batch related queries |
| Webhooks | 1 subscription per resource per app | Use single subscription with broad filter |

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| 403 Forbidden | Missing or insufficient permissions | Add required Graph permissions; grant admin consent |
| 401 Unauthorized | Token expired or invalid | Refresh token; check client secret/cert expiration |
| Empty results | Filter too restrictive or data not yet available | Broaden filter; wait for data pipeline (up to 15 min delay) |
| Webhook validation fails | Notification URL not reachable or wrong response | Ensure endpoint returns validation token as plain text |
| Rate limited (429) | Too many requests | Implement exponential backoff; use batch operations |
| Subscription expired | Max lifetime exceeded | Implement renewal logic; renew 24h before expiration |

## Related Skills

- **[Sentinel Workspace Setup](sentinel-workspace-setup.md)** — Security data that the API queries
- **[Defender XDR Configuration](defender-xdr-configuration.md)** — Incidents and alerts accessible via API
- **[Entra ID Protection](entra-id-protection.md)** — Risk detections via Identity Protection API
- **[Purview DLP Patterns](purview-dlp-patterns.md)** — DLP alerts accessible via Graph
- **[SOAR Playbook Patterns](../soar/)** — Logic Apps that consume Graph Security API
