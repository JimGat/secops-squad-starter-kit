# Graph Security API Library

Zero-dependency Node.js library for the Microsoft Graph Security API (v1.0). Built for SOC automation — alert management, incident correlation, threat intelligence, and security posture tracking.

## Requirements

- **Node.js 18+** (uses native `fetch`)
- Azure AD app registration with appropriate permissions

## Authentication Setup

### App Registration (Azure Portal)

1. Go to **Azure Portal → Azure Active Directory → App registrations → New registration**
2. Name it (e.g., `secops-graph-client`), select **Accounts in this organizational directory only**
3. Under **API Permissions**, add Microsoft Graph **Application** permissions:
   - `SecurityEvents.ReadWrite.All` — alerts and incidents
   - `ThreatIndicators.ReadWrite.OwnedBy` — threat intelligence indicators
   - `SecurityActions.ReadWrite.All` — security actions
4. **Grant admin consent** for the permissions
5. Under **Certificates & secrets**, create a client secret
6. Record: **Tenant ID**, **Application (client) ID**, **Client Secret Value**

### Permission Reference

| Module              | Required Permission                      | Type        |
|---------------------|------------------------------------------|-------------|
| alerts              | `SecurityEvents.ReadWrite.All`          | Application |
| incidents           | `SecurityIncident.ReadWrite.All`        | Application |
| threat-intelligence | `ThreatIndicators.ReadWrite.OwnedBy`    | Application |
| secure-score        | `SecurityEvents.Read.All`               | Application |

## Quick Start

```javascript
const { createClient, alerts, incidents, secureScore, threatIntelligence } = require('./lib/graph-security');

// Create an authenticated client
const client = createClient({
  tenantId: process.env.AZURE_TENANT_ID,
  clientId: process.env.AZURE_CLIENT_ID,
  clientSecret: process.env.AZURE_CLIENT_SECRET,
});
```

### Working with Alerts

```javascript
// List high-severity alerts
const result = await alerts.listAlerts(client, { severity: 'high' });
if (result.ok) {
  console.log(`Found ${result.data.length} high-severity alerts`);
  result.data.forEach(a => console.log(`  [${a.severity}] ${a.title}`));
}

// Get a specific alert
const alert = await alerts.getAlert(client, 'alert-id-here');

// Update an alert
const updated = await alerts.updateAlert(client, 'alert-id-here', {
  status: 'inProgress',
  assignedTo: 'analyst@contoso.com',
  comments: [{ comment: 'Investigating suspicious login activity' }],
});

// Find alerts for a specific user
const userAlerts = await alerts.listAlertsByEntity(client, 'user', 'user@contoso.com');
```

### Working with Incidents

```javascript
// List active incidents
const result = await incidents.listIncidents(client, { status: 'active' });

// Get incident details
const incident = await incidents.getIncident(client, '12345');

// Update incident classification
const updated = await incidents.updateIncident(client, '12345', {
  status: 'resolved',
  classification: 'truePositive',
  determination: 'malware',
});

// Add investigation notes
await incidents.addComment(client, '12345', 'Confirmed malware on host WKS-042. Isolated and remediated.');

// Get all alerts tied to an incident
const relatedAlerts = await incidents.getIncidentAlerts(client, '12345');
```

### Threat Intelligence Indicators

```javascript
// Create a TI indicator from an IOC
const { convertIOCToIndicator, createIndicator } = threatIntelligence;

const conversion = convertIOCToIndicator({
  type: 'ip',
  value: '203.0.113.42',
  action: 'block',
  threatType: 'C2',
  description: 'Known C2 server from incident INC-2026-0042',
  expirationDays: 30,
});

if (conversion.ok) {
  const result = await createIndicator(client, conversion.indicator);
  console.log('Indicator created:', result.ok);
}

// Bulk-create indicators with rate limiting
const iocs = [
  { type: 'ip', value: '198.51.100.1', action: 'alert', threatType: 'C2' },
  { type: 'domain', value: 'evil.example.com', action: 'block', threatType: 'Phishing' },
  { type: 'sha256', value: 'abc123...', action: 'block', threatType: 'Malware' },
];

const indicators = iocs
  .map(convertIOCToIndicator)
  .filter(r => r.ok)
  .map(r => r.indicator);

const batch = await threatIntelligence.bulkCreateIndicators(client, indicators, {
  delayMs: 300,         // 300ms between requests
  stopOnError: false,   // continue on failures
});

console.log(`Created ${batch.results.filter(r => r.ok).length}/${indicators.length} indicators`);
```

### Secure Score

```javascript
// Get current secure score
const score = await secureScore.getSecureScore(client);
if (score.ok) {
  console.log(`Secure Score: ${score.data.currentScore}/${score.data.maxScore}`);
}

// Score trend over 30 days
const history = await secureScore.getSecureScoreHistory(client, 30);

// Get actionable recommendations (sorted by impact)
const recs = await secureScore.getRecommendations(client);
if (recs.ok) {
  recs.data.slice(0, 5).forEach(r => {
    console.log(`  ${r.title} — up to +${r.maxScore} points`);
  });
}
```

## Authentication Methods

### Client Credentials (Default) — App-only, daemon/service

```javascript
const client = createClient({
  tenantId: 'your-tenant-id',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
});
```

### Managed Identity — Azure-hosted automation

```javascript
const client = createClient({ authMethod: 'managedIdentity' });
```

Works automatically on Azure VMs, App Service, Functions, Container Instances, and AKS.

### Device Code — Interactive CLI usage

```javascript
const client = createClient({
  tenantId: 'your-tenant-id',
  clientId: 'your-client-id',
  authMethod: 'deviceCode',
});
```

Prints a device code and URL. User authenticates in a browser while the client polls for completion.

### Pre-acquired Token — Testing or external token management

```javascript
const client = createClient({ token: 'eyJ0eXAi...' });
```

## Error Handling

Every function returns a structured result object — never throws for API errors.

```javascript
const result = await alerts.listAlerts(client, { severity: 'high' });

if (result.ok) {
  // Success — result.data contains the response
  console.log(result.data);
  if (result.nextLink) {
    // More pages available
    const page2 = await alerts.listAlerts(client, { nextLink: result.nextLink });
  }
} else {
  // API error — structured error info
  console.error(`Error: ${result.error}`);
  console.error(`Status: ${result.status}`);   // HTTP status code
  console.error(`Code: ${result.code}`);       // OData error code (if available)
}
```

### Common Error Status Codes

| Status | Meaning                   | Typical Cause                                  |
|--------|---------------------------|-------------------------------------------------|
| 401    | Unauthorized              | Token expired, missing, or invalid              |
| 403    | Forbidden                 | Insufficient API permissions                    |
| 404    | Not Found                 | Invalid alert/incident ID                       |
| 429    | Rate Limited              | Too many requests (auto-retried 3× with backoff)|
| 500    | Internal Server Error     | Transient Graph API issue                       |

Rate limiting (429) is handled automatically with exponential backoff — up to 3 retries before returning the error.

## Pagination

Functions that return lists support OData pagination via `nextLink`:

```javascript
let allAlerts = [];
let result = await alerts.listAlerts(client, { top: 100 });

while (result.ok) {
  allAlerts.push(...result.data);
  if (!result.nextLink) break;
  result = await alerts.listAlerts(client, { nextLink: result.nextLink });
}

console.log(`Total alerts: ${allAlerts.length}`);
```

## Rate Limiting Guidance

The Graph Security API has throttling limits:

- **Alerts/Incidents**: ~150 requests per minute per app
- **TI Indicators**: ~60 requests per minute per app

The library handles 429 responses automatically (3 retries with exponential backoff). For bulk operations, use `bulkCreateIndicators` which includes configurable inter-request delays.

For high-volume automation, consider:
1. Use `$top` to fetch larger pages (fewer requests)
2. Cache results that don't change frequently (secure scores)
3. Use webhook subscriptions instead of polling for real-time alert monitoring

## Integration Examples

### Azure Sentinel / Logic Apps

This library works inside Azure Functions called by Logic Apps playbooks:

```javascript
// Azure Function handler for a Logic App playbook
module.exports = async function (context, req) {
  const client = createClient({ authMethod: 'managedIdentity' });

  const alertId = req.body.alertId;
  const alert = await alerts.getAlert(client, alertId);

  if (!alert.ok) {
    context.res = { status: 500, body: alert.error };
    return;
  }

  // Auto-enrich: check if the alert entity has known TI indicators
  const enriched = await alerts.listAlertsByEntity(
    client, 'ip', alert.data.evidence?.[0]?.ipAddress
  );

  // Update the alert with enrichment results
  await alerts.updateAlert(client, alertId, {
    comments: [{ comment: `Auto-enriched: ${enriched.data?.length || 0} related alerts found` }],
  });

  context.res = { status: 200, body: { alert: alert.data, related: enriched.data } };
};
```

### Automated Incident Response

```javascript
async function autoTriageIncident(client, incidentId) {
  const incident = await incidents.getIncident(client, incidentId);
  if (!incident.ok) return incident;

  const relatedAlerts = await incidents.getIncidentAlerts(client, incidentId);
  if (!relatedAlerts.ok) return relatedAlerts;

  // Simple auto-triage logic
  const highSevAlerts = relatedAlerts.data.filter(a => a.severity === 'high');

  if (highSevAlerts.length > 0) {
    // Escalate
    await incidents.updateIncident(client, incidentId, {
      assignedTo: 'tier2-soc@contoso.com',
      tags: ['auto-escalated', 'high-severity'],
    });
    await incidents.addComment(client, incidentId,
      `Auto-escalated: ${highSevAlerts.length} high-severity alerts detected`
    );
  } else {
    // Assign to Tier 1
    await incidents.updateIncident(client, incidentId, {
      assignedTo: 'tier1-soc@contoso.com',
    });
  }

  return { ok: true, escalated: highSevAlerts.length > 0 };
}
```

## Module Reference

| Module               | Exports                                                             |
|----------------------|---------------------------------------------------------------------|
| `index.js`           | `createClient()`, all modules & constants                           |
| `auth.js`            | `getTokenClientCredentials()`, `getTokenManagedIdentity()`, `getTokenDeviceCode()`, `clearTokenCache()` |
| `alerts.js`          | `listAlerts()`, `getAlert()`, `updateAlert()`, `listAlertsByEntity()`, `SEVERITY`, `ALERT_STATUS` |
| `incidents.js`       | `listIncidents()`, `getIncident()`, `updateIncident()`, `addComment()`, `getIncidentAlerts()`, `INCIDENT_STATUS`, `INCIDENT_CLASSIFICATION`, `INCIDENT_DETERMINATION` |
| `threat-intelligence.js` | `listIndicators()`, `createIndicator()`, `deleteIndicator()`, `bulkCreateIndicators()`, `convertIOCToIndicator()`, `INDICATOR_TYPE`, `INDICATOR_ACTION`, `THREAT_TYPE` |
| `secure-score.js`    | `getSecureScore()`, `getSecureScoreHistory()`, `getControlProfiles()`, `getRecommendations()` |
