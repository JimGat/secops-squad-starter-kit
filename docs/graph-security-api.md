# Graph Security API Library Guide

The **Graph Security API Library** is a zero-dependency Node.js client for Microsoft Graph Security v1.0. Use it to automate alert management, incident correlation, threat intelligence, and security posture tracking.

**Key features:**
- ✅ **4 modules**: alerts, incidents, threat-intelligence, secure-score
- ✅ **3 authentication flows**: Client credentials (app-only), Managed Identity, Device Code
- ✅ **Structured errors**: Never throws; returns `{ok, data?, error?}` format
- ✅ **Zero dependencies**: Uses native Node.js `fetch` API
- ✅ **Rate-limit aware**: Auto-retries with exponential backoff

**Location:** [`lib/graph-security/`](../lib/graph-security/)

---

## Setup: App Registration

Before using the library, register your app in Azure AD:

### Step 1: Create App Registration
1. Go to **Azure Portal → Azure Active Directory → App registrations**
2. Click **+ New registration**
3. Name: `secops-graph-client`
4. Select **Accounts in this organizational directory only**
5. Click **Register**

### Step 2: Grant API Permissions
1. In the new app, click **API Permissions**
2. Click **+ Add a permission → Microsoft Graph**
3. Select **Application permissions** (not Delegated)
4. Add:
   - `SecurityEvents.ReadWrite.All` — alerts, incidents
   - `ThreatIndicators.ReadWrite.OwnedBy` — threat intelligence
   - `SecurityActions.ReadWrite.All` — security actions
5. Click **Grant admin consent**

### Step 3: Create Client Secret
1. Click **Certificates & secrets**
2. Under **Client secrets**, click **+ New client secret**
3. Description: `secops-squad`
4. Expiry: `12 months` (adjust to your policy)
5. Click **Add** and **immediately copy the Value** (you won't see it again)

### Step 4: Record Credentials
Save these for your environment:
- **Directory (tenant) ID** — Found on App → Overview
- **Application (client) ID** — Found on App → Overview
- **Client Secret Value** — From Certificates & secrets (you just copied this)

**Permissions Reference:**

| Module | Permission | Type |
|--------|-----------|------|
| `alerts` | `SecurityEvents.ReadWrite.All` | Application |
| `incidents` | `SecurityIncident.ReadWrite.All` | Application |
| `threat-intelligence` | `ThreatIndicators.ReadWrite.OwnedBy` | Application |
| `secure-score` | `SecurityEvents.Read.All` | Application |

---

## Authentication Methods

### 1. Client Credentials (Default) — App-Only

Best for: Daemons, Azure Functions, Logic Apps, scheduled automation

```javascript
const { createClient } = require('./lib/graph-security');

const client = createClient({
  tenantId: process.env.AZURE_TENANT_ID,
  clientId: process.env.AZURE_CLIENT_ID,
  clientSecret: process.env.AZURE_CLIENT_SECRET,
});

// Use client for all subsequent calls
const alerts = await client.alerts.listAlerts();
```

### 2. Managed Identity — Azure-Hosted Automation

Best for: Azure Functions, App Service, Container Instances, VMs, AKS

```javascript
const client = createClient({ authMethod: 'managedIdentity' });

// Works automatically on Azure-hosted resources
const alerts = await client.alerts.listAlerts();
```

**Setup on Azure:**
1. Enable managed identity on your resource (VM, Function, etc.)
2. Assign the same permissions (SecurityEvents.ReadWrite.All, etc.) to the managed identity
3. No credentials needed — Azure handles auth automatically

### 3. Device Code — Interactive CLI

Best for: Local development, one-off scripts, manual testing

```javascript
const client = createClient({
  tenantId: process.env.AZURE_TENANT_ID,
  clientId: process.env.AZURE_CLIENT_ID,
  authMethod: 'deviceCode',
});

// Prints: "To sign in, use a web browser to open the page
//          https://microsoft.com/devicelogin and enter the code ABC123XYZ"
const alerts = await client.alerts.listAlerts();
```

The user opens the URL in a browser, enters the code, and authenticates. The client polls until complete.

### 4. Pre-Acquired Token — Testing & External Token Management

Best for: Testing, token cache management, external auth systems

```javascript
const client = createClient({ token: 'eyJ0eXAi...' });
```

Pass any valid Graph API bearer token.

---

## Module: Alerts

Manage Sentinel/Defender alerts and alert enrichment.

### List Alerts

```javascript
const { alerts } = require('./lib/graph-security');

// All alerts
const result = await alerts.listAlerts(client);

// Filter by severity
const highSev = await alerts.listAlerts(client, { severity: 'high' });

// Filter by status
const inProgress = await alerts.listAlerts(client, { status: 'inProgress' });

// Pagination
const page2 = await alerts.listAlerts(client, { nextLink: result.nextLink });
```

**Status codes:** `new`, `inProgress`, `resolved`  
**Severity:** `high`, `medium`, `low`, `informational`

### Get Alert Details

```javascript
const result = await alerts.getAlert(client, 'alert-id-123');

if (result.ok) {
  const alert = result.data;
  console.log(`Title: ${alert.title}`);
  console.log(`Severity: ${alert.severity}`);
  console.log(`Status: ${alert.status}`);
  console.log(`Evidence:`, alert.evidence);  // IP, file hash, domain, etc.
} else {
  console.error(`Error: ${result.error}`);
}
```

### Update Alert

```javascript
const result = await alerts.updateAlert(client, 'alert-id-123', {
  status: 'resolved',
  assignedTo: 'analyst@contoso.com',
  comments: [
    { comment: 'False positive: expected behavior during security test' }
  ],
});
```

### Find Alerts by Entity

```javascript
// Alerts involving a specific IP
const ips = await alerts.listAlertsByEntity(client, 'ip', '192.168.1.100');

// Alerts involving a user
const userAlerts = await alerts.listAlertsByEntity(client, 'user', 'user@contoso.com');

// Alerts involving a domain
const domainAlerts = await alerts.listAlertsByEntity(client, 'domain', 'evil.example.com');
```

---

## Module: Incidents

Manage Defender XDR incidents and investigation coordination.

### List Incidents

```javascript
const { incidents } = require('./lib/graph-security');

// All incidents
const result = await incidents.listIncidents(client);

// Active incidents only
const active = await incidents.listIncidents(client, { status: 'active' });

// Filter by determination (only for resolved incidents)
const confirmed = await incidents.listIncidents(client, { determination: 'truePositive' });
```

**Status:** `new`, `inProgress`, `resolved`  
**Classification:** `unknown`, `falsePositive`, `truePositive`  
**Determination:** `unknown`, `apt`, `malware`, `securityPersonnel`, `securityTesting`, `unknownFutureValue`

### Get Incident Details

```javascript
const result = await incidents.getIncident(client, 'incident-123');

if (result.ok) {
  const incident = result.data;
  console.log(`Title: ${incident.displayName}`);
  console.log(`Severity: ${incident.severity}`);
  console.log(`Status: ${incident.status}`);
  console.log(`Created: ${incident.createdDateTime}`);
}
```

### Update Incident

```javascript
await incidents.updateIncident(client, 'incident-123', {
  status: 'resolved',
  classification: 'truePositive',
  determination: 'malware',
  assignedTo: 'tier2-team@contoso.com',
});
```

### Add Comment to Incident

```javascript
await incidents.addComment(client, 'incident-123', 
  'Forensic analysis complete. Malware signature: SHA256:abc123...'
);
```

### Get Alerts Tied to an Incident

```javascript
const result = await incidents.getIncidentAlerts(client, 'incident-123');

if (result.ok) {
  result.data.forEach(alert => {
    console.log(`  - [${alert.severity}] ${alert.title}`);
  });
}
```

---

## Module: Threat Intelligence

Manage threat indicators (IOCs) in Microsoft Graph Security.

### Create Threat Intelligence Indicator

```javascript
const { threatIntelligence, ThreatType, IndicatorAction } = 
  require('./lib/graph-security');

// Direct creation
const result = await threatIntelligence.createIndicator(client, {
  type: 'ipv4',
  value: '203.0.113.42',
  action: 'alert',  // or 'block'
  threatType: 'C2',
  description: 'Known C2 server from incident INC-2026-0042',
  expirationDateTime: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),  // 30 days
});
```

**Indicator types:** `ipv4`, `ipv6`, `domain`, `url`, `email`, `sha256`, `md5`  
**Threat types:** `Anomalous`, `Malware`, `Phishing`, `PrivilegeEscalation`, `Trojan`, `Worm`, `C2`, ...  
**Actions:** `alert`, `block`, `allow`

### Convert IOC to Indicator

Helper function to convert common IOC formats:

```javascript
const { convertIOCToIndicator } = require('./lib/graph-security');

const result = convertIOCToIndicator({
  type: 'domain',
  value: 'command-and-control.example.com',
  action: 'block',
  threatType: 'C2',
  description: 'C2 domain from APT-28',
  expirationDays: 30,
});

if (result.ok) {
  const created = await threatIntelligence.createIndicator(client, result.indicator);
}
```

### Bulk Create Indicators

Ingest multiple IOCs with rate-limiting:

```javascript
const indicators = [
  { type: 'ipv4', value: '198.51.100.1', action: 'block', threatType: 'C2' },
  { type: 'domain', value: 'evil1.example.com', action: 'alert', threatType: 'Phishing' },
  { type: 'sha256', value: 'abc123...', action: 'block', threatType: 'Malware' },
];

const batch = await threatIntelligence.bulkCreateIndicators(client, indicators, {
  delayMs: 300,         // 300ms between requests (rate limiting)
  stopOnError: false,   // Continue on failures
});

console.log(`Created ${batch.results.filter(r => r.ok).length}/${indicators.length}`);
```

### List Indicators

```javascript
const result = await threatIntelligence.listIndicators(client);

if (result.ok) {
  result.data.forEach(indicator => {
    console.log(`  [${indicator.threatType}] ${indicator.value}`);
  });
}
```

### Delete Indicator

```javascript
await threatIntelligence.deleteIndicator(client, 'indicator-id-123');
```

---

## Module: Secure Score

Track and analyze Microsoft security posture.

### Get Current Secure Score

```javascript
const { secureScore } = require('./lib/graph-security');

const result = await secureScore.getSecureScore(client);

if (result.ok) {
  const score = result.data;
  console.log(`Current: ${score.currentScore}/${score.maxScore}`);
  console.log(`Percentage: ${(score.currentScore / score.maxScore * 100).toFixed(1)}%`);
}
```

### Get Secure Score History

Trend analysis over N days:

```javascript
const history = await secureScore.getSecureScoreHistory(client, 30);

if (history.ok) {
  history.data.forEach(snapshot => {
    console.log(`${snapshot.createdDateTime}: ${snapshot.currentScore}`);
  });
}
```

### Get Top Recommendations

Actionable security improvements, sorted by impact:

```javascript
const result = await secureScore.getRecommendations(client);

if (result.ok) {
  result.data.slice(0, 5).forEach(rec => {
    console.log(`
      ${rec.title}
      Impact: +${rec.maxScore} points
      Action: ${rec.actionSteps}
    `);
  });
}
```

### Get Control Profiles

Compliance frameworks (CIS, PCI-DSS, etc.) and their scores:

```javascript
const profiles = await secureScore.getControlProfiles(client);

if (profiles.ok) {
  profiles.data.forEach(profile => {
    console.log(`${profile.name}: ${profile.currentScore}/${profile.maxScore}`);
  });
}
```

---

## Error Handling

All functions return a **structured result object**. They never throw for API errors.

```javascript
const result = await alerts.listAlerts(client, { severity: 'high' });

if (result.ok) {
  // Success
  console.log(`Found ${result.data.length} alerts`);
  
  if (result.nextLink) {
    // More pages available
    const page2 = await alerts.listAlerts(client, { nextLink: result.nextLink });
  }
} else {
  // API error — structured error info
  console.error(`Error: ${result.error}`);
  console.error(`Status: ${result.status}`);     // HTTP status code
  console.error(`Code: ${result.code}`);         // OData error code (if available)
}
```

### Common Error Status Codes

| Status | Meaning | Typical Cause | Recovery |
|--------|---------|---|---|
| 401 | Unauthorized | Token expired or invalid | Refresh token or re-auth |
| 403 | Forbidden | Missing API permissions | Grant app the required permission |
| 404 | Not Found | Invalid alert/incident ID | Verify the ID exists |
| 429 | Rate Limited | Too many requests | Auto-retried 3× by default |
| 500 | Server Error | Transient Graph API issue | Retry with backoff |

**Rate limiting (429) is handled automatically** — the library retries up to 3 times with exponential backoff before returning the error.

---

## Integration Examples

### Example 1: Auto-Triage in Logic Apps

Use the library inside an Azure Function called by a Logic Apps playbook:

```javascript
module.exports = async function(context, req) {
  const { createClient, alerts, incidents } = require('./lib/graph-security');
  
  const client = createClient({ authMethod: 'managedIdentity' });
  
  // Get the alert from Logic Apps
  const alertId = req.body.alertId;
  const alert = await alerts.getAlert(client, alertId);
  
  if (!alert.ok) {
    context.res = { status: 500, body: alert.error };
    return;
  }
  
  // Auto-enrich: check if entities have known TI indicators
  const enriched = await alerts.listAlertsByEntity(
    client, 'ip', alert.data.sourceIpAddress
  );
  
  // Update alert with enrichment
  await alerts.updateAlert(client, alertId, {
    comments: [{
      comment: `Auto-enriched: ${enriched.data?.length || 0} related alerts found`
    }]
  });
  
  context.res = { 
    status: 200, 
    body: { alert: alert.data, relatedAlerts: enriched.data } 
  };
};
```

### Example 2: Bulk Import IOCs

Import threat intelligence from a CSV or external feed:

```javascript
const fs = require('fs');
const csv = require('csv-parse');  // npm install csv-parse
const { createClient, threatIntelligence } = require('./lib/graph-security');

async function importIOCs(csvFile) {
  const client = createClient({ authMethod: 'managedIdentity' });
  
  const indicators = [];
  
  // Parse CSV: column 1 = type, column 2 = value, column 3 = threatType
  fs.createReadStream(csvFile)
    .pipe(csv())
    .on('data', (row) => {
      indicators.push({
        type: row[0],
        value: row[1],
        action: 'alert',
        threatType: row[2],
        description: `Imported from feed on ${new Date().toISOString()}`,
        expirationDays: 90,
      });
    })
    .on('end', async () => {
      // Bulk create with rate limiting
      const batch = await threatIntelligence.bulkCreateIndicators(
        client, indicators, { delayMs: 500, stopOnError: false }
      );
      
      console.log(`✅ Created ${batch.results.filter(r => r.ok).length}/${indicators.length}`);
      console.log(`❌ Failed: ${batch.results.filter(r => !r.ok).length}`);
    });
}
```

### Example 3: Incident Forensics Timeline

Correlate Graph Security incidents with ADX security data:

```javascript
const { createClient, incidents } = require('./lib/graph-security');
const adxCluster = require('kusto-ingest');  // npm install azure-kusto-ingest

async function buildForensicTimeline(incidentId) {
  const client = createClient({ authMethod: 'managedIdentity' });
  
  // Get incident details
  const incident = await incidents.getIncident(client, incidentId);
  if (!incident.ok) throw incident.error;
  
  // Get all alerts in the incident
  const alerts = await incidents.getIncidentAlerts(client, incidentId);
  if (!alerts.ok) throw alerts.error;
  
  // Extract user/IP/domain entities from alerts
  const entities = new Set();
  alerts.data.forEach(alert => {
    if (alert.evidence?.sourceUser) entities.add(alert.evidence.sourceUser);
    if (alert.evidence?.sourceIpAddress) entities.add(alert.evidence.sourceIpAddress);
  });
  
  // Query ADX for forensic timeline
  const adxQuery = `
    union SecurityEvents, IdentityEvents, NetworkTraffic
    | where Account in ('${Array.from(entities).join("','")}')
    | where TimeGenerated between(ago(30d) .. now())
    | sort by TimeGenerated asc
  `;
  
  console.log('Forensic timeline:', adxQuery);
  
  return { incident: incident.data, alerts: alerts.data, entities };
}
```

---

## API Reference

### Exports

| Export | Type | Purpose |
|--------|------|---------|
| `createClient(options)` | Function | Initialize authenticated client |
| `alerts` | Module | Alert management |
| `incidents` | Module | Incident management |
| `threatIntelligence` | Module | Threat indicator management |
| `secureScore` | Module | Security score queries |
| Constants | — | `SEVERITY`, `ALERT_STATUS`, `INCIDENT_STATUS`, etc. |

### Result Format

```typescript
interface Result<T> {
  ok: boolean;
  data?: T;
  error?: string;
  status?: number;     // HTTP status code
  code?: string;       // OData error code
  nextLink?: string;   // Pagination URL
}
```

---

## Troubleshooting

**Q: "403 Forbidden" when creating indicators?**  
A: Verify the app has `ThreatIndicators.ReadWrite.OwnedBy` permission and **admin consent** has been granted.

**Q: "429 Too Many Requests"?**  
A: The library auto-retries with backoff. If persisting, use `bulkCreateIndicators` with higher `delayMs`.

**Q: How do I clear the token cache between auth methods?**  
A: Call `clearTokenCache()` before creating a new client with different auth.

---

## Next Steps

1. **Create app registration** — Follow Setup section above
2. **Install the library** — Copy `lib/graph-security/` to your project
3. **Test a module** — Try listing alerts or incidents
4. **Integrate with automation** — Use in Logic Apps, Azure Functions, or CI/CD
5. **Monitor Secure Score** — Track posture improvements over time

For deeper guidance on each module, see the [Skills Catalog — Detection Engineering](skills-catalog.md) and [Threat Hunting](skills-catalog.md) sections.
