/**
 * Graph Security API — Comprehensive Test Suite
 *
 * Written from the implementation by Carver (Tester/QA).
 * Covers auth, alerts, incidents, threat-intelligence, secure-score, utils, and factory.
 *
 * Run: node --test lib/graph-security/graph-security.test.js
 */

import { describe, it, before, after, beforeEach, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';

// ---------------------------------------------------------------------------
// Module imports — CommonJS modules loaded via createRequire
// ---------------------------------------------------------------------------
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

let auth, alerts, incidents, threatIntelligence, secureScore, utils, graphSecurity;
try {
  auth = require('./auth.js');
  alerts = require('./alerts.js');
  incidents = require('./incidents.js');
  threatIntelligence = require('./threat-intelligence.js');
  secureScore = require('./secure-score.js');
  utils = require('./utils.js');
  graphSecurity = require('./index.js');
} catch (err) {
  const notImplemented = () => { throw new Error(`graph-security module load failed: ${err.message}`); };
  auth = { getTokenClientCredentials: notImplemented, getTokenManagedIdentity: notImplemented, getTokenDeviceCode: notImplemented, clearTokenCache: notImplemented };
  alerts = { listAlerts: notImplemented, getAlert: notImplemented, updateAlert: notImplemented, listAlertsByEntity: notImplemented };
  incidents = { listIncidents: notImplemented, getIncident: notImplemented, updateIncident: notImplemented, addComment: notImplemented, getIncidentAlerts: notImplemented };
  threatIntelligence = { listIndicators: notImplemented, createIndicator: notImplemented, deleteIndicator: notImplemented, bulkCreateIndicators: notImplemented, convertIOCToIndicator: notImplemented };
  secureScore = { getSecureScore: notImplemented, getSecureScoreHistory: notImplemented, getControlProfiles: notImplemented, getRecommendations: notImplemented };
  utils = { graphGet: notImplemented, graphPatch: notImplemented, graphPost: notImplemented, graphDelete: notImplemented, graphRequest: notImplemented, buildFilter: notImplemented, GRAPH_BASE: 'https://graph.microsoft.com/v1.0' };
  graphSecurity = { createClient: notImplemented };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Creates a mock client with a static token. */
function mockClient(token = 'mock-token-abc') {
  return { tenantId: 'test-tenant', getToken: async () => token };
}

/** Creates a mock client whose getToken returns null (simulates auth failure). */
function failingAuthClient() {
  return { tenantId: 'test-tenant', getToken: async () => null };
}

/** Installs a mock global fetch that returns a preset response. */
function mockFetch(status, body, headers = {}) {
  const headerMap = new Map(Object.entries(headers));
  const fn = mock.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => headerMap.get(name) || null },
    json: async () => body,
  }));
  globalThis.fetch = fn;
  return fn;
}

/** Installs a mock fetch that throws a network error. */
function mockFetchError(message = 'connect ECONNREFUSED') {
  const fn = mock.fn(async () => { throw new Error(message); });
  globalThis.fetch = fn;
  return fn;
}

// Save/restore original fetch
let originalFetch;

// ===========================================================================
// 1. AUTH MODULE
// ===========================================================================

describe('auth — client credentials', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; auth.clearTokenCache(); });

  it('returns error when tenantId is missing', async () => {
    const result = await auth.getTokenClientCredentials('', 'cid', 'secret');
    assert.equal(result.ok, false);
    assert.match(result.error, /tenantId/);
  });

  it('returns error when clientId is missing', async () => {
    const result = await auth.getTokenClientCredentials('tid', '', 'secret');
    assert.equal(result.ok, false);
    assert.match(result.error, /clientId/);
  });

  it('returns error when clientSecret is missing', async () => {
    const result = await auth.getTokenClientCredentials('tid', 'cid', '');
    assert.equal(result.ok, false);
    assert.match(result.error, /clientSecret/);
  });

  it('acquires token successfully', async () => {
    mockFetch(200, { access_token: 'tok123', expires_in: 3600 });
    const result = await auth.getTokenClientCredentials('tid', 'cid', 'secret');
    assert.equal(result.ok, true);
    assert.equal(result.token, 'tok123');
    assert.equal(result.expiresIn, 3600);
  });

  it('sends correct form body', async () => {
    const fn = mockFetch(200, { access_token: 'tok', expires_in: 3600 });
    await auth.getTokenClientCredentials('tid', 'cid', 'secret');
    const callArgs = fn.mock.calls[0].arguments;
    const url = callArgs[0];
    assert.match(url, /login\.microsoftonline\.com\/tid\/oauth2\/v2\.0\/token/);
    const opts = callArgs[1];
    assert.equal(opts.method, 'POST');
    assert.match(opts.body, /grant_type=client_credentials/);
    assert.match(opts.body, /client_id=cid/);
  });

  it('returns cached token on second call', async () => {
    const fn = mockFetch(200, { access_token: 'cached-tok', expires_in: 3600 });
    await auth.getTokenClientCredentials('tid', 'cid', 'secret');
    const result2 = await auth.getTokenClientCredentials('tid', 'cid', 'secret');
    assert.equal(result2.ok, true);
    assert.equal(result2.token, 'cached-tok');
    assert.equal(fn.mock.callCount(), 1, 'fetch should only be called once');
  });

  it('handles auth failure response', async () => {
    mockFetch(400, { error: 'invalid_client', error_description: 'Bad credentials' });
    const result = await auth.getTokenClientCredentials('tid', 'cid', 'wrong');
    assert.equal(result.ok, false);
    assert.equal(result.status, 400);
    assert.match(result.error, /Bad credentials/);
  });

  it('handles network error', async () => {
    mockFetchError('ECONNREFUSED');
    const result = await auth.getTokenClientCredentials('tid', 'cid', 'secret');
    assert.equal(result.ok, false);
    assert.match(result.error, /Network error/);
  });

  it('defaults expiresIn to 3600 when not in response', async () => {
    mockFetch(200, { access_token: 'tok' });
    const result = await auth.getTokenClientCredentials('t', 'c', 's');
    assert.equal(result.ok, true);
    assert.equal(result.expiresIn, 3600);
  });

  it('clearTokenCache clears the cache', async () => {
    const fn = mockFetch(200, { access_token: 'tok', expires_in: 3600 });
    await auth.getTokenClientCredentials('tid', 'cid', 'secret');
    auth.clearTokenCache();
    await auth.getTokenClientCredentials('tid', 'cid', 'secret');
    assert.equal(fn.mock.callCount(), 2, 'fetch called twice after cache clear');
  });
});

describe('auth — managed identity', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => {
    globalThis.fetch = originalFetch;
    auth.clearTokenCache();
    delete process.env.IDENTITY_ENDPOINT;
    delete process.env.IDENTITY_HEADER;
  });

  it('uses App Service identity endpoint when env vars set', async () => {
    process.env.IDENTITY_ENDPOINT = 'http://localhost:8081/msi/token';
    process.env.IDENTITY_HEADER = 'secret-header';
    const fn = mockFetch(200, { access_token: 'mi-tok', expires_in: 1800 });
    const result = await auth.getTokenManagedIdentity();
    assert.equal(result.ok, true);
    assert.equal(result.token, 'mi-tok');
    const url = fn.mock.calls[0].arguments[0];
    assert.match(url, /localhost:8081/);
  });

  it('falls back to IMDS when no App Service env', async () => {
    const fn = mockFetch(200, { access_token: 'imds-tok', expires_in: 3600 });
    const result = await auth.getTokenManagedIdentity();
    assert.equal(result.ok, true);
    const url = fn.mock.calls[0].arguments[0];
    assert.match(url, /169\.254\.169\.254/);
  });

  it('handles managed identity auth failure', async () => {
    process.env.IDENTITY_ENDPOINT = 'http://localhost/msi';
    process.env.IDENTITY_HEADER = 'hdr';
    mockFetch(401, { message: 'Identity not found' });
    const result = await auth.getTokenManagedIdentity();
    assert.equal(result.ok, false);
    assert.match(result.error, /Identity not found/);
  });

  it('handles IMDS network error gracefully', async () => {
    mockFetchError('connect ETIMEDOUT');
    const result = await auth.getTokenManagedIdentity();
    assert.equal(result.ok, false);
    assert.match(result.error, /Managed identity not available/);
  });

  it('caches managed identity token', async () => {
    const fn = mockFetch(200, { access_token: 'mi-cached', expires_in: 3600 });
    await auth.getTokenManagedIdentity();
    await auth.getTokenManagedIdentity();
    assert.equal(fn.mock.callCount(), 1);
  });
});

describe('auth — device code', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; auth.clearTokenCache(); });

  it('returns error when tenantId is missing', async () => {
    const result = await auth.getTokenDeviceCode('', 'cid');
    assert.equal(result.ok, false);
    assert.match(result.error, /tenantId/);
  });

  it('returns error when clientId is missing', async () => {
    const result = await auth.getTokenDeviceCode('tid', '');
    assert.equal(result.ok, false);
    assert.match(result.error, /clientId/);
  });

  it('handles device code request failure', async () => {
    mockFetch(400, { error_description: 'Invalid client' });
    const result = await auth.getTokenDeviceCode('tid', 'cid');
    assert.equal(result.ok, false);
    assert.match(result.error, /Invalid client/);
  });

  it('handles network error during device code request', async () => {
    mockFetchError('DNS resolution failed');
    const result = await auth.getTokenDeviceCode('tid', 'cid');
    assert.equal(result.ok, false);
    assert.match(result.error, /Device code request failed/);
  });
});

// ===========================================================================
// 2. ALERTS MODULE
// ===========================================================================

describe('alerts — listAlerts', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await alerts.listAlerts(null);
    assert.equal(result.ok, false);
    assert.match(result.error, /client is required/);
  });

  it('lists alerts with default params', async () => {
    mockFetch(200, { value: [{ id: 'a1', title: 'Alert 1' }] });
    const client = mockClient();
    const result = await alerts.listAlerts(client);
    assert.equal(result.ok, true);
    assert.equal(result.data.length, 1);
    assert.equal(result.data[0].id, 'a1');
  });

  it('applies severity filter', async () => {
    const fn = mockFetch(200, { value: [] });
    const client = mockClient();
    await alerts.listAlerts(client, { severity: 'high' });
    const url = fn.mock.calls[0].arguments[0];
    assert.match(url, /severity\+eq\+%27high%27|severity%20eq%20'high'|severity\+eq\+'high'/i);
  });

  it('applies multiple filters', async () => {
    const fn = mockFetch(200, { value: [] });
    const client = mockClient();
    await alerts.listAlerts(client, { severity: 'high', status: 'new' });
    const url = fn.mock.calls[0].arguments[0];
    assert.match(url, /severity/);
    assert.match(url, /status/);
  });

  it('uses nextLink for pagination', async () => {
    const fn = mockFetch(200, { value: [{ id: 'a2' }] });
    const client = mockClient();
    const nextUrl = 'https://graph.microsoft.com/v1.0/security/alerts_v2?$skiptoken=abc';
    await alerts.listAlerts(client, { nextLink: nextUrl });
    const url = fn.mock.calls[0].arguments[0];
    assert.equal(url, nextUrl);
  });

  it('returns nextLink when present in response', async () => {
    const nextUrl = 'https://graph.microsoft.com/v1.0/security/alerts_v2?$skiptoken=xyz';
    mockFetch(200, { value: [{ id: 'a1' }], '@odata.nextLink': nextUrl });
    const client = mockClient();
    const result = await alerts.listAlerts(client);
    assert.equal(result.ok, true);
    assert.equal(result.nextLink, nextUrl);
  });

  it('applies top parameter', async () => {
    const fn = mockFetch(200, { value: [] });
    const client = mockClient();
    await alerts.listAlerts(client, { top: 10 });
    const url = decodeURIComponent(fn.mock.calls[0].arguments[0]);
    assert.match(url, /\$top=10/);
  });

  it('handles empty results', async () => {
    mockFetch(200, { value: [] });
    const client = mockClient();
    const result = await alerts.listAlerts(client);
    assert.equal(result.ok, true);
    assert.equal(result.data.length, 0);
  });

  it('handles auth failure (null token)', async () => {
    const client = failingAuthClient();
    const result = await alerts.listAlerts(client);
    assert.equal(result.ok, false);
    assert.match(result.error, /authentication token/i);
  });

  it('handles 401 response', async () => {
    mockFetch(401, { error: { code: 'Unauthorized', message: 'Token expired' } });
    const client = mockClient();
    const result = await alerts.listAlerts(client);
    assert.equal(result.ok, false);
    assert.equal(result.status, 401);
  });

  it('handles 500 server error', async () => {
    mockFetch(500, { error: { code: 'InternalServerError', message: 'Server error' } });
    const client = mockClient();
    const result = await alerts.listAlerts(client);
    assert.equal(result.ok, false);
    assert.equal(result.status, 500);
  });
});

describe('alerts — getAlert', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await alerts.getAlert(null, 'a1');
    assert.equal(result.ok, false);
  });

  it('returns error when alertId is missing', async () => {
    const result = await alerts.getAlert(mockClient(), '');
    assert.equal(result.ok, false);
    assert.match(result.error, /alertId/);
  });

  it('returns error when alertId is not a string', async () => {
    const result = await alerts.getAlert(mockClient(), 123);
    assert.equal(result.ok, false);
    assert.match(result.error, /alertId/);
  });

  it('retrieves alert by ID', async () => {
    mockFetch(200, { id: 'alert-1', title: 'Suspicious login' });
    const result = await alerts.getAlert(mockClient(), 'alert-1');
    assert.equal(result.ok, true);
    assert.equal(result.data.id, 'alert-1');
  });

  it('handles 404 not found', async () => {
    mockFetch(404, { error: { code: 'NotFound', message: 'Resource not found' } });
    const result = await alerts.getAlert(mockClient(), 'nonexistent');
    assert.equal(result.ok, false);
    assert.equal(result.status, 404);
  });

  it('encodes alertId in URL', async () => {
    const fn = mockFetch(200, { id: 'a/b' });
    await alerts.getAlert(mockClient(), 'a/b');
    const url = fn.mock.calls[0].arguments[0];
    assert.match(url, /a%2Fb/);
  });
});

describe('alerts — updateAlert', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await alerts.updateAlert(null, 'a1', { status: 'resolved' });
    assert.equal(result.ok, false);
  });

  it('returns error when alertId is missing', async () => {
    const result = await alerts.updateAlert(mockClient(), '', { status: 'resolved' });
    assert.equal(result.ok, false);
  });

  it('returns error when updates is not an object', async () => {
    const result = await alerts.updateAlert(mockClient(), 'a1', null);
    assert.equal(result.ok, false);
    assert.match(result.error, /updates/);
  });

  it('updates alert successfully', async () => {
    mockFetch(200, { id: 'a1', status: 'resolved' });
    const result = await alerts.updateAlert(mockClient(), 'a1', { status: 'resolved' });
    assert.equal(result.ok, true);
    assert.equal(result.data.status, 'resolved');
  });

  it('sends PATCH request with correct body', async () => {
    const fn = mockFetch(200, { id: 'a1' });
    await alerts.updateAlert(mockClient(), 'a1', { status: 'inProgress', assignedTo: 'user@test.com' });
    const opts = fn.mock.calls[0].arguments[1];
    assert.equal(opts.method, 'PATCH');
    const body = JSON.parse(opts.body);
    assert.equal(body.status, 'inProgress');
    assert.equal(body.assignedTo, 'user@test.com');
  });

  it('handles 403 forbidden', async () => {
    mockFetch(403, { error: { code: 'Forbidden', message: 'Insufficient permissions' } });
    const result = await alerts.updateAlert(mockClient(), 'a1', { status: 'resolved' });
    assert.equal(result.ok, false);
    assert.equal(result.status, 403);
  });
});

describe('alerts — listAlertsByEntity', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error for invalid entity type', async () => {
    const result = await alerts.listAlertsByEntity(mockClient(), 'invalid', 'value');
    assert.equal(result.ok, false);
    assert.match(result.error, /entityType/);
  });

  it('returns error for missing entity value', async () => {
    const result = await alerts.listAlertsByEntity(mockClient(), 'ip', '');
    assert.equal(result.ok, false);
    assert.match(result.error, /entityValue/);
  });

  it('searches by user entity', async () => {
    const fn = mockFetch(200, { value: [{ id: 'a1' }] });
    await alerts.listAlertsByEntity(mockClient(), 'user', 'admin@corp.com');
    const url = fn.mock.calls[0].arguments[0];
    assert.match(url, /actorDisplayName/);
  });

  it('searches by IP entity', async () => {
    const fn = mockFetch(200, { value: [] });
    await alerts.listAlertsByEntity(mockClient(), 'ip', '10.0.0.1');
    const url = fn.mock.calls[0].arguments[0];
    assert.match(url, /10\.0\.0\.1/);
  });
});

describe('alerts — constants', () => {
  it('SEVERITY is frozen', () => {
    assert.ok(Object.isFrozen(alerts.SEVERITY));
    assert.equal(alerts.SEVERITY.HIGH, 'high');
    assert.equal(alerts.SEVERITY.MEDIUM, 'medium');
  });

  it('ALERT_STATUS is frozen', () => {
    assert.ok(Object.isFrozen(alerts.ALERT_STATUS));
    assert.equal(alerts.ALERT_STATUS.NEW, 'new');
    assert.equal(alerts.ALERT_STATUS.RESOLVED, 'resolved');
  });
});

// ===========================================================================
// 3. INCIDENTS MODULE
// ===========================================================================

describe('incidents — listIncidents', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await incidents.listIncidents(null);
    assert.equal(result.ok, false);
  });

  it('lists incidents with default params', async () => {
    mockFetch(200, { value: [{ id: 'inc-1' }] });
    const result = await incidents.listIncidents(mockClient());
    assert.equal(result.ok, true);
    assert.equal(result.data.length, 1);
  });

  it('applies status filter', async () => {
    const fn = mockFetch(200, { value: [] });
    await incidents.listIncidents(mockClient(), { status: 'active' });
    const url = fn.mock.calls[0].arguments[0];
    assert.match(url, /status/);
    assert.match(url, /active/);
  });

  it('applies severity filter', async () => {
    const fn = mockFetch(200, { value: [] });
    await incidents.listIncidents(mockClient(), { severity: 'high' });
    const url = fn.mock.calls[0].arguments[0];
    assert.match(url, /severity/);
  });

  it('applies assignedTo filter', async () => {
    const fn = mockFetch(200, { value: [] });
    await incidents.listIncidents(mockClient(), { assignedTo: 'user@corp.com' });
    const url = fn.mock.calls[0].arguments[0];
    assert.match(url, /assignedTo/);
  });

  it('uses nextLink for pagination', async () => {
    const fn = mockFetch(200, { value: [] });
    const nextUrl = 'https://graph.microsoft.com/v1.0/security/incidents?$skiptoken=abc';
    await incidents.listIncidents(mockClient(), { nextLink: nextUrl });
    assert.equal(fn.mock.calls[0].arguments[0], nextUrl);
  });

  it('handles empty results', async () => {
    mockFetch(200, { value: [] });
    const result = await incidents.listIncidents(mockClient());
    assert.equal(result.ok, true);
    assert.deepEqual(result.data, []);
  });
});

describe('incidents — getIncident', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await incidents.getIncident(null, 'inc-1');
    assert.equal(result.ok, false);
  });

  it('returns error when incidentId is missing', async () => {
    const result = await incidents.getIncident(mockClient(), '');
    assert.equal(result.ok, false);
    assert.match(result.error, /incidentId/);
  });

  it('retrieves incident by ID', async () => {
    mockFetch(200, { id: 'inc-1', displayName: 'Phishing campaign' });
    const result = await incidents.getIncident(mockClient(), 'inc-1');
    assert.equal(result.ok, true);
    assert.equal(result.data.displayName, 'Phishing campaign');
  });

  it('handles 404', async () => {
    mockFetch(404, { error: { code: 'NotFound', message: 'Not found' } });
    const result = await incidents.getIncident(mockClient(), 'bad-id');
    assert.equal(result.ok, false);
    assert.equal(result.status, 404);
  });
});

describe('incidents — updateIncident', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await incidents.updateIncident(null, 'inc-1', { status: 'resolved' });
    assert.equal(result.ok, false);
  });

  it('returns error when incidentId is missing', async () => {
    const result = await incidents.updateIncident(mockClient(), '', { status: 'resolved' });
    assert.equal(result.ok, false);
  });

  it('returns error when updates is null', async () => {
    const result = await incidents.updateIncident(mockClient(), 'inc-1', null);
    assert.equal(result.ok, false);
    assert.match(result.error, /updates/);
  });

  it('updates incident successfully', async () => {
    mockFetch(200, { id: 'inc-1', status: 'resolved' });
    const result = await incidents.updateIncident(mockClient(), 'inc-1', {
      status: 'resolved',
      classification: 'truePositive',
      determination: 'malware',
    });
    assert.equal(result.ok, true);
  });

  it('sends correct PATCH body', async () => {
    const fn = mockFetch(200, { id: 'inc-1' });
    await incidents.updateIncident(mockClient(), 'inc-1', { tags: ['reviewed'] });
    const opts = fn.mock.calls[0].arguments[1];
    assert.equal(opts.method, 'PATCH');
    const body = JSON.parse(opts.body);
    assert.deepEqual(body.tags, ['reviewed']);
  });
});

describe('incidents — addComment', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await incidents.addComment(null, 'inc-1', 'hello');
    assert.equal(result.ok, false);
  });

  it('returns error when incidentId is missing', async () => {
    const result = await incidents.addComment(mockClient(), '', 'hello');
    assert.equal(result.ok, false);
  });

  it('returns error when comment is empty', async () => {
    const result = await incidents.addComment(mockClient(), 'inc-1', '');
    assert.equal(result.ok, false);
    assert.match(result.error, /comment/);
  });

  it('adds comment successfully', async () => {
    mockFetch(200, { comment: 'Investigation started' });
    const result = await incidents.addComment(mockClient(), 'inc-1', 'Investigation started');
    assert.equal(result.ok, true);
  });

  it('sends POST with comment body', async () => {
    const fn = mockFetch(200, {});
    await incidents.addComment(mockClient(), 'inc-1', 'test comment');
    const opts = fn.mock.calls[0].arguments[1];
    assert.equal(opts.method, 'POST');
    const body = JSON.parse(opts.body);
    assert.equal(body.comment, 'test comment');
  });
});

describe('incidents — getIncidentAlerts', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await incidents.getIncidentAlerts(null, 'inc-1');
    assert.equal(result.ok, false);
  });

  it('returns error when incidentId is missing', async () => {
    const result = await incidents.getIncidentAlerts(mockClient(), '');
    assert.equal(result.ok, false);
  });

  it('retrieves alerts for incident', async () => {
    mockFetch(200, { value: [{ id: 'a1' }, { id: 'a2' }] });
    const result = await incidents.getIncidentAlerts(mockClient(), 'inc-1');
    assert.equal(result.ok, true);
    assert.equal(result.data.length, 2);
  });

  it('handles empty alert list', async () => {
    mockFetch(200, { value: [] });
    const result = await incidents.getIncidentAlerts(mockClient(), 'inc-1');
    assert.equal(result.ok, true);
    assert.equal(result.data.length, 0);
  });
});

describe('incidents — constants', () => {
  it('INCIDENT_STATUS is frozen', () => {
    assert.ok(Object.isFrozen(incidents.INCIDENT_STATUS));
    assert.equal(incidents.INCIDENT_STATUS.ACTIVE, 'active');
  });

  it('INCIDENT_CLASSIFICATION is frozen', () => {
    assert.ok(Object.isFrozen(incidents.INCIDENT_CLASSIFICATION));
    assert.equal(incidents.INCIDENT_CLASSIFICATION.TRUE_POSITIVE, 'truePositive');
  });

  it('INCIDENT_DETERMINATION is frozen', () => {
    assert.ok(Object.isFrozen(incidents.INCIDENT_DETERMINATION));
    assert.equal(incidents.INCIDENT_DETERMINATION.MALWARE, 'malware');
    assert.equal(incidents.INCIDENT_DETERMINATION.PHISHING, 'phishing');
  });
});

// ===========================================================================
// 4. THREAT INTELLIGENCE MODULE
// ===========================================================================

describe('threatIntelligence — listIndicators', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await threatIntelligence.listIndicators(null);
    assert.equal(result.ok, false);
  });

  it('lists indicators with no filters', async () => {
    mockFetch(200, { value: [{ id: 'ti-1' }] });
    const result = await threatIntelligence.listIndicators(mockClient());
    assert.equal(result.ok, true);
    assert.equal(result.data.length, 1);
  });

  it('applies indicatorType filter', async () => {
    const fn = mockFetch(200, { value: [] });
    await threatIntelligence.listIndicators(mockClient(), { indicatorType: 'networkIPv4' });
    const url = fn.mock.calls[0].arguments[0];
    assert.match(url, /patternType/);
  });

  it('applies action filter', async () => {
    const fn = mockFetch(200, { value: [] });
    await threatIntelligence.listIndicators(mockClient(), { action: 'block' });
    const url = fn.mock.calls[0].arguments[0];
    assert.match(url, /action.*block/);
  });

  it('uses nextLink for pagination', async () => {
    const fn = mockFetch(200, { value: [] });
    const nextUrl = 'https://graph.microsoft.com/v1.0/security/tiIndicators?$skiptoken=x';
    await threatIntelligence.listIndicators(mockClient(), { nextLink: nextUrl });
    assert.equal(fn.mock.calls[0].arguments[0], nextUrl);
  });
});

describe('threatIntelligence — createIndicator', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await threatIntelligence.createIndicator(null, {});
    assert.equal(result.ok, false);
  });

  it('returns error when indicator is null', async () => {
    const result = await threatIntelligence.createIndicator(mockClient(), null);
    assert.equal(result.ok, false);
    assert.match(result.error, /indicator/);
  });

  it('validates required fields', async () => {
    const result = await threatIntelligence.createIndicator(mockClient(), { action: 'block' });
    assert.equal(result.ok, false);
    assert.match(result.error, /required/);
  });

  it('creates indicator successfully', async () => {
    const indicator = {
      action: 'block',
      description: 'Malicious IP',
      expirationDateTime: '2026-12-31T00:00:00Z',
      targetProduct: 'Azure Sentinel',
      threatType: 'Malware',
      tlpLevel: 'amber',
      networkIPv4: '192.168.1.100',
    };
    mockFetch(200, { id: 'ti-new', ...indicator });
    const result = await threatIntelligence.createIndicator(mockClient(), indicator);
    assert.equal(result.ok, true);
    assert.equal(result.data.id, 'ti-new');
  });

  it('sends POST request', async () => {
    const indicator = {
      action: 'alert', description: 'test', expirationDateTime: '2026-12-31T00:00:00Z',
      targetProduct: 'Azure Sentinel', threatType: 'Phishing', tlpLevel: 'white',
    };
    const fn = mockFetch(200, { id: 'ti-1' });
    await threatIntelligence.createIndicator(mockClient(), indicator);
    assert.equal(fn.mock.calls[0].arguments[1].method, 'POST');
  });

  it('checks each required field individually', async () => {
    const base = {
      action: 'block', description: 'test', expirationDateTime: '2026-12-31T00:00:00Z',
      targetProduct: 'Azure Sentinel', threatType: 'Malware', tlpLevel: 'amber',
    };
    for (const field of ['action', 'description', 'expirationDateTime', 'targetProduct', 'threatType', 'tlpLevel']) {
      const copy = { ...base };
      delete copy[field];
      const result = await threatIntelligence.createIndicator(mockClient(), copy);
      assert.equal(result.ok, false, `should fail when ${field} is missing`);
      assert.match(result.error, new RegExp(field));
    }
  });
});

describe('threatIntelligence — deleteIndicator', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await threatIntelligence.deleteIndicator(null, 'ti-1');
    assert.equal(result.ok, false);
  });

  it('returns error when indicatorId is missing', async () => {
    const result = await threatIntelligence.deleteIndicator(mockClient(), '');
    assert.equal(result.ok, false);
    assert.match(result.error, /indicatorId/);
  });

  it('deletes indicator (204 response)', async () => {
    mockFetch(204, null);
    const result = await threatIntelligence.deleteIndicator(mockClient(), 'ti-1');
    assert.equal(result.ok, true);
  });

  it('sends DELETE request', async () => {
    const fn = mockFetch(204, null);
    await threatIntelligence.deleteIndicator(mockClient(), 'ti-1');
    assert.equal(fn.mock.calls[0].arguments[1].method, 'DELETE');
  });

  it('handles 404 on delete', async () => {
    mockFetch(404, { error: { code: 'NotFound', message: 'Not found' } });
    const result = await threatIntelligence.deleteIndicator(mockClient(), 'gone');
    assert.equal(result.ok, false);
    assert.equal(result.status, 404);
  });
});

describe('threatIntelligence — bulkCreateIndicators', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await threatIntelligence.bulkCreateIndicators(null, [{}]);
    assert.equal(result.ok, false);
  });

  it('returns error for empty array', async () => {
    const result = await threatIntelligence.bulkCreateIndicators(mockClient(), []);
    assert.equal(result.ok, false);
    assert.match(result.error, /non-empty array/);
  });

  it('returns error for non-array', async () => {
    const result = await threatIntelligence.bulkCreateIndicators(mockClient(), 'not-array');
    assert.equal(result.ok, false);
  });

  it('creates multiple indicators', async () => {
    const indicator = {
      action: 'block', description: 'test', expirationDateTime: '2026-12-31T00:00:00Z',
      targetProduct: 'Azure Sentinel', threatType: 'Malware', tlpLevel: 'amber',
      networkIPv4: '10.0.0.1',
    };
    mockFetch(200, { id: 'ti-new' });
    const result = await threatIntelligence.bulkCreateIndicators(mockClient(), [indicator, indicator], { delayMs: 0 });
    assert.equal(result.ok, true);
    assert.equal(result.results.length, 2);
    assert.equal(result.results[0].index, 0);
    assert.equal(result.results[1].index, 1);
  });

  it('stops on error when stopOnError=true', async () => {
    // First call will fail validation (missing fields), second should not execute
    const bad = { action: 'block' }; // missing required fields
    const good = {
      action: 'block', description: 'test', expirationDateTime: '2026-12-31T00:00:00Z',
      targetProduct: 'Azure Sentinel', threatType: 'Malware', tlpLevel: 'amber',
    };
    const result = await threatIntelligence.bulkCreateIndicators(mockClient(), [bad, good], { stopOnError: true, delayMs: 0 });
    assert.equal(result.ok, true);
    assert.equal(result.results.length, 1, 'should stop after first error');
    assert.equal(result.results[0].ok, false);
  });

  it('continues on error when stopOnError=false (default)', async () => {
    const bad = { action: 'block' };
    const good = {
      action: 'block', description: 'test', expirationDateTime: '2026-12-31T00:00:00Z',
      targetProduct: 'Azure Sentinel', threatType: 'Malware', tlpLevel: 'amber',
    };
    mockFetch(200, { id: 'ti-1' });
    const result = await threatIntelligence.bulkCreateIndicators(mockClient(), [bad, good], { delayMs: 0 });
    assert.equal(result.ok, true);
    assert.equal(result.results.length, 2);
    assert.equal(result.results[0].ok, false);
    assert.equal(result.results[1].ok, true);
  });
});

describe('threatIntelligence — convertIOCToIndicator', () => {
  it('returns error when ioc is null', () => {
    const result = threatIntelligence.convertIOCToIndicator(null);
    assert.equal(result.ok, false);
  });

  it('returns error when type and value are missing', () => {
    const result = threatIntelligence.convertIOCToIndicator({});
    assert.equal(result.ok, false);
    assert.match(result.error, /type.*value/);
  });

  it('returns error for unknown IOC type', () => {
    const result = threatIntelligence.convertIOCToIndicator({ type: 'foobar', value: 'x' });
    assert.equal(result.ok, false);
    assert.match(result.error, /Unknown IOC type/);
  });

  it('converts IP IOC correctly', () => {
    const result = threatIntelligence.convertIOCToIndicator({ type: 'ip', value: '10.0.0.1' });
    assert.equal(result.ok, true);
    assert.equal(result.indicator.networkIPv4, '10.0.0.1');
    assert.equal(result.indicator.action, 'alert');
    assert.equal(result.indicator.targetProduct, 'Azure Sentinel');
  });

  it('converts domain IOC correctly', () => {
    const result = threatIntelligence.convertIOCToIndicator({ type: 'domain', value: 'evil.com' });
    assert.equal(result.ok, true);
    assert.equal(result.indicator.domainName, 'evil.com');
  });

  it('converts SHA256 IOC correctly', () => {
    const hash = 'abc123def456';
    const result = threatIntelligence.convertIOCToIndicator({ type: 'sha256', value: hash });
    assert.equal(result.ok, true);
    assert.equal(result.indicator.fileSha256, hash);
  });

  it('respects custom action and threatType', () => {
    const result = threatIntelligence.convertIOCToIndicator({
      type: 'url', value: 'http://evil.com', action: 'block', threatType: 'Phishing',
    });
    assert.equal(result.ok, true);
    assert.equal(result.indicator.action, 'block');
    assert.equal(result.indicator.threatType, 'Phishing');
  });

  it('sets expiration based on expirationDays', () => {
    const result = threatIntelligence.convertIOCToIndicator({ type: 'ip', value: '1.2.3.4', expirationDays: 30 });
    assert.equal(result.ok, true);
    const expDate = new Date(result.indicator.expirationDateTime);
    const expectedMin = new Date(Date.now() + 29 * 24 * 60 * 60 * 1000);
    assert.ok(expDate > expectedMin, 'expiration should be ~30 days in the future');
  });

  it('is case insensitive on type', () => {
    const result = threatIntelligence.convertIOCToIndicator({ type: 'IP', value: '1.1.1.1' });
    assert.equal(result.ok, true);
    assert.equal(result.indicator.networkIPv4, '1.1.1.1');
  });
});

describe('threatIntelligence — constants', () => {
  it('INDICATOR_TYPE is frozen', () => {
    assert.ok(Object.isFrozen(threatIntelligence.INDICATOR_TYPE));
    assert.equal(threatIntelligence.INDICATOR_TYPE.IP, 'networkIPv4');
  });

  it('INDICATOR_ACTION is frozen', () => {
    assert.ok(Object.isFrozen(threatIntelligence.INDICATOR_ACTION));
    assert.equal(threatIntelligence.INDICATOR_ACTION.BLOCK, 'block');
  });

  it('THREAT_TYPE is frozen', () => {
    assert.ok(Object.isFrozen(threatIntelligence.THREAT_TYPE));
    assert.equal(threatIntelligence.THREAT_TYPE.PHISHING, 'Phishing');
  });
});

// ===========================================================================
// 5. SECURE SCORE MODULE
// ===========================================================================

describe('secureScore — getSecureScore', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await secureScore.getSecureScore(null);
    assert.equal(result.ok, false);
  });

  it('returns the most recent score', async () => {
    mockFetch(200, { value: [{ id: 'score-1', currentScore: 72 }] });
    const result = await secureScore.getSecureScore(mockClient());
    assert.equal(result.ok, true);
    assert.equal(result.data.currentScore, 72);
  });

  it('returns error when no scores available', async () => {
    mockFetch(200, { value: [] });
    const result = await secureScore.getSecureScore(mockClient());
    assert.equal(result.ok, false);
    assert.match(result.error, /No secure score/);
  });

  it('returns only the first (most recent) score', async () => {
    mockFetch(200, { value: [{ id: 's1', currentScore: 80 }, { id: 's2', currentScore: 70 }] });
    const result = await secureScore.getSecureScore(mockClient());
    assert.equal(result.ok, true);
    assert.equal(result.data.id, 's1');
  });

  it('handles API error', async () => {
    mockFetch(500, { error: { message: 'Internal error' } });
    const result = await secureScore.getSecureScore(mockClient());
    assert.equal(result.ok, false);
    assert.equal(result.status, 500);
  });
});

describe('secureScore — getSecureScoreHistory', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await secureScore.getSecureScoreHistory(null);
    assert.equal(result.ok, false);
  });

  it('returns error for invalid days (0)', async () => {
    const result = await secureScore.getSecureScoreHistory(mockClient(), 0);
    assert.equal(result.ok, false);
    assert.match(result.error, /days/);
  });

  it('returns error for days > 365', async () => {
    const result = await secureScore.getSecureScoreHistory(mockClient(), 400);
    assert.equal(result.ok, false);
  });

  it('returns error for non-number days', async () => {
    const result = await secureScore.getSecureScoreHistory(mockClient(), 'thirty');
    assert.equal(result.ok, false);
  });

  it('retrieves history with default 30 days', async () => {
    const fn = mockFetch(200, { value: [{ id: 's1' }, { id: 's2' }] });
    const result = await secureScore.getSecureScoreHistory(mockClient());
    assert.equal(result.ok, true);
    assert.equal(result.data.length, 2);
    const url = decodeURIComponent(fn.mock.calls[0].arguments[0]);
    assert.match(url, /\$top=30/);
  });

  it('uses custom days parameter', async () => {
    const fn = mockFetch(200, { value: [] });
    await secureScore.getSecureScoreHistory(mockClient(), 7);
    const url = decodeURIComponent(fn.mock.calls[0].arguments[0]);
    assert.match(url, /\$top=7/);
  });
});

describe('secureScore — getControlProfiles', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await secureScore.getControlProfiles(null);
    assert.equal(result.ok, false);
  });

  it('retrieves control profiles', async () => {
    mockFetch(200, { value: [{ id: 'cp1', title: 'Enable MFA' }] });
    const result = await secureScore.getControlProfiles(mockClient());
    assert.equal(result.ok, true);
    assert.equal(result.data[0].title, 'Enable MFA');
  });
});

describe('secureScore — getRecommendations', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('returns error when client is null', async () => {
    const result = await secureScore.getRecommendations(null);
    assert.equal(result.ok, false);
  });

  it('filters out implemented controls', async () => {
    mockFetch(200, {
      value: [
        { id: 'cp1', title: 'Enable MFA', implementationStatus: 'implemented', maxScore: 10 },
        { id: 'cp2', title: 'Use RBAC', implementationStatus: 'notStarted', maxScore: 8 },
      ],
    });
    const result = await secureScore.getRecommendations(mockClient());
    assert.equal(result.ok, true);
    assert.equal(result.data.length, 1);
    assert.equal(result.data[0].id, 'cp2');
  });

  it('sorts by maxScore descending', async () => {
    mockFetch(200, {
      value: [
        { id: 'cp1', implementationStatus: 'notStarted', maxScore: 3 },
        { id: 'cp2', implementationStatus: 'notStarted', maxScore: 10 },
        { id: 'cp3', implementationStatus: 'notStarted', maxScore: 7 },
      ],
    });
    const result = await secureScore.getRecommendations(mockClient());
    assert.equal(result.ok, true);
    assert.equal(result.data[0].maxScore, 10);
    assert.equal(result.data[1].maxScore, 7);
    assert.equal(result.data[2].maxScore, 3);
  });

  it('handles empty profiles', async () => {
    mockFetch(200, { value: [] });
    const result = await secureScore.getRecommendations(mockClient());
    assert.equal(result.ok, true);
    assert.equal(result.data.length, 0);
  });
});

// ===========================================================================
// 6. UTILS MODULE
// ===========================================================================

describe('utils — buildFilter', () => {
  it('builds filter from single field', () => {
    const result = utils.buildFilter({ severity: 'high' });
    assert.equal(result, "severity eq 'high'");
  });

  it('joins multiple fields with "and"', () => {
    const result = utils.buildFilter({ severity: 'high', status: 'active' });
    assert.equal(result, "severity eq 'high' and status eq 'active'");
  });

  it('ignores undefined values', () => {
    const result = utils.buildFilter({ severity: 'high', status: undefined });
    assert.equal(result, "severity eq 'high'");
  });

  it('ignores null values', () => {
    const result = utils.buildFilter({ severity: null, status: 'active' });
    assert.equal(result, "status eq 'active'");
  });

  it('returns empty string for empty object', () => {
    const result = utils.buildFilter({});
    assert.equal(result, '');
  });
});

describe('utils — graphRequest core behavior', () => {
  before(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('sets Authorization header with bearer token', async () => {
    const fn = mockFetch(200, { value: [] });
    await utils.graphGet(mockClient('my-token'), 'test/path');
    const headers = fn.mock.calls[0].arguments[1].headers;
    assert.equal(headers.Authorization, 'Bearer my-token');
  });

  it('returns error when token is null', async () => {
    const result = await utils.graphGet(failingAuthClient(), 'test/path');
    assert.equal(result.ok, false);
    assert.match(result.error, /authentication token/);
  });

  it('handles 204 No Content', async () => {
    mockFetch(204, null);
    const result = await utils.graphDelete(mockClient(), 'test/resource');
    assert.equal(result.ok, true);
  });

  it('unwraps OData value arrays', async () => {
    mockFetch(200, { value: [{ id: '1' }, { id: '2' }], '@odata.count': 2 });
    const result = await utils.graphGet(mockClient(), 'test/collection');
    assert.equal(result.ok, true);
    assert.ok(Array.isArray(result.data));
    assert.equal(result.data.length, 2);
  });

  it('preserves non-array responses', async () => {
    mockFetch(200, { id: 'single', name: 'Test' });
    const result = await utils.graphGet(mockClient(), 'test/item');
    assert.equal(result.ok, true);
    assert.equal(result.data.id, 'single');
  });

  it('extracts @odata.nextLink', async () => {
    const nextUrl = 'https://graph.microsoft.com/v1.0/test?$skiptoken=abc';
    mockFetch(200, { value: [], '@odata.nextLink': nextUrl });
    const result = await utils.graphGet(mockClient(), 'test/path');
    assert.equal(result.nextLink, nextUrl);
  });

  it('handles network error', async () => {
    mockFetchError('socket hang up');
    const result = await utils.graphGet(mockClient(), 'test/path');
    assert.equal(result.ok, false);
    assert.match(result.error, /Network error/);
  });

  it('normalizes 401 error', async () => {
    mockFetch(401, { error: { code: 'Unauthorized', message: 'Token expired' } });
    const result = await utils.graphGet(mockClient(), 'test/path');
    assert.equal(result.ok, false);
    assert.equal(result.status, 401);
    assert.equal(result.code, 'Unauthorized');
  });

  it('normalizes 403 error', async () => {
    mockFetch(403, { error: { code: 'Forbidden', message: 'Insufficient permissions' } });
    const result = await utils.graphGet(mockClient(), 'test/path');
    assert.equal(result.ok, false);
    assert.equal(result.status, 403);
  });

  it('normalizes 404 error', async () => {
    mockFetch(404, { error: { code: 'NotFound', message: 'Resource not found' } });
    const result = await utils.graphGet(mockClient(), 'test/path');
    assert.equal(result.ok, false);
    assert.equal(result.status, 404);
  });

  it('provides friendly message when no OData error body', async () => {
    mockFetch(500, null);
    const result = await utils.graphGet(mockClient(), 'test/path');
    assert.equal(result.ok, false);
    assert.equal(result.status, 500);
    assert.match(result.error, /Internal server error|status 500/i);
  });

  it('graphPost sends JSON body', async () => {
    const fn = mockFetch(200, { id: 'new' });
    await utils.graphPost(mockClient(), 'test/create', { name: 'test' });
    const opts = fn.mock.calls[0].arguments[1];
    assert.equal(opts.method, 'POST');
    assert.equal(JSON.parse(opts.body).name, 'test');
  });

  it('graphPatch sends JSON body', async () => {
    const fn = mockFetch(200, { id: 'updated' });
    await utils.graphPatch(mockClient(), 'test/update', { status: 'done' });
    const opts = fn.mock.calls[0].arguments[1];
    assert.equal(opts.method, 'PATCH');
    assert.equal(JSON.parse(opts.body).status, 'done');
  });

  it('graphGet uses rawUrl when provided', async () => {
    const fn = mockFetch(200, { value: [] });
    const rawUrl = 'https://graph.microsoft.com/v1.0/custom?$skip=10';
    await utils.graphGet(mockClient(), null, { rawUrl });
    assert.equal(fn.mock.calls[0].arguments[0], rawUrl);
  });

  it('GRAPH_BASE is correct', () => {
    assert.equal(utils.GRAPH_BASE, 'https://graph.microsoft.com/v1.0');
  });

  it('handles malformed JSON response gracefully', async () => {
    // Simulate a response where json() throws
    globalThis.fetch = mock.fn(async () => ({
      ok: false,
      status: 502,
      headers: { get: () => null },
      json: async () => { throw new SyntaxError('Unexpected token'); },
    }));
    const result = await utils.graphGet(mockClient(), 'test/path');
    assert.equal(result.ok, false);
    assert.equal(result.status, 502);
  });
});

// ===========================================================================
// 7. INDEX / FACTORY MODULE
// ===========================================================================

describe('createClient — factory', () => {
  it('throws when config is missing', () => {
    assert.throws(() => graphSecurity.createClient(), /config object/);
  });

  it('throws when config is not an object', () => {
    assert.throws(() => graphSecurity.createClient('string'), /config object/);
  });

  it('throws when config is null', () => {
    assert.throws(() => graphSecurity.createClient(null), /config object/);
  });

  it('creates client with pre-acquired token', async () => {
    const client = graphSecurity.createClient({ token: 'pre-tok', tenantId: 'tid' });
    assert.equal(client.tenantId, 'tid');
    const token = await client.getToken();
    assert.equal(token, 'pre-tok');
  });

  it('defaults tenantId to "unknown" for token-only client', async () => {
    const client = graphSecurity.createClient({ token: 'tok' });
    assert.equal(client.tenantId, 'unknown');
  });

  it('throws for clientCredentials when tenantId is missing', () => {
    assert.throws(
      () => graphSecurity.createClient({ clientId: 'cid', clientSecret: 'secret' }),
      /tenantId.*clientId.*clientSecret/
    );
  });

  it('throws for clientCredentials when clientSecret is missing', () => {
    assert.throws(
      () => graphSecurity.createClient({ tenantId: 'tid', clientId: 'cid' }),
      /tenantId.*clientId.*clientSecret/
    );
  });

  it('creates client with clientCredentials method', () => {
    const client = graphSecurity.createClient({
      tenantId: 'tid', clientId: 'cid', clientSecret: 'secret',
    });
    assert.equal(client.tenantId, 'tid');
    assert.equal(typeof client.getToken, 'function');
  });

  it('creates client with managedIdentity method', () => {
    const client = graphSecurity.createClient({ authMethod: 'managedIdentity' });
    assert.equal(client.tenantId, 'managed');
    assert.equal(typeof client.getToken, 'function');
  });

  it('throws for deviceCode when tenantId is missing', () => {
    assert.throws(
      () => graphSecurity.createClient({ authMethod: 'deviceCode', clientId: 'cid' }),
      /tenantId.*clientId/
    );
  });

  it('creates client with deviceCode method', () => {
    const client = graphSecurity.createClient({
      authMethod: 'deviceCode', tenantId: 'tid', clientId: 'cid',
    });
    assert.equal(client.tenantId, 'tid');
  });
});

describe('index — module exports', () => {
  it('exports createClient function', () => {
    assert.equal(typeof graphSecurity.createClient, 'function');
  });

  it('exports auth module', () => {
    assert.ok(graphSecurity.auth);
    assert.equal(typeof graphSecurity.auth.getTokenClientCredentials, 'function');
  });

  it('exports alerts module', () => {
    assert.ok(graphSecurity.alerts);
    assert.equal(typeof graphSecurity.alerts.listAlerts, 'function');
  });

  it('exports incidents module', () => {
    assert.ok(graphSecurity.incidents);
    assert.equal(typeof graphSecurity.incidents.listIncidents, 'function');
  });

  it('exports threatIntelligence module', () => {
    assert.ok(graphSecurity.threatIntelligence);
    assert.equal(typeof graphSecurity.threatIntelligence.listIndicators, 'function');
  });

  it('exports secureScore module', () => {
    assert.ok(graphSecurity.secureScore);
    assert.equal(typeof graphSecurity.secureScore.getSecureScore, 'function');
  });

  it('re-exports SEVERITY constant', () => {
    assert.ok(graphSecurity.SEVERITY);
    assert.equal(graphSecurity.SEVERITY.HIGH, 'high');
  });

  it('re-exports ALERT_STATUS constant', () => {
    assert.ok(graphSecurity.ALERT_STATUS);
    assert.equal(graphSecurity.ALERT_STATUS.NEW, 'new');
  });

  it('re-exports INCIDENT_STATUS constant', () => {
    assert.ok(graphSecurity.INCIDENT_STATUS);
    assert.equal(graphSecurity.INCIDENT_STATUS.ACTIVE, 'active');
  });

  it('re-exports INDICATOR_TYPE constant', () => {
    assert.ok(graphSecurity.INDICATOR_TYPE);
    assert.equal(graphSecurity.INDICATOR_TYPE.IP, 'networkIPv4');
  });
});
