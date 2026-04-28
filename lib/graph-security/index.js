'use strict';

/**
 * @module graph-security
 * Microsoft Graph Security API client library.
 *
 * Zero external dependencies — uses native `fetch` (Node 18+).
 * All API functions return structured result objects `{ok, data?, error?, status?}`
 * instead of throwing exceptions.
 *
 * @example
 * const { createClient, alerts, incidents } = require('./lib/graph-security');
 *
 * const client = createClient({
 *   tenantId: process.env.AZURE_TENANT_ID,
 *   clientId: process.env.AZURE_CLIENT_ID,
 *   clientSecret: process.env.AZURE_CLIENT_SECRET,
 * });
 *
 * const result = await alerts.listAlerts(client, { severity: 'high' });
 * if (result.ok) console.log(result.data);
 */

const auth = require('./auth');
const alerts = require('./alerts');
const incidents = require('./incidents');
const threatIntelligence = require('./threat-intelligence');
const secureScore = require('./secure-score');

/**
 * @typedef {object} GraphClient
 * @property {() => Promise<string|null>} getToken - Returns a valid access token
 * @property {string} tenantId - The Azure AD tenant ID
 */

/**
 * @typedef {object} ClientConfig
 * @property {string} tenantId - Azure AD tenant ID
 * @property {string} [clientId] - Application (client) ID (required for client credentials and device code)
 * @property {string} [clientSecret] - Client secret (required for client credentials flow)
 * @property {'clientCredentials'|'managedIdentity'|'deviceCode'} [authMethod='clientCredentials'] - Authentication method
 * @property {string} [token] - Pre-acquired token (bypasses auth entirely)
 */

/**
 * Creates an authenticated Graph Security API client.
 *
 * Supports three authentication methods:
 * - **clientCredentials** (default): App-only auth using tenantId + clientId + clientSecret
 * - **managedIdentity**: Uses Azure managed identity (no credentials needed)
 * - **deviceCode**: Interactive device code flow for CLI tools
 * - **token**: Pre-acquired bearer token (useful for testing or external token management)
 *
 * @param {ClientConfig} config - Client configuration
 * @returns {GraphClient} An authenticated client wrapper
 */
function createClient(config) {
  if (!config || typeof config !== 'object') {
    throw new Error('createClient requires a config object');
  }

  // Pre-acquired token mode — no auth flow needed
  if (config.token) {
    return {
      tenantId: config.tenantId || 'unknown',
      getToken: async () => config.token,
    };
  }

  const method = config.authMethod || 'clientCredentials';

  if (method === 'managedIdentity') {
    return {
      tenantId: config.tenantId || 'managed',
      getToken: async () => {
        const result = await auth.getTokenManagedIdentity();
        return result.ok ? result.token : null;
      },
    };
  }

  if (method === 'deviceCode') {
    if (!config.tenantId || !config.clientId) {
      throw new Error('deviceCode auth requires tenantId and clientId');
    }
    return {
      tenantId: config.tenantId,
      getToken: async () => {
        const result = await auth.getTokenDeviceCode(config.tenantId, config.clientId);
        return result.ok ? result.token : null;
      },
    };
  }

  // Default: clientCredentials
  if (!config.tenantId || !config.clientId || !config.clientSecret) {
    throw new Error('clientCredentials auth requires tenantId, clientId, and clientSecret');
  }

  return {
    tenantId: config.tenantId,
    getToken: async () => {
      const result = await auth.getTokenClientCredentials(
        config.tenantId,
        config.clientId,
        config.clientSecret
      );
      return result.ok ? result.token : null;
    },
  };
}

module.exports = {
  createClient,

  // Auth (exported for direct use if needed)
  auth,

  // API modules
  alerts,
  incidents,
  threatIntelligence,
  secureScore,

  // Constants re-exported for convenience
  SEVERITY: alerts.SEVERITY,
  ALERT_STATUS: alerts.ALERT_STATUS,
  INCIDENT_STATUS: incidents.INCIDENT_STATUS,
  INCIDENT_CLASSIFICATION: incidents.INCIDENT_CLASSIFICATION,
  INCIDENT_DETERMINATION: incidents.INCIDENT_DETERMINATION,
  INDICATOR_TYPE: threatIntelligence.INDICATOR_TYPE,
  INDICATOR_ACTION: threatIntelligence.INDICATOR_ACTION,
  THREAT_TYPE: threatIntelligence.THREAT_TYPE,
};
