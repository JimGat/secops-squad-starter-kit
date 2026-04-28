'use strict';

/**
 * @module auth
 * Authentication helpers for Microsoft Graph Security API.
 * Uses native fetch (Node 18+). No external dependencies.
 */

const AZURE_AD_BASE = 'https://login.microsoftonline.com';
const GRAPH_SCOPE = 'https://graph.microsoft.com/.default';

/** @type {Map<string, {token: string, expiresAt: number}>} */
const tokenCache = new Map();

/**
 * Checks whether a cached token exists and is still valid (with 5-min buffer).
 * @param {string} cacheKey
 * @returns {{token: string} | null}
 */
function getCachedToken(cacheKey) {
  const entry = tokenCache.get(cacheKey);
  if (!entry) return null;
  const bufferMs = 5 * 60 * 1000; // refresh 5 min before expiry
  if (Date.now() >= entry.expiresAt - bufferMs) {
    tokenCache.delete(cacheKey);
    return null;
  }
  return { token: entry.token };
}

/**
 * Stores a token in the in-memory cache.
 * @param {string} cacheKey
 * @param {string} token
 * @param {number} expiresInSeconds
 */
function cacheToken(cacheKey, token, expiresInSeconds) {
  tokenCache.set(cacheKey, {
    token,
    expiresAt: Date.now() + expiresInSeconds * 1000,
  });
}

/**
 * Clears all cached tokens. Useful for testing or forced re-auth.
 */
function clearTokenCache() {
  tokenCache.clear();
}

/**
 * Acquires an access token using the OAuth 2.0 client credentials flow.
 * Suitable for app-only (daemon) authentication — no user context.
 *
 * @param {string} tenantId - Azure AD tenant ID (GUID or domain)
 * @param {string} clientId - Application (client) ID
 * @param {string} clientSecret - Client secret value
 * @returns {Promise<{ok: true, token: string, expiresIn: number} | {ok: false, error: string, status?: number}>}
 */
async function getTokenClientCredentials(tenantId, clientId, clientSecret) {
  if (!tenantId || typeof tenantId !== 'string') {
    return { ok: false, error: 'tenantId is required and must be a non-empty string' };
  }
  if (!clientId || typeof clientId !== 'string') {
    return { ok: false, error: 'clientId is required and must be a non-empty string' };
  }
  if (!clientSecret || typeof clientSecret !== 'string') {
    return { ok: false, error: 'clientSecret is required and must be a non-empty string' };
  }

  const cacheKey = `cc:${tenantId}:${clientId}`;
  const cached = getCachedToken(cacheKey);
  if (cached) return { ok: true, token: cached.token, expiresIn: 0 };

  const url = `${AZURE_AD_BASE}/${tenantId}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: clientId,
    client_secret: clientSecret,
    scope: GRAPH_SCOPE,
  });

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const data = await res.json();

    if (!res.ok) {
      return {
        ok: false,
        error: data.error_description || data.error || 'Authentication failed',
        status: res.status,
      };
    }

    const expiresIn = data.expires_in || 3600;
    cacheToken(cacheKey, data.access_token, expiresIn);

    return { ok: true, token: data.access_token, expiresIn };
  } catch (err) {
    return { ok: false, error: `Network error: ${err.message}` };
  }
}

/**
 * Acquires an access token using Azure Managed Identity.
 * Works on Azure VMs, App Service, Functions, Container Instances, and AKS.
 *
 * @returns {Promise<{ok: true, token: string, expiresIn: number} | {ok: false, error: string, status?: number}>}
 */
async function getTokenManagedIdentity() {
  const cacheKey = 'mi:default';
  const cached = getCachedToken(cacheKey);
  if (cached) return { ok: true, token: cached.token, expiresIn: 0 };

  const identityEndpoint = process.env.IDENTITY_ENDPOINT;
  const identityHeader = process.env.IDENTITY_HEADER;

  // App Service / Functions managed identity
  if (identityEndpoint && identityHeader) {
    const url = `${identityEndpoint}?api-version=2019-08-01&resource=https://graph.microsoft.com`;
    try {
      const res = await fetch(url, {
        headers: { 'X-IDENTITY-HEADER': identityHeader },
      });
      const data = await res.json();
      if (!res.ok) {
        return {
          ok: false,
          error: data.error_description || data.message || 'Managed identity auth failed',
          status: res.status,
        };
      }
      const expiresIn = data.expires_in ? Number(data.expires_in) : 3600;
      cacheToken(cacheKey, data.access_token, expiresIn);
      return { ok: true, token: data.access_token, expiresIn };
    } catch (err) {
      return { ok: false, error: `Managed identity network error: ${err.message}` };
    }
  }

  // IMDS (VM / VMSS / AKS) fallback
  const imdsUrl =
    'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com';
  try {
    const res = await fetch(imdsUrl, {
      headers: { Metadata: 'true' },
    });
    const data = await res.json();
    if (!res.ok) {
      return {
        ok: false,
        error: data.error_description || data.error || 'IMDS auth failed',
        status: res.status,
      };
    }
    const expiresIn = data.expires_in ? Number(data.expires_in) : 3600;
    cacheToken(cacheKey, data.access_token, expiresIn);
    return { ok: true, token: data.access_token, expiresIn };
  } catch (err) {
    return {
      ok: false,
      error: `Managed identity not available. Ensure this code runs on an Azure resource with managed identity enabled. Details: ${err.message}`,
    };
  }
}

/**
 * Acquires a token using the device code flow (interactive).
 * Prints a user code and verification URL to stdout; the user
 * authenticates in a browser while this function polls for completion.
 *
 * @param {string} tenantId - Azure AD tenant ID (GUID or domain)
 * @param {string} clientId - Application (client) ID (must allow device code flow)
 * @returns {Promise<{ok: true, token: string, expiresIn: number} | {ok: false, error: string, status?: number}>}
 */
async function getTokenDeviceCode(tenantId, clientId) {
  if (!tenantId || typeof tenantId !== 'string') {
    return { ok: false, error: 'tenantId is required and must be a non-empty string' };
  }
  if (!clientId || typeof clientId !== 'string') {
    return { ok: false, error: 'clientId is required and must be a non-empty string' };
  }

  const cacheKey = `dc:${tenantId}:${clientId}`;
  const cached = getCachedToken(cacheKey);
  if (cached) return { ok: true, token: cached.token, expiresIn: 0 };

  // Step 1: Request device code
  const codeUrl = `${AZURE_AD_BASE}/${tenantId}/oauth2/v2.0/devicecode`;
  let deviceCodeData;
  try {
    const res = await fetch(codeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        scope: 'https://graph.microsoft.com/SecurityEvents.ReadWrite.All offline_access',
      }).toString(),
    });
    deviceCodeData = await res.json();
    if (!res.ok) {
      return {
        ok: false,
        error: deviceCodeData.error_description || 'Failed to initiate device code flow',
        status: res.status,
      };
    }
  } catch (err) {
    return { ok: false, error: `Device code request failed: ${err.message}` };
  }

  // Print instructions for the user
  console.log(`\n🔐 ${deviceCodeData.message}\n`);

  // Step 2: Poll for token
  const tokenUrl = `${AZURE_AD_BASE}/${tenantId}/oauth2/v2.0/token`;
  const interval = (deviceCodeData.interval || 5) * 1000;
  const expiresAt = Date.now() + (deviceCodeData.expires_in || 900) * 1000;

  while (Date.now() < expiresAt) {
    await new Promise((resolve) => setTimeout(resolve, interval));

    try {
      const res = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          client_id: clientId,
          device_code: deviceCodeData.device_code,
        }).toString(),
      });

      const data = await res.json();

      if (res.ok) {
        const expiresIn = data.expires_in || 3600;
        cacheToken(cacheKey, data.access_token, expiresIn);
        return { ok: true, token: data.access_token, expiresIn };
      }

      // authorization_pending is expected — keep polling
      if (data.error === 'authorization_pending') continue;

      // slow_down — increase interval (handled implicitly by the server's interval)
      if (data.error === 'slow_down') continue;

      // Any other error is terminal
      return {
        ok: false,
        error: data.error_description || data.error || 'Device code authentication failed',
        status: res.status,
      };
    } catch (err) {
      return { ok: false, error: `Token polling error: ${err.message}` };
    }
  }

  return { ok: false, error: 'Device code flow expired. Please try again.' };
}

module.exports = {
  getTokenClientCredentials,
  getTokenManagedIdentity,
  getTokenDeviceCode,
  clearTokenCache,
};
