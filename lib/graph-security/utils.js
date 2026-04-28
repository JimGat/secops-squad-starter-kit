'use strict';

/**
 * @module utils
 * Shared HTTP helpers for Microsoft Graph Security API calls.
 * Handles authentication headers, error normalization, pagination,
 * and retry logic (429 rate limiting).
 *
 * Internal module — not exported from the public API.
 */

const GRAPH_BASE = 'https://graph.microsoft.com/v1.0';

/**
 * Performs a GET request against the Graph API.
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @param {string|null} path - API path relative to Graph base (omit if using rawUrl)
 * @param {object} [options]
 * @param {string} [options.rawUrl] - Full URL to use instead of building from path
 * @returns {Promise<{ok: true, data: any, nextLink?: string} | {ok: false, error: string, status?: number}>}
 */
async function graphGet(client, path, options = {}) {
  const url = options.rawUrl || `${GRAPH_BASE}/${path}`;
  return graphRequest(client, 'GET', url);
}

/**
 * Performs a PATCH request against the Graph API.
 *
 * @param {import('./index').GraphClient} client
 * @param {string} path - API path relative to Graph base
 * @param {object} body - JSON body
 * @returns {Promise<{ok: true, data: any} | {ok: false, error: string, status?: number}>}
 */
async function graphPatch(client, path, body) {
  return graphRequest(client, 'PATCH', `${GRAPH_BASE}/${path}`, body);
}

/**
 * Performs a POST request against the Graph API.
 *
 * @param {import('./index').GraphClient} client
 * @param {string} path - API path relative to Graph base
 * @param {object} body - JSON body
 * @returns {Promise<{ok: true, data: any} | {ok: false, error: string, status?: number}>}
 */
async function graphPost(client, path, body) {
  return graphRequest(client, 'POST', `${GRAPH_BASE}/${path}`, body);
}

/**
 * Performs a DELETE request against the Graph API.
 *
 * @param {import('./index').GraphClient} client
 * @param {string} path - API path relative to Graph base
 * @returns {Promise<{ok: true} | {ok: false, error: string, status?: number}>}
 */
async function graphDelete(client, path) {
  return graphRequest(client, 'DELETE', `${GRAPH_BASE}/${path}`);
}

/**
 * Core request function with retry logic for 429 (rate limiting) and
 * structured error returns for 401, 403, 404, and other failures.
 *
 * @param {import('./index').GraphClient} client
 * @param {string} method - HTTP method
 * @param {string} url - Full URL
 * @param {object} [body] - JSON body for POST/PATCH
 * @param {number} [retryCount=0] - Current retry attempt
 * @returns {Promise<{ok: true, data?: any, nextLink?: string} | {ok: false, error: string, status?: number}>}
 */
async function graphRequest(client, method, url, body, retryCount = 0) {
  const MAX_RETRIES = 3;

  const token = await client.getToken();
  if (!token) {
    return { ok: false, error: 'Failed to acquire authentication token' };
  }

  const headers = {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };

  const fetchOptions = { method, headers };
  if (body && (method === 'POST' || method === 'PATCH')) {
    fetchOptions.body = JSON.stringify(body);
  }

  try {
    const res = await fetch(url, fetchOptions);

    // 204 No Content (successful DELETE)
    if (res.status === 204) {
      return { ok: true };
    }

    // Rate limited — retry with exponential backoff
    if (res.status === 429 && retryCount < MAX_RETRIES) {
      const retryAfter = parseInt(res.headers.get('Retry-After') || '5', 10);
      const delayMs = retryAfter * 1000 * Math.pow(2, retryCount);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      return graphRequest(client, method, url, body, retryCount + 1);
    }

    let data;
    try {
      data = await res.json();
    } catch {
      data = null;
    }

    if (!res.ok) {
      return normalizeError(res.status, data);
    }

    // Normalize the response — unwrap OData value arrays
    const result = { ok: true };
    if (data && Array.isArray(data.value)) {
      result.data = data.value;
      if (data['@odata.nextLink']) {
        result.nextLink = data['@odata.nextLink'];
      }
    } else {
      result.data = data;
    }

    return result;
  } catch (err) {
    return { ok: false, error: `Network error: ${err.message}` };
  }
}

/**
 * Normalizes Graph API error responses into structured error objects.
 *
 * @param {number} status - HTTP status code
 * @param {object|null} body - Response body (may contain OData error)
 * @returns {{ok: false, error: string, status: number, code?: string}}
 */
function normalizeError(status, body) {
  const oDataError = body?.error;
  const message = oDataError?.message || friendlyStatus(status);
  const code = oDataError?.code;

  const result = { ok: false, error: message, status };
  if (code) result.code = code;
  return result;
}

/**
 * Human-readable fallback messages for common HTTP status codes.
 * @param {number} status
 * @returns {string}
 */
function friendlyStatus(status) {
  const map = {
    400: 'Bad request — check query parameters and request body',
    401: 'Unauthorized — token is missing, expired, or invalid',
    403: 'Forbidden — insufficient permissions for this operation',
    404: 'Resource not found',
    409: 'Conflict — the resource was modified by another request',
    429: 'Rate limited — too many requests. Retry after the Retry-After interval.',
    500: 'Internal server error — retry the request',
    502: 'Bad gateway — the service is temporarily unavailable',
    503: 'Service unavailable — retry after a short delay',
  };
  return map[status] || `Request failed with status ${status}`;
}

/**
 * Builds an OData $filter string from key-value pairs.
 * Joins all parts with ' and '.
 *
 * @param {Record<string, string>} fields - Field name → value mapping
 * @returns {string} OData filter string
 */
function buildFilter(fields) {
  return Object.entries(fields)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => `${k} eq '${v}'`)
    .join(' and ');
}

module.exports = {
  graphGet,
  graphPatch,
  graphPost,
  graphDelete,
  graphRequest,
  buildFilter,
  GRAPH_BASE,
};
