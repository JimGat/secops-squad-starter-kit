'use strict';

/**
 * @module threat-intelligence
 * Threat intelligence indicator management via Microsoft Graph Security API v1.0.
 *
 * All functions return `{ok, data?, error?, status?}` result objects —
 * API errors are never thrown.
 */

const { graphGet, graphPost, graphDelete } = require('./utils');

/** TI indicator types. */
const INDICATOR_TYPE = Object.freeze({
  IP: 'networkIPv4',
  IPV6: 'networkIPv6',
  URL: 'url',
  DOMAIN: 'domainName',
  FILE_HASH_SHA256: 'fileSha256',
  FILE_HASH_SHA1: 'fileSha1',
  FILE_HASH_MD5: 'fileMd5',
  EMAIL: 'email',
});

/** TI indicator actions. */
const INDICATOR_ACTION = Object.freeze({
  ALERT: 'alert',
  ALLOW: 'allow',
  BLOCK: 'block',
});

/** Threat types for indicators. */
const THREAT_TYPE = Object.freeze({
  BOTNET: 'Botnet',
  C2: 'C2',
  CRYPTO_MINING: 'CryptoMining',
  DARKNET: 'Darknet',
  DDOS: 'DDoS',
  MALICIOUS_URL: 'MaliciousUrl',
  MALWARE: 'Malware',
  PHISHING: 'Phishing',
  PROXY: 'Proxy',
  PUA: 'PUA',
  WATCHLIST: 'WatchList',
});

/**
 * Lists threat intelligence indicators with optional filtering.
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @param {object} [filters] - Filtering options
 * @param {string} [filters.indicatorType] - Filter by indicator type
 * @param {string} [filters.action] - Filter by action (alert, allow, block)
 * @param {number} [filters.top] - Results per page
 * @param {string} [filters.nextLink] - Pagination continuation URL
 * @returns {Promise<{ok: true, data: object[], nextLink?: string} | {ok: false, error: string, status?: number}>}
 */
async function listIndicators(client, filters = {}) {
  if (!client) return { ok: false, error: 'client is required' };

  if (filters.nextLink) {
    return graphGet(client, null, { rawUrl: filters.nextLink });
  }

  const params = new URLSearchParams();
  const filterParts = [];
  if (filters.indicatorType) filterParts.push(`patternType eq '${filters.indicatorType}'`);
  if (filters.action) filterParts.push(`action eq '${filters.action}'`);
  if (filterParts.length) params.set('$filter', filterParts.join(' and '));
  if (filters.top) params.set('$top', String(filters.top));

  const query = params.toString();
  return graphGet(client, `security/tiIndicators${query ? '?' + query : ''}`);
}

/**
 * Creates a new threat intelligence indicator.
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @param {object} indicator - The indicator to create
 * @param {string} indicator.action - Action to take (alert, allow, block)
 * @param {string} indicator.description - Human-readable description
 * @param {string} indicator.expirationDateTime - ISO 8601 expiration date
 * @param {string} indicator.targetProduct - Target product (e.g., 'Azure Sentinel')
 * @param {string} indicator.threatType - Threat category (see THREAT_TYPE)
 * @param {string} indicator.tlpLevel - TLP level (white, green, amber, red)
 * @param {string} [indicator.domainName] - Domain name IOC
 * @param {string} [indicator.url] - URL IOC
 * @param {string} [indicator.networkIPv4] - IPv4 address IOC
 * @param {string} [indicator.fileSha256] - SHA-256 hash IOC
 * @returns {Promise<{ok: true, data: object} | {ok: false, error: string, status?: number}>}
 */
async function createIndicator(client, indicator) {
  if (!client) return { ok: false, error: 'client is required' };
  if (!indicator || typeof indicator !== 'object') {
    return { ok: false, error: 'indicator is required and must be an object' };
  }

  const required = ['action', 'description', 'expirationDateTime', 'targetProduct', 'threatType', 'tlpLevel'];
  for (const field of required) {
    if (!indicator[field]) {
      return { ok: false, error: `indicator.${field} is required` };
    }
  }

  return graphPost(client, 'security/tiIndicators', indicator);
}

/**
 * Deletes a threat intelligence indicator.
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @param {string} indicatorId - The indicator ID to delete
 * @returns {Promise<{ok: true} | {ok: false, error: string, status?: number}>}
 */
async function deleteIndicator(client, indicatorId) {
  if (!client) return { ok: false, error: 'client is required' };
  if (!indicatorId || typeof indicatorId !== 'string') {
    return { ok: false, error: 'indicatorId is required and must be a non-empty string' };
  }

  return graphDelete(client, `security/tiIndicators/${encodeURIComponent(indicatorId)}`);
}

/**
 * Creates multiple TI indicators in batch, with built-in rate limiting.
 * Processes indicators sequentially with a configurable delay to respect
 * Graph API throttling limits.
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @param {object[]} indicators - Array of indicator objects (same shape as createIndicator)
 * @param {object} [options] - Batch options
 * @param {number} [options.delayMs=200] - Delay between requests in ms
 * @param {boolean} [options.stopOnError=false] - Stop on first error
 * @returns {Promise<{ok: true, results: Array<{ok: boolean, data?: object, error?: string, index: number}>} | {ok: false, error: string}>}
 */
async function bulkCreateIndicators(client, indicators, options = {}) {
  if (!client) return { ok: false, error: 'client is required' };
  if (!Array.isArray(indicators) || indicators.length === 0) {
    return { ok: false, error: 'indicators must be a non-empty array' };
  }

  const delayMs = options.delayMs ?? 200;
  const stopOnError = options.stopOnError ?? false;
  const results = [];

  for (let i = 0; i < indicators.length; i++) {
    const result = await createIndicator(client, indicators[i]);
    results.push({ ...result, index: i });

    if (!result.ok && stopOnError) break;

    // Rate-limit delay between requests (skip after last)
    if (i < indicators.length - 1 && delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  return { ok: true, results };
}

/**
 * Converts common IOC (Indicator of Compromise) formats into
 * Graph API tiIndicator objects ready for submission.
 *
 * @param {object} ioc - The IOC to convert
 * @param {string} ioc.type - IOC type: 'ip', 'ipv6', 'url', 'domain', 'sha256', 'sha1', 'md5'
 * @param {string} ioc.value - The IOC value
 * @param {string} [ioc.action='alert'] - Action to take
 * @param {string} [ioc.threatType='Malware'] - Threat category
 * @param {string} [ioc.description] - Human description
 * @param {string} [ioc.tlpLevel='amber'] - TLP marking
 * @param {number} [ioc.expirationDays=90] - Days until expiration
 * @param {string} [ioc.targetProduct='Azure Sentinel'] - Target product
 * @returns {{ok: true, indicator: object} | {ok: false, error: string}}
 */
function convertIOCToIndicator(ioc) {
  if (!ioc || typeof ioc !== 'object') {
    return { ok: false, error: 'ioc is required and must be an object' };
  }
  if (!ioc.type || !ioc.value) {
    return { ok: false, error: 'ioc.type and ioc.value are required' };
  }

  const typeMap = {
    ip: 'networkIPv4',
    ipv6: 'networkIPv6',
    url: 'url',
    domain: 'domainName',
    sha256: 'fileSha256',
    sha1: 'fileSha1',
    md5: 'fileMd5',
  };

  const fieldName = typeMap[ioc.type.toLowerCase()];
  if (!fieldName) {
    return { ok: false, error: `Unknown IOC type: ${ioc.type}. Valid: ${Object.keys(typeMap).join(', ')}` };
  }

  const expirationDays = ioc.expirationDays || 90;
  const expirationDate = new Date(Date.now() + expirationDays * 24 * 60 * 60 * 1000);

  const indicator = {
    action: ioc.action || 'alert',
    description: ioc.description || `IOC: ${ioc.type} — ${ioc.value}`,
    expirationDateTime: expirationDate.toISOString(),
    targetProduct: ioc.targetProduct || 'Azure Sentinel',
    threatType: ioc.threatType || 'Malware',
    tlpLevel: ioc.tlpLevel || 'amber',
    [fieldName]: ioc.value,
  };

  return { ok: true, indicator };
}

module.exports = {
  listIndicators,
  createIndicator,
  deleteIndicator,
  bulkCreateIndicators,
  convertIOCToIndicator,
  INDICATOR_TYPE,
  INDICATOR_ACTION,
  THREAT_TYPE,
};
