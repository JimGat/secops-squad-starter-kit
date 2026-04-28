'use strict';

/**
 * @module alerts
 * Security alert management via Microsoft Graph Security API v1.0.
 *
 * All functions return `{ok, data?, error?, status?}` result objects —
 * API errors are never thrown.
 */

const { graphGet, graphPatch, buildFilter } = require('./utils');

/** Common alert severity levels. */
const SEVERITY = Object.freeze({
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFORMATIONAL: 'informational',
  UNKNOWN: 'unknownFutureValue',
});

/** Common alert status values. */
const ALERT_STATUS = Object.freeze({
  NEW: 'new',
  IN_PROGRESS: 'inProgress',
  RESOLVED: 'resolved',
  UNKNOWN: 'unknownFutureValue',
});

/**
 * Lists security alerts with optional OData filtering and pagination.
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @param {object} [filters] - OData filter options
 * @param {string} [filters.severity] - Filter by severity (high, medium, low, informational)
 * @param {string} [filters.status] - Filter by status (new, inProgress, resolved)
 * @param {string} [filters.provider] - Filter by service source / provider
 * @param {number} [filters.top] - Number of results per page (max 1000)
 * @param {string} [filters.nextLink] - Pagination continuation URL
 * @returns {Promise<{ok: true, data: object[], nextLink?: string} | {ok: false, error: string, status?: number}>}
 */
async function listAlerts(client, filters = {}) {
  if (!client) return { ok: false, error: 'client is required' };

  // If we have a nextLink, use it directly (it already includes filters)
  if (filters.nextLink) {
    return graphGet(client, null, { rawUrl: filters.nextLink });
  }

  const filterParts = [];
  if (filters.severity) filterParts.push(`severity eq '${filters.severity}'`);
  if (filters.status) filterParts.push(`status eq '${filters.status}'`);
  if (filters.provider) filterParts.push(`serviceSource eq '${filters.provider}'`);

  const params = new URLSearchParams();
  if (filterParts.length) params.set('$filter', filterParts.join(' and '));
  if (filters.top) params.set('$top', String(filters.top));
  params.set('$orderby', 'createdDateTime desc');

  const query = params.toString();
  const path = `security/alerts_v2${query ? '?' + query : ''}`;

  return graphGet(client, path);
}

/**
 * Retrieves a single security alert by ID.
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @param {string} alertId - The alert ID
 * @returns {Promise<{ok: true, data: object} | {ok: false, error: string, status?: number}>}
 */
async function getAlert(client, alertId) {
  if (!client) return { ok: false, error: 'client is required' };
  if (!alertId || typeof alertId !== 'string') {
    return { ok: false, error: 'alertId is required and must be a non-empty string' };
  }

  return graphGet(client, `security/alerts_v2/${encodeURIComponent(alertId)}`);
}

/**
 * Updates a security alert (status, assignedTo, comments, etc.).
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @param {string} alertId - The alert ID
 * @param {object} updates - Fields to update
 * @param {string} [updates.status] - New status (new, inProgress, resolved)
 * @param {string} [updates.assignedTo] - UPN of the assignee
 * @param {string} [updates.classification] - Alert classification
 * @param {string} [updates.determination] - Alert determination
 * @param {object[]} [updates.comments] - Array of comment objects {comment: string}
 * @returns {Promise<{ok: true, data: object} | {ok: false, error: string, status?: number}>}
 */
async function updateAlert(client, alertId, updates) {
  if (!client) return { ok: false, error: 'client is required' };
  if (!alertId || typeof alertId !== 'string') {
    return { ok: false, error: 'alertId is required and must be a non-empty string' };
  }
  if (!updates || typeof updates !== 'object') {
    return { ok: false, error: 'updates is required and must be an object' };
  }

  return graphPatch(client, `security/alerts_v2/${encodeURIComponent(alertId)}`, updates);
}

/**
 * Lists alerts related to a specific entity (user, IP, host, file hash).
 *
 * Uses OData filtering on the evidence collection within alerts.
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @param {'user'|'ip'|'host'|'fileHash'} entityType - Type of entity to search
 * @param {string} entityValue - The entity value (UPN, IP address, hostname, or SHA-256 hash)
 * @returns {Promise<{ok: true, data: object[], nextLink?: string} | {ok: false, error: string, status?: number}>}
 */
async function listAlertsByEntity(client, entityType, entityValue) {
  if (!client) return { ok: false, error: 'client is required' };

  const validTypes = ['user', 'ip', 'host', 'fileHash'];
  if (!entityType || !validTypes.includes(entityType)) {
    return { ok: false, error: `entityType must be one of: ${validTypes.join(', ')}` };
  }
  if (!entityValue || typeof entityValue !== 'string') {
    return { ok: false, error: 'entityValue is required and must be a non-empty string' };
  }

  // Build a search-oriented filter based on entity type
  const filterMap = {
    user: `actorDisplayName eq '${entityValue}'`,
    ip: `contains(description, '${entityValue}')`,
    host: `contains(description, '${entityValue}')`,
    fileHash: `contains(description, '${entityValue}')`,
  };

  const params = new URLSearchParams();
  params.set('$filter', filterMap[entityType]);
  params.set('$orderby', 'createdDateTime desc');

  return graphGet(client, `security/alerts_v2?${params.toString()}`);
}

module.exports = {
  listAlerts,
  getAlert,
  updateAlert,
  listAlertsByEntity,
  SEVERITY,
  ALERT_STATUS,
};
