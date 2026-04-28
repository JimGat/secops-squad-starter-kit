'use strict';

/**
 * @module incidents
 * Security incident management via Microsoft Graph Security API v1.0.
 *
 * All functions return `{ok, data?, error?, status?}` result objects —
 * API errors are never thrown.
 */

const { graphGet, graphPatch, graphPost } = require('./utils');

/** Incident status values. */
const INCIDENT_STATUS = Object.freeze({
  ACTIVE: 'active',
  RESOLVED: 'resolved',
  REDIRECTED: 'redirected',
  UNKNOWN: 'unknownFutureValue',
});

/** Incident classification values. */
const INCIDENT_CLASSIFICATION = Object.freeze({
  TRUE_POSITIVE: 'truePositive',
  FALSE_POSITIVE: 'falsePositive',
  INFORMATIONAL: 'informationalExpectedActivity',
  UNKNOWN: 'unknownFutureValue',
});

/** Incident determination values. */
const INCIDENT_DETERMINATION = Object.freeze({
  MALWARE: 'malware',
  PHISHING: 'phishing',
  COMPROMISED_ACCOUNT: 'compromisedAccount',
  UNWANTED_SOFTWARE: 'unwantedSoftware',
  MULTI_STAGE_ATTACK: 'multiStagedAttack',
  SECURITY_TESTING: 'securityTesting',
  LINE_OF_BUSINESS_APP: 'lineOfBusinessApplication',
  CONFIRMED_ACTIVITY: 'confirmedActivity',
  NOT_MALICIOUS: 'notMalicious',
  NOT_ENOUGH_DATA: 'notEnoughDataToValidate',
  OTHER: 'other',
  UNKNOWN: 'unknownFutureValue',
});

/**
 * Lists security incidents with optional OData filtering and pagination.
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @param {object} [filters] - OData filter options
 * @param {string} [filters.status] - Filter by status (active, resolved, redirected)
 * @param {string} [filters.severity] - Filter by severity
 * @param {string} [filters.assignedTo] - Filter by assigned user UPN
 * @param {number} [filters.top] - Results per page (max 1000)
 * @param {string} [filters.nextLink] - Pagination continuation URL
 * @returns {Promise<{ok: true, data: object[], nextLink?: string} | {ok: false, error: string, status?: number}>}
 */
async function listIncidents(client, filters = {}) {
  if (!client) return { ok: false, error: 'client is required' };

  if (filters.nextLink) {
    return graphGet(client, null, { rawUrl: filters.nextLink });
  }

  const filterParts = [];
  if (filters.status) filterParts.push(`status eq '${filters.status}'`);
  if (filters.severity) filterParts.push(`severity eq '${filters.severity}'`);
  if (filters.assignedTo) filterParts.push(`assignedTo eq '${filters.assignedTo}'`);

  const params = new URLSearchParams();
  if (filterParts.length) params.set('$filter', filterParts.join(' and '));
  if (filters.top) params.set('$top', String(filters.top));
  params.set('$orderby', 'createdDateTime desc');

  const query = params.toString();
  return graphGet(client, `security/incidents${query ? '?' + query : ''}`);
}

/**
 * Retrieves a single incident by ID, including its alert summary.
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @param {string} incidentId - The incident ID
 * @returns {Promise<{ok: true, data: object} | {ok: false, error: string, status?: number}>}
 */
async function getIncident(client, incidentId) {
  if (!client) return { ok: false, error: 'client is required' };
  if (!incidentId || typeof incidentId !== 'string') {
    return { ok: false, error: 'incidentId is required and must be a non-empty string' };
  }

  return graphGet(client, `security/incidents/${encodeURIComponent(incidentId)}`);
}

/**
 * Updates an incident (status, classification, assignedTo, determination).
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @param {string} incidentId - The incident ID
 * @param {object} updates - Fields to update
 * @param {string} [updates.status] - New status
 * @param {string} [updates.classification] - Classification (truePositive, falsePositive, etc.)
 * @param {string} [updates.determination] - Determination (malware, phishing, etc.)
 * @param {string} [updates.assignedTo] - UPN of the assignee
 * @param {string[]} [updates.tags] - Custom tags
 * @returns {Promise<{ok: true, data: object} | {ok: false, error: string, status?: number}>}
 */
async function updateIncident(client, incidentId, updates) {
  if (!client) return { ok: false, error: 'client is required' };
  if (!incidentId || typeof incidentId !== 'string') {
    return { ok: false, error: 'incidentId is required and must be a non-empty string' };
  }
  if (!updates || typeof updates !== 'object') {
    return { ok: false, error: 'updates is required and must be an object' };
  }

  return graphPatch(client, `security/incidents/${encodeURIComponent(incidentId)}`, updates);
}

/**
 * Adds a comment to an incident.
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @param {string} incidentId - The incident ID
 * @param {string} comment - Comment text
 * @returns {Promise<{ok: true, data: object} | {ok: false, error: string, status?: number}>}
 */
async function addComment(client, incidentId, comment) {
  if (!client) return { ok: false, error: 'client is required' };
  if (!incidentId || typeof incidentId !== 'string') {
    return { ok: false, error: 'incidentId is required and must be a non-empty string' };
  }
  if (!comment || typeof comment !== 'string') {
    return { ok: false, error: 'comment is required and must be a non-empty string' };
  }

  return graphPost(
    client,
    `security/incidents/${encodeURIComponent(incidentId)}/comments`,
    { comment }
  );
}

/**
 * Retrieves all alerts associated with an incident.
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @param {string} incidentId - The incident ID
 * @returns {Promise<{ok: true, data: object[]} | {ok: false, error: string, status?: number}>}
 */
async function getIncidentAlerts(client, incidentId) {
  if (!client) return { ok: false, error: 'client is required' };
  if (!incidentId || typeof incidentId !== 'string') {
    return { ok: false, error: 'incidentId is required and must be a non-empty string' };
  }

  return graphGet(client, `security/incidents/${encodeURIComponent(incidentId)}/alerts`);
}

module.exports = {
  listIncidents,
  getIncident,
  updateIncident,
  addComment,
  getIncidentAlerts,
  INCIDENT_STATUS,
  INCIDENT_CLASSIFICATION,
  INCIDENT_DETERMINATION,
};
