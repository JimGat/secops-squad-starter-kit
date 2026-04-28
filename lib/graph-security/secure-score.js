'use strict';

/**
 * @module secure-score
 * Microsoft Secure Score retrieval and analysis via Graph Security API v1.0.
 *
 * All functions return `{ok, data?, error?, status?}` result objects —
 * API errors are never thrown.
 */

const { graphGet } = require('./utils');

/**
 * Retrieves the most recent secure score with category breakdown.
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @returns {Promise<{ok: true, data: object} | {ok: false, error: string, status?: number}>}
 */
async function getSecureScore(client) {
  if (!client) return { ok: false, error: 'client is required' };

  const result = await graphGet(client, 'security/secureScores?$top=1&$orderby=createdDateTime desc');
  if (!result.ok) return result;

  const scores = result.data;
  if (!scores || scores.length === 0) {
    return { ok: false, error: 'No secure score data available' };
  }

  return { ok: true, data: scores[0] };
}

/**
 * Retrieves secure score history over a given number of days.
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @param {number} [days=30] - Number of days of history to retrieve
 * @returns {Promise<{ok: true, data: object[]} | {ok: false, error: string, status?: number}>}
 */
async function getSecureScoreHistory(client, days = 30) {
  if (!client) return { ok: false, error: 'client is required' };
  if (typeof days !== 'number' || days < 1 || days > 365) {
    return { ok: false, error: 'days must be a number between 1 and 365' };
  }

  const sinceDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const params = new URLSearchParams({
    $filter: `createdDateTime ge ${sinceDate}`,
    $orderby: 'createdDateTime desc',
    $top: String(Math.min(days, 1000)),
  });

  return graphGet(client, `security/secureScores?${params.toString()}`);
}

/**
 * Retrieves available security control profiles and their potential score impact.
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @returns {Promise<{ok: true, data: object[]} | {ok: false, error: string, status?: number}>}
 */
async function getControlProfiles(client) {
  if (!client) return { ok: false, error: 'client is required' };

  return graphGet(client, 'security/secureScoreControlProfiles');
}

/**
 * Retrieves actionable security recommendations based on control profiles.
 * Returns controls sorted by maximum score impact (highest impact first).
 *
 * @param {import('./index').GraphClient} client - Authenticated Graph client
 * @returns {Promise<{ok: true, data: object[]} | {ok: false, error: string, status?: number}>}
 */
async function getRecommendations(client) {
  if (!client) return { ok: false, error: 'client is required' };

  const result = await getControlProfiles(client);
  if (!result.ok) return result;

  const profiles = result.data || [];

  // Sort by maxScore descending so the highest-impact actions come first
  const recommendations = profiles
    .filter((p) => p.implementationStatus !== 'implemented')
    .map((p) => ({
      id: p.id,
      title: p.title,
      maxScore: p.maxScore,
      currentScore: p.currentScore,
      implementationStatus: p.implementationStatus,
      actionType: p.actionType,
      remediation: p.remediation,
      service: p.service,
      threats: p.threats,
      tier: p.tier,
      userImpact: p.userImpact,
      implementationCost: p.implementationCost,
    }))
    .sort((a, b) => (b.maxScore || 0) - (a.maxScore || 0));

  return { ok: true, data: recommendations };
}

module.exports = {
  getSecureScore,
  getSecureScoreHistory,
  getControlProfiles,
  getRecommendations,
};
