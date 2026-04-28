"use strict";

const fs = require("fs");
const path = require("path");

const PLUGINS_DIR = ".squad/plugins";
const MANIFEST_FILE = "plugin.json";

/**
 * @typedef {Object} PluginManifest
 * @property {string} name
 * @property {string} version
 * @property {'skill'|'persona'|'template'} type
 * @property {string} description
 * @property {string} [author]
 * @property {string[]} files
 */

const REQUIRED_MANIFEST_FIELDS = ["name", "version", "type", "description", "files"];
const VALID_TYPES = ["skill", "persona", "template"];

/**
 * Validate a plugin.json manifest object.
 * @param {object} manifest
 * @returns {{ valid: boolean, errors: string[] }}
 */
function validateManifest(manifest) {
  const errors = [];

  if (!manifest || typeof manifest !== "object") {
    return { valid: false, errors: ["Manifest must be a JSON object"] };
  }

  for (const field of REQUIRED_MANIFEST_FIELDS) {
    if (!(field in manifest)) {
      errors.push(`Missing required field: '${field}'`);
    }
  }

  if (manifest.name && typeof manifest.name !== "string") {
    errors.push("'name' must be a string");
  }

  if (manifest.name && !/^[a-z0-9][a-z0-9._-]*$/i.test(manifest.name)) {
    errors.push("'name' must start with alphanumeric and contain only alphanumeric, dots, hyphens, underscores");
  }

  if (manifest.version && typeof manifest.version !== "string") {
    errors.push("'version' must be a string");
  }

  if (manifest.type && !VALID_TYPES.includes(manifest.type)) {
    errors.push(`'type' must be one of: ${VALID_TYPES.join(", ")}`);
  }

  if (manifest.files && !Array.isArray(manifest.files)) {
    errors.push("'files' must be an array of strings");
  }

  if (manifest.files && Array.isArray(manifest.files)) {
    for (const f of manifest.files) {
      if (typeof f !== "string") {
        errors.push(`Each entry in 'files' must be a string, got: ${typeof f}`);
        break;
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Get the plugins directory path for a project root.
 * @param {string} [rootDir] - Project root (defaults to cwd)
 * @returns {string}
 */
function getPluginsDir(rootDir) {
  return path.join(rootDir || process.cwd(), PLUGINS_DIR);
}

/**
 * Scan .squad/plugins/ for installed plugins.
 * @param {string} [rootDir]
 * @returns {PluginManifest[]}
 */
function listPlugins(rootDir) {
  const pluginsDir = getPluginsDir(rootDir);
  if (!fs.existsSync(pluginsDir)) return [];

  const plugins = [];

  const entries = fs.readdirSync(pluginsDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith("_")) continue;

    const manifestPath = path.join(pluginsDir, entry.name, MANIFEST_FILE);
    if (!fs.existsSync(manifestPath)) continue;

    try {
      const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      const validation = validateManifest(manifest);
      plugins.push({
        ...manifest,
        _dir: entry.name,
        _valid: validation.valid,
        _errors: validation.errors,
      });
    } catch {
      plugins.push({
        name: entry.name,
        _dir: entry.name,
        _valid: false,
        _errors: ["Invalid plugin.json — not valid JSON"],
      });
    }
  }

  return plugins;
}

/**
 * Load a specific plugin by name.
 * @param {string} name
 * @param {string} [rootDir]
 * @returns {PluginManifest|null}
 */
function loadPlugin(name, rootDir) {
  const pluginDir = path.join(getPluginsDir(rootDir), name);
  const manifestPath = path.join(pluginDir, MANIFEST_FILE);

  if (!fs.existsSync(manifestPath)) return null;

  try {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    return { ...manifest, _dir: name };
  } catch {
    return null;
  }
}

module.exports = {
  listPlugins,
  loadPlugin,
  validateManifest,
  getPluginsDir,
  PLUGINS_DIR,
  MANIFEST_FILE,
  VALID_TYPES,
};
