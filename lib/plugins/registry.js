"use strict";

const fs = require("fs");
const path = require("path");
const { getPluginsDir } = require("./index");

const REGISTRY_FILE = "registry.json";

/**
 * Get the path to the registry file.
 * @param {string} [rootDir]
 * @returns {string}
 */
function getRegistryPath(rootDir) {
  return path.join(getPluginsDir(rootDir), REGISTRY_FILE);
}

/**
 * Load the registry from disk.
 * @param {string} [rootDir]
 * @returns {Object.<string, object>}
 */
function load(rootDir) {
  const registryPath = getRegistryPath(rootDir);

  if (!fs.existsSync(registryPath)) {
    return {};
  }

  try {
    return JSON.parse(fs.readFileSync(registryPath, "utf8"));
  } catch {
    return {};
  }
}

/**
 * Save the registry to disk.
 * @param {string} rootDir
 * @param {Object} data
 */
function save(rootDir, data) {
  const registryPath = getRegistryPath(rootDir);
  const dir = path.dirname(registryPath);

  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(registryPath, JSON.stringify(data, null, 2) + "\n", "utf8");
}

/**
 * Register a plugin in the registry.
 * @param {string} rootDir
 * @param {object} entry - { name, version, type, source, sourceType, installedAt }
 */
function register(rootDir, entry) {
  const data = load(rootDir);
  data[entry.name] = {
    version: entry.version,
    type: entry.type,
    source: entry.source,
    sourceType: entry.sourceType,
    installedAt: entry.installedAt,
  };
  save(rootDir, data);
}

/**
 * Unregister a plugin from the registry.
 * @param {string} rootDir
 * @param {string} name
 */
function unregister(rootDir, name) {
  const data = load(rootDir);
  delete data[name];
  save(rootDir, data);
}

/**
 * List all registered plugins.
 * @param {string} [rootDir]
 * @returns {Array<{ name: string, version: string, type: string, source: string, sourceType: string, installedAt: string }>}
 */
function list(rootDir) {
  const data = load(rootDir);
  return Object.entries(data).map(([name, info]) => ({
    name,
    ...info,
  }));
}

/**
 * Get a registered plugin by name.
 * @param {string} rootDir
 * @param {string} name
 * @returns {object|null}
 */
function get(rootDir, name) {
  const data = load(rootDir);
  if (!(name in data)) return null;
  return { name, ...data[name] };
}

/**
 * Remove a plugin from the registry (alias for unregister).
 */
function remove(rootDir, name) {
  return unregister(rootDir, name);
}

module.exports = {
  load,
  save,
  register,
  unregister,
  list,
  get,
  remove,
};
