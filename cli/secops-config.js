"use strict";

const fs = require("fs");
const path = require("path");
const yaml = require("js-yaml");

const SECOPS_DIR = ".secops";
const SUPPORTED_SCHEMA_VERSIONS = ["1.0"];

/**
 * Resolve the .secops/ directory from a root directory.
 * Returns the absolute path or null if it doesn't exist.
 */
function secopsDir(rootDir) {
  const dir = path.join(rootDir || process.cwd(), SECOPS_DIR);
  return fs.existsSync(dir) ? dir : null;
}

/**
 * Safely read and parse a YAML file. Returns null on any failure.
 */
function readYaml(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const content = fs.readFileSync(filePath, "utf8");
    return yaml.load(content) || null;
  } catch {
    return null;
  }
}

/**
 * Validate that a parsed YAML object has a supported schema_version.
 * Returns { ok: true } or { ok: false, error: string }.
 */
function checkSchemaVersion(data, filePath) {
  if (!data || typeof data !== "object") {
    return { ok: false, error: `${filePath}: empty or invalid YAML` };
  }
  if (!data.schema_version) {
    return { ok: false, error: `${filePath}: missing schema_version` };
  }
  if (!SUPPORTED_SCHEMA_VERSIONS.includes(data.schema_version)) {
    return {
      ok: false,
      error: `${filePath}: unsupported schema_version "${data.schema_version}" (supported: ${SUPPORTED_SCHEMA_VERSIONS.join(", ")})`,
    };
  }
  return { ok: true };
}

/**
 * Load and parse .secops/environment.yaml.
 * Returns the parsed object or null if missing/invalid.
 */
function loadEnvironment(rootDir) {
  const dir = secopsDir(rootDir);
  if (!dir) return null;
  return readYaml(path.join(dir, "environment.yaml"));
}

/**
 * Load a specific workspace config from .secops/workspaces/<name>.yaml.
 * Returns the parsed object or null if missing.
 */
function loadWorkspace(name, rootDir) {
  const dir = secopsDir(rootDir);
  if (!dir) return null;
  return readYaml(path.join(dir, "workspaces", `${name}.yaml`));
}

/**
 * List all workspace files in .secops/workspaces/.
 * Returns an array of { name, data } objects.
 */
function listWorkspaces(rootDir) {
  const dir = secopsDir(rootDir);
  if (!dir) return [];

  const wsDir = path.join(dir, "workspaces");
  if (!fs.existsSync(wsDir)) return [];

  return fs
    .readdirSync(wsDir)
    .filter((f) => f.endsWith(".yaml") && f !== "README.md")
    .map((f) => {
      const name = f.replace(/\.yaml$/, "");
      const data = readYaml(path.join(wsDir, f));
      return { name, data };
    })
    .filter((w) => w.data !== null);
}

/**
 * Load .secops/data-sources/data-source-map.yaml.
 * Returns the parsed object or null.
 */
function loadDataSourceMap(rootDir) {
  const dir = secopsDir(rootDir);
  if (!dir) return null;
  return readYaml(path.join(dir, "data-sources", "data-source-map.yaml"));
}

/**
 * Load .secops/data-sources/migrations.yaml.
 * Returns the parsed object or null.
 */
function loadMigrations(rootDir) {
  const dir = secopsDir(rootDir);
  if (!dir) return null;
  return readYaml(path.join(dir, "data-sources", "migrations.yaml"));
}

/**
 * Load .secops/discovery-log.yaml.
 * Returns the parsed object or null.
 */
function loadDiscoveryLog(rootDir) {
  const dir = secopsDir(rootDir);
  if (!dir) return null;
  return readYaml(path.join(dir, "discovery-log.yaml"));
}

/**
 * Validate all .secops/ YAML files for existence and schema_version.
 * Returns { valid: boolean, results: Array<{ file, ok, error? }> }.
 */
function validateAll(rootDir) {
  const dir = secopsDir(rootDir);
  if (!dir) {
    return {
      valid: false,
      results: [{ file: SECOPS_DIR, ok: false, error: ".secops/ directory not found" }],
    };
  }

  const files = [
    { rel: "environment.yaml", required: true },
    { rel: path.join("data-sources", "data-source-map.yaml"), required: true },
    { rel: path.join("data-sources", "migrations.yaml"), required: false },
    { rel: "discovery-log.yaml", required: false },
  ];

  // Add workspace files dynamically
  const wsDir = path.join(dir, "workspaces");
  if (fs.existsSync(wsDir)) {
    fs.readdirSync(wsDir)
      .filter((f) => f.endsWith(".yaml"))
      .forEach((f) => files.push({ rel: path.join("workspaces", f), required: false }));
  }

  const results = [];
  for (const entry of files) {
    const filePath = path.join(dir, entry.rel);
    const displayPath = path.join(SECOPS_DIR, entry.rel);

    if (!fs.existsSync(filePath)) {
      if (entry.required) {
        results.push({ file: displayPath, ok: false, error: "file not found (required)" });
      }
      // Skip optional missing files — not an error
      continue;
    }

    const data = readYaml(filePath);
    const check = checkSchemaVersion(data, displayPath);
    results.push({ file: displayPath, ...check });
  }

  return {
    valid: results.every((r) => r.ok),
    results,
  };
}

module.exports = {
  SECOPS_DIR,
  SUPPORTED_SCHEMA_VERSIONS,
  secopsDir,
  readYaml,
  checkSchemaVersion,
  loadEnvironment,
  loadWorkspace,
  listWorkspaces,
  loadDataSourceMap,
  loadMigrations,
  loadDiscoveryLog,
  validateAll,
};
