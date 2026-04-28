"use strict";

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const { validateManifest, getPluginsDir, MANIFEST_FILE } = require("./index");
const registry = require("./registry");

/**
 * Copy a directory recursively.
 */
function copyDirSync(src, dest) {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }

  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDirSync(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

/**
 * Remove a directory recursively.
 */
function rmSync(dirPath) {
  if (typeof fs.rmSync === "function") {
    fs.rmSync(dirPath, { recursive: true, force: true });
  } else {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        rmSync(fullPath);
      } else {
        fs.unlinkSync(fullPath);
      }
    }
    fs.rmdirSync(dirPath);
  }
}

/**
 * Determine the source type: local path, git URL, or npm package.
 * @param {string} source
 * @returns {'local'|'git'|'npm'}
 */
function detectSourceType(source) {
  if (
    source.startsWith("https://") ||
    source.startsWith("git://") ||
    source.startsWith("git@") ||
    source.endsWith(".git")
  ) {
    return "git";
  }

  if (
    fs.existsSync(source) ||
    source.startsWith("./") ||
    source.startsWith("../") ||
    source.startsWith("/") ||
    /^[A-Z]:[/\\]/i.test(source)
  ) {
    return "local";
  }

  return "npm";
}

/**
 * Install a plugin from a local path.
 */
function installFromLocal(source, rootDir) {
  const resolved = path.resolve(source);

  if (!fs.existsSync(resolved)) {
    return { ok: false, error: `Source path not found: ${resolved}` };
  }

  if (!fs.statSync(resolved).isDirectory()) {
    return { ok: false, error: `Source must be a directory: ${resolved}` };
  }

  const manifestPath = path.join(resolved, MANIFEST_FILE);
  if (!fs.existsSync(manifestPath)) {
    return { ok: false, error: `No ${MANIFEST_FILE} found in: ${resolved}` };
  }

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch (err) {
    return { ok: false, error: `Invalid ${MANIFEST_FILE}: ${err.message}` };
  }

  const validation = validateManifest(manifest);
  if (!validation.valid) {
    return {
      ok: false,
      error: `Invalid manifest:\n  ${validation.errors.join("\n  ")}`,
    };
  }

  const destDir = path.join(getPluginsDir(rootDir), manifest.name);
  if (fs.existsSync(destDir)) {
    return {
      ok: false,
      error: `Plugin '${manifest.name}' is already installed. Remove it first.`,
    };
  }

  copyDirSync(resolved, destDir);

  registry.register(rootDir, {
    name: manifest.name,
    version: manifest.version,
    type: manifest.type,
    source: resolved,
    sourceType: "local",
    installedAt: new Date().toISOString(),
  });

  return { ok: true, name: manifest.name };
}

/**
 * Install a plugin from a git URL.
 */
function installFromGit(url, rootDir) {
  const tempDir = path.join(getPluginsDir(rootDir), `_clone_${Date.now()}`);

  try {
    fs.mkdirSync(tempDir, { recursive: true });

    execSync(`git clone --depth 1 "${url}" "${tempDir}"`, {
      encoding: "utf8",
      timeout: 60000,
      stdio: ["pipe", "pipe", "pipe"],
    });

    const manifestPath = path.join(tempDir, MANIFEST_FILE);
    if (!fs.existsSync(manifestPath)) {
      rmSync(tempDir);
      return { ok: false, error: `No ${MANIFEST_FILE} found in git repository` };
    }

    let manifest;
    try {
      manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    } catch (err) {
      rmSync(tempDir);
      return { ok: false, error: `Invalid ${MANIFEST_FILE}: ${err.message}` };
    }

    const validation = validateManifest(manifest);
    if (!validation.valid) {
      rmSync(tempDir);
      return {
        ok: false,
        error: `Invalid manifest:\n  ${validation.errors.join("\n  ")}`,
      };
    }

    const destDir = path.join(getPluginsDir(rootDir), manifest.name);
    if (fs.existsSync(destDir)) {
      rmSync(tempDir);
      return {
        ok: false,
        error: `Plugin '${manifest.name}' is already installed. Remove it first.`,
      };
    }

    fs.renameSync(tempDir, destDir);

    // Remove .git directory from installed plugin
    const gitDir = path.join(destDir, ".git");
    if (fs.existsSync(gitDir)) {
      rmSync(gitDir);
    }

    registry.register(rootDir, {
      name: manifest.name,
      version: manifest.version,
      type: manifest.type,
      source: url,
      sourceType: "git",
      installedAt: new Date().toISOString(),
    });

    return { ok: true, name: manifest.name };
  } catch (err) {
    if (fs.existsSync(tempDir)) {
      rmSync(tempDir);
    }
    return { ok: false, error: `Git clone failed: ${err.message}` };
  }
}

/**
 * Install a plugin from npm.
 */
function installFromNpm(packageName, rootDir) {
  const tempDir = path.join(getPluginsDir(rootDir), `_npm_${Date.now()}`);

  try {
    fs.mkdirSync(tempDir, { recursive: true });

    execSync(`npm pack "${packageName}" --pack-destination "${tempDir}"`, {
      encoding: "utf8",
      timeout: 60000,
      stdio: ["pipe", "pipe", "pipe"],
    });

    const tarballs = fs.readdirSync(tempDir).filter((f) => f.endsWith(".tgz"));
    if (tarballs.length === 0) {
      rmSync(tempDir);
      return { ok: false, error: `Failed to download npm package: ${packageName}` };
    }

    const tarball = path.join(tempDir, tarballs[0]);
    execSync(`tar -xzf "${tarball}" -C "${tempDir}"`, {
      encoding: "utf8",
      timeout: 30000,
      stdio: ["pipe", "pipe", "pipe"],
    });

    const extractedDir = path.join(tempDir, "package");
    if (!fs.existsSync(extractedDir)) {
      rmSync(tempDir);
      return { ok: false, error: "Failed to extract npm package" };
    }

    const manifestPath = path.join(extractedDir, MANIFEST_FILE);
    if (!fs.existsSync(manifestPath)) {
      rmSync(tempDir);
      return { ok: false, error: `No ${MANIFEST_FILE} found in npm package` };
    }

    let manifest;
    try {
      manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    } catch (err) {
      rmSync(tempDir);
      return { ok: false, error: `Invalid ${MANIFEST_FILE}: ${err.message}` };
    }

    const validation = validateManifest(manifest);
    if (!validation.valid) {
      rmSync(tempDir);
      return {
        ok: false,
        error: `Invalid manifest:\n  ${validation.errors.join("\n  ")}`,
      };
    }

    const destDir = path.join(getPluginsDir(rootDir), manifest.name);
    if (fs.existsSync(destDir)) {
      rmSync(tempDir);
      return {
        ok: false,
        error: `Plugin '${manifest.name}' is already installed. Remove it first.`,
      };
    }

    copyDirSync(extractedDir, destDir);
    rmSync(tempDir);

    registry.register(rootDir, {
      name: manifest.name,
      version: manifest.version,
      type: manifest.type,
      source: packageName,
      sourceType: "npm",
      installedAt: new Date().toISOString(),
    });

    return { ok: true, name: manifest.name };
  } catch (err) {
    if (fs.existsSync(tempDir)) {
      rmSync(tempDir);
    }
    return { ok: false, error: `npm install failed: ${err.message}` };
  }
}

/**
 * Install a plugin from any supported source.
 * @param {string} source - Local path, git URL, or npm package name
 * @param {string} [rootDir] - Project root
 * @returns {{ ok: boolean, name?: string, error?: string }}
 */
function install(source, rootDir) {
  rootDir = rootDir || process.cwd();
  const sourceType = detectSourceType(source);

  const pluginsDir = getPluginsDir(rootDir);
  if (!fs.existsSync(pluginsDir)) {
    fs.mkdirSync(pluginsDir, { recursive: true });
  }

  switch (sourceType) {
    case "local":
      return installFromLocal(source, rootDir);
    case "git":
      return installFromGit(source, rootDir);
    case "npm":
      return installFromNpm(source, rootDir);
    default:
      return { ok: false, error: `Unknown source type: ${source}` };
  }
}

/**
 * Uninstall a plugin by name.
 * @param {string} name - Plugin name
 * @param {string} [rootDir] - Project root
 * @returns {{ ok: boolean, error?: string }}
 */
function uninstall(name, rootDir) {
  rootDir = rootDir || process.cwd();
  const pluginDir = path.join(getPluginsDir(rootDir), name);

  if (!fs.existsSync(pluginDir)) {
    return { ok: false, error: `Plugin '${name}' is not installed` };
  }

  rmSync(pluginDir);
  registry.unregister(rootDir, name);

  return { ok: true };
}

module.exports = {
  install,
  uninstall,
  detectSourceType,
};
