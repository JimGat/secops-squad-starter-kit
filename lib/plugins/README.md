# plugins

Plugin system for extending secops-squad with custom skills, personas, and templates.

## Files

| File | Purpose |
|------|---------|
| `index.js` | Core API — `listPlugins()`, `loadPlugin()`, `validateManifest()`, `getPluginsDir()` |
| `registry.js` | Plugin registry — `load()`, `save()`, `register()`, `unregister()`, `list()`, `get()` |
| `installer.js` | Install/uninstall — `install()`, `uninstall()`, `detectSourceType()` |

## Plugin Types

| Type | Description |
|------|-------------|
| `skill` | Adds investigation/response skills |
| `persona` | Adds AI persona definitions |
| `template` | Adds project templates |

## Source Types

- **Local path** — directory on disk
- **Git URL** — cloned at install time
- **npm package** — installed from npm registry

## Install Location

Plugins are installed to `.squad/plugins/<name>/`.

## Plugin Manifest (`plugin.json`)

```json
{
  "name": "my-plugin",
  "version": "1.0.0",
  "type": "skill",
  "description": "What this plugin adds",
  "files": ["file1.md", "file2.md"]
}
```

## CLI Usage

```bash
# Install a plugin
secops-squad plugin install <source>

# List installed plugins
secops-squad plugin list

# Remove a plugin
secops-squad plugin remove <name>
```

## API

```js
const { listPlugins, loadPlugin, validateManifest } = require('./lib/plugins');
const { install, uninstall } = require('./lib/plugins/installer');
const registry = require('./lib/plugins/registry');

// List all installed plugins
const plugins = listPlugins();

// Install from a local path
await install('./path/to/plugin');

// Validate a plugin manifest
const errors = validateManifest(manifest);
```
