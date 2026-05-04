# lib/ — Shared Libraries

Shared Node.js libraries that power the CLI and provide programmatic APIs.

## Modules

| Module | Directory | Description |
|--------|-----------|-------------|
| **graph-security** | [lib/graph-security/](graph-security/) | Microsoft Graph Security API client — alerts, incidents, TI, secure score |
| **kql-validator** | [lib/kql-validator/](kql-validator/) | Offline KQL syntax validation — parser, operators, reporter |
| **mitre-mapping** | [lib/mitre-mapping/](mitre-mapping/) | MITRE ATT&CK coverage analysis — scans skills, builds coverage map |
| **plugins** | [lib/plugins/](plugins/) | Plugin system — install, validate, registry for skills/personas/templates |
| **azure-auth** | [lib/azure-auth/](azure-auth/) | Azure authentication helpers *(placeholder — `.gitkeep` only)* |

## Requirements

- **Node.js 18+** (graph-security uses native `fetch`)

## Testing

```bash
node --test lib/**/*.test.js
# or
npm test
```

## Architecture

All modules use **zero external dependencies** — only Node.js built-ins. The sole exception is `js-yaml`, which is a dependency of the root package (not of the libraries themselves).

Each module is a self-contained directory with its own `index.js` entry point and can be required directly:

```js
const { validateQuery } = require('./lib/kql-validator');
const { scanSkills } = require('./lib/mitre-mapping');
const { listPlugins } = require('./lib/plugins');
```

See each module's README for detailed API documentation:

- [graph-security/README.md](graph-security/README.md)
- [kql-validator/README.md](kql-validator/README.md)
- [mitre-mapping/README.md](mitre-mapping/README.md)
- [plugins/README.md](plugins/README.md)

> **Note:** `azure-auth/` is a placeholder for future Azure authentication work.
