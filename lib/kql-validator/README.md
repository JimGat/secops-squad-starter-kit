# kql-validator

Offline KQL (Kusto Query Language) syntax validator. No Azure connectivity required.

## Files

| File | Purpose |
|------|---------|
| `index.js` | Main API — `validateQuery()`, `validateFile()`, `validateDirectory()`, `extractQueries()` |
| `parser.js` | KQL parser (tokenizer + structural validator) |
| `operators.js` | Known KQL operators, functions, and table names |
| `reporter.js` | `formatResults()` and `buildSummary()` for output formatting |
| `kql-validator.test.js` | Tests |
| `fixtures/` | Test KQL files |

## Features

- Validates raw KQL strings, individual files, or entire directories
- Extracts and validates KQL from markdown code blocks (`` ```kql `` or `` ```kusto ``)
- Output formats: **console**, **CI**, and **JSON**
- 5 MB max file size limit
- Fully offline — no Azure connectivity required

## API

```js
const { validateQuery, validateFile, validateDirectory, extractQueries } = require('./lib/kql-validator');

// Validate a raw KQL string
const result = validateQuery('SecurityEvent | where TimeGenerated > ago(1d)');
// { valid: true, errors: [], warnings: [] }

// Validate a file
const fileResult = validateFile('./queries/hunting.kql');

// Validate all KQL files in a directory
const dirResults = validateDirectory('./queries');

// Extract KQL blocks from markdown
const queries = extractQueries(markdownContent);
```

## CLI Usage

```bash
secops-squad kql validate <file|glob>
```

## CI Integration

Used by `.github/workflows/kql-validate.yml` to validate KQL on every PR.

## Testing

```bash
node --test lib/kql-validator/kql-validator.test.js
```
