# mitre-mapping

MITRE ATT&CK coverage mapping utility. Scans skills for technique references and builds coverage reports.

## Exports

| Export | Description |
|--------|-------------|
| `scanSkills(skillsDir)` | Scans `skills/` directory, extracts MITRE technique IDs from frontmatter and body |
| `buildCoverageMap(skills)` | Builds structured coverage map by tactic and technique |
| `findGaps(coverageMap)` | Identifies missing top-20 commonly attacked techniques |
| `generateReport(coverageMap, format)` | Output as `'summary'`, `'json'`, or `'markdown'` |
| `parseFrontmatter(content)` | Minimal zero-dep YAML frontmatter parser |
| `TACTICS` | All 14 ATT&CK tactics |
| `TECHNIQUE_TACTIC_MAP` | Technique → tactic mapping |
| `TECHNIQUE_NAMES` | Technique ID → name mapping |

## Reference Data

Uses **MITRE ATT&CK Enterprise Matrix v15** (April 2024).

## API

```js
const { scanSkills, buildCoverageMap, findGaps, generateReport } = require('./lib/mitre-mapping');

const skills = scanSkills('./skills');
const coverage = buildCoverageMap(skills);

// Find gaps in coverage
const gaps = findGaps(coverage);

// Generate a report
console.log(generateReport(coverage, 'summary'));
```

## Dependencies

None — uses only Node.js built-ins.

## Usage

Used by `docs/mitre-coverage.md` generation to produce ATT&CK coverage documentation.
