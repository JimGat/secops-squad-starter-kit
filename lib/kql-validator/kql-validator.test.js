/**
 * KQL Validator — Comprehensive Test Suite
 *
 * Written from the spec by Carver (Tester/QA).
 * Tests are spec-driven — they define the contract, not the implementation.
 *
 * Run: node --test lib/kql-validator/kql-validator.test.js
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdirSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

// Import the module under test — will fail cleanly if not yet built
let validateQuery, validateFile, validateDirectory, extractQueries;
try {
  const mod = await import('./index.js');
  validateQuery = mod.validateQuery;
  validateFile = mod.validateFile;
  validateDirectory = mod.validateDirectory;
  extractQueries = mod.extractQueries;
} catch (err) {
  // Provide stub functions so tests run (and fail) rather than crash on import
  const notImplemented = () => { throw new Error('kql-validator module not yet available'); };
  validateQuery = notImplemented;
  validateFile = notImplemented;
  validateDirectory = notImplemented;
  extractQueries = notImplemented;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FIXTURES_DIR = resolve(import.meta.dirname, 'fixtures');
const TEMP_DIR = resolve(import.meta.dirname, '__test_tmp__');

function ensureTempDir() {
  if (!existsSync(TEMP_DIR)) {
    mkdirSync(TEMP_DIR, { recursive: true });
  }
}

function cleanTempDir() {
  if (existsSync(TEMP_DIR)) {
    rmSync(TEMP_DIR, { recursive: true, force: true });
  }
}

function writeTempFile(name, content) {
  ensureTempDir();
  const p = join(TEMP_DIR, name);
  writeFileSync(p, content, 'utf-8');
  return p;
}

// ---------------------------------------------------------------------------
// 1. Valid KQL Queries
// ---------------------------------------------------------------------------

describe('validateQuery — valid KQL', () => {
  it('simple where clause', () => {
    const result = validateQuery('SecurityEvent | where TimeGenerated > ago(1h)');
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('let binding with pipe chain', () => {
    const kql = 'let lookback = 24h; SignInLogs | where TimeGenerated > ago(lookback) | summarize count() by UserPrincipalName';
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('project operator with multiple columns', () => {
    const kql = 'DeviceProcessEvents | where ActionType == "ProcessCreated" | project Timestamp, DeviceName, FileName';
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('join with kind parameter', () => {
    const kql = 'SecurityAlert | where Severity == "High" | join kind=inner (SecurityIncident) on SystemAlertId';
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('comment-only query', () => {
    const result = validateQuery('// This is a comment');
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('multiple let statements with threshold logic', () => {
    const kql = 'let threshold = 10; SecurityEvent | where EventID == 4625 | summarize FailedAttempts = count() by TargetAccount | where FailedAttempts > threshold';
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('query with extend and iff()', () => {
    const kql = 'SignInLogs | where ResultType != "0" | extend RiskLevel = iff(RiskLevelDuringSignIn == "high", "Critical", "Normal")';
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('query with mv-expand', () => {
    const kql = 'SecurityAlert | mv-expand todynamic(Entities) | project AlertName, Entities';
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('union of two tables', () => {
    const kql = 'union SecurityEvent, SecurityAlert | where TimeGenerated > ago(1d) | summarize count() by Type';
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('query with dynamic literal', () => {
    const kql = 'let ids = dynamic([4625, 4648, 4672]); SecurityEvent | where EventID in (ids)';
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });
});

// ---------------------------------------------------------------------------
// 2. Invalid KQL Queries
// ---------------------------------------------------------------------------

describe('validateQuery — invalid KQL', () => {
  it('starts with pipe — no table name', () => {
    const result = validateQuery('| where TimeGenerated > ago(1h)');
    assert.equal(result.valid, false);
    assert.ok(result.errors.length > 0, 'should report at least one error');
  });

  it('double pipe', () => {
    const result = validateQuery('SecurityEvent | | where foo');
    assert.equal(result.valid, false);
    assert.ok(result.errors.length > 0);
  });

  it('unbalanced parentheses — unclosed', () => {
    const result = validateQuery('SecurityEvent | where (unclosed');
    assert.equal(result.valid, false);
    assert.ok(result.errors.length > 0);
  });

  it('single = instead of ==', () => {
    const result = validateQuery('SecurityEvent | where x = 5');
    assert.equal(result.valid, false);
    assert.ok(result.errors.length > 0);
  });

  it('let without semicolon before pipe', () => {
    const kql = 'let x = 5\nSecurityEvent | where EventID == x';
    const result = validateQuery(kql);
    assert.equal(result.valid, false);
    assert.ok(result.errors.length > 0);
  });

  it('unclosed string literal', () => {
    const result = validateQuery('"unclosed string');
    assert.equal(result.valid, false);
    assert.ok(result.errors.length > 0);
  });

  it('unbalanced parentheses — extra closing', () => {
    const result = validateQuery('SecurityEvent | where Status == "OK")');
    assert.equal(result.valid, false);
    assert.ok(result.errors.length > 0);
  });

  it('empty operator after pipe', () => {
    const result = validateQuery('SecurityEvent |');
    assert.equal(result.valid, false);
    assert.ok(result.errors.length > 0);
  });
});

// ---------------------------------------------------------------------------
// 3. Edge Cases
// ---------------------------------------------------------------------------

describe('validateQuery — edge cases', () => {
  it('empty string is valid (no errors, no warnings)', () => {
    const result = validateQuery('');
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
    assert.equal(result.warnings.length, 0);
  });

  it('whitespace-only string is valid', () => {
    const result = validateQuery('   \n\t  \n  ');
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('multi-line query with line continuations', () => {
    const kql = [
      'SecurityEvent',
      '| where TimeGenerated > ago(1h)',
      '| where EventID == 4625',
      '| summarize count() by TargetAccount',
    ].join('\n');
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('nested function calls', () => {
    const kql = 'DeviceNetworkEvents | where array_length(split(RemoteUrl, "/")) > 5';
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('string literal containing KQL operators (should not confuse parser)', () => {
    const kql = 'SecurityEvent | where Message contains "| where"';
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('very long query (1000+ characters)', () => {
    const columns = Array.from({ length: 100 }, (_, i) => `Column${i}`).join(', ');
    const kql = `SecurityEvent | where TimeGenerated > ago(1h) | project ${columns} | summarize count() by ${columns}`;
    assert.ok(kql.length > 1000, 'test query should exceed 1000 chars');
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('unicode characters in string literals', () => {
    const kql = 'SecurityEvent | where AccountName == "ü日本語テスト"';
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('multiple let statements before main query', () => {
    const kql = [
      'let t1 = 1h;',
      'let t2 = 24h;',
      'let threshold = 10;',
      'SecurityEvent',
      '| where TimeGenerated > ago(t1)',
      '| summarize c = count() by TargetAccount',
      '| where c > threshold',
    ].join('\n');
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('query with single-line comment mid-query', () => {
    const kql = [
      'SecurityEvent',
      '// filter to last hour',
      '| where TimeGenerated > ago(1h)',
    ].join('\n');
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('query using has_any with dynamic array', () => {
    const kql = 'DeviceProcessEvents | where ProcessCommandLine has_any (dynamic(["-enc", "-encoded"]))';
    const result = validateQuery(kql);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });
});

// ---------------------------------------------------------------------------
// 4. Markdown Extraction (extractQueries)
// ---------------------------------------------------------------------------

describe('extractQueries — markdown extraction', () => {
  it('markdown with 1 KQL block extracts 1 query', () => {
    const md = [
      '# Title',
      '',
      '```kql',
      'SecurityEvent | where TimeGenerated > ago(1h)',
      '```',
    ].join('\n');
    const queries = extractQueries(md);
    assert.equal(queries.length, 1);
    assert.ok(queries[0].includes('SecurityEvent'));
  });

  it('markdown with 3 KQL blocks extracts 3 queries', () => {
    const md = [
      '## A',
      '```kql',
      'SignInLogs | take 10',
      '```',
      '## B',
      '```kql',
      'SecurityEvent | take 10',
      '```',
      '## C',
      '```kql',
      'SecurityAlert | take 10',
      '```',
    ].join('\n');
    const queries = extractQueries(md);
    assert.equal(queries.length, 3);
  });

  it('markdown with no KQL blocks extracts 0', () => {
    const md = '# No queries here\n\nJust plain text.\n';
    const queries = extractQueries(md);
    assert.equal(queries.length, 0);
  });

  it('```kusto blocks are also extracted (alias)', () => {
    const md = [
      '```kusto',
      'SecurityEvent | count',
      '```',
    ].join('\n');
    const queries = extractQueries(md);
    assert.equal(queries.length, 1);
    assert.ok(queries[0].includes('SecurityEvent'));
  });

  it('empty KQL block handled gracefully', () => {
    const md = '```kql\n\n```\n';
    const queries = extractQueries(md);
    // Should either return 0 queries (skip empty) or 1 empty string — either is acceptable
    assert.ok(Array.isArray(queries));
    if (queries.length > 0) {
      assert.equal(queries[0].trim(), '');
    }
  });

  it('mixed code blocks — only KQL extracted', () => {
    const md = [
      '```js',
      'console.log("hello");',
      '```',
      '```kql',
      'SecurityEvent | take 1',
      '```',
      '```python',
      'print("hi")',
      '```',
    ].join('\n');
    const queries = extractQueries(md);
    assert.equal(queries.length, 1);
    assert.ok(queries[0].includes('SecurityEvent'));
  });

  it('extracts from real fixture file (sample-skill.md)', () => {
    const md = readFileSync(join(FIXTURES_DIR, 'sample-skill.md'), 'utf-8');
    const queries = extractQueries(md);
    // sample-skill.md has 2 ```kql blocks and 1 ```kusto block = 3 total
    assert.equal(queries.length, 3, 'should extract all KQL and kusto blocks');
    // Verify none of the JS code leaked in
    for (const q of queries) {
      assert.ok(!q.includes('console.log'), 'should not extract JS code');
    }
  });
});

// ---------------------------------------------------------------------------
// 5. File Validation (validateFile)
// ---------------------------------------------------------------------------

describe('validateFile — file-level validation', () => {
  after(() => cleanTempDir());

  it('valid .kql fixture file passes', () => {
    const result = validateFile(join(FIXTURES_DIR, 'valid-hunting-query.kql'));
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('valid detection rule fixture passes', () => {
    const result = validateFile(join(FIXTURES_DIR, 'valid-detection-rule.kql'));
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('invalid syntax fixture fails', () => {
    const result = validateFile(join(FIXTURES_DIR, 'invalid-syntax.kql'));
    assert.equal(result.valid, false);
    assert.ok(result.errors.length > 0, 'should report errors for invalid syntax');
  });

  it('non-existent file returns appropriate error', () => {
    const result = validateFile(join(FIXTURES_DIR, 'does-not-exist.kql'));
    assert.equal(result.valid, false);
    assert.ok(result.errors.length > 0);
    // Error message should mention file not found or similar
    const errorText = result.errors.map(e => typeof e === 'string' ? e : e.message || JSON.stringify(e)).join(' ');
    assert.ok(
      /not found|no such file|does not exist|ENOENT/i.test(errorText),
      `error should indicate missing file, got: ${errorText}`
    );
  });

  it('empty file is valid', () => {
    const p = writeTempFile('empty.kql', '');
    const result = validateFile(p);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('temp file with valid KQL passes', () => {
    const p = writeTempFile('good.kql', 'SecurityEvent | where EventID == 4625 | take 10');
    const result = validateFile(p);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('temp file with invalid KQL fails', () => {
    const p = writeTempFile('bad.kql', '| where nope');
    const result = validateFile(p);
    assert.equal(result.valid, false);
    assert.ok(result.errors.length > 0);
  });
});

// ---------------------------------------------------------------------------
// 6. Directory Validation (validateDirectory)
// ---------------------------------------------------------------------------

describe('validateDirectory — directory-level validation', () => {
  const DIR = join(TEMP_DIR, 'dir-test');

  before(() => {
    mkdirSync(DIR, { recursive: true });
    writeFileSync(join(DIR, 'good1.kql'), 'SecurityEvent | where EventID == 4625', 'utf-8');
    writeFileSync(join(DIR, 'good2.kql'), 'SignInLogs | where ResultType != "0" | take 100', 'utf-8');
    writeFileSync(join(DIR, 'bad1.kql'), '| where TimeGenerated > ago(1h)', 'utf-8');
    writeFileSync(join(DIR, 'bad2.kql'), 'SecurityEvent | | where foo', 'utf-8');
  });

  after(() => cleanTempDir());

  it('returns a results Map and summary object', () => {
    const out = validateDirectory(DIR);
    assert.ok(out.results instanceof Map || typeof out.results === 'object', 'results should be Map or object');
    assert.ok(out.summary, 'should have summary');
    assert.ok(typeof out.summary.total === 'number');
    assert.ok(typeof out.summary.valid === 'number');
    assert.ok(typeof out.summary.invalid === 'number');
  });

  it('summary counts match expected (2 valid, 2 invalid)', () => {
    const out = validateDirectory(DIR);
    assert.equal(out.summary.total, 4);
    assert.equal(out.summary.valid, 2);
    assert.equal(out.summary.invalid, 2);
  });

  it('individual file results accessible', () => {
    const out = validateDirectory(DIR);
    const getResult = (name) => {
      if (out.results instanceof Map) return out.results.get(join(DIR, name));
      return out.results[join(DIR, name)];
    };
    const good = getResult('good1.kql');
    assert.ok(good, 'should have result for good1.kql');
    assert.equal(good.valid, true);

    const bad = getResult('bad1.kql');
    assert.ok(bad, 'should have result for bad1.kql');
    assert.equal(bad.valid, false);
  });

  it('empty directory returns summary with 0 total', () => {
    const emptyDir = join(TEMP_DIR, 'empty-dir');
    mkdirSync(emptyDir, { recursive: true });
    const out = validateDirectory(emptyDir);
    assert.equal(out.summary.total, 0);
    assert.equal(out.summary.valid, 0);
    assert.equal(out.summary.invalid, 0);
  });

  it('non-existent directory handled gracefully', () => {
    // Should either throw or return an error result — either is acceptable
    try {
      const out = validateDirectory(join(TEMP_DIR, 'no-such-dir'));
      // If it doesn't throw, it should indicate failure somehow
      assert.ok(out.summary.total === 0 || out.errors, 'should handle missing dir gracefully');
    } catch (err) {
      // Throwing is acceptable — just verify it's a sensible error
      assert.ok(/not found|no such|does not exist|ENOENT/i.test(err.message));
    }
  });
});

// ---------------------------------------------------------------------------
// 7. Warning Detection
// ---------------------------------------------------------------------------

describe('validateQuery — warning detection', () => {
  it('project * emits a performance warning', () => {
    const result = validateQuery('SecurityEvent | project *');
    // Should be valid but with a warning about wildcard projection
    assert.equal(result.valid, true);
    assert.ok(result.warnings.length > 0, 'should warn about project *');
  });

  it('large table query without time filter emits a warning', () => {
    // SecurityEvent is a known large table — querying without time filter is risky
    const result = validateQuery('SecurityEvent | summarize count() by EventID');
    assert.equal(result.valid, true);
    assert.ok(result.warnings.length > 0, 'should warn about missing time filter on large table');
  });

  it('query with time filter does NOT warn about missing time filter', () => {
    const result = validateQuery('SecurityEvent | where TimeGenerated > ago(1h) | summarize count() by EventID');
    assert.equal(result.valid, true);
    const timeWarnings = result.warnings.filter(
      w => typeof w === 'string' ? /time/i.test(w) : /time/i.test(w.message || '')
    );
    assert.equal(timeWarnings.length, 0, 'should not warn about time when filter present');
  });

  it('valid query with no issues has empty warnings array', () => {
    const result = validateQuery('SecurityEvent | where TimeGenerated > ago(1h) | project TimeGenerated, EventID');
    assert.equal(result.valid, true);
    assert.equal(result.warnings.length, 0);
  });
});

// ---------------------------------------------------------------------------
// 8. Return Shape Contract
// ---------------------------------------------------------------------------

describe('validateQuery — return shape contract', () => {
  it('returns object with valid, errors, warnings', () => {
    const result = validateQuery('SecurityEvent | take 10');
    assert.ok(typeof result === 'object' && result !== null);
    assert.ok('valid' in result, 'result must have .valid');
    assert.ok('errors' in result, 'result must have .errors');
    assert.ok('warnings' in result, 'result must have .warnings');
    assert.ok(typeof result.valid === 'boolean');
    assert.ok(Array.isArray(result.errors));
    assert.ok(Array.isArray(result.warnings));
  });

  it('errors array items are descriptive (not empty strings)', () => {
    const result = validateQuery('| where oops');
    for (const err of result.errors) {
      const text = typeof err === 'string' ? err : err.message || JSON.stringify(err);
      assert.ok(text.length > 0, 'error entries must be non-empty');
    }
  });
});

// ---------------------------------------------------------------------------
// 9. Fixture Integration (sanity checks on fixture files)
// ---------------------------------------------------------------------------

describe('fixture file sanity', () => {
  it('valid-hunting-query.kql exists and is non-empty', () => {
    const content = readFileSync(join(FIXTURES_DIR, 'valid-hunting-query.kql'), 'utf-8');
    assert.ok(content.length > 100, 'fixture should be a realistic query');
    assert.ok(content.includes('DeviceProcessEvents'), 'should reference expected table');
  });

  it('valid-detection-rule.kql exists and is non-empty', () => {
    const content = readFileSync(join(FIXTURES_DIR, 'valid-detection-rule.kql'), 'utf-8');
    assert.ok(content.length > 100);
    assert.ok(content.includes('SignInLogs'));
  });

  it('invalid-syntax.kql contains known bad patterns', () => {
    const content = readFileSync(join(FIXTURES_DIR, 'invalid-syntax.kql'), 'utf-8');
    assert.ok(content.includes('| |'), 'should have double pipe');
    assert.ok(content.includes('"unclosed string'), 'should have unclosed string');
  });

  it('sample-skill.md has kql and kusto blocks', () => {
    const content = readFileSync(join(FIXTURES_DIR, 'sample-skill.md'), 'utf-8');
    assert.ok(content.includes('```kql'), 'should have kql code blocks');
    assert.ok(content.includes('```kusto'), 'should have kusto code blocks');
    assert.ok(content.includes('```js'), 'should have js code blocks for negative testing');
  });
});
