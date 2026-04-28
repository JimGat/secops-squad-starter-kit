// KQL syntax parser — offline structural validation.
// Does NOT connect to any Azure workspace.

'use strict';

const { OPERATORS, FUNCTIONS, TABLE_NAMES } = require('./operators');

/**
 * @typedef {Object} ValidationError
 * @property {'error'} severity
 * @property {string} message
 * @property {number} [line] - 1-based line number
 * @property {number} [column] - 1-based column
 * @property {string} rule - Machine-readable rule ID
 */

/**
 * @typedef {Object} ValidationWarning
 * @property {'warning'} severity
 * @property {string} message
 * @property {number} [line]
 * @property {number} [column]
 * @property {string} rule
 */

/**
 * @typedef {Object} ParseResult
 * @property {boolean} valid
 * @property {ValidationError[]} errors
 * @property {ValidationWarning[]} warnings
 */

/**
 * Strip KQL comments from source.
 * Handles // line comments and /* block comments.
 * Preserves line structure so line numbers stay valid.
 * @param {string} source
 * @returns {string}
 */
function stripComments(source) {
  let result = '';
  let i = 0;
  let inString = false;
  let stringChar = '';

  while (i < source.length) {
    if (!inString && (source[i] === '"' || source[i] === "'")) {
      inString = true;
      stringChar = source[i];
      result += source[i];
      i++;
      continue;
    }

    if (inString) {
      if (source[i] === '\\' && i + 1 < source.length) {
        result += source[i] + source[i + 1];
        i += 2;
        continue;
      }
      if (source[i] === stringChar) {
        inString = false;
      }
      result += source[i];
      i++;
      continue;
    }

    // Line comment
    if (source[i] === '/' && i + 1 < source.length && source[i + 1] === '/') {
      while (i < source.length && source[i] !== '\n') {
        result += ' ';
        i++;
      }
      continue;
    }

    // Block comment
    if (source[i] === '/' && i + 1 < source.length && source[i + 1] === '*') {
      i += 2;
      while (i < source.length) {
        if (source[i] === '*' && i + 1 < source.length && source[i + 1] === '/') {
          i += 2;
          break;
        }
        result += source[i] === '\n' ? '\n' : ' ';
        i++;
      }
      continue;
    }

    result += source[i];
    i++;
  }

  return result;
}

/**
 * Check for balanced delimiters: (), [], {}, "", ''
 * @param {string} source - Comment-stripped source
 * @returns {ValidationError[]}
 */
function checkDelimiters(source) {
  const errors = [];
  const stack = [];
  const pairs = { '(': ')', '[': ']', '{': '}' };
  const closers = { ')': '(', ']': '[', '}': '{' };
  let inString = false;
  let stringChar = '';
  let line = 1;
  let col = 1;

  for (let i = 0; i < source.length; i++) {
    const ch = source[i];

    if (ch === '\n') { line++; col = 1; continue; }

    if (!inString && (ch === '"' || ch === "'")) {
      inString = true;
      stringChar = ch;
      stack.push({ char: ch, line, col, type: 'string' });
      col++;
      continue;
    }

    if (inString) {
      if (ch === '\\' && i + 1 < source.length) { i++; col += 2; continue; }
      if (ch === stringChar) { inString = false; stack.pop(); }
      col++;
      continue;
    }

    if (pairs[ch]) {
      stack.push({ char: ch, line, col, type: 'delimiter' });
    }

    if (closers[ch]) {
      const last = stack.length > 0 ? stack[stack.length - 1] : null;
      if (!last || last.type !== 'delimiter' || last.char !== closers[ch]) {
        errors.push({
          severity: 'error',
          message: `Unmatched closing '${ch}'`,
          line, column: col,
          rule: 'unmatched-delimiter',
        });
      } else {
        stack.pop();
      }
    }

    col++;
  }

  for (const item of stack) {
    if (item.type === 'string') {
      errors.push({
        severity: 'error',
        message: `Unterminated string literal starting with ${item.char}`,
        line: item.line, column: item.col,
        rule: 'unterminated-string',
      });
    } else {
      errors.push({
        severity: 'error',
        message: `Unclosed '${item.char}' — expected matching '${pairs[item.char]}'`,
        line: item.line, column: item.col,
        rule: 'unmatched-delimiter',
      });
    }
  }

  return errors;
}

/**
 * Validate let statement syntax.
 * @param {string} source - Comment-stripped source
 * @returns {{ errors: ValidationError[], warnings: ValidationWarning[] }}
 */
function checkLetStatements(source) {
  const errors = [];
  const warnings = [];
  const lines = source.split('\n');

  let inLet = false;
  let letStartLine = 0;
  let parenDepth = 0;
  let braceDepth = 0;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed) continue;

    if (!inLet) {
      const letMatch = trimmed.match(/^let\s+(\w+)\s*=/i);
      if (letMatch) {
        // Check if the line contains a semicolon (let statement completed on same line)
        const semiIndex = findLetSemicolon(trimmed);
        if (semiIndex >= 0) {
          // Let statement properly terminated on this line
          continue;
        }

        // No semicolon on this line — start tracking multi-line let
        inLet = true;
        letStartLine = i;
        parenDepth = 0;
        braceDepth = 0;

        let inStr = false;
        let strCh = '';
        for (const ch of trimmed) {
          if (!inStr && (ch === '"' || ch === "'")) { inStr = true; strCh = ch; continue; }
          if (inStr) { if (ch === strCh) inStr = false; continue; }
          if (ch === '(') parenDepth++;
          if (ch === ')') parenDepth--;
          if (ch === '{') braceDepth++;
          if (ch === '}') braceDepth--;
        }

        if (parenDepth <= 0 && braceDepth <= 0) {
          // Single-line let without semicolon
          errors.push({
            severity: 'error',
            message: 'let statement must end with a semicolon',
            line: i + 1,
            rule: 'let-missing-semicolon',
          });
          inLet = false;
        }
      }
    } else {
      let inStr = false;
      let strCh = '';
      for (const ch of trimmed) {
        if (!inStr && (ch === '"' || ch === "'")) { inStr = true; strCh = ch; continue; }
        if (inStr) { if (ch === strCh) inStr = false; continue; }
        if (ch === '(') parenDepth++;
        if (ch === ')') parenDepth--;
        if (ch === '{') braceDepth++;
        if (ch === '}') braceDepth--;
      }

      if (parenDepth <= 0 && braceDepth <= 0) {
        const semiIndex = findLetSemicolon(trimmed);
        if (semiIndex < 0 && !trimmed.endsWith(';')) {
          errors.push({
            severity: 'error',
            message: `let statement (started on line ${letStartLine + 1}) must end with a semicolon`,
            line: i + 1,
            rule: 'let-missing-semicolon',
          });
        }
        inLet = false;
      }
    }
  }

  return { errors, warnings };
}

/**
 * Find the semicolon that terminates a let statement, respecting strings and nested delimiters.
 * Returns the index of the semicolon, or -1 if not found.
 * @param {string} line
 * @returns {number}
 */
function findLetSemicolon(line) {
  let inStr = false;
  let strCh = '';
  let parenDepth = 0;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (!inStr && (ch === '"' || ch === "'")) { inStr = true; strCh = ch; continue; }
    if (inStr) {
      if (ch === '\\' && i + 1 < line.length) { i++; continue; }
      if (ch === strCh) inStr = false;
      continue;
    }
    if (ch === '(') parenDepth++;
    if (ch === ')') parenDepth--;
    if (ch === ';' && parenDepth <= 0) return i;
  }
  return -1;
}

/**
 * Validate pipe operator usage.
 * @param {string} source - Comment-stripped source
 * @returns {{ errors: ValidationError[], warnings: ValidationWarning[] }}
 */
function checkPipeOperators(source) {
  const errors = [];
  const warnings = [];
  const lines = source.split('\n');

  // Check if query starts with a pipe (no table name)
  const firstNonEmpty = lines.findIndex(l => l.trim().length > 0);
  if (firstNonEmpty >= 0) {
    const first = lines[firstNonEmpty].trim();
    // Skip let statements — they're valid first lines
    if (first.startsWith('|') && !/^let\b/i.test(first)) {
      errors.push({
        severity: 'error',
        message: 'Query starts with a pipe operator — expected a table name or let statement',
        line: firstNonEmpty + 1,
        rule: 'leading-pipe',
      });
    }
  }

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed) continue;

    // Empty pipeline stages: `| |`
    if (/\|\s*\|/.test(trimmed)) {
      errors.push({
        severity: 'error',
        message: 'Empty pipeline stage — two consecutive pipe operators',
        line: i + 1,
        rule: 'empty-pipe-stage',
      });
    }

    // Check for known operators after pipe (skip inside strings)
    const pipeMatches = trimmed.matchAll(/\|\s*([a-z][a-z0-9_-]*)/gi);
    for (const match of pipeMatches) {
      const op = match[1].toLowerCase();
      if (!OPERATORS.has(op)) {
        warnings.push({
          severity: 'warning',
          message: `Unknown tabular operator '${match[1]}' — verify this is a valid KQL operator or plugin`,
          line: i + 1,
          rule: 'unknown-operator',
        });
      }
    }

    // Trailing pipe at end of query
    if (/\|\s*$/.test(trimmed) && i === lines.length - 1) {
      errors.push({
        severity: 'error',
        message: 'Query ends with a trailing pipe operator',
        line: i + 1,
        rule: 'trailing-pipe',
      });
    }
  }

  // Also check: trailing pipe on any line that is the last non-empty line
  const lastNonEmpty = (() => {
    for (let j = lines.length - 1; j >= 0; j--) {
      if (lines[j].trim().length > 0) return j;
    }
    return -1;
  })();
  if (lastNonEmpty >= 0 && /\|\s*$/.test(lines[lastNonEmpty].trim()) && lastNonEmpty !== lines.length - 1) {
    errors.push({
      severity: 'error',
      message: 'Query ends with a trailing pipe operator',
      line: lastNonEmpty + 1,
      rule: 'trailing-pipe',
    });
  }

  return { errors, warnings };
}

/**
 * Check for common KQL mistakes and best practice warnings.
 * @param {string} source - Comment-stripped source
 * @returns {{ errors: ValidationError[], warnings: ValidationWarning[] }}
 */
function checkCommonMistakes(source) {
  const errors = [];
  const warnings = [];
  const lines = source.split('\n');

  let hasTimeFilter = false;
  let referencesKnownTable = false;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed) continue;

    // Track whether a TimeGenerated filter exists anywhere
    if (/TimeGenerated\s*[><=]/i.test(trimmed)) {
      hasTimeFilter = true;
    }

    // Track references to known large tables
    for (const tbl of TABLE_NAMES) {
      if (tbl.startsWith('_')) continue; // skip functions like _GetWatchlist
      if (new RegExp(`\\b${tbl}\\b`).test(trimmed) && !/["']/.test(trimmed.split(tbl)[0].slice(-1))) {
        referencesKnownTable = true;
      }
    }

    // Single `=` in where clause → error (KQL uses == for equality)
    if (/\|\s*where\b/i.test(trimmed)) {
      const whereBody = trimmed.replace(/.*\|\s*where\s+/i, '');
      // Only check up to the next pipe operator to avoid false positives
      const nextPipeIdx = whereBody.indexOf(' |');
      const whereOnly = nextPipeIdx >= 0 ? whereBody.substring(0, nextPipeIdx) : whereBody;
      // Match single = that isn't ==, !=, >=, <=, =~, !~
      if (/[^!=<>~]=[^=~]/.test(whereOnly) && !/\b(let|set)\b/i.test(whereOnly)) {
        errors.push({
          severity: 'error',
          message: "Use of '=' instead of '==' in where clause — KQL uses '==' for equality comparison",
          line: i + 1,
          rule: 'where-assignment',
        });
      }
    }

    // project * — performance warning
    if (/\|\s*project\s+\*\s*$/i.test(trimmed)) {
      warnings.push({
        severity: 'warning',
        message: "'project *' returns all columns — consider projecting only needed columns for better performance",
        line: i + 1,
        rule: 'project-wildcard',
      });
    }
  }

  // Missing time filter on known table
  if (referencesKnownTable && !hasTimeFilter) {
    warnings.push({
      severity: 'warning',
      message: 'Query references a known table without a TimeGenerated filter — consider adding a time filter to limit scan scope',
      rule: 'missing-time-filter',
    });
  }

  return { errors, warnings };
}

/**
 * Validate a KQL query string.
 * @param {string} kql - Raw KQL source code
 * @returns {ParseResult}
 */
function parse(kql) {
  // null/undefined → invalid
  if (kql == null || typeof kql !== 'string') {
    return {
      valid: false,
      errors: [{ severity: 'error', message: 'Empty or invalid KQL input', rule: 'empty-input' }],
      warnings: [],
    };
  }

  // Empty or whitespace-only → valid (nothing to check)
  const trimmed = kql.trim();
  if (trimmed.length === 0) {
    return { valid: true, errors: [], warnings: [] };
  }

  const stripped = stripComments(kql);

  // Comment-only query → valid
  if (stripped.trim().length === 0) {
    return { valid: true, errors: [], warnings: [] };
  }

  const allErrors = [];
  const allWarnings = [];

  allErrors.push(...checkDelimiters(stripped));

  const letResult = checkLetStatements(stripped);
  allErrors.push(...letResult.errors);
  allWarnings.push(...letResult.warnings);

  const pipeResult = checkPipeOperators(stripped);
  allErrors.push(...pipeResult.errors);
  allWarnings.push(...pipeResult.warnings);

  const mistakeResult = checkCommonMistakes(stripped);
  allErrors.push(...mistakeResult.errors);
  allWarnings.push(...mistakeResult.warnings);

  allErrors.sort((a, b) => (a.line || 0) - (b.line || 0));
  allWarnings.sort((a, b) => (a.line || 0) - (b.line || 0));

  return {
    valid: allErrors.length === 0,
    errors: allErrors,
    warnings: allWarnings,
  };
}

module.exports = { parse, stripComments, checkDelimiters, checkLetStatements, checkPipeOperators, checkCommonMistakes };
