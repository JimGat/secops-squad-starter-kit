// KQL Validator — offline KQL syntax validation library.
// No external dependencies. No Azure connectivity.

'use strict';

const fs = require('fs');
const path = require('path');
const { parse } = require('./parser');
const { formatResults, buildSummary } = require('./reporter');
const { OPERATORS, FUNCTIONS, TABLE_NAMES } = require('./operators');

/**
 * @typedef {import('./parser').ParseResult} ParseResult
 */

/**
 * @typedef {Object} DirectoryOptions
 * @property {string[]} [extensions] - File extensions to scan (default: ['.kql'])
 * @property {boolean} [recursive] - Scan subdirectories (default: true)
 * @property {boolean} [includeMarkdown] - Also extract and validate KQL from .md files (default: false)
 * @property {string} [format] - Output format: 'console' | 'ci' | 'json' (default: 'console')
 */

/**
 * @typedef {Object} DirectoryResult
 * @property {Map<string, ParseResult>} results - Per-file results
 * @property {{ totalFiles: number, passed: number, failed: number, errors: number, warnings: number }} summary
 */

// Max file size to prevent memory issues (5 MB)
const MAX_FILE_SIZE = 5 * 1024 * 1024;

/**
 * Validate a KQL query string.
 * @param {string} kqlString - Raw KQL source code
 * @returns {ParseResult} Validation result with errors and warnings
 */
function validateQuery(kqlString) {
  return parse(kqlString);
}

/**
 * Validate a KQL file.
 * @param {string} filePath - Path to a .kql file
 * @returns {ParseResult} Validation result
 */
function validateFile(filePath) {
  const resolved = path.resolve(filePath);

  if (!fs.existsSync(resolved)) {
    return {
      valid: false,
      errors: [{ severity: 'error', message: `File not found: ${resolved}`, rule: 'file-not-found' }],
      warnings: [],
    };
  }

  const stat = fs.statSync(resolved);

  if (stat.size === 0) {
    return { valid: true, errors: [], warnings: [] };
  }

  if (stat.size > MAX_FILE_SIZE) {
    return {
      valid: false,
      errors: [{ severity: 'error', message: `File exceeds ${MAX_FILE_SIZE / 1024 / 1024}MB limit (${(stat.size / 1024 / 1024).toFixed(1)}MB)`, rule: 'file-too-large' }],
      warnings: [],
    };
  }

  const content = fs.readFileSync(resolved, 'utf-8');
  return parse(content);
}

/**
 * Extract KQL code blocks from markdown content.
 * Looks for fenced code blocks tagged as ```kql or ```kusto
 * @param {string} markdownContent - Raw markdown text
 * @returns {string[]} Extracted query strings
 */
function extractQueries(markdownContent) {
  if (!markdownContent || typeof markdownContent !== 'string') {
    return [];
  }

  const results = [];
  const lines = markdownContent.split('\n');
  let inKqlBlock = false;
  let blockLines = [];

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();

    if (!inKqlBlock && /^```\s*(kql|kusto)\s*$/i.test(trimmed)) {
      inKqlBlock = true;
      blockLines = [];
      continue;
    }

    if (inKqlBlock) {
      if (/^```\s*$/.test(trimmed)) {
        inKqlBlock = false;
        results.push(blockLines.join('\n'));
        continue;
      }
      blockLines.push(lines[i]);
    }
  }

  // Handle unclosed code block
  if (inKqlBlock && blockLines.length > 0) {
    results.push(blockLines.join('\n'));
  }

  return results;
}

/**
 * Collect files from a directory matching the given extensions.
 * @param {string} dirPath
 * @param {string[]} extensions
 * @param {boolean} recursive
 * @returns {string[]}
 */
function collectFiles(dirPath, extensions, recursive) {
  const files = [];
  const resolved = path.resolve(dirPath);

  if (!fs.existsSync(resolved)) {
    return files;
  }

  const entries = fs.readdirSync(resolved, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(resolved, entry.name);

    // Skip hidden dirs and node_modules
    if (entry.name.startsWith('.') || entry.name === 'node_modules') {
      continue;
    }

    if (entry.isDirectory() && recursive) {
      files.push(...collectFiles(fullPath, extensions, recursive));
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (extensions.includes(ext)) {
        files.push(fullPath);
      }
    }
  }

  return files;
}

/**
 * Validate all KQL files in a directory.
 * @param {string} dirPath - Directory to scan
 * @param {DirectoryOptions} [options] - Scan options
 * @returns {DirectoryResult} Aggregated results with summary
 */
function validateDirectory(dirPath, options = {}) {
  const {
    extensions = ['.kql'],
    recursive = true,
    includeMarkdown = false,
    format = 'console',
  } = options;

  const exts = [...extensions];
  if (includeMarkdown && !exts.includes('.md')) {
    exts.push('.md');
  }

  const results = new Map();
  const files = collectFiles(dirPath, exts, recursive);

  for (const filePath of files) {
    const ext = path.extname(filePath).toLowerCase();

    if (ext === '.md') {
      // Extract KQL from markdown and validate each block
      const content = fs.readFileSync(filePath, 'utf-8');
      const queries = extractQueries(content);

      if (queries.length === 0) continue;

      const fileErrors = [];
      const fileWarnings = [];

      for (const query of queries) {
        const result = parse(query);
        fileErrors.push(...result.errors);
        fileWarnings.push(...result.warnings);
      }

      results.set(filePath, {
        valid: fileErrors.length === 0,
        errors: fileErrors,
        warnings: fileWarnings,
      });
    } else {
      results.set(filePath, validateFile(filePath));
    }
  }

  return {
    results,
    summary: buildSummary(results),
  };
}

module.exports = {
  validateQuery,
  validateFile,
  validateDirectory,
  extractQueries,
  // Re-export for convenience
  formatResults,
  buildSummary,
  OPERATORS,
  FUNCTIONS,
  TABLE_NAMES,
};
