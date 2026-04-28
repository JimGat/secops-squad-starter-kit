// Output formatter for KQL validation results.
// Supports console, CI (GitHub Actions annotations), and JSON formats.

'use strict';

/**
 * @typedef {'console' | 'ci' | 'json'} OutputFormat
 */

/**
 * Format a single file's validation result for console output.
 * @param {string} filePath
 * @param {{ valid: boolean, errors: Array, warnings: Array }} result
 * @returns {string}
 */
function formatConsoleResult(filePath, result) {
  const lines = [];

  if (result.valid && result.warnings.length === 0) {
    lines.push(`  \u2705 ${filePath}`);
    return lines.join('\n');
  }

  if (result.valid && result.warnings.length > 0) {
    lines.push(`  \u26A0\uFE0F  ${filePath}`);
  } else {
    lines.push(`  \u274C ${filePath}`);
  }

  for (const err of result.errors) {
    const loc = err.line ? `:${err.line}${err.column ? ':' + err.column : ''}` : '';
    lines.push(`    ERROR${loc} [${err.rule}] ${err.message}`);
  }

  for (const warn of result.warnings) {
    const loc = warn.line ? `:${warn.line}${warn.column ? ':' + warn.column : ''}` : '';
    lines.push(`    WARN${loc} [${warn.rule}] ${warn.message}`);
  }

  return lines.join('\n');
}

/**
 * Format a single file's validation result as GitHub Actions annotations.
 * @param {string} filePath
 * @param {{ valid: boolean, errors: Array, warnings: Array }} result
 * @returns {string}
 */
function formatCIResult(filePath, result) {
  const lines = [];

  for (const err of result.errors) {
    const lineNum = err.line ? `,line=${err.line}` : '';
    const colNum = err.column ? `,col=${err.column}` : '';
    lines.push(`::error file=${filePath}${lineNum}${colNum}::[${err.rule}] ${err.message}`);
  }

  for (const warn of result.warnings) {
    const lineNum = warn.line ? `,line=${warn.line}` : '';
    const colNum = warn.column ? `,col=${warn.column}` : '';
    lines.push(`::warning file=${filePath}${lineNum}${colNum}::[${warn.rule}] ${warn.message}`);
  }

  return lines.join('\n');
}

/**
 * Format validation results for output.
 * @param {Map<string, { valid: boolean, errors: Array, warnings: Array }>} results
 * @param {OutputFormat} format
 * @returns {string}
 */
function formatResults(results, format) {
  if (format === 'json') {
    const obj = {};
    for (const [filePath, result] of results) {
      obj[filePath] = result;
    }
    return JSON.stringify(obj, null, 2);
  }

  const lines = [];
  let totalErrors = 0;
  let totalWarnings = 0;
  let totalFiles = 0;
  let passedFiles = 0;

  for (const [filePath, result] of results) {
    totalFiles++;
    totalErrors += result.errors.length;
    totalWarnings += result.warnings.length;
    if (result.valid) passedFiles++;

    if (format === 'ci') {
      const ciOutput = formatCIResult(filePath, result);
      if (ciOutput) lines.push(ciOutput);
    } else {
      lines.push(formatConsoleResult(filePath, result));
    }
  }

  if (format === 'console') {
    lines.unshift(`\nKQL Validation Results\n${'='.repeat(40)}`);
    lines.push('');
    lines.push(`${'='.repeat(40)}`);
    lines.push(`Files: ${passedFiles}/${totalFiles} passed (${totalFiles - passedFiles} failed)`);
    if (totalErrors > 0) lines.push(`Errors: ${totalErrors}`);
    if (totalWarnings > 0) lines.push(`Warnings: ${totalWarnings}`);
    lines.push(totalErrors === 0 ? '\u2705 All files valid' : '\u274C Validation failed');
  }

  return lines.join('\n');
}

/**
 * Build a summary object from results.
 * @param {Map<string, { valid: boolean, errors: Array, warnings: Array }>} results
 * @returns {{ total: number, valid: number, invalid: number, errors: number, warnings: number }}
 */
function buildSummary(results) {
  let total = 0;
  let valid = 0;
  let invalid = 0;
  let errors = 0;
  let warnings = 0;

  for (const [, result] of results) {
    total++;
    if (result.valid) { valid++; } else { invalid++; }
    errors += result.errors.length;
    warnings += result.warnings.length;
  }

  return { total, valid, invalid, errors, warnings };
}

module.exports = { formatResults, formatConsoleResult, formatCIResult, buildSummary };
