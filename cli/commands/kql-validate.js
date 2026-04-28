"use strict";

const fs = require("fs");
const path = require("path");

const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
};

/**
 * Expand a glob-like pattern into matching file paths.
 * Supports simple patterns: *.kql, **\/*.md, skills/**\/*.md
 */
function expandGlob(pattern, baseDir) {
  const files = [];

  // If pattern points to a single file, return it directly
  const resolved = path.resolve(baseDir, pattern);
  if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
    return [resolved];
  }

  // Simple glob expansion
  const isRecursive = pattern.includes("**");
  const ext = path.extname(pattern);
  const dirPart = pattern.replace(/\*\*[/\\]?/, "").replace(/\*\.[a-z]+$/i, "");
  const searchDir = dirPart ? path.resolve(baseDir, dirPart) : baseDir;

  if (!fs.existsSync(searchDir)) return files;

  function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (entry.name.startsWith(".") || entry.name === "node_modules") continue;
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory() && isRecursive) {
        walk(fullPath);
      } else if (entry.isFile()) {
        if (ext && path.extname(entry.name).toLowerCase() === ext) {
          files.push(fullPath);
        }
      }
    }
  }

  walk(searchDir);
  return files;
}

/**
 * Load the KQL validator library.
 */
function loadValidator() {
  const libPath = path.join(__dirname, "..", "..", "lib", "kql-validator");
  try {
    return require(libPath);
  } catch (err) {
    console.error(
      `${c.red}❌ Failed to load KQL validator library: ${err.message}${c.reset}`
    );
    process.exit(1);
  }
}

function formatTableOutput(results) {
  const rows = [];

  for (const [filePath, result] of results) {
    const relPath = path.relative(process.cwd(), filePath);

    if (result.valid && result.warnings.length === 0) {
      rows.push({
        file: relPath,
        status: "pass",
        message: "Valid",
      });
    }

    for (const err of result.errors) {
      rows.push({
        file: relPath,
        line: err.line || "-",
        status: "fail",
        message: `[${err.rule}] ${err.message}`,
      });
    }

    for (const warn of result.warnings) {
      rows.push({
        file: relPath,
        line: warn.line || "-",
        status: "warn",
        message: `[${warn.rule}] ${warn.message}`,
      });
    }
  }

  if (rows.length === 0) {
    console.log(`\n${c.yellow}No files to validate.${c.reset}\n`);
    return;
  }

  const fileW = Math.max(6, ...rows.map((r) => r.file.length)) + 2;
  const lineW = 6;
  const statusW = 8;

  console.log(
    `\n${c.bold}${"File".padEnd(fileW)}${"Line".padEnd(lineW)}${"Status".padEnd(statusW)}Message${c.reset}`
  );
  console.log("─".repeat(fileW + lineW + statusW + 40));

  for (const row of rows) {
    const statusColor =
      row.status === "pass" ? c.green : row.status === "warn" ? c.yellow : c.red;
    const line = row.line !== undefined ? String(row.line) : "-";

    console.log(
      `${row.file.padEnd(fileW)}${line.padEnd(lineW)}${statusColor}${row.status.padEnd(statusW)}${c.reset}${row.message}`
    );
  }

  console.log("");
}

function printHelp() {
  console.log(`
${c.cyan}${c.bold}secops-squad kql validate${c.reset} — Validate KQL queries

${c.bold}Usage:${c.reset}
  secops-squad kql validate <file|glob>

${c.bold}Options:${c.reset}
  --format table|json  Output format (default: table)

${c.bold}Supported inputs:${c.reset}
  .kql files     Validated directly
  .md files      KQL code blocks (\`\`\`kql ... \`\`\`) are extracted and validated

${c.bold}Examples:${c.reset}
  secops-squad kql validate templates/kql/hunting.kql
  secops-squad kql validate "*.kql"
  secops-squad kql validate "skills/**/*.md"
  secops-squad kql validate "skills/kql/*.md" --format json
`);
}

async function run(args) {
  // The CLI router sends us args after "kql", so first arg should be "validate"
  // But we also handle being called directly with the file pattern as first arg
  let fileArgs = args;
  let subcommand = args[0];

  if (subcommand === "validate") {
    fileArgs = args.slice(1);
  } else if (subcommand === "--help" || subcommand === "-h" || !subcommand) {
    printHelp();
    return;
  }

  if (fileArgs.length === 0 || fileArgs[0] === "--help" || fileArgs[0] === "-h") {
    printHelp();
    return;
  }

  // Parse flags
  const formatIdx = fileArgs.indexOf("--format");
  const outputFormat = formatIdx !== -1 ? fileArgs[formatIdx + 1] : "table";
  const pattern = fileArgs.find(
    (a) => !a.startsWith("--") && a !== outputFormat
  );

  if (!pattern) {
    console.error(
      `${c.red}❌ File path or glob pattern required.${c.reset}`
    );
    printHelp();
    process.exit(1);
  }

  const validator = loadValidator();
  const baseDir = process.cwd();
  const files = expandGlob(pattern, baseDir);

  if (files.length === 0) {
    console.error(
      `${c.red}❌ No files matched pattern: ${pattern}${c.reset}`
    );
    process.exit(1);
  }

  // Validate each file
  const results = new Map();

  for (const filePath of files) {
    const ext = path.extname(filePath).toLowerCase();

    if (ext === ".md") {
      const content = fs.readFileSync(filePath, "utf8");
      const queries = validator.extractQueries(content);

      if (queries.length === 0) continue;

      const fileErrors = [];
      const fileWarnings = [];

      for (const query of queries) {
        const result = validator.validateQuery(query);
        fileErrors.push(...result.errors);
        fileWarnings.push(...result.warnings);
      }

      results.set(filePath, {
        valid: fileErrors.length === 0,
        errors: fileErrors,
        warnings: fileWarnings,
      });
    } else if (ext === ".kql") {
      results.set(filePath, validator.validateFile(filePath));
    } else {
      // Try to validate as KQL anyway
      results.set(filePath, validator.validateFile(filePath));
    }
  }

  if (results.size === 0) {
    console.log(`\n${c.yellow}No KQL content found in matched files.${c.reset}\n`);
    return;
  }

  // Output results
  if (outputFormat === "json") {
    const obj = {};
    for (const [filePath, result] of results) {
      obj[path.relative(baseDir, filePath)] = result;
    }
    console.log(JSON.stringify(obj, null, 2));
  } else {
    formatTableOutput(results);

    // Summary
    const summary = validator.buildSummary(results);
    if (summary.invalid === 0) {
      console.log(
        `${c.green}✅ All ${summary.total} file(s) passed validation.${c.reset}\n`
      );
    } else {
      console.log(
        `${c.red}❌ ${summary.invalid}/${summary.total} file(s) failed (${summary.errors} error(s), ${summary.warnings} warning(s))${c.reset}\n`
      );
    }
  }

  // Exit code: 1 on any failure
  let hasFailures = false;
  for (const [, result] of results) {
    if (!result.valid) {
      hasFailures = true;
      break;
    }
  }

  if (hasFailures) {
    process.exit(1);
  }
}

module.exports = { run };
