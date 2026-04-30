"use strict";

const fs = require("fs");
const path = require("path");
const readline = require("readline");
const yaml = require("js-yaml");

const SECOPS_DIR = ".secops";

// ANSI color helpers
const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  red: "\x1b[31m",
};

const CLOUD_OPTIONS = [
  { value: "azure-commercial", label: "Azure Commercial" },
  { value: "azure-government", label: "Azure Government (GCC-High / DoD)" },
  { value: "azure-china", label: "Azure China (21Vianet)" },
  { value: "azure-stack", label: "Azure Stack (on-premises)" },
];

const REGION_SUGGESTIONS = [
  "eastus",
  "eastus2",
  "westus2",
  "westus3",
  "centralus",
  "northeurope",
  "westeurope",
  "uksouth",
  "southeastasia",
  "australiaeast",
];

/**
 * Template for a minimal environment.yaml.
 */
function generateEnvironmentYaml(opts) {
  return {
    schema_version: "1.0",
    organization: {
      name: opts.orgName,
      cloud: opts.cloud,
      primary_region: opts.region,
      data_residency: opts.residency || "us",
      org_type: opts.orgType || "enterprise",
    },
    tenants: [],
    subscriptions: [],
    default_workspace: null,
    lighthouse: { delegations: [] },
    managed_customers: [],
  };
}

/**
 * Template for a starter data-source-map.yaml.
 */
function generateDataSourceMap() {
  return {
    schema_version: "1.0",
    sources: {},
    cross_cloud_identity_mapping: { method: "none" },
  };
}

/**
 * Template for a starter migrations.yaml.
 */
function generateMigrations() {
  return {
    schema_version: "1.0",
    migrations: [],
  };
}

/**
 * Template for a starter discovery-log.yaml.
 */
function generateDiscoveryLog() {
  return {
    schema_version: "1.0",
    discoveries: [],
  };
}

function createPrompt() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  rl.on("close", () => {
    console.log(`\n${c.yellow}Setup cancelled.${c.reset}`);
    process.exit(0);
  });

  const ask = (question) =>
    new Promise((resolve) => {
      rl.question(question, (answer) => resolve(answer.trim()));
    });

  return { rl, ask };
}

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function writeYamlFile(filePath, data, header) {
  const content =
    (header ? header + "\n" : "") +
    yaml.dump(data, { lineWidth: 100, noRefs: true, quotingType: '"' });
  fs.writeFileSync(filePath, content, "utf8");
}

/**
 * Non-interactive init: generate .secops/ from flags.
 */
function initNonInteractive(rootDir, args) {
  const orgName = getFlag(args, "--org") || "My Organization";
  const cloud = getFlag(args, "--cloud") || "azure-commercial";
  const region = getFlag(args, "--region") || "eastus2";

  return scaffoldSecops(rootDir, { orgName, cloud, region });
}

function getFlag(args, flag) {
  const idx = args.indexOf(flag);
  return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : null;
}

/**
 * Interactive init: prompt the user for basic info.
 */
async function initInteractive(rootDir) {
  const { rl, ask } = createPrompt();

  console.log(
    `\n${c.cyan}${c.bold}  ⚔️  SecOps Environment Setup${c.reset}\n`
  );
  console.log(
    `${c.dim}  This will create a .secops/ directory with starter config files.${c.reset}\n`
  );

  // Org name
  const orgName = await ask(
    `${c.cyan}? ${c.bold}Organization name:${c.reset} `
  );
  if (!orgName) {
    rl.close();
    console.error(`${c.red}❌ Organization name is required.${c.reset}`);
    process.exit(1);
  }

  // Cloud type
  console.log(`\n${c.cyan}? ${c.bold}Cloud environment:${c.reset}`);
  CLOUD_OPTIONS.forEach((o, i) => {
    console.log(`  ${c.bold}${i + 1}.${c.reset} ${o.label}`);
  });
  const cloudChoice = await ask(`\n  ${c.cyan}Enter number (1-${CLOUD_OPTIONS.length}):${c.reset} `);
  const cloudIdx = parseInt(cloudChoice, 10) - 1;
  const cloud =
    cloudIdx >= 0 && cloudIdx < CLOUD_OPTIONS.length
      ? CLOUD_OPTIONS[cloudIdx].value
      : "azure-commercial";

  // Primary region
  console.log(
    `\n${c.dim}  Common regions: ${REGION_SUGGESTIONS.slice(0, 5).join(", ")}${c.reset}`
  );
  const region =
    (await ask(`${c.cyan}? ${c.bold}Primary region:${c.reset} ${c.dim}(eastus2)${c.reset} `)) ||
    "eastus2";

  rl.close();

  return scaffoldSecops(rootDir, { orgName, cloud, region });
}

/**
 * Create the .secops/ directory structure and starter files.
 */
function scaffoldSecops(rootDir, opts) {
  const base = path.join(rootDir, SECOPS_DIR);

  // Check if .secops/ already exists
  if (fs.existsSync(path.join(base, "environment.yaml"))) {
    console.log(
      `\n${c.yellow}⚠️  .secops/environment.yaml already exists — skipping scaffold.${c.reset}`
    );
    console.log(
      `${c.dim}  Delete .secops/ first if you want to regenerate.${c.reset}\n`
    );
    return false;
  }

  ensureDir(base);
  ensureDir(path.join(base, "workspaces"));
  ensureDir(path.join(base, "data-sources"));
  ensureDir(path.join(base, "identity"));
  ensureDir(path.join(base, "alerting"));
  ensureDir(path.join(base, "compliance"));

  // environment.yaml
  writeYamlFile(
    path.join(base, "environment.yaml"),
    generateEnvironmentYaml(opts),
    "# .secops/environment.yaml — Primary Environment Descriptor\n# Generated by secops-squad init --secops"
  );

  // data-source-map.yaml
  writeYamlFile(
    path.join(base, "data-sources", "data-source-map.yaml"),
    generateDataSourceMap(),
    "# .secops/data-sources/data-source-map.yaml — Data Source Location Map\n# Generated by secops-squad init --secops"
  );

  // migrations.yaml
  writeYamlFile(
    path.join(base, "data-sources", "migrations.yaml"),
    generateMigrations(),
    "# .secops/data-sources/migrations.yaml — Data Migration Tracking\n# Generated by secops-squad init --secops"
  );

  // discovery-log.yaml
  writeYamlFile(
    path.join(base, "discovery-log.yaml"),
    generateDiscoveryLog(),
    "# .secops/discovery-log.yaml — Agent-Discovered Environment Facts\n# Generated by secops-squad init --secops"
  );

  // README.md (if not present)
  const readmePath = path.join(base, "README.md");
  if (!fs.existsSync(readmePath)) {
    fs.writeFileSync(
      readmePath,
      `# .secops/ — Customer Environment Knowledge

This directory contains your organization's environment configuration
for secops-squad agents.

## Key Files

| File | Purpose |
|------|---------|
| \`environment.yaml\` | Primary environment descriptor (org, tenants, subscriptions) |
| \`workspaces/*.yaml\` | Log Analytics / ADX workspace definitions |
| \`data-sources/data-source-map.yaml\` | Maps data tables to their physical locations |
| \`data-sources/migrations.yaml\` | Active data migration tracking |
| \`discovery-log.yaml\` | Agent-discovered facts (append-only) |

## Commands

\`\`\`bash
secops-squad env              # Show environment summary
secops-squad env validate     # Validate all YAML files
secops-squad env workspaces   # List configured workspaces
secops-squad env data-sources # Show data source map
\`\`\`

Schema version: 1.0
`,
      "utf8"
    );
  }

  console.log(`
${c.green}${c.bold}✅ .secops/ environment created!${c.reset}

${c.cyan}Generated files:${c.reset}
  ${c.dim}•${c.reset} .secops/environment.yaml
  ${c.dim}•${c.reset} .secops/data-sources/data-source-map.yaml
  ${c.dim}•${c.reset} .secops/data-sources/migrations.yaml
  ${c.dim}•${c.reset} .secops/discovery-log.yaml
  ${c.dim}•${c.reset} .secops/README.md

${c.cyan}Next steps:${c.reset}
  ${c.bold}1.${c.reset} Edit ${c.cyan}.secops/environment.yaml${c.reset} to add your tenants & subscriptions
  ${c.bold}2.${c.reset} Add workspace files to ${c.cyan}.secops/workspaces/${c.reset}
  ${c.bold}3.${c.reset} Run ${c.cyan}secops-squad env validate${c.reset} to check your config
`);

  return true;
}

/**
 * Entry point — called from init command with --secops flag,
 * or directly as secops-squad init --secops.
 */
async function run(args) {
  const rootDir = process.cwd();
  const nonInteractive = args.includes("--no-interactive");

  if (nonInteractive) {
    initNonInteractive(rootDir, args);
  } else {
    await initInteractive(rootDir);
  }
}

module.exports = { run, scaffoldSecops };
