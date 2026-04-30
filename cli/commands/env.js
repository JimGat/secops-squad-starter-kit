"use strict";

const path = require("path");
const secops = require("../secops-config");

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

function fatal(msg) {
  console.error(`${c.red}❌ ${msg}${c.reset}`);
  process.exit(1);
}

/**
 * secops-squad env — Show environment summary
 */
function showSummary(rootDir) {
  const env = secops.loadEnvironment(rootDir);
  if (!env) {
    fatal(
      ".secops/environment.yaml not found. Run `secops-squad init --secops` to create one."
    );
  }

  const org = env.organization || {};
  const tenants = env.tenants || [];
  const subs = env.subscriptions || [];

  console.log(
    `\n${c.cyan}${c.bold}  SecOps Environment Summary${c.reset}\n`
  );
  console.log(`  ${c.bold}Organization:${c.reset}  ${org.name || "(not set)"}`);
  console.log(`  ${c.bold}Cloud:${c.reset}         ${org.cloud || "(not set)"}`);
  console.log(`  ${c.bold}Region:${c.reset}        ${org.primary_region || "(not set)"}`);
  console.log(`  ${c.bold}Org Type:${c.reset}      ${org.org_type || "enterprise"}`);
  console.log(`  ${c.bold}Residency:${c.reset}     ${org.data_residency || "(not set)"}`);
  console.log(`  ${c.bold}Tenants:${c.reset}       ${tenants.length}`);
  console.log(`  ${c.bold}Subscriptions:${c.reset} ${subs.length}`);
  console.log(
    `  ${c.bold}Default WS:${c.reset}    ${env.default_workspace || "(none)"}`
  );
  console.log(
    `  ${c.bold}Schema:${c.reset}        v${env.schema_version || "?"}`
  );

  // Tenant details
  if (tenants.length > 0) {
    console.log(`\n  ${c.cyan}${c.bold}Tenants:${c.reset}`);
    for (const t of tenants) {
      console.log(
        `    ${c.dim}•${c.reset} ${t.name || t.id} ${c.dim}(${t.type || "unknown"})${c.reset}`
      );
    }
  }

  // Subscription details
  if (subs.length > 0) {
    console.log(`\n  ${c.cyan}${c.bold}Subscriptions:${c.reset}`);
    for (const s of subs) {
      console.log(
        `    ${c.dim}•${c.reset} ${s.name || s.id} ${c.dim}— ${s.purpose || ""}${c.reset}`
      );
    }
  }

  // MSSP info
  const customers = env.managed_customers || [];
  if (org.org_type === "mssp" && customers.length > 0) {
    console.log(`\n  ${c.cyan}${c.bold}Managed Customers:${c.reset} ${customers.length}`);
    for (const cust of customers) {
      console.log(
        `    ${c.dim}•${c.reset} ${cust.name} ${c.dim}(${cust.access_type || "unknown"})${c.reset}`
      );
    }
  }

  console.log();
}

/**
 * secops-squad env validate — Validate all .secops/ files
 */
function showValidation(rootDir) {
  const result = secops.validateAll(rootDir);

  console.log(
    `\n${c.cyan}${c.bold}  SecOps Config Validation${c.reset}\n`
  );

  for (const r of result.results) {
    if (r.ok) {
      console.log(`  ${c.green}✅${c.reset} ${r.file}`);
    } else {
      console.log(`  ${c.red}❌${c.reset} ${r.file} — ${r.error}`);
    }
  }

  console.log();

  if (result.valid) {
    console.log(`  ${c.green}${c.bold}All files valid.${c.reset}\n`);
  } else {
    console.log(
      `  ${c.red}${c.bold}Validation failed.${c.reset} Fix errors above and re-run.\n`
    );
    process.exit(1);
  }
}

/**
 * secops-squad env workspaces — List configured workspaces
 */
function showWorkspaces(rootDir) {
  const env = secops.loadEnvironment(rootDir);
  const workspaces = secops.listWorkspaces(rootDir);

  console.log(
    `\n${c.cyan}${c.bold}  Configured Workspaces${c.reset}\n`
  );

  if (workspaces.length === 0) {
    console.log(`  ${c.dim}No workspace files found in .secops/workspaces/${c.reset}\n`);
    return;
  }

  const defaultWs = env && env.default_workspace;

  for (const ws of workspaces) {
    const d = ws.data;
    const isDefault = ws.name === defaultWs;
    const marker = isDefault ? ` ${c.green}(default)${c.reset}` : "";

    console.log(`  ${c.bold}${d.name || ws.name}${c.reset}${marker}`);
    console.log(`    ${c.dim}File:${c.reset}       ${ws.name}.yaml`);
    console.log(`    ${c.dim}Region:${c.reset}     ${d.region || "(unknown)"}`);
    console.log(`    ${c.dim}Sentinel:${c.reset}   ${d.sentinel_enabled ? "enabled" : "disabled"}`);
    console.log(`    ${c.dim}Tier:${c.reset}       ${d.tier || "(unknown)"}`);
    console.log(
      `    ${c.dim}Retention:${c.reset}  ${d.retention ? `${d.retention.interactive_days}d interactive / ${d.retention.archive_days}d archive` : "(unknown)"}`
    );

    const tables = d.custom_tables || [];
    if (tables.length > 0) {
      console.log(`    ${c.dim}Custom tables:${c.reset} ${tables.length}`);
    }

    const connectors = d.data_connectors || [];
    const connected = connectors.filter((dc) => dc.status === "connected").length;
    if (connectors.length > 0) {
      console.log(
        `    ${c.dim}Connectors:${c.reset} ${connected}/${connectors.length} connected`
      );
    }
    console.log();
  }
}

/**
 * secops-squad env data-sources — Show data source map
 */
function showDataSources(rootDir) {
  const dsMap = secops.loadDataSourceMap(rootDir);

  console.log(
    `\n${c.cyan}${c.bold}  Data Source Map${c.reset}\n`
  );

  if (!dsMap || !dsMap.sources) {
    console.log(
      `  ${c.dim}No data source map found. Create .secops/data-sources/data-source-map.yaml${c.reset}\n`
    );
    return;
  }

  const sources = dsMap.sources;
  const entries = Object.entries(sources);

  // Group by location
  const byLocation = {};
  for (const [name, info] of entries) {
    const loc = info.location || "unknown";
    if (!byLocation[loc]) byLocation[loc] = [];
    byLocation[loc].push({ name, ...info });
  }

  for (const [loc, tables] of Object.entries(byLocation)) {
    console.log(`  ${c.bold}${loc.toUpperCase()}${c.reset} (${tables.length} tables)`);
    for (const t of tables) {
      const tierBadge =
        t.tier === "Basic"
          ? `${c.yellow}Basic${c.reset}`
          : t.tier === "Archive"
            ? `${c.dim}Archive${c.reset}`
            : t.tier === "Auxiliary"
              ? `${c.dim}Auxiliary${c.reset}`
              : `${c.green}Analytics${c.reset}`;

      const vol = t.daily_gb != null ? `${t.daily_gb} GB/day` : "";
      console.log(
        `    ${c.dim}•${c.reset} ${t.name} ${c.dim}[${tierBadge}${c.dim}]${c.reset} ${c.dim}${vol}${c.reset}`
      );
    }
    console.log();
  }

  // Migration summary
  const migrations = secops.loadMigrations(rootDir);
  if (migrations && migrations.migrations && migrations.migrations.length > 0) {
    const active = migrations.migrations.filter(
      (m) => m.status === "in-progress" || m.status === "planned"
    );
    if (active.length > 0) {
      console.log(`  ${c.yellow}${c.bold}Active Migrations:${c.reset}`);
      for (const m of active) {
        const badge =
          m.status === "in-progress"
            ? `${c.yellow}in-progress${c.reset}`
            : `${c.dim}planned${c.reset}`;
        console.log(`    ${c.dim}•${c.reset} [${badge}] ${m.description}`);
      }
      console.log();
    }
  }

  // Cross-cloud identity
  const mapping = dsMap.cross_cloud_identity_mapping;
  if (mapping && mapping.method !== "none") {
    console.log(
      `  ${c.dim}Cross-cloud identity mapping: ${mapping.method}${c.reset}\n`
    );
  }
}

/**
 * Main entry point — dispatches subcommands.
 */
async function run(args) {
  const rootDir = process.cwd();
  const sub = args[0];

  if (args.includes("--help") || args.includes("-h")) {
    console.log(`
Usage: secops-squad env [subcommand]

Subcommands:
  (none)         Show environment summary
  validate       Validate all .secops/ YAML files
  workspaces     List configured workspaces
  data-sources   Show data source map summary
`);
    return;
  }

  switch (sub) {
    case "validate":
      showValidation(rootDir);
      break;
    case "workspaces":
      showWorkspaces(rootDir);
      break;
    case "data-sources":
      showDataSources(rootDir);
      break;
    default:
      showSummary(rootDir);
      break;
  }
}

module.exports = { run };
