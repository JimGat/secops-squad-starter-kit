"use strict";

const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { execSync } = require("child_process");
const yaml = require("js-yaml");

const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
};

function fatal(msg) {
  console.error(`${c.red}❌ ${msg}${c.reset}`);
  process.exit(1);
}

function execSafe(cmd) {
  try {
    return execSync(cmd, { encoding: "utf8", timeout: 10000, stdio: ["pipe", "pipe", "pipe"] }).trim();
  } catch {
    return null;
  }
}

function prompt(rl, question) {
  return new Promise((resolve) => rl.question(question, resolve));
}

function ensureSecopsDirs(rootDir) {
  const dirs = [
    path.join(rootDir, ".secops"),
    path.join(rootDir, ".secops", "workspaces"),
  ];
  for (const dir of dirs) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }
}

function loadEnvironment(rootDir) {
  const envPath = path.join(rootDir, ".secops", "environment.yaml");
  if (!fs.existsSync(envPath)) return null;
  try {
    return yaml.load(fs.readFileSync(envPath, "utf8")) || {};
  } catch {
    return null;
  }
}

function saveEnvironment(rootDir, envData) {
  const envPath = path.join(rootDir, ".secops", "environment.yaml");
  fs.writeFileSync(envPath, yaml.dump(envData, { lineWidth: 120 }), "utf8");
}

/**
 * workspace connect — verify Azure login, gather workspace details, write config
 */
async function connect(rootDir) {
  console.log(`\n${c.cyan}${c.bold}secops-squad workspace connect${c.reset}\n`);

  // Verify Azure login
  const azResult = execSafe("az account show --output json");
  if (!azResult) {
    console.log(`${c.yellow}⚠️  Azure not logged in. Run ${c.cyan}az login${c.reset}${c.yellow} first.${c.reset}`);
    console.log(`${c.dim}You can still configure workspace details and connect Azure later.${c.reset}\n`);
  } else {
    try {
      const account = JSON.parse(azResult);
      console.log(`${c.green}✅ Azure logged in${c.reset}`);
      console.log(`   ${c.bold}Subscription:${c.reset} ${account.name || "(unknown)"} (${account.id || ""})`);
      console.log(`   ${c.bold}Tenant:${c.reset}       ${account.tenantId || "(unknown)"}\n`);
    } catch {
      console.log(`${c.yellow}⚠️  Azure CLI returned unexpected output.${c.reset}\n`);
    }
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  let workspaceName, resourceGroup, subscriptionId;
  try {
    workspaceName = (await prompt(rl, `  ${c.bold}Workspace name${c.reset} (e.g. my-sentinel-workspace): `)).trim();
    if (!workspaceName) fatal("Workspace name is required.");

    resourceGroup = (await prompt(rl, `  ${c.bold}Resource group${c.reset}: `)).trim();
    if (!resourceGroup) fatal("Resource group is required.");

    subscriptionId = (await prompt(rl, `  ${c.bold}Subscription ID${c.reset} (leave blank to use current): `)).trim();
  } finally {
    rl.close();
  }

  // If no subscription provided, try to get it from az account
  if (!subscriptionId && azResult) {
    try {
      const account = JSON.parse(azResult);
      subscriptionId = account.id || "";
    } catch {
      subscriptionId = "";
    }
  }

  ensureSecopsDirs(rootDir);

  // Write workspace YAML
  const workspaceData = {
    schema_version: "1.0",
    name: workspaceName,
    resource_group: resourceGroup,
    subscription_id: subscriptionId || null,
    connected_at: new Date().toISOString(),
  };

  const workspacePath = path.join(rootDir, ".secops", "workspaces", `${workspaceName}.yaml`);
  fs.writeFileSync(workspacePath, yaml.dump(workspaceData, { lineWidth: 120 }), "utf8");
  console.log(`\n${c.green}✅ Workspace config written:${c.reset} .secops/workspaces/${workspaceName}.yaml`);

  // Update environment.yaml default_workspace
  let envData = loadEnvironment(rootDir) || { schema_version: "1.0" };
  envData.default_workspace = workspaceName;
  saveEnvironment(rootDir, envData);
  console.log(`${c.green}✅ Default workspace set to:${c.reset} ${c.cyan}${workspaceName}${c.reset}\n`);
  console.log(`${c.dim}Run ${c.cyan}secops-squad workspace status${c.reset}${c.dim} to verify.${c.reset}\n`);
}

/**
 * workspace status — show current workspace connection status
 */
function status(rootDir) {
  console.log(`\n${c.cyan}${c.bold}secops-squad workspace status${c.reset}\n`);

  const envData = loadEnvironment(rootDir);
  if (!envData) {
    console.log(`${c.yellow}⚠️  No .secops/environment.yaml found.${c.reset}`);
    console.log(`   Run ${c.cyan}secops-squad init --secops${c.reset} or ${c.cyan}secops-squad workspace connect${c.reset}\n`);
    return;
  }

  const defaultWs = envData.default_workspace;
  if (!defaultWs) {
    console.log(`${c.yellow}⚠️  No default workspace configured.${c.reset}`);
    console.log(`   Run ${c.cyan}secops-squad workspace connect${c.reset} to set one.\n`);
    return;
  }

  console.log(`  ${c.bold}Default workspace:${c.reset} ${c.cyan}${defaultWs}${c.reset}`);

  const wsPath = path.join(rootDir, ".secops", "workspaces", `${defaultWs}.yaml`);
  if (!fs.existsSync(wsPath)) {
    console.log(`  ${c.yellow}⚠️  Workspace file not found:${c.reset} .secops/workspaces/${defaultWs}.yaml\n`);
    return;
  }

  let wsData;
  try {
    wsData = yaml.load(fs.readFileSync(wsPath, "utf8")) || {};
  } catch {
    console.log(`  ${c.red}❌ Could not parse workspace file.${c.reset}\n`);
    return;
  }

  console.log(`  ${c.bold}Resource group:${c.reset}    ${wsData.resource_group || "(not set)"}`);
  console.log(`  ${c.bold}Subscription ID:${c.reset}   ${wsData.subscription_id || "(not set)"}`);
  console.log(`  ${c.bold}Connected at:${c.reset}      ${wsData.connected_at || "(unknown)"}`);

  // Optionally verify Azure login
  const azResult = execSafe("az account show --output json");
  if (azResult) {
    try {
      const account = JSON.parse(azResult);
      console.log(`\n  ${c.green}✅ Azure logged in${c.reset}`);
      console.log(`  ${c.bold}Subscription:${c.reset}      ${account.name || "(unknown)"} (${account.id || ""})`);
      console.log(`  ${c.bold}Tenant:${c.reset}            ${account.tenantId || "(unknown)"}`);
    } catch {
      console.log(`\n  ${c.yellow}⚠️  Azure CLI returned unexpected output.${c.reset}`);
    }
  } else {
    console.log(`\n  ${c.yellow}⚠️  Azure not logged in — run: az login${c.reset}`);
  }

  console.log("");
}

/**
 * workspace disconnect — remove default_workspace from environment.yaml (preserves workspace file)
 */
function disconnect(rootDir) {
  console.log(`\n${c.cyan}${c.bold}secops-squad workspace disconnect${c.reset}\n`);

  const envData = loadEnvironment(rootDir);
  if (!envData) {
    console.log(`${c.yellow}⚠️  No .secops/environment.yaml found — nothing to disconnect.${c.reset}\n`);
    return;
  }

  const current = envData.default_workspace;
  if (!current) {
    console.log(`${c.yellow}⚠️  No default workspace is set — nothing to disconnect.${c.reset}\n`);
    return;
  }

  delete envData.default_workspace;
  saveEnvironment(rootDir, envData);

  console.log(`${c.green}✅ Disconnected workspace:${c.reset} ${c.cyan}${current}${c.reset}`);
  console.log(`${c.dim}Workspace file preserved at .secops/workspaces/${current}.yaml${c.reset}\n`);
}

async function run(args) {
  const rootDir = process.cwd();
  const subcommand = args[0];

  switch (subcommand) {
    case "connect":
      await connect(rootDir);
      break;
    case "status":
    case undefined:
      status(rootDir);
      break;
    case "disconnect":
      disconnect(rootDir);
      break;
    default:
      console.error(`${c.red}Unknown workspace subcommand: ${subcommand}${c.reset}`);
      console.error(`Usage: secops-squad workspace [connect|status|disconnect]`);
      process.exit(1);
  }
}

module.exports = { run };
