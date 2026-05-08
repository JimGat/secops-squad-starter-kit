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

function execAz(cmd, opts = {}) {
  const timeout = opts.timeout || 30000;
  const stdio = opts.inherit ? "inherit" : ["pipe", "pipe", "pipe"];
  try {
    const result = execSync(cmd, { encoding: "utf8", timeout, stdio });
    return typeof result === "string" ? result.trim() : "";
  } catch (err) {
    if (opts.allowFail) return null;
    throw err;
  }
}

function execSafe(cmd) {
  return execAz(cmd, { allowFail: true, timeout: 10000 });
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
 * workspace connect — auto-discover Sentinel workspaces from Azure, write config
 */
async function connect(rootDir) {
  console.log(`\n${c.cyan}${c.bold}secops-squad workspace connect${c.reset}\n`);

  // ── Step 1: Check az CLI is installed ──
  const azVersion = execSafe("az version --output json");
  if (!azVersion) {
    fatal(
      `Azure CLI (az) is not installed or not on PATH.\n` +
      `  Install it from: https://aka.ms/installazurecli\n` +
      `  Then re-run: secops-squad workspace connect`
    );
  }

  // ── Step 2: Ensure user is logged in ──
  let accountJson = execSafe("az account show --output json");
  if (!accountJson) {
    console.log(`${c.yellow}⚠️  Not logged in to Azure. Launching browser login...${c.reset}\n`);
    try {
      execAz("az login", { inherit: true, timeout: 120000 });
    } catch {
      fatal("Azure login failed or was cancelled. Please run 'az login' manually and retry.");
    }
    accountJson = execSafe("az account show --output json");
    if (!accountJson) {
      fatal("Still not logged in after az login. Please check your credentials.");
    }
  }

  const currentAccount = JSON.parse(accountJson);
  console.log(`${c.green}✅ Azure logged in${c.reset}`);
  console.log(`   ${c.bold}Tenant:${c.reset} ${currentAccount.tenantId || "(unknown)"}\n`);

  // ── Step 3: List subscriptions and let user pick ──
  let subsJson;
  try {
    subsJson = execAz("az account list --output json --all");
  } catch {
    fatal("Failed to list Azure subscriptions. Check your Azure CLI installation.");
  }

  const allSubs = JSON.parse(subsJson).filter((s) => s.state === "Enabled");
  if (allSubs.length === 0) {
    fatal("No enabled Azure subscriptions found for this account.");
  }

  let selectedSub;
  if (allSubs.length === 1) {
    selectedSub = allSubs[0];
    console.log(`${c.cyan}Using subscription:${c.reset} ${selectedSub.name} (${selectedSub.id})\n`);
  } else {
    console.log(`${c.bold}Available subscriptions:${c.reset}\n`);
    for (let i = 0; i < allSubs.length; i++) {
      const marker = allSubs[i].isDefault ? ` ${c.green}(current)${c.reset}` : "";
      console.log(`  ${c.cyan}${i + 1}.${c.reset} ${allSubs[i].name} ${c.dim}(${allSubs[i].id})${c.reset}${marker}`);
    }

    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    let choice;
    try {
      const defaultIdx = allSubs.findIndex((s) => s.isDefault);
      const defaultLabel = defaultIdx >= 0 ? ` [${defaultIdx + 1}]` : "";
      choice = (await prompt(rl, `\n  ${c.bold}Select subscription${c.reset}${defaultLabel}: `)).trim();
    } finally {
      rl.close();
    }

    if (!choice) {
      const defaultIdx = allSubs.findIndex((s) => s.isDefault);
      selectedSub = defaultIdx >= 0 ? allSubs[defaultIdx] : allSubs[0];
    } else {
      const idx = parseInt(choice, 10);
      if (isNaN(idx) || idx < 1 || idx > allSubs.length) {
        fatal(`Invalid selection: ${choice}. Enter a number between 1 and ${allSubs.length}.`);
      }
      selectedSub = allSubs[idx - 1];
    }
    console.log(`\n${c.cyan}Selected:${c.reset} ${selectedSub.name}\n`);
  }

  // ── Step 4: Set active subscription ──
  try {
    execAz(`az account set --subscription "${selectedSub.id}"`);
  } catch {
    fatal(`Failed to set subscription to ${selectedSub.name} (${selectedSub.id}).`);
  }

  // ── Step 5: List Log Analytics workspaces ──
  console.log(`${c.dim}Discovering Log Analytics workspaces...${c.reset}`);

  let workspacesJson;
  try {
    workspacesJson = execAz(
      `az monitor log-analytics workspace list --subscription "${selectedSub.id}" --output json`
    );
  } catch {
    fatal(
      `Failed to list Log Analytics workspaces in subscription "${selectedSub.name}".\n` +
      `  Ensure you have Reader permissions on the subscription.`
    );
  }

  const laWorkspaces = JSON.parse(workspacesJson);
  if (laWorkspaces.length === 0) {
    fatal(
      `No Log Analytics workspaces found in subscription "${selectedSub.name}".\n` +
      `  Try a different subscription or create a workspace in the Azure portal first.`
    );
  }

  // ── Step 6: Check Sentinel (SecurityInsights solution) on each workspace ──
  console.log(`${c.dim}Checking Sentinel status on ${laWorkspaces.length} workspace(s)...${c.reset}\n`);

  const workspaceCandidates = [];
  for (const ws of laWorkspaces) {
    const wsName = ws.name;
    // Extract resource group from the resource ID: /subscriptions/.../resourceGroups/<rg>/...
    const rgMatch = (ws.id || "").match(/\/resourceGroups\/([^/]+)/i);
    const rg = rgMatch ? rgMatch[1] : "";

    let sentinelEnabled = false;
    const sentinelUrl =
      `https://management.azure.com/subscriptions/${selectedSub.id}` +
      `/resourceGroups/${rg}` +
      `/providers/Microsoft.OperationsManagement/solutions/SecurityInsights(${wsName})` +
      `?api-version=2015-11-01-preview`;

    const sentinelResult = execAz(
      `az rest --method get --url "${sentinelUrl}" --output json`,
      { allowFail: true }
    );
    if (sentinelResult) {
      sentinelEnabled = true;
    }

    workspaceCandidates.push({
      name: wsName,
      resourceGroup: rg,
      customerId: ws.customerId || "",
      location: ws.location || "",
      sku: (ws.sku && ws.sku.name) || "",
      sentinelEnabled,
    });
  }

  // ── Step 7: Present workspaces to user ──
  const sentinelWorkspaces = workspaceCandidates.filter((w) => w.sentinelEnabled);
  const nonSentinelWorkspaces = workspaceCandidates.filter((w) => !w.sentinelEnabled);

  let pickList;
  if (sentinelWorkspaces.length > 0) {
    pickList = sentinelWorkspaces;
    console.log(`${c.green}✅ Found ${sentinelWorkspaces.length} Sentinel-enabled workspace(s):${c.reset}\n`);
  } else {
    pickList = workspaceCandidates;
    console.log(
      `${c.yellow}⚠️  No Sentinel-enabled workspaces found. ` +
      `Listing all ${workspaceCandidates.length} Log Analytics workspace(s):${c.reset}\n`
    );
  }

  for (let i = 0; i < pickList.length; i++) {
    const w = pickList[i];
    const sentinel = w.sentinelEnabled ? `${c.green}Sentinel${c.reset}` : `${c.dim}no Sentinel${c.reset}`;
    console.log(
      `  ${c.cyan}${i + 1}.${c.reset} ${c.bold}${w.name}${c.reset}` +
      `  ${c.dim}rg:${c.reset}${w.resourceGroup}` +
      `  ${c.dim}region:${c.reset}${w.location}` +
      `  [${sentinel}]`
    );
  }

  if (nonSentinelWorkspaces.length > 0 && sentinelWorkspaces.length > 0) {
    console.log(
      `\n  ${c.dim}(${nonSentinelWorkspaces.length} workspace(s) without Sentinel omitted)${c.reset}`
    );
  }

  let selectedWs;
  if (pickList.length === 1) {
    selectedWs = pickList[0];
    console.log(`\n${c.cyan}Auto-selected:${c.reset} ${selectedWs.name}\n`);
  } else {
    const rl2 = readline.createInterface({ input: process.stdin, output: process.stdout });
    let wsChoice;
    try {
      wsChoice = (await prompt(rl2, `\n  ${c.bold}Select workspace${c.reset} [1]: `)).trim();
    } finally {
      rl2.close();
    }

    if (!wsChoice) {
      selectedWs = pickList[0];
    } else {
      const idx = parseInt(wsChoice, 10);
      if (isNaN(idx) || idx < 1 || idx > pickList.length) {
        fatal(`Invalid selection: ${wsChoice}. Enter a number between 1 and ${pickList.length}.`);
      }
      selectedWs = pickList[idx - 1];
    }
    console.log(`\n${c.cyan}Selected:${c.reset} ${selectedWs.name}\n`);
  }

  // ── Step 8: Write workspace YAML ──
  ensureSecopsDirs(rootDir);

  const workspaceData = {
    schema_version: "1.0",
    name: selectedWs.name,
    workspace_id: selectedWs.customerId,
    resource_group: selectedWs.resourceGroup,
    subscription: selectedSub.id,
    region: selectedWs.location,
    sentinel_enabled: selectedWs.sentinelEnabled,
    tier: selectedWs.sku || null,
  };

  const workspacePath = path.join(rootDir, ".secops", "workspaces", `${selectedWs.name}.yaml`);
  fs.writeFileSync(workspacePath, yaml.dump(workspaceData, { lineWidth: 120 }), "utf8");
  console.log(`${c.green}✅ Workspace config written:${c.reset} .secops/workspaces/${selectedWs.name}.yaml`);

  // ── Step 9: Update environment.yaml default_workspace ──
  let envData = loadEnvironment(rootDir) || { schema_version: "1.0" };
  envData.default_workspace = selectedWs.name;
  saveEnvironment(rootDir, envData);
  console.log(`${c.green}✅ Default workspace set to:${c.reset} ${c.cyan}${selectedWs.name}${c.reset}\n`);

  // Summary
  console.log(`${c.dim}  Workspace ID:    ${selectedWs.customerId}${c.reset}`);
  console.log(`${c.dim}  Resource group:   ${selectedWs.resourceGroup}${c.reset}`);
  console.log(`${c.dim}  Subscription:     ${selectedSub.name} (${selectedSub.id})${c.reset}`);
  console.log(`${c.dim}  Region:           ${selectedWs.location}${c.reset}`);
  console.log(`${c.dim}  Sentinel:         ${selectedWs.sentinelEnabled ? "enabled" : "not detected"}${c.reset}`);
  console.log(`${c.dim}  Tier:             ${selectedWs.sku || "unknown"}${c.reset}\n`);
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

  console.log(`  ${c.bold}Workspace ID:${c.reset}      ${wsData.workspace_id || "(not set)"}`);
  console.log(`  ${c.bold}Resource group:${c.reset}    ${wsData.resource_group || "(not set)"}`);
  console.log(`  ${c.bold}Subscription:${c.reset}      ${wsData.subscription || "(not set)"}`);
  console.log(`  ${c.bold}Region:${c.reset}            ${wsData.region || "(not set)"}`);
  console.log(`  ${c.bold}Sentinel:${c.reset}          ${wsData.sentinel_enabled ? "enabled" : "not detected"}`);

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
