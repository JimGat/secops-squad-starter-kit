"use strict";

const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { execSync } = require("child_process");

const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
};

const CONFIG_FILE = "secops-squad.config.json";

/**
 * Parse description from a .bicep file's header comments.
 */
function parseBicepDescription(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  const lines = content.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    // Look for description in header comments
    if (trimmed.startsWith("//") && !trimmed.startsWith("// ===")) {
      const text = trimmed.replace(/^\/\/\s*/, "").trim();
      if (text.length > 10 && !text.startsWith("─") && !text.startsWith("===")) {
        return text;
      }
    }
  }

  return "No description available";
}

/**
 * Scan templates/bicep/soar/ for available playbooks.
 */
function scanPlaybooks(rootDir) {
  const soarDir = path.join(rootDir, "templates", "bicep", "soar");
  if (!fs.existsSync(soarDir)) return [];

  return fs
    .readdirSync(soarDir)
    .filter((f) => f.endsWith(".bicep") && f !== "main.bicep")
    .map((f) => {
      const filePath = path.join(soarDir, f);
      return {
        name: path.basename(f, ".bicep"),
        file: f,
        path: filePath,
        description: parseBicepDescription(filePath),
      };
    });
}

/**
 * Read project config and extract Azure parameters.
 */
function readConfig(rootDir) {
  const configPath = path.join(rootDir, CONFIG_FILE);
  if (!fs.existsSync(configPath)) return null;

  try {
    return JSON.parse(fs.readFileSync(configPath, "utf8"));
  } catch {
    return null;
  }
}

/**
 * Check if Azure CLI is available and authenticated.
 */
function checkAzCli() {
  try {
    execSync("az account show --output none 2>&1", {
      encoding: "utf8",
      timeout: 10000,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { ok: true };
  } catch (err) {
    // Check if az is even installed
    try {
      execSync("az --version", {
        encoding: "utf8",
        timeout: 5000,
        stdio: ["pipe", "pipe", "pipe"],
      });
      return { ok: false, error: "Azure CLI installed but not authenticated. Run: az login" };
    } catch {
      return { ok: false, error: "Azure CLI not found. Install from: https://aka.ms/installazurecliwindows" };
    }
  }
}

/**
 * Extract Bicep parameters from a template file.
 */
function extractBicepParams(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  const params = [];
  const paramRegex = /^param\s+(\w+)\s+(\w+)(?:\s*=\s*(.+))?/gm;
  let match;

  while ((match = paramRegex.exec(content)) !== null) {
    const descMatch = content.slice(0, match.index).match(/@description\('([^']+)'\)\s*$/);
    params.push({
      name: match[1],
      type: match[2],
      default: match[3] ? match[3].trim() : null,
      description: descMatch ? descMatch[1] : "",
      required: !match[3],
    });
  }

  return params;
}

function handleList(rootDir) {
  const playbooks = scanPlaybooks(rootDir);

  if (playbooks.length === 0) {
    console.log(
      `\n${c.yellow}No playbooks found in templates/bicep/soar/.${c.reset}\n`
    );
    return;
  }

  console.log(`\n${c.bold}Available SOAR Playbooks${c.reset}\n`);

  const nameW = Math.max(20, ...playbooks.map((p) => p.name.length)) + 2;

  for (const pb of playbooks) {
    console.log(
      `  ${c.cyan}${pb.name.padEnd(nameW)}${c.reset}${c.dim}${pb.description}${c.reset}`
    );
  }

  console.log(`\n${c.dim}${playbooks.length} playbook(s) available${c.reset}\n`);
}

async function handleDeploy(args, rootDir) {
  const name = args.find((a) => !a.startsWith("--"));
  const dryRun = args.includes("--dry-run");

  if (!name) {
    console.error(
      `${c.red}❌ Playbook name required: secops-squad playbook deploy <name>${c.reset}`
    );
    process.exit(1);
  }

  const playbooks = scanPlaybooks(rootDir);
  const playbook = playbooks.find((p) => p.name === name);

  if (!playbook) {
    console.error(`${c.red}❌ Playbook '${name}' not found.${c.reset}`);
    console.log(`\n${c.cyan}Available playbooks:${c.reset}`);
    for (const p of playbooks) {
      console.log(`  ${p.name}`);
    }
    process.exit(1);
  }

  // Check Azure CLI
  if (!dryRun) {
    const azCheck = checkAzCli();
    if (!azCheck.ok) {
      console.error(`${c.red}❌ ${azCheck.error}${c.reset}`);
      process.exit(1);
    }
  }

  // Read config for Azure parameters
  const config = readConfig(rootDir);
  const params = extractBicepParams(playbook.path);

  // Build parameter values from config
  const paramValues = {};
  for (const param of params) {
    if (param.name === "location" && param.default) continue; // Uses default
    if (param.name === "workspaceName" && config?.sentinel?.workspaceName) {
      paramValues[param.name] = config.sentinel.workspaceName;
    } else if (param.name === "workspaceResourceGroup" && config?.sentinel?.resourceGroup) {
      paramValues[param.name] = config.sentinel.resourceGroup;
    } else if (param.required && !param.default) {
      paramValues[param.name] = `<${param.name}>`;
    }
  }

  // Build the az deployment command
  const resourceGroup = config?.sentinel?.resourceGroup || "<resource-group>";
  const templatePath = path.relative(rootDir, playbook.path).replace(/\\/g, "/");

  let cmd = `az deployment group create \\\n`;
  cmd += `  --resource-group ${resourceGroup} \\\n`;
  cmd += `  --template-file ${templatePath}`;

  if (Object.keys(paramValues).length > 0) {
    cmd += ` \\\n  --parameters`;
    for (const [key, value] of Object.entries(paramValues)) {
      cmd += ` ${key}="${value}"`;
    }
  }

  console.log(`\n${c.cyan}${c.bold}Deploy: ${name}${c.reset}`);
  console.log(`${c.dim}${playbook.description}${c.reset}\n`);

  // Show required parameters
  const requiredParams = params.filter((p) => p.required && !p.default);
  if (requiredParams.length > 0) {
    console.log(`${c.bold}Required parameters:${c.reset}`);
    for (const p of requiredParams) {
      const fromConfig = paramValues[p.name] && !paramValues[p.name].startsWith("<");
      const source = fromConfig ? `${c.green}(from config)${c.reset}` : `${c.yellow}(needs value)${c.reset}`;
      console.log(
        `  ${c.cyan}${p.name}${c.reset} (${p.type}) ${source}`
      );
      if (p.description) {
        console.log(`    ${c.dim}${p.description}${c.reset}`);
      }
    }
    console.log("");
  }

  console.log(`${c.bold}Command:${c.reset}\n`);
  console.log(`  ${c.cyan}${cmd}${c.reset}\n`);

  if (dryRun) {
    console.log(`${c.dim}--dry-run: Command shown but not executed.${c.reset}\n`);
    return;
  }

  // Ask for confirmation
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const answer = await new Promise((resolve) => {
    rl.question(
      `${c.yellow}Execute this deployment? (y/N): ${c.reset}`,
      (ans) => resolve(ans.trim())
    );
  });

  rl.close();

  if (answer.toLowerCase() !== "y") {
    console.log(`\n${c.dim}Deployment cancelled.${c.reset}\n`);
    return;
  }

  // Check for placeholder values
  const hasPlaceholders = Object.values(paramValues).some((v) =>
    v.startsWith("<")
  );
  if (hasPlaceholders) {
    console.error(
      `\n${c.red}❌ Cannot deploy — some parameters still have placeholder values.${c.reset}`
    );
    console.error(
      `${c.dim}Update secops-squad.config.json with your Azure details or provide values manually.${c.reset}\n`
    );
    process.exit(1);
  }

  console.log(`\n${c.cyan}Deploying...${c.reset}\n`);
  try {
    const output = execSync(
      `az deployment group create --resource-group ${resourceGroup} --template-file "${playbook.path}" --parameters ${Object.entries(paramValues).map(([k, v]) => `${k}="${v}"`).join(" ")}`,
      { encoding: "utf8", stdio: "inherit", timeout: 300000 }
    );
    console.log(`\n${c.green}✅ Deployment complete.${c.reset}\n`);
  } catch (err) {
    console.error(`\n${c.red}❌ Deployment failed.${c.reset}\n`);
    process.exit(1);
  }
}

function printHelp() {
  console.log(`
${c.cyan}${c.bold}secops-squad playbook${c.reset} — SOAR playbook management

${c.bold}Usage:${c.reset}
  secops-squad playbook list
  secops-squad playbook deploy <name> [--dry-run]

${c.bold}Subcommands:${c.reset}
  list      List available SOAR playbooks
  deploy    Generate and optionally execute deployment command

${c.bold}Options:${c.reset}
  --dry-run  Show the deployment command without executing

${c.bold}Examples:${c.reset}
  secops-squad playbook list
  secops-squad playbook deploy phishing-response --dry-run
  secops-squad playbook deploy teams-notification
`);
}

async function run(args) {
  const rootDir = process.cwd();

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    printHelp();
    return;
  }

  const subcommand = args[0];
  const subArgs = args.slice(1);

  switch (subcommand) {
    case "list":
      handleList(rootDir);
      break;
    case "deploy":
      await handleDeploy(subArgs, rootDir);
      break;
    default:
      console.error(`${c.red}Unknown subcommand: ${subcommand}${c.reset}`);
      printHelp();
      process.exit(1);
  }
}

module.exports = { run };
