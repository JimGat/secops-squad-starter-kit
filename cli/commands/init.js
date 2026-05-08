"use strict";

const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { execSync } = require("child_process");

// ANSI color helpers — no dependencies
const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  red: "\x1b[31m",
  magenta: "\x1b[35m",
  white: "\x1b[37m",
};

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONFIG_FILE = "secops-squad.config.json";
const SCHEMA_FILE = "secops-squad.config.schema.json";
const SQUAD_DIR = ".squad";

const PERSONA_FILES = ["team.md", "routing.md", "skills.json", "ceremonies.md"];

function printBanner() {
  console.log(`
${c.cyan}${c.bold}  ┌─────────────────────────────────────────┐
  │                                         │
  │   ⚔️  secops-squad init                  │
  │   SecOps team setup wizard              │
  │                                         │
  └─────────────────────────────────────────┘${c.reset}
`);
}

function discoverPersonas(rootDir) {
  const personasDir = path.join(rootDir, "personas");
  if (!fs.existsSync(personasDir)) return [];

  return fs
    .readdirSync(personasDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => {
      const name = d.name;
      const readmePath = path.join(personasDir, name, "README.md");
      let description = "";
      let hasFiles = false;

      if (fs.existsSync(readmePath)) {
        const content = fs.readFileSync(readmePath, "utf8");
        // First non-heading, non-empty line as description
        const lines = content.split("\n");
        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith("#")) {
            description = trimmed;
            break;
          }
        }
        hasFiles = true;
      }

      // Check if persona has the required files
      const fileCount = PERSONA_FILES.filter((f) =>
        fs.existsSync(path.join(personasDir, name, f))
      ).length;

      return {
        name,
        description: description || `${name} persona`,
        ready: fileCount === PERSONA_FILES.length,
        fileCount,
      };
    });
}

function createPrompt() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  // Handle Ctrl+C gracefully
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

function tryAzDiscovery() {
  try {
    const result = execSync("az account show --output json 2>&1", {
      encoding: "utf8",
      timeout: 10000,
    });
    const account = JSON.parse(result);
    return {
      subscriptionId: account.id || "",
      tenantId: account.tenantId || "",
      subscriptionName: account.name || "",
    };
  } catch {
    return null;
  }
}

function validateConfig(config, schemaPath) {
  if (!fs.existsSync(schemaPath)) return [];

  const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
  const errors = [];

  // Basic validation against schema
  if (schema.required) {
    for (const field of schema.required) {
      if (!(field in config)) {
        errors.push(`Missing required field: ${field}`);
      }
    }
  }

  if (schema.properties) {
    if (schema.properties.persona && schema.properties.persona.enum) {
      if (config.persona && !schema.properties.persona.enum.includes(config.persona)) {
        errors.push(
          `Invalid persona: ${config.persona}. Must be one of: ${schema.properties.persona.enum.join(", ")}`
        );
      }
    }

    if (config.azure) {
      if (config.azure.subscriptionId && !GUID_RE.test(config.azure.subscriptionId)) {
        errors.push("Invalid Azure subscription ID format (expected GUID)");
      }
      if (config.azure.tenantId && !GUID_RE.test(config.azure.tenantId)) {
        errors.push("Invalid Azure tenant ID format (expected GUID)");
      }
    }

    if (config.sentinel) {
      if (config.sentinel.workspaceId && !GUID_RE.test(config.sentinel.workspaceId)) {
        errors.push("Invalid Sentinel workspace ID format (expected GUID)");
      }
    }
  }

  return errors;
}

function copyPersonaFiles(rootDir, personaName) {
  const srcDir = path.join(rootDir, "personas", personaName);
  const destDir = path.join(rootDir, SQUAD_DIR);

  let copied = 0;
  let skipped = 0;

  for (const file of PERSONA_FILES) {
    const src = path.join(srcDir, file);
    const dest = path.join(destDir, file);

    if (!fs.existsSync(src)) continue;

    if (fs.existsSync(dest)) {
      skipped++;
      continue;
    }

    fs.copyFileSync(src, dest);
    copied++;
  }

  return { copied, skipped };
}

async function run(args) {
  // Find project root (where package.json lives)
  let rootDir = process.cwd();
  const pkgPath = path.join(rootDir, "package.json");

  // Support --no-interactive mode with --persona flag
  const nonInteractive = args.includes("--no-interactive");
  const personaIdx = args.indexOf("--persona");
  const presetPersona = personaIdx !== -1 ? args[personaIdx + 1] : null;

  printBanner();

  // Check for existing config
  const configPath = path.join(rootDir, CONFIG_FILE);
  if (fs.existsSync(configPath)) {
    console.log(
      `${c.yellow}⚠️  Found existing ${CONFIG_FILE}${c.reset}`
    );
    if (nonInteractive) {
      console.log(`${c.dim}  Re-running init will update persona files but keep config.${c.reset}\n`);
    } else {
      const { rl, ask } = createPrompt();
      const answer = await ask(
        `${c.yellow}  Overwrite existing configuration? (y/N): ${c.reset}`
      );
      if (answer.toLowerCase() !== "y") {
        console.log(`\n${c.green}Keeping existing config. Run ${c.bold}secops-squad doctor${c.reset}${c.green} to validate.${c.reset}`);
        rl.close();
        return;
      }
      rl.close();
    }
  }

  // Discover personas
  const personas = discoverPersonas(rootDir);
  if (personas.length === 0) {
    console.error(
      `${c.red}❌ No personas found in personas/ directory.${c.reset}`
    );
    process.exit(1);
  }

  const config = {};
  let selectedPersona;

  if (nonInteractive && presetPersona) {
    // Non-interactive mode
    selectedPersona = personas.find((p) => p.name === presetPersona);
    if (!selectedPersona) {
      console.error(
        `${c.red}❌ Unknown persona: ${presetPersona}${c.reset}`
      );
      console.error(
        `Available: ${personas.map((p) => p.name).join(", ")}`
      );
      process.exit(1);
    }
    config.teamName = selectedPersona.name;
    config.persona = selectedPersona.name;
  } else {
    // Interactive mode
    const { rl, ask } = createPrompt();

    // Step 1: Team name
    const defaultName = path.basename(rootDir);
    const teamName = await ask(
      `${c.cyan}? ${c.bold}Team name${c.reset} ${c.dim}(${defaultName})${c.reset}: `
    );
    config.teamName = teamName || defaultName;

    // Step 2: Persona selection
    console.log(`\n${c.cyan}? ${c.bold}What persona fits your team?${c.reset}\n`);
    personas.forEach((p, i) => {
      const status = p.ready ? `${c.green}ready${c.reset}` : `${c.dim}scaffold only${c.reset}`;
      console.log(
        `  ${c.bold}${i + 1}.${c.reset} ${c.cyan}${p.name}${c.reset} [${status}]`
      );
      console.log(`     ${c.dim}${p.description}${c.reset}`);
    });

    let choice;
    while (true) {
      const input = await ask(
        `\n${c.cyan}  Enter number (1-${personas.length}): ${c.reset}`
      );
      const num = parseInt(input, 10);
      if (num >= 1 && num <= personas.length) {
        choice = num - 1;
        break;
      }
      console.log(`${c.red}  Please enter a number between 1 and ${personas.length}.${c.reset}`);
    }

    selectedPersona = personas[choice];
    config.persona = selectedPersona.name;
    console.log(
      `\n${c.green}  ✓ Selected: ${c.bold}${selectedPersona.name}${c.reset}`
    );

    // Step 3: Azure connection
    console.log(`\n${c.cyan}? ${c.bold}Do you have an Azure subscription connected?${c.reset}`);
    const hasAzure = await ask(`  ${c.dim}(y/N):${c.reset} `);

    if (hasAzure.toLowerCase() === "y") {
      // Try az CLI discovery first
      console.log(`\n${c.dim}  Checking Azure CLI...${c.reset}`);
      const discovered = tryAzDiscovery();

      if (discovered && discovered.subscriptionId) {
        console.log(
          `${c.green}  ✓ Found Azure subscription: ${c.bold}${discovered.subscriptionName}${c.reset}`
        );
        console.log(
          `${c.dim}    Subscription: ${discovered.subscriptionId}${c.reset}`
        );
        console.log(
          `${c.dim}    Tenant:       ${discovered.tenantId}${c.reset}`
        );

        const useDiscovered = await ask(
          `\n  ${c.cyan}Use this subscription? (Y/n):${c.reset} `
        );

        if (useDiscovered.toLowerCase() !== "n") {
          config.azure = {
            subscriptionId: discovered.subscriptionId,
            tenantId: discovered.tenantId,
          };
        }
      }

      if (!config.azure) {
        // Manual entry
        console.log(
          `\n${c.dim}  Enter Azure details (leave blank to skip):${c.reset}`
        );

        const subId = await ask(`  ${c.cyan}Subscription ID: ${c.reset}`);
        const tenantId = await ask(`  ${c.cyan}Tenant ID:       ${c.reset}`);

        if (subId || tenantId) {
          config.azure = {};
          if (subId) {
            if (!GUID_RE.test(subId)) {
              console.log(`${c.yellow}  ⚠️  Subscription ID doesn't look like a GUID — saving anyway.${c.reset}`);
            }
            config.azure.subscriptionId = subId;
          }
          if (tenantId) {
            if (!GUID_RE.test(tenantId)) {
              console.log(`${c.yellow}  ⚠️  Tenant ID doesn't look like a GUID — saving anyway.${c.reset}`);
            }
            config.azure.tenantId = tenantId;
          }
        }
      }

      // Sentinel workspace (optional)
      console.log(
        `\n${c.cyan}? ${c.bold}Sentinel workspace details${c.reset} ${c.dim}(optional, press Enter to skip)${c.reset}`
      );

      const wsId = await ask(`  ${c.cyan}Workspace ID:   ${c.reset}`);
      const wsName = await ask(`  ${c.cyan}Workspace name: ${c.reset}`);
      const wsRg = await ask(`  ${c.cyan}Resource group: ${c.reset}`);

      if (wsId || wsName || wsRg) {
        config.sentinel = {};
        if (wsId) config.sentinel.workspaceId = wsId;
        if (wsName) config.sentinel.workspaceName = wsName;
        if (wsRg) config.sentinel.resourceGroup = wsRg;
      }
    } else {
      console.log(
        `\n${c.dim}  No problem — connect later with: ${c.cyan}secops-squad workspace connect${c.reset}`
      );
    }

    rl.close();
  }

  // Validate config against schema
  const schemaPath = path.join(rootDir, SCHEMA_FILE);
  const errors = validateConfig(config, schemaPath);
  if (errors.length > 0) {
    console.log(`\n${c.yellow}⚠️  Config validation warnings:${c.reset}`);
    errors.forEach((e) => console.log(`   ${c.yellow}• ${e}${c.reset}`));
  }

  // Write config
  if (config.azure && Object.keys(config.azure).length === 0) delete config.azure;
  if (config.sentinel && Object.keys(config.sentinel).length === 0) delete config.sentinel;

  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", "utf8");
  console.log(`\n${c.green}✅ Written ${c.bold}${CONFIG_FILE}${c.reset}`);

  // Copy persona files
  if (selectedPersona.ready) {
    const { copied, skipped } = copyPersonaFiles(rootDir, selectedPersona.name);
    if (copied > 0) {
      console.log(
        `${c.green}✅ Installed ${c.bold}${selectedPersona.name}${c.reset}${c.green} persona files (${copied} copied)${c.reset}`
      );
    }
    if (skipped > 0) {
      console.log(
        `${c.dim}   ${skipped} file(s) already existed in ${SQUAD_DIR}/ — kept existing${c.reset}`
      );
    }
  } else {
    console.log(
      `${c.yellow}⚠️  Persona ${c.bold}${selectedPersona.name}${c.reset}${c.yellow} is a scaffold — persona files not yet available.${c.reset}`
    );
    console.log(
      `${c.dim}   The persona directory exists but needs team.md, routing.md, etc.${c.reset}`
    );
  }

  // Success!
  console.log(`
${c.green}${c.bold}✅ Ready! Your ${selectedPersona.name} team is set up.${c.reset}

${c.cyan}Next steps:${c.reset}
  ${c.bold}1.${c.reset} Run ${c.cyan}secops-squad doctor${c.reset} to verify your environment
  ${c.bold}2.${c.reset} Review ${c.cyan}.squad/team.md${c.reset} to see your team roster
  ${c.bold}3.${c.reset} Run ${c.cyan}secops-squad status${c.reset} to see loaded skills${
    !config.azure
      ? `\n  ${c.bold}4.${c.reset} Validate your environment with ${c.cyan}secops-squad env validate${c.reset}`
      : ""
  }
`);
}

module.exports = { run };
