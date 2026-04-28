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
  magenta: "\x1b[35m",
};

const SQUAD_DIR = ".squad";
const CONFIG_FILE = "secops-squad.config.json";
const PERSONA_FILES = ["team.md", "routing.md", "skills.json", "ceremonies.md"];

/**
 * Discover personas from the personas/ directory.
 */
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

      if (fs.existsSync(readmePath)) {
        const content = fs.readFileSync(readmePath, "utf8");
        for (const line of content.split("\n")) {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith("#")) {
            description = trimmed;
            break;
          }
        }
      }

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

/**
 * Parse a skills.json file and return skill names.
 */
function parseSkillNames(skillsPath) {
  if (!fs.existsSync(skillsPath)) return [];

  try {
    const data = JSON.parse(fs.readFileSync(skillsPath, "utf8"));
    const names = new Set();

    if (data.skills?.shared) {
      for (const s of data.skills.shared) names.add(s.name);
    }
    if (data.skills?.per_agent) {
      for (const agentSkills of Object.values(data.skills.per_agent)) {
        for (const s of agentSkills) names.add(s.name);
      }
    }

    return [...names];
  } catch {
    return [];
  }
}

function handleList(rootDir) {
  const personas = discoverPersonas(rootDir);

  if (personas.length === 0) {
    console.log(`\n${c.yellow}No personas found in personas/ directory.${c.reset}\n`);
    return;
  }

  // Check current persona
  let currentPersona = null;
  const configPath = path.join(rootDir, CONFIG_FILE);
  if (fs.existsSync(configPath)) {
    try {
      const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
      currentPersona = config.persona;
    } catch { /* ignore */ }
  }

  console.log(`\n${c.bold}Available Personas${c.reset}\n`);

  for (const p of personas) {
    const active = p.name === currentPersona ? ` ${c.green}(active)${c.reset}` : "";
    const status = p.ready
      ? `${c.green}ready${c.reset}`
      : `${c.dim}scaffold (${p.fileCount}/${PERSONA_FILES.length} files)${c.reset}`;

    console.log(`  ${c.cyan}${c.bold}${p.name}${c.reset}${active} [${status}]`);
    console.log(`    ${c.dim}${p.description}${c.reset}`);
  }

  console.log(`\n${c.dim}${personas.length} persona(s) available${c.reset}\n`);
}

function handleSwitch(args, rootDir) {
  const name = args[0];
  if (!name) {
    console.error(`${c.red}❌ Persona name required: secops-squad persona switch <name>${c.reset}`);
    process.exit(1);
  }

  const personas = discoverPersonas(rootDir);
  const persona = personas.find((p) => p.name === name);

  if (!persona) {
    console.error(`${c.red}❌ Unknown persona: ${name}${c.reset}`);
    console.log(`\n${c.cyan}Available personas:${c.reset}`);
    for (const p of personas) {
      console.log(`  ${p.name}`);
    }
    process.exit(1);
  }

  if (!persona.ready) {
    console.error(
      `${c.red}❌ Persona '${name}' is a scaffold — missing required files.${c.reset}`
    );
    console.error(
      `${c.dim}   Has ${persona.fileCount}/${PERSONA_FILES.length} files. Needs: ${PERSONA_FILES.join(", ")}${c.reset}`
    );
    process.exit(1);
  }

  const squadDir = path.join(rootDir, SQUAD_DIR);
  const srcDir = path.join(rootDir, "personas", name);

  // Determine what skills will change
  const currentSkillsPath = path.join(squadDir, "skills.json");
  const newSkillsPath = path.join(srcDir, "skills.json");
  const currentSkills = parseSkillNames(currentSkillsPath);
  const newSkills = parseSkillNames(newSkillsPath);

  const added = newSkills.filter((s) => !currentSkills.includes(s));
  const removed = currentSkills.filter((s) => !newSkills.includes(s));
  const kept = newSkills.filter((s) => currentSkills.includes(s));

  // Back up current config files
  const backupDir = path.join(squadDir, "backups", `pre-switch-${Date.now()}`);
  let backedUp = 0;
  for (const file of PERSONA_FILES) {
    const src = path.join(squadDir, file);
    if (fs.existsSync(src)) {
      if (!fs.existsSync(backupDir)) {
        fs.mkdirSync(backupDir, { recursive: true });
      }
      fs.copyFileSync(src, path.join(backupDir, file));
      backedUp++;
    }
  }

  if (backedUp > 0) {
    console.log(
      `\n${c.dim}  Backed up ${backedUp} file(s) to ${path.relative(rootDir, backupDir)}${c.reset}`
    );
  }

  // Copy new persona files
  let copied = 0;
  for (const file of PERSONA_FILES) {
    const src = path.join(srcDir, file);
    const dest = path.join(squadDir, file);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, dest);
      copied++;
    }
  }

  // Update config file
  const configPath = path.join(rootDir, CONFIG_FILE);
  if (fs.existsSync(configPath)) {
    try {
      const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
      config.persona = name;
      fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", "utf8");
    } catch { /* leave config as-is */ }
  }

  // Report
  console.log(
    `\n${c.green}✅ Switched to persona: ${c.bold}${name}${c.reset}`
  );
  console.log(`${c.dim}   Installed ${copied} persona files${c.reset}`);

  if (added.length > 0 || removed.length > 0) {
    console.log(`\n${c.bold}  Skill changes:${c.reset}`);
    for (const s of added) {
      console.log(`    ${c.green}+ ${s}${c.reset}`);
    }
    for (const s of removed) {
      console.log(`    ${c.red}- ${s}${c.reset}`);
    }
    if (kept.length > 0) {
      console.log(`    ${c.dim}  ${kept.length} skill(s) unchanged${c.reset}`);
    }
  }

  console.log(
    `\n${c.dim}Run ${c.cyan}secops-squad doctor${c.reset}${c.dim} to verify the new configuration.${c.reset}\n`
  );
}

function printHelp() {
  console.log(`
${c.cyan}${c.bold}secops-squad persona${c.reset} — Manage personas

${c.bold}Usage:${c.reset}
  secops-squad persona list
  secops-squad persona switch <name>

${c.bold}Subcommands:${c.reset}
  list      Show available personas with descriptions
  switch    Switch to a different persona (backs up current config)

${c.bold}Examples:${c.reset}
  secops-squad persona list
  secops-squad persona switch detection-engineering
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
    case "switch":
      handleSwitch(subArgs, rootDir);
      break;
    default:
      console.error(`${c.red}Unknown subcommand: ${subcommand}${c.reset}`);
      printHelp();
      process.exit(1);
  }
}

module.exports = { run };
