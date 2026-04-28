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

const VALID_CATEGORIES = [
  "kql",
  "soar",
  "detection",
  "log-analytics",
  "adx",
  "msft-security",
];

/**
 * Parse YAML frontmatter from a markdown skill file.
 * Returns null if no frontmatter found.
 */
function parseFrontmatter(content) {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!match) return null;

  const yaml = match[1];
  const meta = {};

  for (const line of yaml.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;

    const colonIdx = trimmed.indexOf(":");
    if (colonIdx === -1) continue;

    const key = trimmed.slice(0, colonIdx).trim();
    const value = trimmed.slice(colonIdx + 1).trim();

    if (key === "mitre_attack" || key === "products") {
      // Collect array values from subsequent lines
      meta[key] = [];
    } else {
      meta[key] = value;
    }
  }

  // Second pass for arrays
  const lines = yaml.split("\n");
  let currentArray = null;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("- ")) {
      if (currentArray && meta[currentArray]) {
        let val = trimmed.slice(2).trim();
        // Strip inline comments
        const commentIdx = val.indexOf("#");
        if (commentIdx > 0) val = val.slice(0, commentIdx).trim();
        meta[currentArray].push(val);
      }
    } else {
      const colonIdx = trimmed.indexOf(":");
      if (colonIdx !== -1) {
        const key = trimmed.slice(0, colonIdx).trim();
        if (key === "mitre_attack" || key === "products") {
          currentArray = key;
        } else {
          currentArray = null;
        }
      }
    }
  }

  return meta;
}

/**
 * Scan skills/ directory and return all skills with metadata.
 */
function scanSkills(rootDir) {
  const skillsDir = path.join(rootDir, "skills");
  if (!fs.existsSync(skillsDir)) return [];

  const skills = [];

  const categories = fs
    .readdirSync(skillsDir, { withFileTypes: true })
    .filter((d) => d.isDirectory());

  for (const cat of categories) {
    const catDir = path.join(skillsDir, cat.name);
    const files = fs.readdirSync(catDir).filter((f) => f.endsWith(".md"));

    for (const file of files) {
      const filePath = path.join(catDir, file);
      const content = fs.readFileSync(filePath, "utf8");
      const meta = parseFrontmatter(content);

      skills.push({
        name: path.basename(file, ".md"),
        category: cat.name,
        difficulty: meta?.difficulty || "unknown",
        mitre_tags: meta?.mitre_attack || [],
        products: meta?.products || [],
        title: meta?.title || path.basename(file, ".md"),
        author: meta?.author || "",
        version: meta?.version || "",
        path: filePath,
      });
    }
  }

  return skills;
}

function printSkillTable(skills) {
  // Column widths
  const nameW = Math.max(20, ...skills.map((s) => s.name.length)) + 2;
  const catW = Math.max(10, ...skills.map((s) => s.category.length)) + 2;
  const diffW = 14;
  const mitreW = 8;
  const prodW = 40;

  const header =
    "Name".padEnd(nameW) +
    "Category".padEnd(catW) +
    "Difficulty".padEnd(diffW) +
    "MITRE".padEnd(mitreW) +
    "Products";

  console.log(`\n${c.bold}${header}${c.reset}`);
  console.log("─".repeat(nameW + catW + diffW + mitreW + prodW));

  for (const skill of skills) {
    const products = skill.products.join(", ").slice(0, prodW - 2);
    console.log(
      `${c.cyan}${skill.name.padEnd(nameW)}${c.reset}` +
        `${skill.category.padEnd(catW)}` +
        `${skill.difficulty.padEnd(diffW)}` +
        `${String(skill.mitre_tags.length).padEnd(mitreW)}` +
        `${c.dim}${products}${c.reset}`
    );
  }

  console.log(`\n${c.dim}${skills.length} skill(s) found${c.reset}\n`);
}

function handleList(args, rootDir) {
  const categoryIdx = args.indexOf("--category");
  const categoryFilter = categoryIdx !== -1 ? args[categoryIdx + 1] : null;
  const jsonOutput = args.includes("--json");

  if (categoryFilter && !VALID_CATEGORIES.includes(categoryFilter)) {
    console.error(
      `${c.red}❌ Unknown category: ${categoryFilter}${c.reset}`
    );
    console.error(
      `${c.dim}Valid categories: ${VALID_CATEGORIES.join(", ")}${c.reset}`
    );
    process.exit(1);
  }

  let skills = scanSkills(rootDir);

  if (categoryFilter) {
    skills = skills.filter((s) => s.category === categoryFilter);
  }

  if (skills.length === 0) {
    console.log(
      `\n${c.yellow}No skills found${categoryFilter ? ` in category '${categoryFilter}'` : ""}.${c.reset}\n`
    );
    return;
  }

  if (jsonOutput) {
    console.log(JSON.stringify(skills, null, 2));
    return;
  }

  printSkillTable(skills);
}

function handleAdd(args, rootDir) {
  const name = args[0];
  if (!name) {
    console.error(`${c.red}❌ Skill name required: secops-squad skill add <name>${c.reset}`);
    process.exit(1);
  }

  const allSkills = scanSkills(rootDir);
  const skill = allSkills.find((s) => s.name === name);

  if (!skill) {
    console.error(`${c.red}❌ Skill '${name}' not found.${c.reset}`);
    console.log(`\n${c.cyan}Available skills:${c.reset}`);
    for (const s of allSkills) {
      console.log(`  ${c.dim}${s.category}/${c.reset}${s.name}`);
    }
    process.exit(1);
  }

  // Copy to .squad/skills/
  const destDir = path.join(rootDir, ".squad", "skills");
  if (!fs.existsSync(destDir)) {
    fs.mkdirSync(destDir, { recursive: true });
  }

  const destFile = path.join(destDir, `${name}.md`);
  if (fs.existsSync(destFile)) {
    console.log(
      `${c.yellow}⚠️  Skill '${name}' is already in your workspace.${c.reset}`
    );
    return;
  }

  fs.copyFileSync(skill.path, destFile);
  console.log(
    `${c.green}✅ Added skill '${c.bold}${name}${c.reset}${c.green}' (${skill.category}) to .squad/skills/${c.reset}`
  );
  console.log(
    `${c.dim}   MITRE tags: ${skill.mitre_tags.join(", ") || "none"}${c.reset}`
  );
  console.log(
    `${c.dim}   Products: ${skill.products.join(", ") || "none"}${c.reset}\n`
  );
}

function printHelp() {
  console.log(`
${c.cyan}${c.bold}secops-squad skill${c.reset} — Manage skills

${c.bold}Usage:${c.reset}
  secops-squad skill list [--category <cat>] [--json]
  secops-squad skill add <name>

${c.bold}Subcommands:${c.reset}
  list    List available skills from the built-in library
  add     Copy a skill to the active workspace (.squad/skills/)

${c.bold}Options:${c.reset}
  --category <cat>  Filter by category (${VALID_CATEGORIES.join(", ")})
  --json            Output in JSON format

${c.bold}Examples:${c.reset}
  secops-squad skill list
  secops-squad skill list --category kql
  secops-squad skill add threat-hunting-foundations
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
      handleList(subArgs, rootDir);
      break;
    case "add":
      handleAdd(subArgs, rootDir);
      break;
    default:
      console.error(`${c.red}Unknown subcommand: ${subcommand}${c.reset}`);
      printHelp();
      process.exit(1);
  }
}

module.exports = { run };
