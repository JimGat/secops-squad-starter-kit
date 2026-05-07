"use strict";

const fs = require("fs");
const path = require("path");
const readline = require("readline");

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

const CHARACTER_BANKS = {
  "The Wire": ["McNulty", "Bunk", "Kima", "Freamon", "Carver", "Herc", "Sydnor", "Daniels", "Rhonda", "Prez"],
  "The Usual Suspects": ["Keaton", "McManus", "Fenster", "Hockney", "Verbal", "Kobayashi"],
  "Reservoir Dogs": ["White", "Orange", "Blonde", "Pink", "Blue", "Brown", "Eddie", "Joe"],
  "Alien": ["Ripley", "Dallas", "Kane", "Lambert", "Parker", "Brett", "Ash", "Bishop"],
  "Ocean's Eleven": ["Danny", "Rusty", "Linus", "Reuben", "Basher", "Virgil", "Turk", "Livingston", "Yen", "Frank", "Saul", "Tess", "Roman", "Isabel"],
  "Arrested Development": ["Michael", "Gob", "Buster", "Lucille", "Lindsay", "Tobias", "George", "Maeby", "Annyong", "Oscar", "Kitty", "Barry", "Lupe", "Narrator", "Bland"],
  "Star Wars": ["Solo", "Leia", "Chewie", "Lando", "Wedge", "Ackbar", "Mothma", "Syndulla", "Ahsoka", "Rex", "Cassian", "Jyn"],
  "The Matrix": ["Neo", "Trinity", "Morpheus", "Tank", "Dozer", "Switch", "Apoc", "Mouse", "Cypher", "Niobe"],
  "Firefly": ["Mal", "Zoe", "Wash", "Inara", "Jayne", "Kaylee", "Simon", "River", "Book", "Badger"],
  "The Goonies": ["Mikey", "Chunk", "Mouth", "Data", "Sloth", "Brand", "Stef", "Andy"],
  "The Simpsons": ["Homer", "Marge", "Bart", "Lisa", "Maggie", "Burns", "Smithers", "Flanders", "Milhouse", "Krusty", "Moe", "Barney", "Wiggum", "Skinner", "Apu", "Ralph", "Nelson", "Comic", "Otto", "Lenny"],
  "Breaking Bad": ["Walter", "Jesse", "Hank", "Skyler", "Gus", "Mike", "Saul", "Tuco", "Badger", "Skinny", "Lydia", "Todd"],
  "Lost": ["Jack", "Kate", "Sawyer", "Locke", "Hurley", "Sayid", "Jin", "Sun", "Claire", "Charlie", "Desmond", "Ben", "Juliet", "Miles", "Faraday", "Lapidus", "Richard", "Eko"],
  "Marvel Cinematic Universe": ["Stark", "Rogers", "Romanoff", "Banner", "Barton", "Thor", "Fury", "Coulson", "Danvers", "Okoye", "Shuri", "Parker", "Strange", "Wanda", "Vision", "Rhodes", "Nebula", "Rocket", "Groot", "Gamora", "Quill", "Drax", "Mantis", "Loki", "Valkyrie"],
  "DC Universe": ["Wayne", "Kent", "Diana", "Barry", "Arthur", "Cyborg", "Gordon", "Alfred", "Quinn", "Zatanna", "Constantine", "Canary", "Arrow", "Martian", "Hawkgirl", "Oracle", "Nightwing", "Batgirl"],
  "Futurama": ["Fry", "Leela", "Bender", "Professor", "Amy", "Hermes", "Zoidberg", "Kif", "Nibbler", "Scruffy", "Calculon", "Flexo"],
  "Star Trek: TOS": ["Kirk", "Spock", "McCoy", "Scotty", "Uhura", "Sulu", "Chekov", "Chapel", "Rand", "Pike", "Number One", "M'Benga"],
  "Star Trek: TNG": ["Picard", "Riker", "Data", "Worf", "LaForge", "Troi", "Crusher", "Wesley", "Ro", "Guinan", "Q", "O'Brien", "Pulaski", "Yar", "Barclay"],
  "Star Trek: DS9": ["Sisko", "Kira", "Odo", "Dax", "Bashir", "O'Brien", "Worf", "Quark", "Jake", "Garak", "Martok", "Nog", "Rom", "Winn", "Dukat"],
  "Star Trek: Voyager": ["Janeway", "Chakotay", "Tuvok", "Paris", "Torres", "Kim", "Seven", "Doctor", "Neelix", "Kes", "Ayala", "Carey", "Naomi"],
  "Star Trek: Strange New Worlds": ["Pike", "Spock", "Uhura", "La'an", "Ortegas", "Chapel", "M'Benga", "Hemmer", "Una", "Kyle"],
};

const SQUAD_DIR = ".squad";

function findRoot() {
  return process.cwd();
}

function createPrompt() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  rl.on("close", () => {
    console.log(`\n${c.yellow}Recast cancelled.${c.reset}`);
    process.exit(0);
  });

  const ask = (question) =>
    new Promise((resolve) => {
      rl.question(question, (answer) => resolve(answer.trim()));
    });

  return { rl, ask };
}

function loadJSON(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n", "utf8");
}

function replaceAll(str, search, replacement) {
  return str.split(search).join(replacement);
}

async function run(args) {
  const rootDir = findRoot();
  const squadDir = path.join(rootDir, SQUAD_DIR);

  // Parse flags
  const dryRun = args.includes("--dry-run");
  const noInteractive = args.includes("--no-interactive");
  const universeIdx = args.indexOf("--universe");
  const presetUniverse = universeIdx !== -1 ? args[universeIdx + 1] : null;

  // Load casting files
  const policyPath = path.join(squadDir, "casting", "policy.json");
  const registryPath = path.join(squadDir, "casting", "registry.json");
  const historyPath = path.join(squadDir, "casting", "history.json");

  if (!fs.existsSync(policyPath) || !fs.existsSync(registryPath)) {
    console.error(`${c.red}❌ Casting files not found. Run ${c.bold}secops-squad init${c.reset}${c.red} first.${c.reset}`);
    process.exit(1);
  }

  const policy = loadJSON(policyPath);
  const registry = loadJSON(registryPath);
  const history = fs.existsSync(historyPath) ? loadJSON(historyPath) : { universe_usage_history: [], assignment_cast_snapshots: {} };

  const universes = policy.allowlist_universes || [];
  const capacity = policy.universe_capacity || {};

  // Identify castable agents (non-exempt, active)
  const castableAgents = Object.entries(registry.agents)
    .filter(([, info]) => info.cast_type !== "exempt" && info.status === "active")
    .map(([name, info]) => ({ name, ...info }));

  const neededSlots = castableAgents.length;

  // Select universe
  let selectedUniverse;

  if (presetUniverse) {
    if (!universes.includes(presetUniverse)) {
      console.error(`${c.red}❌ Unknown universe: "${presetUniverse}"${c.reset}`);
      console.error(`${c.dim}Available: ${universes.join(", ")}${c.reset}`);
      process.exit(1);
    }
    selectedUniverse = presetUniverse;
  } else if (noInteractive) {
    console.error(`${c.red}❌ --no-interactive requires --universe "Name"${c.reset}`);
    process.exit(1);
  } else {
    // Interactive menu
    console.log(`\n${c.cyan}${c.bold}  ⚔️  secops-squad recast${c.reset}`);
    console.log(`${c.dim}  Re-theme your squad with a new universe${c.reset}\n`);
    console.log(`${c.cyan}? ${c.bold}Choose a universe:${c.reset}\n`);

    universes.forEach((u, i) => {
      const cap = capacity[u] || "?";
      const fits = (capacity[u] || 0) >= neededSlots;
      const capLabel = fits
        ? `${c.green}${cap} chars${c.reset}`
        : `${c.red}${cap} chars (need ${neededSlots})${c.reset}`;
      console.log(`  ${c.bold}${String(i + 1).padStart(2)}.${c.reset} ${c.cyan}${u}${c.reset} ${c.dim}[${capLabel}${c.dim}]${c.reset}`);
    });

    const { rl, ask } = createPrompt();
    let choice;
    while (true) {
      const input = await ask(`\n${c.cyan}  Enter number (1-${universes.length}): ${c.reset}`);
      const num = parseInt(input, 10);
      if (num >= 1 && num <= universes.length) {
        choice = num - 1;
        break;
      }
      console.log(`${c.red}  Please enter a number between 1 and ${universes.length}.${c.reset}`);
    }
    selectedUniverse = universes[choice];
    rl.close();
  }

  // Validate capacity
  const bank = CHARACTER_BANKS[selectedUniverse];
  if (!bank) {
    console.error(`${c.red}❌ No character bank defined for "${selectedUniverse}".${c.reset}`);
    process.exit(1);
  }

  if (bank.length < neededSlots) {
    console.error(`${c.red}❌ "${selectedUniverse}" only has ${bank.length} characters but you need ${neededSlots}.${c.reset}`);
    const larger = universes.filter((u) => (capacity[u] || 0) >= neededSlots);
    if (larger.length > 0) {
      console.error(`${c.dim}Try one of: ${larger.join(", ")}${c.reset}`);
    }
    process.exit(1);
  }

  // Allocate characters to agents
  const assignments = [];
  const usedChars = [];
  for (let i = 0; i < castableAgents.length; i++) {
    const agent = castableAgents[i];
    const newChar = bank[i];
    const newName = newChar.toLowerCase();
    usedChars.push(newChar);
    assignments.push({
      oldName: agent.name,
      newName,
      newChar,
      role: agent.role,
      emoji: agent.emoji,
    });
  }

  // Show plan
  console.log(`\n${c.cyan}${c.bold}  Recast: ${selectedUniverse}${c.reset}\n`);

  if (dryRun) {
    console.log(`${c.yellow}  [DRY RUN] No changes will be made.${c.reset}\n`);
  }

  // Before/after table
  console.log(`  ${c.bold}${"Old Name".padEnd(12)} → ${"New Name".padEnd(12)} Role${c.reset}`);
  console.log(`  ${c.dim}${"─".repeat(45)}${c.reset}`);
  for (const a of assignments) {
    console.log(`  ${a.oldName.padEnd(12)} → ${c.green}${a.newName.padEnd(12)}${c.reset} ${c.dim}${a.role}${c.reset}`);
  }
  console.log();

  if (dryRun) {
    console.log(`${c.green}✅ Dry run complete. No files changed.${c.reset}\n`);
    return;
  }

  // Perform the rename operations
  const teamMdPath = path.join(squadDir, "team.md");
  const routingMdPath = path.join(squadDir, "routing.md");

  // 1. Rename agent folders and update charters
  for (const a of assignments) {
    const oldDir = path.join(squadDir, "agents", a.oldName);
    const newDir = path.join(squadDir, "agents", a.newName);

    if (a.oldName === a.newName) continue;

    if (fs.existsSync(oldDir)) {
      fs.renameSync(oldDir, newDir);
    }

    // Update charter.md inside the renamed folder
    const charterPath = path.join(newDir, "charter.md");
    if (fs.existsSync(charterPath)) {
      let charter = fs.readFileSync(charterPath, "utf8");
      // Replace old name references (case-insensitive first char for display name)
      const oldDisplay = a.oldName.charAt(0).toUpperCase() + a.oldName.slice(1);
      const newDisplay = a.newName.charAt(0).toUpperCase() + a.newName.slice(1);
      charter = replaceAll(charter, oldDisplay, newDisplay);
      charter = replaceAll(charter, a.oldName, a.newName);
      fs.writeFileSync(charterPath, charter, "utf8");
    }
  }

  // 2. Update team.md
  if (fs.existsSync(teamMdPath)) {
    let teamMd = fs.readFileSync(teamMdPath, "utf8");
    for (const a of assignments) {
      if (a.oldName === a.newName) continue;
      const oldDisplay = a.oldName.charAt(0).toUpperCase() + a.oldName.slice(1);
      const newDisplay = a.newName.charAt(0).toUpperCase() + a.newName.slice(1);
      // Update roster table rows
      teamMd = replaceAll(teamMd, `| ${oldDisplay} |`, `| ${newDisplay} |`);
      teamMd = replaceAll(teamMd, `agents/${a.oldName}/`, `agents/${a.newName}/`);
    }
    fs.writeFileSync(teamMdPath, teamMd, "utf8");
  }

  // 3. Update routing.md
  if (fs.existsSync(routingMdPath)) {
    let routingMd = fs.readFileSync(routingMdPath, "utf8");
    for (const a of assignments) {
      if (a.oldName === a.newName) continue;
      const oldDisplay = a.oldName.charAt(0).toUpperCase() + a.oldName.slice(1);
      const newDisplay = a.newName.charAt(0).toUpperCase() + a.newName.slice(1);
      routingMd = replaceAll(routingMd, oldDisplay, newDisplay);
      routingMd = replaceAll(routingMd, a.oldName, a.newName);
    }
    fs.writeFileSync(routingMdPath, routingMd, "utf8");
  }

  // 4. Update registry.json
  const newAgents = {};
  for (const [name, info] of Object.entries(registry.agents)) {
    const assignment = assignments.find((a) => a.oldName === name);
    if (assignment) {
      newAgents[assignment.newName] = {
        ...info,
        universe: selectedUniverse,
        character: assignment.newChar,
      };
    } else {
      newAgents[name] = info;
    }
  }
  registry.agents = newAgents;
  writeJSON(registryPath, registry);

  // 5. Update history.json
  const snapshot = {
    timestamp: new Date().toISOString(),
    universe: selectedUniverse,
    assignments: assignments.map((a) => ({
      agent: a.newName,
      character: a.newChar,
      role: a.role,
      previous_name: a.oldName,
    })),
  };
  history.universe_usage_history.push({
    universe: selectedUniverse,
    timestamp: snapshot.timestamp,
  });
  history.assignment_cast_snapshots[snapshot.timestamp] = snapshot;
  writeJSON(historyPath, history);

  console.log(`${c.green}${c.bold}✅ Recast complete!${c.reset} Your squad is now themed as ${c.cyan}${c.bold}${selectedUniverse}${c.reset}.`);
  console.log(`${c.dim}   ${assignments.length} agents renamed. Exempt agents unchanged.${c.reset}\n`);
}

module.exports = { run };
