"use strict";

const fs = require("fs");
const path = require("path");
const { install, uninstall } = require("../../lib/plugins/installer");
const { listPlugins } = require("../../lib/plugins/index");
const registry = require("../../lib/plugins/registry");

const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
};

function handleList(rootDir) {
  const plugins = listPlugins(rootDir);
  const registered = registry.list(rootDir);

  if (plugins.length === 0 && registered.length === 0) {
    console.log(
      `\n${c.dim}No plugins installed. Install one with:${c.reset}`
    );
    console.log(
      `  ${c.cyan}secops-squad plugin install <source>${c.reset}\n`
    );
    return;
  }

  console.log(`\n${c.bold}Installed Plugins${c.reset}\n`);

  const nameW = Math.max(20, ...plugins.map((p) => (p.name || "").length)) + 2;
  const verW = 10;
  const typeW = 12;

  console.log(
    `${c.bold}${"Name".padEnd(nameW)}${"Version".padEnd(verW)}${"Type".padEnd(typeW)}Description${c.reset}`
  );
  console.log("─".repeat(nameW + verW + typeW + 30));

  for (const plugin of plugins) {
    const statusIcon = plugin._valid ? "" : ` ${c.red}(invalid)${c.reset}`;
    console.log(
      `${c.cyan}${(plugin.name || plugin._dir).padEnd(nameW)}${c.reset}` +
        `${(plugin.version || "?").padEnd(verW)}` +
        `${(plugin.type || "?").padEnd(typeW)}` +
        `${c.dim}${plugin.description || ""}${c.reset}${statusIcon}`
    );
  }

  console.log(`\n${c.dim}${plugins.length} plugin(s) installed${c.reset}\n`);
}

function handleInstall(args, rootDir) {
  const source = args[0];

  if (!source) {
    console.error(
      `${c.red}❌ Source required: secops-squad plugin install <path|git-url|npm-package>${c.reset}`
    );
    process.exit(1);
  }

  console.log(`\n${c.cyan}Installing plugin from: ${c.bold}${source}${c.reset}\n`);

  const result = install(source, rootDir);

  if (!result.ok) {
    console.error(`${c.red}❌ ${result.error}${c.reset}\n`);
    process.exit(1);
  }

  console.log(
    `${c.green}✅ Plugin '${c.bold}${result.name}${c.reset}${c.green}' installed successfully.${c.reset}\n`
  );
}

function handleRemove(args, rootDir) {
  const name = args[0];

  if (!name) {
    console.error(
      `${c.red}❌ Plugin name required: secops-squad plugin remove <name>${c.reset}`
    );
    process.exit(1);
  }

  const result = uninstall(name, rootDir);

  if (!result.ok) {
    console.error(`${c.red}❌ ${result.error}${c.reset}\n`);
    process.exit(1);
  }

  console.log(
    `${c.green}✅ Plugin '${c.bold}${name}${c.reset}${c.green}' removed.${c.reset}\n`
  );
}

function printHelp() {
  console.log(`
${c.cyan}${c.bold}secops-squad plugin${c.reset} — Plugin management

${c.bold}Usage:${c.reset}
  secops-squad plugin install <source>
  secops-squad plugin list
  secops-squad plugin remove <name>

${c.bold}Subcommands:${c.reset}
  install   Install a plugin from local path, git URL, or npm package
  list      List installed plugins
  remove    Remove an installed plugin

${c.bold}Source types:${c.reset}
  Local path:   ./my-plugin or /absolute/path/to/plugin
  Git URL:      https://github.com/user/plugin.git
  npm package:  my-secops-plugin

${c.bold}Plugin structure:${c.reset}
  Each plugin needs a ${c.cyan}plugin.json${c.reset} manifest:
  {
    "name": "my-custom-skill",
    "version": "1.0.0",
    "type": "skill|persona|template",
    "description": "...",
    "author": "...",
    "files": ["SKILL.md", "queries/*.kql"]
  }

${c.bold}Examples:${c.reset}
  secops-squad plugin install ./my-local-plugin
  secops-squad plugin install https://github.com/user/secops-skill.git
  secops-squad plugin list
  secops-squad plugin remove my-custom-skill
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
    case "install":
      handleInstall(subArgs, rootDir);
      break;
    case "list":
      handleList(rootDir);
      break;
    case "remove":
      handleRemove(subArgs, rootDir);
      break;
    default:
      console.error(`${c.red}Unknown subcommand: ${subcommand}${c.reset}`);
      printHelp();
      process.exit(1);
  }
}

module.exports = { run };
