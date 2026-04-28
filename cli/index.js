#!/usr/bin/env node

"use strict";

const COMMANDS = {
  init: {
    description: "Set up a new secops-squad project",
    usage: "secops-squad init [--persona <name>] [--no-interactive]",
  },
  doctor: {
    description: "Check environment prerequisites and configuration health",
    usage: "secops-squad doctor",
  },
  status: {
    description: "Show current config, loaded persona, and active skills",
    usage: "secops-squad status",
  },
  skill: {
    description: "Load, inspect, or list available skills",
    usage: "secops-squad skill [list|info <name>|load <name>]",
  },
  persona: {
    description: "Switch or inspect the active persona",
    usage: "secops-squad persona [list|switch <name>|info <name>]",
  },
  workspace: {
    description: "Manage Microsoft Sentinel workspace connection",
    usage: "secops-squad workspace [connect|status|disconnect]",
  },
  kql: {
    description: "KQL query tools — validate, format, explain",
    usage: "secops-squad kql [validate|run <file>|explain <file>]",
  },
  playbook: {
    description: "SOAR playbook scaffolding and deployment",
    usage: "secops-squad playbook [scaffold|deploy|list]",
  },
};

function printBanner() {
  console.log(`
  ┌─────────────────────────────────────┐
  │         secops-squad v0.1.0         │
  │  AI SecOps team for Microsoft       │
  │  Security stack                     │
  └─────────────────────────────────────┘
  `);
}

function printHelp() {
  printBanner();
  console.log("Usage: secops-squad <command> [options]\n");
  console.log("Commands:\n");

  const padSize = Math.max(...Object.keys(COMMANDS).map((k) => k.length)) + 2;
  for (const [name, cmd] of Object.entries(COMMANDS)) {
    console.log(`  ${name.padEnd(padSize)} ${cmd.description}`);
  }

  console.log("\nRun secops-squad <command> --help for command-specific usage.\n");
}

function handleCommand(command, args) {
  const cmd = COMMANDS[command];
  if (!cmd) {
    console.error(`Unknown command: ${command}`);
    console.error(`Run 'secops-squad --help' to see available commands.\n`);
    process.exit(1);
  }

  // Stub: each command will be implemented in cli/commands/<name>.js
  console.log(`[secops-squad] ${cmd.description}`);
  console.log(`Usage: ${cmd.usage}`);
  console.log(`\nThis command is not yet implemented. Phase 2 will add full functionality.`);
}

function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    printHelp();
    process.exit(0);
  }

  if (args.includes("--version") || args.includes("-v")) {
    console.log("0.1.0");
    process.exit(0);
  }

  const command = args[0];
  const commandArgs = args.slice(1);
  handleCommand(command, commandArgs);
}

main();
