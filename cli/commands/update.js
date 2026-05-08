"use strict";

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
};

const REMOTE_NAME = "starter-kit";
const REMOTE_URL =
  "https://github.com/x3nc0n/secops-squad-starter-kit.git";

function printBanner() {
  console.log(`
${c.cyan}${c.bold}  ┌─────────────────────────────────────────┐
  │                                         │
  │   ⚔️  secops-squad update                │
  │   Pull latest starter-kit changes       │
  │                                         │
  └─────────────────────────────────────────┘${c.reset}
`);
}

function exec(cmd) {
  return execSync(cmd, { encoding: "utf8", timeout: 60000 }).trim();
}

function isGitRepo() {
  try {
    exec("git rev-parse --is-inside-work-tree");
    return true;
  } catch {
    return false;
  }
}

function hasUncommittedChanges() {
  try {
    const status = exec("git status --porcelain");
    return status.length > 0;
  } catch {
    return false;
  }
}

function remoteExists() {
  try {
    const remotes = exec("git remote");
    return remotes.split("\n").includes(REMOTE_NAME);
  } catch {
    return false;
  }
}

function addRemote() {
  console.log(
    `${c.dim}  Adding ${REMOTE_NAME} remote → ${REMOTE_URL}${c.reset}`
  );
  exec(`git remote add ${REMOTE_NAME} ${REMOTE_URL}`);
  console.log(`${c.green}  ✓ Remote added${c.reset}`);
}

function fetchRemote() {
  console.log(`${c.dim}  Fetching from ${REMOTE_NAME}...${c.reset}`);
  exec(`git fetch ${REMOTE_NAME}`);
  console.log(`${c.green}  ✓ Fetched latest changes${c.reset}`);
}

function merge() {
  try {
    const output = exec(
      `git merge ${REMOTE_NAME}/main --allow-unrelated-histories --no-edit`
    );
    return { success: true, output };
  } catch (err) {
    return { success: false, output: err.stderr || err.stdout || err.message };
  }
}

async function run() {
  printBanner();

  // Pre-flight: git available?
  if (!isGitRepo()) {
    console.error(
      `${c.red}❌ Not a git repository. Run this from your secops-squad project root.${c.reset}`
    );
    process.exit(1);
  }

  // Warn about uncommitted changes
  if (hasUncommittedChanges()) {
    console.log(
      `${c.yellow}⚠️  You have uncommitted changes. Commit or stash them first to avoid merge issues.${c.reset}\n`
    );
    console.log(
      `${c.dim}  Run: git add -A && git commit -m "save work before update"${c.reset}\n`
    );
    process.exit(1);
  }

  // Step 1: Ensure remote exists
  if (remoteExists()) {
    console.log(
      `${c.dim}  Remote ${REMOTE_NAME} already configured — skipping add${c.reset}`
    );
  } else {
    try {
      addRemote();
    } catch (err) {
      console.error(
        `${c.red}❌ Failed to add remote: ${err.message}${c.reset}`
      );
      process.exit(1);
    }
  }

  // Step 2: Fetch
  try {
    fetchRemote();
  } catch (err) {
    console.error(
      `${c.red}❌ Failed to fetch from ${REMOTE_NAME}. Check your network connection.${c.reset}`
    );
    console.error(`${c.dim}  ${err.message}${c.reset}`);
    process.exit(1);
  }

  // Step 3: Merge
  console.log(
    `${c.dim}  Merging ${REMOTE_NAME}/main into your project...${c.reset}`
  );
  const result = merge();

  if (result.success) {
    if (result.output.includes("Already up to date")) {
      console.log(
        `\n${c.green}${c.bold}✅ Already up to date — no new changes from the starter kit.${c.reset}\n`
      );
    } else {
      console.log(
        `\n${c.green}${c.bold}✅ Update complete!${c.reset}`
      );
      console.log(`${c.dim}${result.output}${c.reset}\n`);
      console.log(
        `${c.cyan}Next steps:${c.reset}`
      );
      console.log(
        `  ${c.bold}1.${c.reset} Review the changes with ${c.cyan}git diff HEAD~1${c.reset}`
      );
      console.log(
        `  ${c.bold}2.${c.reset} Run ${c.cyan}secops-squad doctor${c.reset} to verify your environment`
      );
      console.log();
    }
  } else {
    console.log(
      `\n${c.yellow}${c.bold}⚠️  Merge conflicts detected.${c.reset}`
    );
    console.log(
      `${c.yellow}  The starter-kit changes conflict with your local modifications.${c.reset}\n`
    );
    console.log(`${c.cyan}To resolve:${c.reset}`);
    console.log(
      `  ${c.bold}1.${c.reset} Open the conflicting files and resolve the merge markers`
    );
    console.log(
      `  ${c.bold}2.${c.reset} Stage resolved files: ${c.cyan}git add <file>${c.reset}`
    );
    console.log(
      `  ${c.bold}3.${c.reset} Complete the merge: ${c.cyan}git commit${c.reset}`
    );
    console.log(
      `\n${c.dim}  Tip: Your customizations in .secops/ and .squad/ are safe —\n  the merge only adds or updates starter-kit files.${c.reset}\n`
    );
    process.exit(1);
  }
}

module.exports = { run };
