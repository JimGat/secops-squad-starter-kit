# Decision: Update Command Uses Git Remote Merge Strategy

**Date:** 2026-05-08T15:06:07.002-05:00
**By:** Sydnor (Platform Dev)
**Status:** Implemented

## What

Added `secops-squad update` CLI command that pulls latest starter-kit changes via a git remote named `starter-kit`. Uses `git merge --allow-unrelated-histories` since installed projects have no shared git history with the template repo.

## Why

The install flow (install.ps1/install.sh) shallow-clones the starter-kit, deletes `.git`, and inits a fresh repo. Users had no way to get upstream improvements. A git-remote-based merge is the simplest approach that preserves local customizations while pulling new files.

## Impact

- **All agents:** The `starter-kit` remote may appear in `.git/config` after users run `update`. Don't treat it as the project's origin.
- **Sydnor:** Owns this command going forward. Any starter-kit structural changes (new top-level dirs, renamed files) should be tested against the merge path.
- **Kima/Freamon/Herc:** New skills or templates added to the starter-kit will flow to users via this command automatically.
