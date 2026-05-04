# Decision: Bicep Template Phase 2 Integration Pattern

**Date:** 2026-05-04T07:53:46-05:00
**By:** Carver (Tester/QA)
**Status:** Proposed

## What

All 11 Bicep templates now include standardized Phase 2 integration comment blocks that reference PowerShell wrapper skills, `.secops/` config files, and post-deployment scripts. A new `templates/bicep/README.md` serves as the central cross-reference.

## Key Design Choices

1. **Comment-only changes** — No Bicep logic was modified. Integration points are documented via comment blocks, not code changes. This preserves template correctness and avoids deployment regressions.

2. **Forward-referenced scripts** — Templates reference `Configure-SoarPlaybooks.ps1` and `Configure-AdxSecurityLake.ps1` that don't exist yet. These scripts should be created by Herc/Sydnor as Phase 2 deliverables.

3. **Rate limiting cross-reference** — Every template references `rate-limiting.md` with specific API limits relevant to its domain (e.g., MDE 100 calls/min for malware-containment, Graph 10K/10min for compromised-account).

4. **`.secops/` is advisory, not enforced** — Templates document which `.secops/` files to consult but don't programmatically read them. Bicep runs in ARM context where local files aren't accessible. The post-deployment scripts will be the enforcement point.

## QA Observations

- **Gap: No deployment validation tests exist** — There's no CI that validates Bicep templates compile (`az bicep build`). Recommend adding a CI step.
- **Gap: Post-deployment scripts are vapor** — The referenced PS1 scripts need to be implemented. Tracked as forward references.
- **Gap: README references `sentinel/` template directory** — The `templates/bicep/sentinel/` directory exists but only contains `.gitkeep`. The README architecture diagram doesn't mention it (correct, since it has no templates).

## Impact

- **Herc:** Needs to create `Configure-SoarPlaybooks.ps1` and `Configure-AdxSecurityLake.ps1`
- **Sydnor:** README references `secops-squad env validate` — must be functional
- **All agents:** Should consult `templates/bicep/README.md` before deploying templates
