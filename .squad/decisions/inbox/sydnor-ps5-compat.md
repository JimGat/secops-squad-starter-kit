# Decision: ASCII-Only Policy for PowerShell Scripts

**Date:** 2026-05-08T15:50:14.020-05:00
**Author:** Sydnor (Platform Dev)
**Status:** Proposed

## Context

A user on PowerShell 5.1 hit a `ParseException` (`UnexpectedToken`) when running `install.ps1`. The root cause: PS5 reads UTF-8 files without a BOM as ANSI (Windows-1252). Emoji characters (✅, ❌, ⚠️) and Unicode box-drawing characters (┌─┐│└─┘) became garbled multi-byte sequences under ANSI interpretation, breaking string parsing.

## Decision

All PowerShell scripts in this repository (`.ps1`, `.psm1`, `.psd1`) must:

1. **Use only ASCII characters (U+0000–U+007F) in source code.** No emoji, no box-drawing, no em-dashes, no smart quotes. Use ASCII equivalents: `[OK]`, `[FAIL]`, `[WARN]`, `+---+`/`|` for boxes, `--` for dashes.
2. **Be saved with UTF-8 BOM encoding** (`EF BB BF` byte prefix). This tells PS5 to interpret the file as UTF-8 rather than ANSI.

Both measures together provide defense in depth — ASCII content survives any encoding interpretation, and the BOM provides correct decoding if Unicode is ever reintroduced accidentally.

## Consequences

- PowerShell scripts will look slightly less pretty in terminals that support Unicode, but they will work everywhere.
- Contributors adding Unicode characters to PS scripts will need to be corrected in review.
- A CI lint step could enforce this in the future (e.g., `grep -P '[^\x00-\x7F]'` on `.ps1` files).
