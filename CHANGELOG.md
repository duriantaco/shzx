# Changelog

All notable changes to shzx will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-03-08

### Added
- **Write/Edit hook** — shzx now intercepts file writes and edits in Claude Code, flagging sensitive files (`.env`, credentials, SSH keys, system paths) and shell scripts.
- **Colored output** — risk levels, warnings, and shzx prefix are color-coded in both the CLI and Claude Code hook output.
- **`NO_COLOR` support** — respects the [no-color.org](https://no-color.org) standard. Also supports `--no-color` CLI flag.
- **Malformed command warning** — when `shlex.split` fails on malformed quoting, a warning is added to the analysis.
- **Type hints** — all public functions across all modules are fully annotated.
- **`constants.py`** — all magic numbers extracted into named constants (35 risk score constants and 3 thresholds).
- **Integration tests** — 4 new test files covering `hook.py`, `install.py`, `explaincmd.py`, and `shzx.py` (27 new tests).
- **Codex setup instructions** — `AGENTS.md`-based integration for OpenAI Codex.

### Fixed
- **Bundled git flags bug** — `git clean -xfd` (bundled flags) was silently missed. Now correctly detected using character membership, matching the pattern used for `tar`.
- **Hook low-risk passthrough** — low/medium risk commands were silently passing through with invisible `additionalContext`. All risk levels now show analysis in the user-facing approval prompt.

### Changed
- `install.py` registers 3 hook matchers (`Bash`, `Write`, `Edit`) instead of just `Bash`.
- `install.py` and its `uninstall()` function accept an optional `settings_dir` parameter for testing.

## [0.1.0] - 2025-01-01

### Added
- Initial release.
- Command analysis for 30+ commands with risk scoring.
- Pipe, `&&`, `;` chain parsing.
- Command substitution detection (`$(...)` and backticks).
- `bash -c` / `sh -c` recursive analysis.
- Inline code scanning for Python, Node.js, and Ruby.
- Claude Code `PreToolUse` hook for Bash commands.
- Standalone CLI (`shzx -c`) and JSON output (`explaincmd`).
- One-command install/uninstall (`shzx-install` / `shzx-uninstall`).
