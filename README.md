# shzx

**Human-readable approval guard for AI coding agents.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-green.svg)](https://www.python.org)
[![242 tests](https://img.shields.io/badge/tests-242_passing-brightgreen.svg)](#)
[![Skylos Grade](https://img.shields.io/badge/Skylos-A%2B%20%28100%29-brightgreen)](https://github.com/duriantaco/skylos)

shzx sits between an AI coding agent and your terminal. Every shell command is intercepted, translated into plain English, assigned a risk level, and shown to you for approval — before anything runs.

Stop blindly approving `rm -rf` commands. Know what your AI agent is doing.

> **Works with [Claude Code](https://docs.anthropic.com/en/docs/claude-code), [Codex](https://openai.com/index/codex/), and Anti-Gravity.**

---

## Why shzx?

AI coding agents are powerful — but they run shell commands on your machine. One wrong `rm -rf`, one `curl | bash`, and your work is gone. shzx gives you:

- **Plain English summaries** — no more guessing what `find . -name "*.log" -exec rm {} \;` does
- **Risk scoring** — every command rated low, medium, high, or critical
- **Automatic blocking** — critical-risk commands are denied before they can run
- **File write protection** — flags writes to `.env`, credentials, system paths, and shell scripts
- **Zero config** — one command to install, works immediately
- **Colored output** — risk levels are color-coded so you never miss a warning
- **NO_COLOR support** — respects the [no-color.org](https://no-color.org) standard

---

## Example

Agent proposes:
```bash
find /Users/oha/project -name "*.log" -exec rm {} \;
```

shzx shows:
```
[shzx] Risk: HIGH
[shzx] Summary: Search /Users/oha/project for files named *.log and delete them.
[shzx] Intent: Find and permanently delete files
[shzx] Warning: High Risk: This searches for files and permanently deletes them automatically.
```

---

## Quick Start

```bash
pip install .
shzx-install
```

That's it. Two commands. shzx is now guarding your terminal.

---

## Setup

### Claude Code (hooks)

```bash
pip install .
shzx-install
```

`shzx-install` writes the hook config into `~/.claude/settings.json` automatically. It registers hooks for **Bash**, **Write**, and **Edit** tools.

To uninstall:

```bash
shzx-uninstall
```

How it works with Claude Code:

- **Critical risk** — command is automatically blocked. Claude gets the analysis and must find a safer approach.
- **High / Medium / Low risk** — triggers an approval prompt showing the risk analysis. You decide.

shzx also intercepts **Write** and **Edit** tool calls, flagging sensitive files (`.env`, credentials, system paths) and shell scripts.

### Codex

Codex hardcodes `/bin/bash` for command execution, so shzx can't intercept commands automatically. Instead, add instructions to your project's `AGENTS.md`:

```markdown
## Shell Safety

Before running any shell command, evaluate it through shzx first:

\`\`\`bash
explaincmd "the command you want to run"
\`\`\`

If the risk is **high** or **critical**, explain the risks to the user and ask
for explicit approval before proceeding. Never run critical-risk commands without
confirmation.
```

This tells Codex to check commands through shzx before executing them. It won't block commands automatically like the Claude Code hook does — it relies on Codex following the instructions.

### Anti-Gravity

shzx is integrated as a workflow. Ask Anti-Gravity to use the `/explain_commands` workflow or to evaluate commands through `shzx.py`.

### Manual / Standalone

```bash
shzx -c "any command here"
```

Use `--no-color` or set the `NO_COLOR` environment variable to disable colored output.

For JSON output (useful for scripting and CI):

```bash
explaincmd "any command here"
```

---

## How It Works

shzx parses each command (including pipes, `&&`, `;` chains, command substitutions, and `bash -c` wrappers) and evaluates:

- **Effects** — reads files, writes files, deletes files, network access, privilege escalation, git state changes
- **Risk level** — low (safe), medium (be aware), high (review carefully), critical (auto-blocked)
- **Intent** — what the command is trying to accomplish in plain English
- **Warnings** — specific dangers (force flags, in-place edits, remote code execution, recursive deletes, etc.)

### Risk Levels

| Level | Score | What happens |
|-------|-------|-------------|
| **Low** | 0–19 | Prompt shown with analysis |
| **Medium** | 20–49 | Prompt shown with analysis |
| **High** | 50–89 | Prompt shown with warnings |
| **Critical** | 90+ | Automatically blocked |

---

## Supported Commands

**File operations:** `find`, `rm`, `mv`/`cp`, `ln`, `chmod`/`chown`, `mkdir`/`touch`, `tee`, `sed`, `tar`, `zip`/`unzip`

**Viewing:** `ls`/`pwd`/`tree`/`wc`/`cat`/`less`/`more`/`head`/`tail`, `grep`/`rg`, `awk`, `jq`

**Network:** `curl`/`wget`, `ssh`/`scp`, `rsync`, `nc`/`ncat`/`netcat`, `telnet`, `nmap`, `tcpdump`

**Package managers:** `npm`/`yarn`/`pnpm`/`pip`/`cargo`

**Shell/scripting:** `bash`/`sh`, `python`/`node`/`ruby`, `xargs`, `echo`

**Git:** `git` (status, log, diff, clean, reset, push, etc.)

**System admin:** `sudo`, `kill`/`killall`/`pkill`, `systemctl`/`service`, `crontab`, `passwd`, `useradd`/`userdel`/`groupadd`, `mount`/`umount`, `dd`, `fdisk`/`mkfs`/`parted`

**Security/firewall:** `iptables`/`ufw`/`nft`, `openssl`, `gpg`, `base64`

**Containers:** `docker` (run, exec, rm, build, pull, push)

**Other:** `make`, `open`/`xdg-open`, `pbcopy`/`pbpaste`/`xclip`

Unknown commands get a generic handler that still detects file path arguments and flags.

### Inline Code Analysis

shzx scans inline code passed to `python -c`, `node -e`, and `ruby -e` for dangerous patterns like `os.system()`, `child_process`, `eval()`, file deletion, and network access. The code snippet is included in the summary so you can see exactly what's being executed.

---

## Project Structure

```
shzx.py    — CLI entrypoint. Arg handling, colored display, user confirmation.
analyzer.py     — Tokenizes commands, computes risk level, checks dangerous compositions.
handlers.py     — Command handlers. Knows what 30+ commands do.
constants.py    — Named risk score constants and thresholds.
hook.py         — Claude Code PreToolUse hook (Bash, Write, Edit). Colored output.
install.py      — Installs/uninstalls hooks into ~/.claude/settings.json.
explaincmd.py   — Standalone JSON output mode.
tests/          — 242 tests (unit + integration).
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. All contributions welcome — new command handlers, better risk heuristics, integrations with other agents.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
