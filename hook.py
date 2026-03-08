from __future__ import annotations

import os
import sys
import json
from analyzer import analyze_command

SENSITIVE_PATHS = [
    ".env", ".envrc",
    "credentials", "secrets",
    ".pem", ".key", ".cert",
    "id_rsa", "id_ed25519",
    "shadow", "passwd",
    ".ssh/config", ".aws/",
    ".netrc", ".npmrc",
    "settings.json",
    ".gitconfig",
]

SENSITIVE_DIRS = [
    "/etc/", "/usr/", "/bin/", "/sbin/",
    "/System/", "/Library/",
]


def _color_enabled() -> bool:
    return "NO_COLOR" not in os.environ


def _c(code: str, text: str) -> str:
    if _color_enabled():
        return f"\033[{code}m{text}\033[0m"
    return text


def _risk_colored(risk: str) -> str:
    r = risk.upper()
    if r == "CRITICAL":
        return _c("41;97", f" {r} ")
    elif r == "HIGH":
        return _c("91", r)
    elif r == "MEDIUM":
        return _c("93", r)
    return _c("92", r)


def _prefix() -> str:
    return _c("96", "[shzx]")


## checks write edit tool calls against sensitive paths and sys dir to flag risky file mods
def _analyze_write(tool_name: str, tool_input: dict) -> dict | None:
    file_path = tool_input.get("file_path", "")
    if not file_path:
        return None

    p = _prefix()
    lines = []
    warnings = []
    risk = "low"

    lines.append(f"{p} Tool: {_c('1', tool_name)}")
    lines.append(f"{p} File: {_c('93', file_path)}")

    for pattern in SENSITIVE_PATHS:
        if pattern in file_path.lower():
            warnings.append(f"Targets sensitive file matching '{pattern}'")
            risk = "high"

    for d in SENSITIVE_DIRS:
        if file_path.startswith(d):
            warnings.append(f"Writes to system directory {d}")
            risk = "high"

    if tool_name == "Write" and os.path.exists(file_path):
        warnings.append("Overwrites existing file")
        if risk == "low":
            risk = "medium"

    if file_path.endswith((".sh", ".bash", ".zsh")):
        warnings.append("Creates/modifies a shell script")
        if risk == "low":
            risk = "medium"

    lines.append(f"{p} Risk: {_risk_colored(risk)}")
    for w in warnings:
        lines.append(f"{p} {_c('91', f'Warning: {w}')}")

    if not warnings:
        lines.append(f"{p} Summary: Standard file write")

    return {"risk": risk, "context": "\n".join(lines)}


## entry point for CC pretooluse hook. 
def main() -> None:
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        if not cmd:
            sys.exit(0)

        analysis = analyze_command(cmd)
        risk = analysis["risk"]

        p = _prefix()
        lines = []
        lines.append(f"{p} Risk: {_risk_colored(risk)}")
        lines.append(f"{p} Summary: {analysis['summary']}")
        lines.append(f"{p} Intent: {analysis['likely_intent']}")
        for w in analysis["warnings"]:
            lines.append(f"{p} {_c('91', f'Warning: {w}')}")

        context = "\n".join(lines)

        if risk == "critical":
            decision = "deny"
        else:
            decision = "ask"

        result = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": context,
            }
        }
        print(json.dumps(result))
        sys.exit(0)

    if tool_name in ("Write", "Edit"):
        analysis = _analyze_write(tool_name, tool_input)
        if not analysis:
            sys.exit(0)

        risk = analysis["risk"]
        context = analysis["context"]

        result = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": context,
            }
        }
        print(json.dumps(result))
        sys.exit(0)

    sys.exit(0)


if __name__ == "__main__":
    main()
