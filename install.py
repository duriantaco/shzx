from __future__ import annotations

import json
import sys
from pathlib import Path

HOOK_ENTRIES = [
    {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "shzx-hook"}],
    },
    {
        "matcher": "Write",
        "hooks": [{"type": "command", "command": "shzx-hook"}],
    },
    {
        "matcher": "Edit",
        "hooks": [{"type": "command", "command": "shzx-hook"}],
    },
]

def main(settings_dir: Path | None = None) -> None:
    claude_dir = settings_dir if settings_dir is not None else Path.home() / ".claude"
    settings_path = claude_dir / "settings.json"

    claude_dir.mkdir(exist_ok=True)

    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except (json.JSONDecodeError, OSError):
            print(f"Error: could not parse {settings_path}")
            sys.exit(1)
    else:
        settings = {}

    hooks = settings.setdefault("hooks", {})
    pre_tool = hooks.setdefault("PreToolUse", [])

    for entry in pre_tool:
        for h in entry.get("hooks", []):
            if "shzx" in h.get("command", ""):
                print("shzx hook is already installed.")
                return

    for hook_entry in HOOK_ENTRIES:
        pre_tool.append(hook_entry)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    print(f"shzx hook installed in {settings_path}")


def uninstall(settings_dir: Path | None = None) -> None:
    claude_dir = settings_dir if settings_dir is not None else Path.home() / ".claude"
    settings_path = claude_dir / "settings.json"

    if not settings_path.exists():
        print("Nothing to uninstall.")
        return

    try:
        settings = json.loads(settings_path.read_text())
    except (json.JSONDecodeError, OSError):
        print(f"Error: could not parse {settings_path}")
        sys.exit(1)

    pre_tool = settings.get("hooks", {}).get("PreToolUse", [])
    filtered = [
        entry for entry in pre_tool
        if not any("shzx" in h.get("command", "") for h in entry.get("hooks", []))
    ]

    if len(filtered) == len(pre_tool):
        print("shzx hook not found in settings.")
        return

    settings["hooks"]["PreToolUse"] = filtered
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    print(f"shzx hook removed from {settings_path}")


if __name__ == "__main__":
    main()
