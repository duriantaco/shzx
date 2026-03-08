from __future__ import annotations

import sys
import json
from analyzer import analyze_command

def main() -> None:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No command provided"}))
        sys.exit(1)

    result = analyze_command(sys.argv[1])
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
