from __future__ import annotations

import os
import sys
import subprocess
from analyzer import analyze_command


def _use_color(force_no_color: bool = False) -> bool:
    if force_no_color:
        return False
    if "NO_COLOR" in os.environ:
        return False
    if not sys.stdout.isatty():
        return False
    return True


def _c(code: str, text: str, use_color: bool) -> str:
    if use_color:
        return f"\033[{code}m{text}\033[0m"
    return text


def main() -> None:
    args = sys.argv[1:]
    no_color = False
    if '--no-color' in args:
        no_color = True
        args.remove('--no-color')

    if len(args) > 1 and args[0] in ('-c', '-lc', '-ic'):
        cmd = args[1]
        analysis = analyze_command(cmd)
        color = _use_color(force_no_color=no_color)

        print(f"\n{_c('96', 'AI Agent wants to run:', color)}")
        print(f"{_c('93', cmd, color)}\n")

        risk = analysis['risk'].upper()
        if risk == 'CRITICAL':
            risk_str = _c('41;97', f" {risk} ", color)
        elif risk == 'HIGH':
            risk_str = _c('91', risk, color)
        elif risk == 'MEDIUM':
            risk_str = _c('93', risk, color)
        else:
            risk_str = _c('92', risk, color)

        print(f"Summary: {analysis['summary']}")
        print(f"Risk: {risk_str}")
        print(f"Likely Intent: {analysis['likely_intent']}")

        if analysis['warnings']:
            for w in analysis['warnings']:
                print(_c('91', f"Warning: {w}", color))

        if analysis['risk'] == 'critical':
            print(f"\n{_c('41;97', ' *** CRITICAL RISK COMMAND *** ', color)}")
            print(_c('91', "You must type the full word 'yes' to allow this command.", color))
            while True:
                try:
                    ans = input("\nAllow? (type 'yes' or 'no'): ").strip().lower()
                except EOFError:
                    sys.exit(1)

                if ans == 'yes':
                    sys.exit(subprocess.call(['bash', '-c', cmd]))
                elif ans in ['n', 'no']:
                    print("Command blocked by user.")
                    sys.exit(1)
                else:
                    print(_c('91', "Please type the full word 'yes' to confirm, or 'no' to cancel.", color))
        else:
            while True:
                try:
                    ans = input("\nAllow? (y/n): ").strip().lower()
                except EOFError:
                    sys.exit(1)

                if ans in ['y', 'yes']:
                    sys.exit(subprocess.call(['bash', '-c', cmd]))
                elif ans in ['n', 'no']:
                    print("Command blocked by user.")
                    sys.exit(1)
    else:
        sys.exit(subprocess.call(['bash'] + args))

if __name__ == '__main__':
    main()
