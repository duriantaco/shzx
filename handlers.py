from __future__ import annotations

import re
from constants import (
    RISK_FIND_DELETE,
    RISK_RM_BASE,
    RISK_RM_FORCE_RECURSIVE,
    RISK_GIT_STATE_CHANGE,
    RISK_GIT_CLEAN_FLAGS,
    RISK_PKG_INSTALL,
    RISK_CURL_WGET,
    RISK_BASH_C,
    RISK_SUDO,
    RISK_MV_CP_FORCE,
    RISK_MV_CP_BASE,
    RISK_CHMOD_RECURSIVE,
    RISK_CHMOD_CHOWN_BASE,
    RISK_MAKE,
    RISK_SED_INPLACE,
    RISK_TAR_EXTRACT,
    RISK_UNZIP,
    RISK_INLINE_CODE,
    RISK_SSH_SCP,
    RISK_SSH_REMOTE_CMD,
    RISK_DOCKER_RUN,
    RISK_DOCKER_EXEC,
    RISK_DOCKER_RM,
    RISK_DOCKER_BUILD,
    RISK_DOCKER_PULL_PUSH,
    RISK_UNKNOWN_CMD,
    RISK_NETCAT,
    RISK_TELNET,
    RISK_RSYNC,
    RISK_NMAP,
    RISK_TCPDUMP,
    RISK_KILL,
    RISK_SYSTEMCTL,
    RISK_CRONTAB_EDIT,
    RISK_CRONTAB_LIST,
    RISK_PASSWD,
    RISK_USER_MGMT,
    RISK_MOUNT,
    RISK_DISK_MGMT,
    RISK_IPTABLES,
    RISK_DD,
    RISK_LN,
    RISK_LN_FORCE,
    RISK_TEE,
    RISK_OPENSSL,
    RISK_GPG,
)

## regex patterns for detecting dangerous ops inside inline code (-c/-e flags).
DANGEROUS_CODE_PATTERNS = {
    'python': [
        (r'os\.(system|popen)\s*\(', "Runs a shell command", 40, []),
        (r'subprocess\.(run|call|Popen|check_output|check_call)', "Spawns a subprocess", 40, []),
        (r'shutil\.rmtree', "Recursively deletes a directory tree", 40, ["deletes_files"]),
        (r'os\.(remove|unlink|rmdir)\s*\(', "Deletes files", 30, ["deletes_files"]),
        (r'open\s*\(.*[\'\"](w|a)', "Opens a file for writing", 10, ["writes_files"]),
        (r'(eval|exec)\s*\(', "Executes dynamically constructed code", 20, []),
        (r'__import__\s*\(', "Dynamically imports a module", 20, []),
        (r'(socket\.|urllib|requests\.(get|post|put|delete|patch))', "Performs network access", 10, ["network_access"]),
    ],
    'node': [
        (r'child_process', "Uses child process module", 40, []),
        (r'fs\.\w*(unlink|rmdir|rm)Sync?\s*\(', "Deletes files", 30, ["deletes_files"]),
        (r'fs\.\w*[Ww]rite', "Writes to filesystem", 10, ["writes_files"]),
        (r'(eval|Function)\s*\(', "Executes dynamic code", 20, []),
        (r'(exec|execSync)\s*\(', "Executes a shell command", 40, []),
        (r'require\s*\(\s*[\'"]http', "Loads HTTP module", 10, ["network_access"]),
    ],
    'ruby': [
        (r'(system|exec)\s*[\(\s]', "Runs a shell command", 40, []),
        (r'`[^`]+`', "Executes via backtick shell", 40, []),
        (r'%x[{\(]', "Executes via shell", 40, []),
        (r'File\.(delete|unlink)', "Deletes files", 30, ["deletes_files"]),
        (r'FileUtils\.rm', "Removes files", 30, ["deletes_files"]),
        (r'eval\s*[\(\s]', "Evaluates dynamic code", 20, []),
    ],
}

def _scan_inline_code(lang_key: str, code_str: str, node: dict) -> None:
    patterns = DANGEROUS_CODE_PATTERNS.get(lang_key, [])
    for regex, desc, risk_add, effect_keys in patterns:
        if re.search(regex, code_str):
            warning = f"Inline code: {desc}"
            if warning not in node["warnings"]:
                node["warnings"].append(warning)
                node["risk_score"] += risk_add
                for eff in effect_keys:
                    node["effects"][eff] = True

def split_args(tokens: list[str], start: int = 1) -> tuple[list[str], list[str]]:
    args = []
    flags = []
    for t in tokens[start:]:
        if t.startswith('-'):
            flags.append(t)
        else:
            args.append(t)
    return args, flags

# maps a tokenized command to a risk node with summary, intent etc
def parse_single_command(tokens: list[str], raw_part: str) -> dict | None:
    if not tokens:
        return None

    cmd = tokens[0]

    node = {
        "command": cmd,
        "effects": {
            "reads_files": False,
            "writes_files": False,
            "deletes_files": False,
            "network_access": False,
            "privilege_escalation": False,
            "changes_git_state": False
        },
        "summary": "",
        "intent": "",
        "warnings": [],
        "risk_score": 0
    }

    if cmd == 'find':
        node["effects"]["reads_files"] = True

        paths = []
        for t in tokens[1:]:
            if t.startswith('-'):
                break
            paths.append(t)

        if paths:
            path_str = " ".join(paths)
        else:
            path_str = "the current directory"

        names = []
        for i in range(len(tokens)):
            if tokens[i] in ['-name', '-iname'] and i + 1 < len(tokens):
                names.append(tokens[i+1])

        if names:
            name_str = " or ".join(names)
            node["summary"] = f"Search {path_str} for files named {name_str}"
            node["intent"] = f"Locate files ({name_str})"
        else:
            node["summary"] = f"Search {path_str} for files"
            node["intent"] = "Locate files"

        if "-exec" in tokens and "rm" in tokens:
            node["effects"]["deletes_files"] = True
            node["risk_score"] += RISK_FIND_DELETE
            node["summary"] += " and delete them"

        if "2>/dev/null" in raw_part:
            node["summary"] += " (ignoring permission errors)"

    elif cmd in ['grep', 'rg']:
        node["effects"]["reads_files"] = True

        args, _ = split_args(tokens)

        if args:
            pattern = args[0]
            if len(args) > 1:
                targets = " ".join(args[1:])
            else:
                targets = "files"
            node["summary"] = f"Search {targets} for '{pattern}'"
        else:
            node["summary"] = "Search for text"

        node["intent"] = "Find text in files"

    elif cmd == 'rm':
        node["effects"]["deletes_files"] = True
        node["risk_score"] += RISK_RM_BASE

        targets, flags = split_args(tokens)

        if targets:
            target_str = " ".join(targets)
        else:
            target_str = "files"

        if "-rf" in flags or ("-r" in flags and "-f" in flags):
            node["risk_score"] += RISK_RM_FORCE_RECURSIVE
            node["warnings"].append(f"Forcefully deletes {target_str} without asking.")
            node["summary"] = f"Force delete {target_str}"
        else:
            node["summary"] = f"Delete {target_str}"

        node["intent"] = "Remove files permanently"

    elif cmd == 'echo':
        args, _ = split_args(tokens)
        if '>' in tokens:
            node["effects"]["writes_files"] = True
            node["summary"] = "Write text into a file"
            node["intent"] = "Write to a file"
        else:
            node["summary"] = "Print text"
            node["intent"] = "Display text"

    elif cmd == 'git':
        if len(tokens) > 1:
            subcmd = tokens[1]

            if subcmd in ['status', 'log', 'diff', 'show', 'branch']:
                node["effects"]["reads_files"] = True
                node["summary"] = f"Check git {subcmd}"
                node["intent"] = "Review repository state"

            elif subcmd in ['clean', 'reset', 'checkout', 'restore', 'push']:
                node["effects"]["changes_git_state"] = True
                node["risk_score"] += RISK_GIT_STATE_CHANGE
                node["warnings"].append(f"Changes repository state: git {subcmd}")
                node["summary"] = f"Modify repository using git {subcmd}"
                if subcmd in ['clean', 'reset']:
                    node["intent"] = "Reset or discard local changes"
                else:
                    node["intent"] = "Change git state"
                if subcmd == 'clean':
                    clean_flags = ""
                    for t in tokens[2:]:
                        if t.startswith('-'):
                            clean_flags += t.lstrip('-')
                    if 'x' in clean_flags or 'f' in clean_flags or 'd' in clean_flags:
                        node["risk_score"] += RISK_GIT_CLEAN_FLAGS
                        node["warnings"].append("This removes untracked and potentially ignored files permanently.")
            else:
                node["effects"]["changes_git_state"] = True
                node["summary"] = f"Run git {subcmd}"
                node["intent"] = f"Git {subcmd}"
        else:
            node["summary"] = "Run git"

    elif cmd in ['npm', 'yarn', 'pnpm', 'pip', 'cargo']:
        node["effects"]["network_access"] = True

        if len(tokens) > 1:
            subcmd = tokens[1]
            if subcmd in ['install', 'add', 'i']:
                node["effects"]["writes_files"] = True
                node["risk_score"] += RISK_PKG_INSTALL

                pkg_args, _ = split_args(tokens, start=2)
                packages = " ".join(pkg_args)
                if packages:
                    pkg_str = f" ({packages})"
                else:
                    pkg_str = ""

                node["warnings"].append("Downloads and installs software from the internet.")
                node["summary"] = f"Install packages{pkg_str} using {cmd}"
                node["intent"] = "Install dependencies"
            else:
                node["summary"] = f"Run {cmd} {subcmd}"
                node["intent"] = "Use package manager"
        else:
            node["summary"] = f"Run {cmd}"

    elif cmd in ['curl', 'wget']:
        node["effects"]["network_access"] = True
        node["risk_score"] += RISK_CURL_WGET

        urls, _ = split_args(tokens)
        if urls:
            target = urls[0]
        else:
            target = "the internet"

        node["summary"] = f"Download data from {target}"
        node["intent"] = "Fetch web resources"

    elif cmd in ['bash', 'sh']:
        if "-c" in tokens:
            node["risk_score"] += RISK_BASH_C
            c_idx = tokens.index("-c")
            if c_idx + 1 < len(tokens):
                node["inner_command"] = tokens[c_idx + 1]
            node["summary"] = "Execute a shell script string"
            node["intent"] = "Run arbitrary commands"
        else:
            script, _ = split_args(tokens)
            if script:
                script_str = script[0]
            else:
                script_str = "a script"
            node["summary"] = f"Run script {script_str}"
            node["intent"] = "Execute script"

    elif cmd == 'sudo':
        node["effects"]["privilege_escalation"] = True
        node["risk_score"] += RISK_SUDO
        node["warnings"].append("Requests administrative (root) privileges.")

        if len(tokens) > 1:
            inner_cmd = tokens[1]
            node["summary"] = f"Run {inner_cmd} as administrator"
            node["intent"] = "Execute highly privileged operation"
        else:
            node["summary"] = "Run a command as administrator"
            node["intent"] = "Elevate privileges"

    elif cmd in ['mkdir', 'touch']:
        node["effects"]["writes_files"] = True
        args, _ = split_args(tokens)
        targets = " ".join(args)
        if cmd == "mkdir":
            action = "Create directory"
        else:
            action = "Create file"
        node["summary"] = f"{action} {targets}"
        node["intent"] = action

    elif cmd in ['ls', 'pwd', 'tree', 'wc', 'cat', 'less', 'more', 'head', 'tail']:
        node["effects"]["reads_files"] = True
        args, _ = split_args(tokens)
        targets = " ".join(args)
        if targets:
            node["summary"] = f"View {targets} using {cmd}"
        else:
            node["summary"] = f"View information using {cmd}"
        node["intent"] = "Inspect files or directories"

    elif cmd == 'awk':
        node["effects"]["reads_files"] = True
        args, _ = split_args(tokens)
        if len(args) > 1:
            files = " ".join(args[1:])
            node["summary"] = f"Process {files} with awk"
        else:
            node["summary"] = "Process input with awk"
        node["intent"] = "Transform text with awk"

    elif cmd == 'jq':
        node["effects"]["reads_files"] = True
        args, _ = split_args(tokens)
        if len(args) > 1:
            files = " ".join(args[1:])
            node["summary"] = f"Parse JSON from {files}"
        else:
            node["summary"] = "Parse JSON input"
        node["intent"] = "Extract data from JSON"

    elif cmd in ['mv', 'cp']:
        node["effects"]["writes_files"] = True
        if cmd == 'mv':
            node["effects"]["deletes_files"] = True
        args, flags = split_args(tokens)

        if '-f' in flags or '--force' in flags:
            node["risk_score"] += RISK_MV_CP_FORCE
            node["warnings"].append("Force flag: will overwrite without asking.")

        if cmd == 'mv':
            verb = "Move"
        else:
            verb = "Copy"

        if len(args) >= 2:
            src = " ".join(args[:-1])
            dest = args[-1]
            node["summary"] = f"{verb} {src} -> {dest}"
            node["intent"] = f"{verb} files"
        else:
            node["summary"] = f"{verb} files"
            node["intent"] = f"{verb} files"
        node["risk_score"] += RISK_MV_CP_BASE

    elif cmd in ['chmod', 'chown']:
        node["effects"]["writes_files"] = True
        args, flags = split_args(tokens)

        if '-R' in flags or '--recursive' in flags:
            node["risk_score"] += RISK_CHMOD_RECURSIVE
            node["warnings"].append(f"Recursive {cmd}: affects all files in subdirectories.")

        if cmd == 'chmod':
            thing = "permissions"
        else:
            thing = "ownership"

        if args:
            mode_or_owner = args[0]
            if len(args) > 1:
                targets = " ".join(args[1:])
            else:
                targets = "files"
            if cmd == 'chmod':
                node["summary"] = f"Change permissions of {targets} to {mode_or_owner}"
            else:
                node["summary"] = f"Change owner of {targets} to {mode_or_owner}"
        else:
            node["summary"] = f"Change {thing}"
        node["intent"] = f"Modify file {thing}"
        node["risk_score"] += RISK_CHMOD_CHOWN_BASE

    elif cmd == 'make':
        node["effects"]["writes_files"] = True
        args, _ = split_args(tokens)
        if args:
            targets = " ".join(args)
            node["summary"] = f"Build target(s): {targets}"
        else:
            node["summary"] = "Build default target"
        node["intent"] = "Run build system"
        node["risk_score"] += RISK_MAKE

    elif cmd == 'sed':
        args, flags = split_args(tokens)
        if '-i' in flags or any(f.startswith('-i') for f in flags):
            node["effects"]["writes_files"] = True
            node["risk_score"] += RISK_SED_INPLACE
            node["warnings"].append("In-place edit: modifies files directly.")
            if args:
                if len(args) > 1:
                    files = " ".join(args[1:])
                else:
                    files = "files"
                node["summary"] = f"Edit {files} in-place with sed"
            else:
                node["summary"] = "Edit files in-place with sed"
            node["intent"] = "Modify files with sed"
        else:
            node["effects"]["reads_files"] = True
            if args and len(args) > 1:
                files = " ".join(args[1:])
                node["summary"] = f"Filter {files} with sed"
            else:
                node["summary"] = "Filter input with sed"
            node["intent"] = "Transform text with sed"

    elif cmd == 'tar':
        args, flags = split_args(tokens)
        bundled = ""
        for f in flags:
            bundled += f.lstrip('-')

        if 'x' in bundled:
            node["effects"]["writes_files"] = True
            node["risk_score"] += RISK_TAR_EXTRACT
            if args:
                node["summary"] = f"Extract archive {args[0]}"
            else:
                node["summary"] = "Extract archive"
            node["intent"] = "Extract files from archive"
        elif 'c' in bundled:
            node["effects"]["reads_files"] = True
            if args:
                node["summary"] = f"Create archive {args[0]}"
            else:
                node["summary"] = "Create archive"
            node["intent"] = "Create archive"
        elif 't' in bundled:
            node["effects"]["reads_files"] = True
            if args:
                node["summary"] = f"List contents of {args[0]}"
            else:
                node["summary"] = "List archive contents"
            node["intent"] = "Inspect archive"
        else:
            node["effects"]["reads_files"] = True
            node["summary"] = "Run tar"
            node["intent"] = "Archive operation"

    elif cmd == 'zip':
        node["effects"]["writes_files"] = True
        args, _ = split_args(tokens)
        if args:
            node["summary"] = f"Create zip archive {args[0]}"
        else:
            node["summary"] = "Create zip archive"
        node["intent"] = "Compress files"

    elif cmd == 'unzip':
        node["effects"]["writes_files"] = True
        node["risk_score"] += RISK_UNZIP
        args, _ = split_args(tokens)

        if args:
            node["summary"] = f"Extract {args[0]}"
            node["warnings"].append("Extracting may overwrite existing files.")
        else:
            node["summary"] = "Extract zip archive"
        node["intent"] = "Extract compressed files"

    elif cmd in ['python', 'python3', 'node', 'ruby']:
        node["effects"]["reads_files"] = True
        args, flags = split_args(tokens)
        inline_flags = {'-c', '-e'}
        if inline_flags & set(flags):
            node["risk_score"] += RISK_INLINE_CODE
            code_str = ""
            for i, t in enumerate(tokens):
                if t in ('-c', '-e') and i + 1 < len(tokens):
                    code_str = tokens[i + 1]
                    break
            lang_key = 'python' if cmd in ('python', 'python3') else cmd
            if code_str:
                _scan_inline_code(lang_key, code_str, node)
                snippet = code_str[:80]
                if len(code_str) > 80:
                    snippet += "..."
                node["summary"] = f"Run {cmd} code: {snippet}"
            else:
                node["summary"] = f"Run inline {cmd} code"
            node["intent"] = f"Run inline {cmd} script"
        elif args:
            script = args[0]
            node["summary"] = f"Run {cmd} script {script}"
            node["intent"] = f"Execute {cmd} script"
        else:
            node["summary"] = f"Start {cmd} interpreter"
            node["intent"] = f"Run {cmd}"

    elif cmd in ['ssh', 'scp']:
        node["effects"]["network_access"] = True
        node["risk_score"] += RISK_SSH_SCP
        args, _ = split_args(tokens)

        if cmd == 'ssh':
            if args:
                host = args[0]
                if len(args) > 1:
                    remote_cmd = " ".join(args[1:])
                    node["summary"] = f"SSH to {host} and run: {remote_cmd}"
                    node["risk_score"] += RISK_SSH_REMOTE_CMD
                    node["warnings"].append("Executes a command on a remote machine.")
                else:
                    node["summary"] = f"SSH to {host}"
                node["intent"] = "Remote shell access"
            else:
                node["summary"] = "SSH connection"
                node["intent"] = "Remote shell access"
        else:
            if args:
                node["summary"] = f"Copy files via SCP: {' '.join(args[:3])}"
            else:
                node["summary"] = "Copy files via SCP"
            node["intent"] = "Remote file transfer"

    elif cmd == 'docker':
        node["effects"]["network_access"] = True
        if len(tokens) > 1:
            subcmd = tokens[1]
            sub_args, _ = split_args(tokens, start=2)
            if subcmd == 'run':
                node["risk_score"] += RISK_DOCKER_RUN
                if sub_args:
                    image = sub_args[0]
                else:
                    image = "an image"
                node["summary"] = f"Run Docker container from {image}"
                node["intent"] = "Run container"
            elif subcmd == 'exec':
                node["risk_score"] += RISK_DOCKER_EXEC
                if sub_args:
                    container = sub_args[0]
                else:
                    container = "a container"
                node["summary"] = f"Execute command in container {container}"
                node["intent"] = "Run command in container"
            elif subcmd == 'rm':
                node["effects"]["deletes_files"] = True
                node["risk_score"] += RISK_DOCKER_RM
                if sub_args:
                    targets = " ".join(sub_args)
                else:
                    targets = "containers"
                node["summary"] = f"Remove Docker container(s): {targets}"
                node["intent"] = "Remove container"
            elif subcmd == 'build':
                node["risk_score"] += RISK_DOCKER_BUILD
                node["summary"] = "Build Docker image"
                node["intent"] = "Build container image"
            elif subcmd in ['pull', 'push']:
                node["risk_score"] += RISK_DOCKER_PULL_PUSH
                if sub_args:
                    image = sub_args[0]
                else:
                    image = "an image"
                node["summary"] = f"Docker {subcmd} {image}"
                if subcmd == 'pull':
                    node["intent"] = "Download container image"
                else:
                    node["intent"] = "Upload container image"
            else:
                node["summary"] = f"Run docker {subcmd}"
                node["intent"] = f"Docker {subcmd}"
        else:
            node["summary"] = "Run docker"
            node["intent"] = "Docker operation"

    elif cmd == 'xargs':
        sub_tokens = []
        skip_next = False
        for t in tokens[1:]:
            if skip_next:
                skip_next = False
                continue

            if t.startswith('-') and not sub_tokens:
                if t in ['-I', '-n', '-P', '-L', '-d']:
                    skip_next = True
                continue

            sub_tokens.append(t)
        if sub_tokens:
            sub_node = parse_single_command(sub_tokens, " ".join(sub_tokens))
            if sub_node:
                node["effects"] = sub_node["effects"]
                node["risk_score"] = sub_node["risk_score"]
                node["warnings"] = sub_node["warnings"]
                node["summary"] = f"xargs: {sub_node['summary']}"
                node["intent"] = sub_node["intent"]
            else:
                node["summary"] = f"Run xargs {sub_tokens[0]}"
                node["intent"] = "Execute command via xargs"
        else:
            node["summary"] = "Run xargs (echo by default)"
            node["intent"] = "Batch execute command"

    elif cmd in ['nc', 'ncat', 'netcat']:
        node["effects"]["network_access"] = True
        node["risk_score"] += RISK_NETCAT
        args, flags = split_args(tokens)
        node["warnings"].append("Netcat can open raw network connections.")
        if args:
            host = args[0]
            port = args[1] if len(args) > 1 else ""
            target = f"{host}:{port}" if port else host
            if '-l' in flags or '--listen' in flags:
                node["summary"] = f"Listen for connections on {target}"
                node["intent"] = "Open network listener"
                node["warnings"].append("Opens a listening port on this machine.")
            else:
                node["summary"] = f"Connect to {target}"
                node["intent"] = "Raw network connection"
        else:
            node["summary"] = "Open raw network connection"
            node["intent"] = "Network access"

    elif cmd == 'telnet':
        node["effects"]["network_access"] = True
        node["risk_score"] += RISK_TELNET
        args, _ = split_args(tokens)
        node["warnings"].append("Telnet sends data unencrypted.")
        if args:
            host = args[0]
            port = args[1] if len(args) > 1 else "23"
            node["summary"] = f"Connect to {host}:{port} via telnet (unencrypted)"
            node["intent"] = "Unencrypted remote connection"
        else:
            node["summary"] = "Open telnet connection"
            node["intent"] = "Unencrypted remote connection"

    elif cmd == 'rsync':
        node["effects"]["reads_files"] = True
        node["effects"]["writes_files"] = True
        node["risk_score"] += RISK_RSYNC
        args, flags = split_args(tokens)
        if '--delete' in flags:
            node["effects"]["deletes_files"] = True
            node["risk_score"] += 20
            node["warnings"].append("--delete removes files at destination that don't exist at source.")
        if any(':' in a for a in args):
            node["effects"]["network_access"] = True
        if len(args) >= 2:
            node["summary"] = f"Sync {args[0]} -> {args[-1]}"
        elif args:
            node["summary"] = f"Sync {args[0]}"
        else:
            node["summary"] = "Sync files with rsync"
        node["intent"] = "Synchronize files"

    elif cmd == 'nmap':
        node["effects"]["network_access"] = True
        node["risk_score"] += RISK_NMAP
        args, _ = split_args(tokens)
        node["warnings"].append("Network scanning tool — may trigger security alerts.")
        if args:
            node["summary"] = f"Scan network target {args[0]}"
        else:
            node["summary"] = "Scan network"
        node["intent"] = "Network reconnaissance"

    elif cmd == 'tcpdump':
        node["effects"]["network_access"] = True
        node["risk_score"] += RISK_TCPDUMP
        node["warnings"].append("Captures network traffic (may include sensitive data).")
        args, flags = split_args(tokens)
        if '-w' in flags:
            node["effects"]["writes_files"] = True
            node["summary"] = "Capture network traffic to file"
        else:
            node["summary"] = "Capture and display network traffic"
        node["intent"] = "Network packet capture"

    elif cmd in ['kill', 'killall', 'pkill']:
        node["risk_score"] += RISK_KILL
        args, flags = split_args(tokens)
        if '-9' in flags or '-KILL' in flags or '-SIGKILL' in flags:
            node["warnings"].append("Force kill — process cannot clean up.")
            node["risk_score"] += 10
        if cmd == 'kill' and args:
            node["summary"] = f"Kill process {' '.join(args)}"
        elif cmd == 'killall' and args:
            node["summary"] = f"Kill all processes named {args[0]}"
        elif cmd == 'pkill' and args:
            node["summary"] = f"Kill processes matching '{args[0]}'"
        else:
            node["summary"] = "Terminate processes"
        node["intent"] = "Stop running processes"

    elif cmd in ['systemctl', 'service']:
        node["risk_score"] += RISK_SYSTEMCTL
        args, _ = split_args(tokens)
        if cmd == 'systemctl' and args:
            action = args[0]
            service = args[1] if len(args) > 1 else "a service"
            node["summary"] = f"Systemctl {action} {service}"
            if action in ('stop', 'disable', 'mask'):
                node["warnings"].append(f"Stops or disables system service: {service}")
            elif action in ('start', 'restart', 'enable'):
                node["warnings"].append(f"Starts or enables system service: {service}")
        elif cmd == 'service' and len(args) >= 2:
            service, action = args[0], args[1]
            node["summary"] = f"Service {service} {action}"
        else:
            node["summary"] = "Manage system service"
        node["intent"] = "Manage system services"

    elif cmd == 'crontab':
        args, flags = split_args(tokens)
        if '-e' in flags:
            node["effects"]["writes_files"] = True
            node["risk_score"] += RISK_CRONTAB_EDIT
            node["warnings"].append("Edits scheduled tasks (cron jobs).")
            node["summary"] = "Edit cron jobs"
            node["intent"] = "Modify scheduled tasks"
        elif '-r' in flags:
            node["effects"]["deletes_files"] = True
            node["risk_score"] += RISK_CRONTAB_EDIT
            node["warnings"].append("Removes ALL cron jobs for current user.")
            node["summary"] = "Remove all cron jobs"
            node["intent"] = "Delete scheduled tasks"
        elif '-l' in flags:
            node["effects"]["reads_files"] = True
            node["risk_score"] += RISK_CRONTAB_LIST
            node["summary"] = "List cron jobs"
            node["intent"] = "View scheduled tasks"
        else:
            node["effects"]["writes_files"] = True
            node["risk_score"] += RISK_CRONTAB_EDIT
            node["summary"] = "Modify cron jobs"
            node["intent"] = "Modify scheduled tasks"

    elif cmd == 'passwd':
        node["effects"]["writes_files"] = True
        node["risk_score"] += RISK_PASSWD
        args, _ = split_args(tokens)
        if args:
            node["summary"] = f"Change password for user {args[0]}"
        else:
            node["summary"] = "Change current user's password"
        node["intent"] = "Modify user credentials"

    elif cmd in ['useradd', 'userdel', 'groupadd', 'groupdel', 'usermod']:
        node["effects"]["writes_files"] = True
        node["risk_score"] += RISK_USER_MGMT
        args, _ = split_args(tokens)
        target = args[0] if args else "unknown"
        if 'del' in cmd:
            node["effects"]["deletes_files"] = True
            node["summary"] = f"Delete {'user' if 'user' in cmd else 'group'} {target}"
            node["warnings"].append(f"Permanently removes a {'user account' if 'user' in cmd else 'group'}.")
        elif 'mod' in cmd:
            node["summary"] = f"Modify user {target}"
        else:
            node["summary"] = f"Create {'user' if 'user' in cmd else 'group'} {target}"
        node["intent"] = "Manage users/groups"

    elif cmd in ['mount', 'umount']:
        node["risk_score"] += RISK_MOUNT
        args, _ = split_args(tokens)
        if cmd == 'mount':
            node["effects"]["writes_files"] = True
            if len(args) >= 2:
                node["summary"] = f"Mount {args[0]} at {args[1]}"
            elif args:
                node["summary"] = f"Mount {args[0]}"
            else:
                node["summary"] = "List mounted filesystems"
                node["risk_score"] = 0
            node["intent"] = "Mount filesystem"
        else:
            if args:
                node["summary"] = f"Unmount {args[0]}"
            else:
                node["summary"] = "Unmount filesystem"
            node["intent"] = "Unmount filesystem"

    elif cmd in ['fdisk', 'mkfs', 'parted', 'mkswap']:
        node["effects"]["writes_files"] = True
        node["risk_score"] += RISK_DISK_MGMT
        args, _ = split_args(tokens)
        node["warnings"].append("Disk management — can destroy all data on a drive.")
        if args:
            node["summary"] = f"Modify disk/partition {args[0]} using {cmd}"
        else:
            node["summary"] = f"Disk management using {cmd}"
        node["intent"] = "Manage disk partitions"

    elif cmd in ['iptables', 'ip6tables', 'nft', 'ufw']:
        node["effects"]["network_access"] = True
        node["risk_score"] += RISK_IPTABLES
        args, _ = split_args(tokens)
        node["warnings"].append("Modifies firewall rules — can lock you out of the system.")
        if args:
            node["summary"] = f"Modify firewall rules: {cmd} {' '.join(args[:4])}"
        else:
            node["summary"] = f"Modify firewall rules using {cmd}"
        node["intent"] = "Configure firewall"

    elif cmd == 'dd':
        node["effects"]["reads_files"] = True
        node["effects"]["writes_files"] = True
        node["risk_score"] += RISK_DD
        node["warnings"].append("dd writes raw data — wrong target can destroy a disk.")
        src = ""
        dest = ""
        for t in tokens[1:]:
            if t.startswith("if="):
                src = t[3:]
            elif t.startswith("of="):
                dest = t[3:]
        if src and dest:
            node["summary"] = f"Copy raw data: {src} -> {dest}"
        elif dest:
            node["summary"] = f"Write raw data to {dest}"
        elif src:
            node["summary"] = f"Read raw data from {src}"
        else:
            node["summary"] = "Copy raw data blocks"
        node["intent"] = "Raw disk/data copy"

    elif cmd == 'ln':
        node["effects"]["writes_files"] = True
        args, flags = split_args(tokens)
        if '-f' in flags or '--force' in flags:
            node["risk_score"] += RISK_LN_FORCE
            node["warnings"].append("Force flag: overwrites existing link target.")
        else:
            node["risk_score"] += RISK_LN
        if '-s' in flags or '--symbolic' in flags:
            link_type = "symbolic link"
        else:
            link_type = "hard link"
        if len(args) >= 2:
            node["summary"] = f"Create {link_type}: {args[-1]} -> {args[0]}"
        elif args:
            node["summary"] = f"Create {link_type} to {args[0]}"
        else:
            node["summary"] = f"Create {link_type}"
        node["intent"] = "Create file link"

    elif cmd == 'tee':
        node["effects"]["reads_files"] = True
        node["effects"]["writes_files"] = True
        node["risk_score"] += RISK_TEE
        args, flags = split_args(tokens)
        if '-a' in flags or '--append' in flags:
            mode = "append to"
        else:
            mode = "write to"
        if args:
            node["summary"] = f"Copy stdin and {mode} {' '.join(args)}"
        else:
            node["summary"] = "Copy stdin to stdout and files"
        node["intent"] = "Duplicate output to files"

    elif cmd in ['openssl', 'gpg']:
        node["effects"]["reads_files"] = True
        node["risk_score"] += RISK_OPENSSL if cmd == 'openssl' else RISK_GPG
        args, _ = split_args(tokens)
        if cmd == 'openssl' and args:
            subcmd = args[0]
            if subcmd in ('req', 'genrsa', 'genpkey', 'ecparam'):
                node["effects"]["writes_files"] = True
                node["summary"] = f"Generate cryptographic key/certificate ({subcmd})"
                node["intent"] = "Generate crypto material"
            elif subcmd in ('enc', 'aes-256-cbc'):
                node["summary"] = f"Encrypt/decrypt data with openssl {subcmd}"
                node["intent"] = "Encrypt or decrypt data"
            elif subcmd == 's_client':
                node["effects"]["network_access"] = True
                node["summary"] = "Test TLS connection"
                node["intent"] = "Debug TLS/SSL"
            else:
                node["summary"] = f"Run openssl {subcmd}"
                node["intent"] = "Cryptographic operation"
        elif cmd == 'gpg':
            if '--decrypt' in tokens or '-d' in tokens:
                node["summary"] = "Decrypt GPG-encrypted data"
                node["intent"] = "Decrypt data"
            elif '--encrypt' in tokens or '-e' in tokens:
                node["effects"]["writes_files"] = True
                node["summary"] = "Encrypt data with GPG"
                node["intent"] = "Encrypt data"
            elif '--sign' in tokens or '-s' in tokens:
                node["effects"]["writes_files"] = True
                node["summary"] = "Sign data with GPG"
                node["intent"] = "Cryptographic signing"
            else:
                node["summary"] = "GPG cryptographic operation"
                node["intent"] = "Cryptographic operation"
        else:
            node["summary"] = f"Run {cmd}"
            node["intent"] = "Cryptographic operation"

    elif cmd in ['base64']:
        node["effects"]["reads_files"] = True
        args, flags = split_args(tokens)
        if '-d' in flags or '--decode' in flags or '-D' in flags:
            node["summary"] = "Decode base64 data"
            node["intent"] = "Decode data"
        else:
            node["summary"] = "Encode data as base64"
            node["intent"] = "Encode data"

    elif cmd in ['open', 'xdg-open']:
        args, _ = split_args(tokens)
        if args:
            node["summary"] = f"Open {args[0]} with default application"
        else:
            node["summary"] = "Open with default application"
        node["intent"] = "Open file/URL externally"

    elif cmd in ['pbcopy', 'pbpaste', 'xclip', 'xsel']:
        if cmd in ('pbcopy', 'xclip', 'xsel'):
            node["summary"] = "Copy stdin to clipboard"
            node["intent"] = "Copy to clipboard"
        else:
            node["summary"] = "Paste from clipboard"
            node["intent"] = "Read clipboard"

    else:
        args, flags = split_args(tokens)
        file_paths = []
        for a in args:
            if '/' in a or '.' in a:
                file_paths.append(a)

        if file_paths:
            shown = ", ".join(file_paths[:3])
            if len(file_paths) > 3:
                shown += f" (+{len(file_paths) - 3} more)"
            node["summary"] = f"Run '{cmd}' on {shown}"

        elif args:
            shown = " ".join(args[:3])
            if len(args) > 3:
                shown += " ..."
            node["summary"] = f"Run '{cmd}' with args: {shown}"

        else:
            node["summary"] = f"Run command '{cmd}'"
        node["intent"] = "Execute system command"
        node["risk_score"] += RISK_UNKNOWN_CMD

    return node
