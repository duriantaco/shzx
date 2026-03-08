from __future__ import annotations

import re
import shlex
from handlers import parse_single_command
from constants import (
    RISK_THRESHOLD_CRITICAL,
    RISK_THRESHOLD_HIGH,
    RISK_THRESHOLD_MEDIUM,
    RISK_CURL_PIPE_EXEC,
    RISK_WGET_PIPE_EXEC,
    RISK_FIND_EXEC_RM_COMPOSITION,
    RISK_SUDO_RM_RF,
    RISK_GIT_RESET_CLEAN,
    RISK_ECHO_REDIRECT,
    RISK_DEEP_NESTING,
    RISK_COMMAND_SUBSTITUTION,
)

def check_dangerous_composition(command_string: str, results: dict) -> dict:
    warnings = results.get("warnings", [])
    intents = results.get("intents", [])
    risk_score = results.get("risk_score", 0)

    if "curl" in command_string and ("| bash" in command_string or "| sh" in command_string):
        warnings.append("Critical: This downloads and immediately executes code from the internet.")
        risk_score += RISK_CURL_PIPE_EXEC
        intents.append("Download and execute remote script")

    if "wget" in command_string and ("| bash" in command_string or "| sh" in command_string):
        warnings.append("Critical: This downloads and immediately executes code from the internet.")
        risk_score += RISK_WGET_PIPE_EXEC
        intents.append("Download and execute remote script")

    if "find" in command_string and "-exec rm" in command_string:
        warnings.append("High Risk: This searches for files and permanently deletes them automatically.")
        risk_score += RISK_FIND_EXEC_RM_COMPOSITION
        intents.append("Find and permanently delete files")

    if "sudo" in command_string and "rm" in command_string and ("-rf" in command_string or ("-r" in command_string and "-f" in command_string)):
        warnings.append("Critical: This forcefully deletes files with administrative privileges.")
        risk_score += RISK_SUDO_RM_RF
        intents.append("Forcefully delete files as administrator")

    if "git reset --hard" in command_string and "git clean -xfd" in command_string:
        warnings.append("Critical: This completely obliterates all uncommitted changes and untracked files in the repository.")
        risk_score += RISK_GIT_RESET_CLEAN
        intents.append("Completely wipe all uncommitted work")

    unquoted = re.sub(r'''(["']).*?\1''', '', command_string)
    if "echo" in command_string and re.search(r'(?<!\d)(?<!&)>(?!&)', unquoted):
        warnings.append("Medium Risk: This overwrites a file with new content.")
        risk_score += RISK_ECHO_REDIRECT
        intents.append("Write text into a file")

    results["warnings"] = warnings
    results["risk_score"] = risk_score
    results["intents"] = intents
    return results

def _detect_substitutions(command_string: str) -> list[str]:
    subs = []

    i = 0
    while i < len(command_string) - 1:
        if command_string[i] == '$' and command_string[i + 1] == '(':
            depth = 1
            start = i + 2
            j = start
            while j < len(command_string) and depth > 0:
                if command_string[j] == '(' and j > 0 and command_string[j - 1] == '$':
                    depth += 1
                elif command_string[j] == ')':
                    depth -= 1
                j += 1
            if depth == 0:
                subs.append(command_string[start:j - 1])
            i = j
        else:
            i += 1

    for match in re.finditer(r'`([^`]+)`', command_string):
        subs.append(match.group(1))

    return subs

def _merge_internal_result(results: dict, inner: dict) -> None:
    for k in results["effects"]:
        results["effects"][k] = results["effects"][k] or inner["effects"][k]
    results["risk_score"] += inner["risk_score"]
    for w in inner["warnings"]:
        if w not in results["warnings"]:
            results["warnings"].append(w)
    for intent in inner.get("intents", []):
        if intent not in results["intents"]:
            results["intents"].append(intent)

def _analyze_internal(command_string: str, _depth: int = 0) -> dict:
    results = {
        "summary": "",
        "risk": "low",
        "effects": {
            "reads_files": False,
            "writes_files": False,
            "deletes_files": False,
            "network_access": False,
            "privilege_escalation": False,
            "changes_git_state": False
        },
        "likely_intent": "Modify or inspect system state",
        "warnings": [],
        "risk_score": 0,
        "intents": []
    }

    if _depth > 5:
        results["summary"] = "Deeply nested command."
        results["risk"] = "high"
        results["risk_score"] = RISK_DEEP_NESTING
        results["warnings"].append("Command nesting too deep to fully analyze.")
        return results

    results = check_dangerous_composition(command_string, results)

    substitutions = _detect_substitutions(command_string)
    if substitutions:
        results["warnings"].append("Contains embedded command substitution(s).")
        results["risk_score"] += RISK_COMMAND_SUBSTITUTION
        for sub_cmd in substitutions:
            inner = _analyze_internal(sub_cmd, _depth + 1)
            _merge_internal_result(results, inner)

    try:
        tokens = shlex.split(command_string)
    except ValueError:
        tokens = command_string.split()
        results["warnings"].append("Command has malformed quoting; analysis may be incomplete.")

    pipelines = []
    current_pipe = []

    for token in tokens:
        if token == '|':
            pipelines.append(current_pipe)
            current_pipe = []
        elif token == '&&':
            pipelines.append(current_pipe)
            pipelines.append(['AND'])
            current_pipe = []
        elif token == ';':
            pipelines.append(current_pipe)
            pipelines.append(['SEQ'])
            current_pipe = []
        else:
            current_pipe.append(token)

    if current_pipe:
        pipelines.append(current_pipe)

    summaries = []
    pipe_count = 0

    for pipe in pipelines:
        if not pipe:
            continue

        if pipe == ['AND']:
            summaries.append("AND THEN")
            continue

        if pipe == ['SEQ']:
            summaries.append("AND")
            continue

        pipe_count += 1
        raw_segment = " ".join(pipe)
        node = parse_single_command(pipe, raw_segment)

        if node:
             for k in results["effects"]:
                results["effects"][k] = results["effects"][k] or node["effects"][k]

             results["risk_score"] += node["risk_score"]

             for w in node["warnings"]:
                 if w not in results["warnings"]:
                     results["warnings"].append(w)

             if node["intent"] and node["intent"] not in results["intents"]:
                 results["intents"].append(node["intent"])

             summaries.append(node["summary"])

             if "inner_command" in node:
                 inner = _analyze_internal(node["inner_command"], _depth + 1)
                 _merge_internal_result(results, inner)
                 if inner["summary"]:
                     summaries[-1] = f"Shell executes: {inner['summary'].rstrip('.')}"

    final_summary_parts = []
    for i, s in enumerate(summaries):
        if s in ["AND THEN", "AND"]:
            final_summary_parts.append(f", {s.lower()} ")
        elif i > 0 and summaries[i-1] not in ["AND THEN", "AND"]:
            final_summary_parts.append(f" -> {s.lower()}")
        else:
            final_summary_parts.append(s)

    final_summary = "".join(final_summary_parts)

    results["summary"] = final_summary.strip().capitalize() + "."

    if results["intents"]:
        results["likely_intent"] = results["intents"][-1]

    if results["risk_score"] >= RISK_THRESHOLD_CRITICAL:
        results["risk"] = "critical"
    elif results["risk_score"] >= RISK_THRESHOLD_HIGH:
        results["risk"] = "high"
    elif results["risk_score"] >= RISK_THRESHOLD_MEDIUM:
        results["risk"] = "medium"
    else:
        results["risk"] = "low"

    return results

def analyze_command(command_string: str) -> dict:
    results = _analyze_internal(command_string)
    del results["risk_score"]
    del results["intents"]
    return results
