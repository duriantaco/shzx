import json
import os
import subprocess
import sys
import unittest


def run_hook(input_data):
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "hook"],
        input=json.dumps(input_data),
        capture_output=True,
        text=True,
        env=env,
    )
    return proc


def run_hook_with_color(input_data):
    env = os.environ.copy()
    env.pop("NO_COLOR", None)
    proc = subprocess.run(
        [sys.executable, "-m", "hook"],
        input=json.dumps(input_data),
        capture_output=True,
        text=True,
        env=env,
    )
    return proc


class TestHookCriticalDeny(unittest.TestCase):

    def test_critical_command_denied(self):
        data = {"tool_name": "Bash", "tool_input": {"command": "sudo rm -rf /"}}
        proc = run_hook(data)
        self.assertEqual(proc.returncode, 0)
        result = json.loads(proc.stdout)
        decision = result["hookSpecificOutput"]["permissionDecision"]
        self.assertEqual(decision, "deny")

    def test_critical_reason_contains_risk(self):
        data = {"tool_name": "Bash", "tool_input": {"command": "sudo rm -rf /"}}
        proc = run_hook(data)
        result = json.loads(proc.stdout)
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("CRITICAL", reason)


class TestHookHighAsk(unittest.TestCase):

    def test_high_risk_asks(self):
        data = {"tool_name": "Bash", "tool_input": {"command": "rm file.txt"}}
        proc = run_hook(data)
        result = json.loads(proc.stdout)
        decision = result["hookSpecificOutput"]["permissionDecision"]
        self.assertEqual(decision, "ask")

    def test_high_reason_contains_summary(self):
        data = {"tool_name": "Bash", "tool_input": {"command": "rm file.txt"}}
        proc = run_hook(data)
        result = json.loads(proc.stdout)
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("Summary:", reason)


class TestHookLowMediumAsk(unittest.TestCase):

    def test_low_risk_asks_user(self):
        data = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
        proc = run_hook(data)
        result = json.loads(proc.stdout)
        output = result["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "ask")
        self.assertIn("LOW", output["permissionDecisionReason"])

    def test_medium_risk_asks_user(self):
        data = {"tool_name": "Bash", "tool_input": {"command": "curl http://example.com"}}
        proc = run_hook(data)
        result = json.loads(proc.stdout)
        output = result["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "ask")
        self.assertIn("MEDIUM", output["permissionDecisionReason"])


class TestHookEdgeCases(unittest.TestCase):

    def test_empty_command_exits_zero(self):
        data = {"tool_name": "Bash", "tool_input": {"command": ""}}
        proc = run_hook(data)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "")

    def test_malformed_json_exits_zero(self):
        env = os.environ.copy()
        env["NO_COLOR"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "hook"],
            input="not json at all",
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "")

    def test_context_format_has_all_fields(self):
        data = {"tool_name": "Bash", "tool_input": {"command": "git push"}}
        proc = run_hook(data)
        result = json.loads(proc.stdout)
        ctx = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("Risk:", ctx)
        self.assertIn("Summary:", ctx)
        self.assertIn("Intent:", ctx)


class TestHookColor(unittest.TestCase):

    def test_color_output_contains_ansi(self):
        data = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
        proc = run_hook_with_color(data)
        result = json.loads(proc.stdout)
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("\033[", reason)

    def test_no_color_strips_ansi(self):
        data = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
        proc = run_hook(data)
        result = json.loads(proc.stdout)
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertNotIn("\033[", reason)


class TestHookWriteTool(unittest.TestCase):

    def test_write_normal_file_asks(self):
        data = {"tool_name": "Write", "tool_input": {"file_path": "/tmp/foo.txt"}}
        proc = run_hook(data)
        result = json.loads(proc.stdout)
        output = result["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "ask")
        self.assertIn("Tool: Write", output["permissionDecisionReason"])

    def test_write_sensitive_file_warns(self):
        data = {"tool_name": "Write", "tool_input": {"file_path": "/home/user/.env"}}
        proc = run_hook(data)
        result = json.loads(proc.stdout)
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("sensitive", reason.lower())
        self.assertIn("HIGH", reason)

    def test_write_system_dir_warns(self):
        data = {"tool_name": "Write", "tool_input": {"file_path": "/etc/hosts"}}
        proc = run_hook(data)
        result = json.loads(proc.stdout)
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("system directory", reason.lower())
        self.assertIn("HIGH", reason)

    def test_write_shell_script_medium(self):
        data = {"tool_name": "Write", "tool_input": {"file_path": "/tmp/deploy.sh"}}
        proc = run_hook(data)
        result = json.loads(proc.stdout)
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("shell script", reason.lower())

    def test_write_no_file_path_passthrough(self):
        data = {"tool_name": "Write", "tool_input": {}}
        proc = run_hook(data)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "")


class TestHookEditTool(unittest.TestCase):

    def test_edit_normal_file_asks(self):
        data = {"tool_name": "Edit", "tool_input": {"file_path": "/tmp/foo.py"}}
        proc = run_hook(data)
        result = json.loads(proc.stdout)
        output = result["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "ask")
        self.assertIn("Tool: Edit", output["permissionDecisionReason"])

    def test_edit_sensitive_file_warns(self):
        data = {"tool_name": "Edit", "tool_input": {"file_path": "/home/user/.ssh/config"}}
        proc = run_hook(data)
        result = json.loads(proc.stdout)
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("sensitive", reason.lower())


class TestHookUnknownTool(unittest.TestCase):

    def test_unknown_tool_passthrough(self):
        data = {"tool_name": "SomethingElse", "tool_input": {"foo": "bar"}}
        proc = run_hook(data)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
