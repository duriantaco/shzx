import subprocess
import sys
import unittest


class TestshzxApprove(unittest.TestCase):

    def test_approve_runs_command(self):
        proc = subprocess.run(
            [sys.executable, "-m", "shzx", "-c", "echo shzx_test_ok"],
            input="y\n",
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("shzx_test_ok", proc.stdout)

    def test_deny_blocks_command(self):
        proc = subprocess.run(
            [sys.executable, "-m", "shzx", "-c", "echo deny_marker_xyz"],
            input="n\n",
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("blocked", proc.stdout.lower())
        
        occurrences = proc.stdout.count("deny_marker_xyz")
        self.assertEqual(occurrences, 1, "Command was executed despite deny")


class TestshzxDisplay(unittest.TestCase):

    def test_displays_risk_and_summary(self):
        proc = subprocess.run(
            [sys.executable, "-m", "shzx", "-c", "ls -la"],
            input="n\n",
            capture_output=True,
            text=True,
        )
        self.assertIn("Risk:", proc.stdout)
        self.assertIn("Summary:", proc.stdout)


class TestshzxNoColor(unittest.TestCase):

    def test_no_color_flag_strips_ansi(self):
        proc = subprocess.run(
            [sys.executable, "-m", "shzx", "--no-color", "-c", "ls -la"],
            input="n\n",
            capture_output=True,
            text=True,
        )
        self.assertNotIn("\033[", proc.stdout)

    def test_no_color_env_strips_ansi(self):
        import os
        env = os.environ.copy()
        env["NO_COLOR"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "shzx", "-c", "ls -la"],
            input="n\n",
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertNotIn("\033[", proc.stdout)


class TestshzxEOF(unittest.TestCase):

    def test_eof_exits_nonzero(self):
        proc = subprocess.run(
            [sys.executable, "-m", "shzx", "-c", "echo hello"],
            input="",
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
