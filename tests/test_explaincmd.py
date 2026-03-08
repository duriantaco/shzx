import json
import subprocess
import sys
import unittest


class TestExplainCmd(unittest.TestCase):

    def test_valid_json_output(self):
        proc = subprocess.run(
            [sys.executable, "-m", "explaincmd", "ls -la"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        result = json.loads(proc.stdout)
        self.assertIn("summary", result)
        self.assertIn("risk", result)
        self.assertIn("effects", result)

    def test_no_args_error(self):
        proc = subprocess.run(
            [sys.executable, "-m", "explaincmd"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        result = json.loads(proc.stdout)
        self.assertIn("error", result)

    def test_critical_risk_detected(self):
        proc = subprocess.run(
            [sys.executable, "-m", "explaincmd", "sudo rm -rf /"],
            capture_output=True,
            text=True,
        )
        result = json.loads(proc.stdout)
        self.assertEqual(result["risk"], "critical")

    def test_low_risk_detected(self):
        proc = subprocess.run(
            [sys.executable, "-m", "explaincmd", "cat file.txt"],
            capture_output=True,
            text=True,
        )
        result = json.loads(proc.stdout)
        self.assertEqual(result["risk"], "low")


if __name__ == "__main__":
    unittest.main()
