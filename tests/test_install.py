import json
import tempfile
import unittest
from pathlib import Path

from install import main, uninstall


class TestInstallFresh(unittest.TestCase):

    def test_creates_settings_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            main(settings_dir=d)
            settings = json.loads((d / "settings.json").read_text())
            self.assertIn("hooks", settings)
            pre_tool = settings["hooks"]["PreToolUse"]
            self.assertEqual(len(pre_tool), 3)
            matchers = [e["matcher"] for e in pre_tool]
            self.assertIn("Bash", matchers)
            self.assertIn("Write", matchers)
            self.assertIn("Edit", matchers)

    def test_creates_directory_if_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "subdir"
            main(settings_dir=d)
            self.assertTrue((d / "settings.json").exists())


class TestInstallExisting(unittest.TestCase):

    def test_preserves_other_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            existing = {"some_key": "some_value", "hooks": {}}
            (d / "settings.json").write_text(json.dumps(existing))
            main(settings_dir=d)
            settings = json.loads((d / "settings.json").read_text())
            self.assertEqual(settings["some_key"], "some_value")
            self.assertEqual(len(settings["hooks"]["PreToolUse"]), 3)

    def test_preserves_other_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            other_hook = {"matcher": "Other", "hooks": [{"type": "command", "command": "other-tool"}]}
            existing = {"hooks": {"PreToolUse": [other_hook]}}
            (d / "settings.json").write_text(json.dumps(existing))
            main(settings_dir=d)
            settings = json.loads((d / "settings.json").read_text())
            self.assertEqual(len(settings["hooks"]["PreToolUse"]), 4)
            self.assertEqual(settings["hooks"]["PreToolUse"][0], other_hook)


class TestInstallIdempotency(unittest.TestCase):

    def test_no_duplicate_on_double_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            main(settings_dir=d)
            main(settings_dir=d)
            settings = json.loads((d / "settings.json").read_text())
            self.assertEqual(len(settings["hooks"]["PreToolUse"]), 3)


class TestUninstall(unittest.TestCase):

    def test_removes_hook(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            main(settings_dir=d)
            uninstall(settings_dir=d)
            settings = json.loads((d / "settings.json").read_text())
            self.assertEqual(len(settings["hooks"]["PreToolUse"]), 0)

    def test_uninstall_nothing_to_remove(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            # no settings file.. should not error
            uninstall(settings_dir=d)

    def test_uninstall_preserves_other_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            other_hook = {"matcher": "Other", "hooks": [{"type": "command", "command": "other-tool"}]}
            main(settings_dir=d)
            settings = json.loads((d / "settings.json").read_text())
            settings["hooks"]["PreToolUse"].insert(0, other_hook)
            (d / "settings.json").write_text(json.dumps(settings))
            uninstall(settings_dir=d)
            settings = json.loads((d / "settings.json").read_text())
            self.assertEqual(len(settings["hooks"]["PreToolUse"]), 1)
            self.assertEqual(settings["hooks"]["PreToolUse"][0], other_hook)


if __name__ == "__main__":
    unittest.main()
