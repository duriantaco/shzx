import unittest
from handlers import split_args, parse_single_command


class TestSplitArgs(unittest.TestCase):

    def test_separates_args_from_flags(self):
        tokens = ["cmd", "file.txt", "-f", "other", "--verbose"]
        args, flags = split_args(tokens)
        self.assertEqual(args, ["file.txt", "other"])
        self.assertEqual(flags, ["-f", "--verbose"])

    def test_custom_start_index(self):
        tokens = ["npm", "install", "-D", "lodash", "express"]
        args, flags = split_args(tokens, start=2)
        self.assertEqual(args, ["lodash", "express"])
        self.assertEqual(flags, ["-D"])

    def test_all_args_no_flags(self):
        args, flags = split_args(["cmd", "a", "b", "c"])
        self.assertEqual(args, ["a", "b", "c"])
        self.assertEqual(flags, [])

    def test_all_flags_no_args(self):
        args, flags = split_args(["cmd", "-x", "-y"])
        self.assertEqual(args, [])
        self.assertEqual(flags, ["-x", "-y"])

    def test_only_command_token(self):
        args, flags = split_args(["cmd"])
        self.assertEqual(args, [])
        self.assertEqual(flags, [])


class TestParseEmpty(unittest.TestCase):

    def test_empty_tokens_returns_none(self):
        self.assertIsNone(parse_single_command([], ""))

    def test_node_has_all_required_keys(self):
        node = parse_single_command(["ls"], "ls")
        for key in ["command", "effects", "summary", "intent", "warnings", "risk_score"]:
            self.assertIn(key, node)

    def test_all_effects_default_false(self):
        node = parse_single_command(["unknowncmd"], "unknowncmd")
        for key in ["reads_files", "writes_files", "deletes_files",
                     "network_access", "privilege_escalation", "changes_git_state"]:
            self.assertIn(key, node["effects"])


class TestFind(unittest.TestCase):

    def test_with_path_and_name(self):
        node = parse_single_command(
            ["find", "/tmp", "-name", "*.log"],
            "find /tmp -name *.log"
        )
        self.assertTrue(node["effects"]["reads_files"])
        self.assertIn("/tmp", node["summary"])
        self.assertIn("*.log", node["summary"])
        self.assertIn("*.log", node["intent"])

    def test_no_path_defaults_to_current_dir(self):
        node = parse_single_command(["find", "-name", "x"], "find -name x")
        self.assertIn("the current directory", node["summary"])

    def test_multiple_names(self):
        node = parse_single_command(
            ["find", ".", "-name", "*.py", "-o", "-name", "*.js"],
            "find . -name '*.py' -o -name '*.js'"
        )
        self.assertIn("*.py", node["summary"])
        self.assertIn("*.js", node["summary"])

    def test_no_name_filter(self):
        node = parse_single_command(["find", "/var"], "find /var")
        self.assertEqual(node["intent"], "Locate files")

    def test_exec_rm_sets_delete(self):
        node = parse_single_command(
            ["find", ".", "-exec", "rm", "{}", ";"],
            "find . -exec rm {} ;"
        )
        self.assertTrue(node["effects"]["deletes_files"])
        self.assertEqual(node["risk_score"], 50)
        self.assertIn("delete", node["summary"].lower())

    def test_2dev_null_in_raw(self):
        node = parse_single_command(
            ["find", "/x", "-name", "y"],
            "find /x -name y 2>/dev/null"
        )
        self.assertIn("ignoring permission errors", node["summary"])


class TestGrep(unittest.TestCase):

    def test_pattern_and_target(self):
        node = parse_single_command(["grep", "-r", "TODO", "src/"], "grep -r TODO src/")
        self.assertTrue(node["effects"]["reads_files"])
        self.assertIn("TODO", node["summary"])
        self.assertIn("src/", node["summary"])

    def test_pattern_only(self):
        node = parse_single_command(["grep", "error"], "grep error")
        self.assertIn("files", node["summary"])

    def test_no_args(self):
        node = parse_single_command(["grep"], "grep")
        self.assertEqual(node["summary"], "Search for text")

    def test_rg_alias(self):
        node = parse_single_command(["rg", "pattern"], "rg pattern")
        self.assertEqual(node["intent"], "Find text in files")


class TestRm(unittest.TestCase):

    def test_basic_delete(self):
        node = parse_single_command(["rm", "file.txt"], "rm file.txt")
        self.assertTrue(node["effects"]["deletes_files"])
        self.assertFalse(node["effects"]["writes_files"])
        self.assertEqual(node["risk_score"], 50)
        self.assertIn("file.txt", node["summary"])
        self.assertEqual(node["intent"], "Remove files permanently")

    def test_rf_bundled(self):
        node = parse_single_command(["rm", "-rf", "/tmp/stuff"], "rm -rf /tmp/stuff")
        self.assertEqual(node["risk_score"], 100)
        self.assertEqual(len(node["warnings"]), 1)
        self.assertIn("force", node["summary"].lower())

    def test_r_and_f_separate(self):
        node = parse_single_command(["rm", "-r", "-f", "dir/"], "rm -r -f dir/")
        self.assertEqual(node["risk_score"], 100)

    def test_no_targets(self):
        node = parse_single_command(["rm"], "rm")
        self.assertIn("files", node["summary"])

class TestEcho(unittest.TestCase):

    def test_plain_print(self):
        node = parse_single_command(["echo", "hello", "world"], "echo hello world")
        self.assertFalse(node["effects"]["writes_files"])
        self.assertEqual(node["intent"], "Display text")
        self.assertEqual(node["risk_score"], 0)

    def test_redirect_writes(self):
        node = parse_single_command(["echo", "hi", ">", "f.txt"], "echo hi > f.txt")
        self.assertTrue(node["effects"]["writes_files"])
        self.assertEqual(node["intent"], "Write to a file")


class TestGit(unittest.TestCase):

    def test_read_only_subcommands(self):
        for sub in ["status", "log", "diff", "show", "branch"]:
            node = parse_single_command(["git", sub], f"git {sub}")
            self.assertTrue(node["effects"]["reads_files"])
            self.assertFalse(node["effects"]["changes_git_state"])
            self.assertEqual(node["risk_score"], 0)
            self.assertEqual(node["intent"], "Review repository state")

    def test_state_changing_subcommands(self):
        for sub in ["clean", "reset", "checkout", "restore", "push"]:
            node = parse_single_command(["git", sub], f"git {sub}")
            self.assertTrue(node["effects"]["changes_git_state"])
            self.assertEqual(node["risk_score"], 30)
            self.assertEqual(len(node["warnings"]), 1)

    def test_clean_with_separate_flags(self):
        node = parse_single_command(["git", "clean", "-x", "-f", "-d"], "git clean -x -f -d")
        self.assertEqual(node["risk_score"], 50)
        self.assertEqual(len(node["warnings"]), 2)

    def test_clean_bundled_flags_detected(self):
        node = parse_single_command(["git", "clean", "-xfd"], "git clean -xfd")
        self.assertEqual(node["risk_score"], 50)
        self.assertEqual(len(node["warnings"]), 2)

    def test_other_subcommand(self):
        node = parse_single_command(["git", "commit", "-m", "msg"], "git commit -m msg")
        self.assertTrue(node["effects"]["changes_git_state"])
        self.assertEqual(node["intent"], "Git commit")

    def test_bare_git(self):
        node = parse_single_command(["git"], "git")
        self.assertEqual(node["summary"], "Run git")


class TestPackageManagers(unittest.TestCase):

    def test_npm_install_with_package(self):
        node = parse_single_command(["npm", "install", "lodash"], "npm install lodash")
        self.assertTrue(node["effects"]["network_access"])
        self.assertTrue(node["effects"]["writes_files"])
        self.assertEqual(node["risk_score"], 20)
        self.assertIn("lodash", node["summary"])
        self.assertEqual(node["intent"], "Install dependencies")

    def test_install_aliases(self):
        for sub in ["install", "add", "i"]:
            node = parse_single_command(["yarn", sub, "pkg"], f"yarn {sub} pkg")
            self.assertEqual(node["intent"], "Install dependencies")

    def test_all_managers_recognized(self):
        for mgr in ["npm", "yarn", "pnpm", "pip", "cargo"]:
            node = parse_single_command([mgr, "test"], f"{mgr} test")
            self.assertTrue(node["effects"]["network_access"])

    def test_non_install_subcommand(self):
        node = parse_single_command(["npm", "test"], "npm test")
        self.assertEqual(node["intent"], "Use package manager")
        self.assertFalse(node["effects"]["writes_files"])

    def test_bare_manager(self):
        node = parse_single_command(["cargo"], "cargo")
        self.assertEqual(node["summary"], "Run cargo")

class TestCurlWget(unittest.TestCase):

    def test_curl_with_url(self):
        node = parse_single_command(["curl", "https://example.com"], "curl https://example.com")
        self.assertTrue(node["effects"]["network_access"])
        self.assertEqual(node["risk_score"], 20)
        self.assertIn("example.com", node["summary"])

    def test_wget_no_url(self):
        node = parse_single_command(["wget"], "wget")
        self.assertIn("the internet", node["summary"])

    def test_intent(self):
        node = parse_single_command(["curl", "http://x"], "curl http://x")
        self.assertEqual(node["intent"], "Fetch web resources")


class TestBashSh(unittest.TestCase):

    def test_bash_dash_c(self):
        node = parse_single_command(["bash", "-c", "echo hi"], "bash -c 'echo hi'")
        self.assertEqual(node["risk_score"], 40)
        self.assertEqual(node["intent"], "Run arbitrary commands")

    def test_bash_script_file(self):
        node = parse_single_command(["bash", "deploy.sh"], "bash deploy.sh")
        self.assertIn("deploy.sh", node["summary"])
        self.assertEqual(node["intent"], "Execute script")

    def test_sh_bare(self):
        node = parse_single_command(["sh"], "sh")
        self.assertIn("a script", node["summary"])

    def test_sh_dash_c(self):
        node = parse_single_command(["sh", "-c", "ls"], "sh -c ls")
        self.assertEqual(node["risk_score"], 40)


class TestSudo(unittest.TestCase):

    def test_sudo_with_command(self):
        node = parse_single_command(["sudo", "apt", "update"], "sudo apt update")
        self.assertTrue(node["effects"]["privilege_escalation"])
        self.assertEqual(node["risk_score"], 80)
        self.assertIn("apt", node["summary"])
        self.assertEqual(node["intent"], "Execute highly privileged operation")

    def test_sudo_bare(self):
        node = parse_single_command(["sudo"], "sudo")
        self.assertEqual(node["intent"], "Elevate privileges")

    def test_sudo_warning(self):
        node = parse_single_command(["sudo", "rm", "x"], "sudo rm x")
        self.assertTrue(any("administrative" in w.lower() for w in node["warnings"]))

class TestMkdirTouch(unittest.TestCase):

    def test_mkdir(self):
        node = parse_single_command(["mkdir", "-p", "a/b/c"], "mkdir -p a/b/c")
        self.assertTrue(node["effects"]["writes_files"])
        self.assertIn("Create directory", node["summary"])
        self.assertIn("a/b/c", node["summary"])

    def test_touch(self):
        node = parse_single_command(["touch", "new.txt"], "touch new.txt")
        self.assertIn("Create file", node["summary"])
        self.assertEqual(node["intent"], "Create file")

class TestViewers(unittest.TestCase):

    def test_all_viewer_commands(self):
        for cmd in ["ls", "pwd", "tree", "wc", "cat", "less", "more", "head", "tail"]:
            node = parse_single_command([cmd], cmd)
            self.assertTrue(node["effects"]["reads_files"])
            self.assertEqual(node["intent"], "Inspect files or directories")

    def test_with_target(self):
        node = parse_single_command(["cat", "f.txt"], "cat f.txt")
        self.assertIn("f.txt", node["summary"])
        self.assertIn("cat", node["summary"])

    def test_without_target(self):
        node = parse_single_command(["ls"], "ls")
        self.assertIn("View information", node["summary"])

class TestAwk(unittest.TestCase):

    def test_with_input_file(self):
        node = parse_single_command(["awk", "{print $1}", "data.csv"], "awk '{print $1}' data.csv")
        self.assertTrue(node["effects"]["reads_files"])
        self.assertIn("data.csv", node["summary"])
        self.assertEqual(node["intent"], "Transform text with awk")

    def test_without_file(self):
        node = parse_single_command(["awk", "{print}"], "awk '{print}'")
        self.assertEqual(node["summary"], "Process input with awk")

class TestJq(unittest.TestCase):

    def test_with_file(self):
        node = parse_single_command(["jq", ".name", "data.json"], "jq '.name' data.json")
        self.assertIn("data.json", node["summary"])
        self.assertEqual(node["intent"], "Extract data from JSON")

    def test_stdin_only(self):
        node = parse_single_command(["jq", "."], "jq '.'")
        self.assertEqual(node["summary"], "Parse JSON input")

class TestMvCp(unittest.TestCase):

    def test_mv_sets_both_write_and_delete(self):
        node = parse_single_command(["mv", "a.txt", "b.txt"], "mv a.txt b.txt")
        self.assertTrue(node["effects"]["writes_files"])
        self.assertTrue(node["effects"]["deletes_files"])
        self.assertIn("Move", node["summary"])
        self.assertIn("a.txt -> b.txt", node["summary"])

    def test_cp_no_delete(self):
        node = parse_single_command(["cp", "a", "b"], "cp a b")
        self.assertTrue(node["effects"]["writes_files"])
        self.assertFalse(node["effects"]["deletes_files"])
        self.assertIn("Copy", node["summary"])

    def test_force_flag(self):
        node = parse_single_command(["cp", "-f", "a", "b"], "cp -f a b")
        self.assertTrue(any("overwrite" in w.lower() for w in node["warnings"]))
        self.assertEqual(node["risk_score"], 30)  # 20 force + 10 base

    def test_force_long_flag(self):
        node = parse_single_command(["mv", "--force", "a", "b"], "mv --force a b")
        self.assertTrue(any("overwrite" in w.lower() for w in node["warnings"]))

    def test_multi_source(self):
        node = parse_single_command(["cp", "a", "b", "c", "dest/"], "cp a b c dest/")
        self.assertIn("a b c -> dest/", node["summary"])

    def test_no_args(self):
        node = parse_single_command(["mv"], "mv")
        self.assertEqual(node["summary"], "Move files")

class TestChmodChown(unittest.TestCase):

    def test_chmod_basic(self):
        node = parse_single_command(["chmod", "755", "script.sh"], "chmod 755 script.sh")
        self.assertTrue(node["effects"]["writes_files"])
        self.assertIn("755", node["summary"])
        self.assertIn("script.sh", node["summary"])
        self.assertIn("permissions", node["intent"])

    def test_chown_basic(self):
        node = parse_single_command(["chown", "root", "file"], "chown root file")
        self.assertIn("ownership", node["intent"])
        self.assertIn("root", node["summary"])

    def test_recursive_adds_risk(self):
        node = parse_single_command(["chmod", "-R", "777", "/var"], "chmod -R 777 /var")
        self.assertEqual(node["risk_score"], 35)  # 25 recursive + 10 base
        self.assertTrue(any("Recursive" in w for w in node["warnings"]))

    def test_recursive_long_flag(self):
        node = parse_single_command(["chown", "--recursive", "u:g", "/x"], "chown --recursive u:g /x")
        self.assertTrue(any("Recursive" in w for w in node["warnings"]))

    def test_no_args(self):
        node = parse_single_command(["chmod"], "chmod")
        self.assertEqual(node["summary"], "Change permissions")

    def test_no_target_files(self):
        node = parse_single_command(["chmod", "644"], "chmod 644")
        self.assertIn("files", node["summary"])

class TestMake(unittest.TestCase):

    def test_with_target(self):
        node = parse_single_command(["make", "clean"], "make clean")
        self.assertTrue(node["effects"]["writes_files"])
        self.assertIn("clean", node["summary"])
        self.assertEqual(node["risk_score"], 10)

    def test_default_target(self):
        node = parse_single_command(["make"], "make")
        self.assertEqual(node["summary"], "Build default target")

    def test_multiple_targets(self):
        node = parse_single_command(["make", "clean", "all"], "make clean all")
        self.assertIn("clean", node["summary"])
        self.assertIn("all", node["summary"])

class TestSed(unittest.TestCase):

    def test_inplace_with_file(self):
        node = parse_single_command(["sed", "-i", "s/foo/bar/", "f.txt"], "sed -i 's/foo/bar/' f.txt")
        self.assertTrue(node["effects"]["writes_files"])
        self.assertFalse(node["effects"]["reads_files"])
        self.assertEqual(node["risk_score"], 30)
        self.assertIn("f.txt", node["summary"])
        self.assertTrue(any("In-place" in w for w in node["warnings"]))

    def test_inplace_no_file(self):
        node = parse_single_command(["sed", "-i", "s/a/b/"], "sed -i 's/a/b/'")
        self.assertEqual(node["summary"], "Edit files in-place with sed")

    def test_inplace_bundled_flag(self):
        node = parse_single_command(["sed", "-ie", "s/x/y/", "f"], "sed -ie 's/x/y/' f")
        self.assertTrue(node["effects"]["writes_files"])

    def test_read_only(self):
        node = parse_single_command(["sed", "s/a/b/", "file"], "sed 's/a/b/' file")
        self.assertTrue(node["effects"]["reads_files"])
        self.assertFalse(node["effects"]["writes_files"])
        self.assertIn("file", node["summary"])
        self.assertEqual(node["intent"], "Transform text with sed")

    def test_read_only_no_file(self):
        node = parse_single_command(["sed", "s/a/b/"], "sed 's/a/b/'")
        self.assertEqual(node["summary"], "Filter input with sed")

class TestTar(unittest.TestCase):

    def test_extract(self):
        node = parse_single_command(["tar", "-xzf", "archive.tar.gz"], "tar -xzf archive.tar.gz")
        self.assertTrue(node["effects"]["writes_files"])
        self.assertEqual(node["risk_score"], 10)
        self.assertIn("archive.tar.gz", node["summary"])

    def test_extract_no_file(self):
        node = parse_single_command(["tar", "-x"], "tar -x")
        self.assertEqual(node["summary"], "Extract archive")

    def test_create(self):
        node = parse_single_command(["tar", "-czf", "out.tar.gz", "src/"], "tar -czf out.tar.gz src/")
        self.assertTrue(node["effects"]["reads_files"])
        self.assertIn("Create archive", node["summary"])

    def test_list(self):
        node = parse_single_command(["tar", "-tf", "a.tar"], "tar -tf a.tar")
        self.assertIn("List contents", node["summary"])
        self.assertEqual(node["intent"], "Inspect archive")

    def test_unknown_flags(self):
        node = parse_single_command(["tar", "--help"], "tar --help")
        self.assertEqual(node["intent"], "Archive operation")

class TestZipUnzip(unittest.TestCase):

    def test_zip(self):
        node = parse_single_command(["zip", "out.zip", "a", "b"], "zip out.zip a b")
        self.assertTrue(node["effects"]["writes_files"])
        self.assertIn("out.zip", node["summary"])
        self.assertEqual(node["intent"], "Compress files")

    def test_zip_no_args(self):
        node = parse_single_command(["zip"], "zip")
        self.assertEqual(node["summary"], "Create zip archive")

    def test_unzip(self):
        node = parse_single_command(["unzip", "file.zip"], "unzip file.zip")
        self.assertTrue(node["effects"]["writes_files"])
        self.assertEqual(node["risk_score"], 10)
        self.assertIn("file.zip", node["summary"])
        self.assertTrue(any("overwrite" in w.lower() for w in node["warnings"]))

    def test_unzip_no_args(self):
        node = parse_single_command(["unzip"], "unzip")
        self.assertEqual(node["summary"], "Extract zip archive")
        self.assertEqual(len(node["warnings"]), 0)

class TestScriptLangs(unittest.TestCase):

    def test_python_script(self):
        node = parse_single_command(["python3", "app.py"], "python3 app.py")
        self.assertTrue(node["effects"]["reads_files"])
        self.assertIn("app.py", node["summary"])
        self.assertEqual(node["risk_score"], 0)

    def test_python_inline(self):
        node = parse_single_command(["python", "-c", "print(1)"], "python -c 'print(1)'")
        self.assertIn("print(1)", node["summary"])
        self.assertEqual(node["risk_score"], 20)

    def test_node_inline_e(self):
        node = parse_single_command(["node", "-e", "console.log(1)"], "node -e 'console.log(1)'")
        self.assertEqual(node["risk_score"], 20)

    def test_ruby_bare(self):
        node = parse_single_command(["ruby"], "ruby")
        self.assertIn("interpreter", node["summary"])

    def test_all_langs_recognized(self):
        for lang in ["python", "python3", "node", "ruby"]:
            node = parse_single_command([lang, "x.py"], f"{lang} x.py")
            self.assertTrue(node["effects"]["reads_files"])

class TestSshScp(unittest.TestCase):

    def test_ssh_host_only(self):
        node = parse_single_command(["ssh", "myhost"], "ssh myhost")
        self.assertTrue(node["effects"]["network_access"])
        self.assertEqual(node["risk_score"], 20)
        self.assertIn("myhost", node["summary"])

    def test_ssh_with_remote_command(self):
        node = parse_single_command(["ssh", "host", "ls", "/tmp"], "ssh host ls /tmp")
        self.assertIn("ls /tmp", node["summary"])
        self.assertEqual(node["risk_score"], 40)
        self.assertTrue(any("remote" in w.lower() for w in node["warnings"]))

    def test_ssh_bare(self):
        node = parse_single_command(["ssh"], "ssh")
        self.assertEqual(node["summary"], "SSH connection")

    def test_scp_with_args(self):
        node = parse_single_command(["scp", "file", "host:/tmp/"], "scp file host:/tmp/")
        self.assertEqual(node["intent"], "Remote file transfer")
        self.assertIn("file", node["summary"])

    def test_scp_bare(self):
        node = parse_single_command(["scp"], "scp")
        self.assertEqual(node["summary"], "Copy files via SCP")

class TestDocker(unittest.TestCase):

    def test_run(self):
        node = parse_single_command(["docker", "run", "nginx"], "docker run nginx")
        self.assertTrue(node["effects"]["network_access"])
        self.assertEqual(node["risk_score"], 20)
        self.assertIn("nginx", node["summary"])
        self.assertEqual(node["intent"], "Run container")

    def test_run_no_image(self):
        node = parse_single_command(["docker", "run"], "docker run")
        self.assertIn("an image", node["summary"])

    def test_exec(self):
        node = parse_single_command(
            ["docker", "exec", "mycontainer", "bash"],
            "docker exec mycontainer bash"
        )
        self.assertEqual(node["risk_score"], 15)
        self.assertIn("mycontainer", node["summary"])

    def test_exec_no_container(self):
        node = parse_single_command(["docker", "exec"], "docker exec")
        self.assertIn("a container", node["summary"])

    def test_rm(self):
        node = parse_single_command(["docker", "rm", "c1", "c2"], "docker rm c1 c2")
        self.assertTrue(node["effects"]["deletes_files"])
        self.assertIn("c1 c2", node["summary"])

    def test_rm_no_targets(self):
        node = parse_single_command(["docker", "rm"], "docker rm")
        self.assertIn("containers", node["summary"])

    def test_build(self):
        node = parse_single_command(["docker", "build", "."], "docker build .")
        self.assertEqual(node["risk_score"], 10)
        self.assertEqual(node["intent"], "Build container image")

    def test_pull(self):
        node = parse_single_command(["docker", "pull", "ubuntu"], "docker pull ubuntu")
        self.assertIn("ubuntu", node["summary"])
        self.assertEqual(node["intent"], "Download container image")

    def test_push(self):
        node = parse_single_command(["docker", "push", "myimg"], "docker push myimg")
        self.assertEqual(node["intent"], "Upload container image")

    def test_push_no_image(self):
        node = parse_single_command(["docker", "push"], "docker push")
        self.assertIn("an image", node["summary"])

    def test_other_subcommand(self):
        node = parse_single_command(["docker", "inspect", "c1"], "docker inspect c1")
        self.assertEqual(node["intent"], "Docker inspect")

    def test_bare(self):
        node = parse_single_command(["docker"], "docker")
        self.assertEqual(node["summary"], "Run docker")
        self.assertEqual(node["intent"], "Docker operation")

class TestXargs(unittest.TestCase):

    def test_xargs_rm(self):
        node = parse_single_command(["xargs", "rm"], "xargs rm")
        self.assertTrue(node["effects"]["deletes_files"])
        self.assertEqual(node["risk_score"], 50)
        self.assertIn("xargs", node["summary"].lower())

    def test_skips_flags_with_args(self):
        node = parse_single_command(
            ["xargs", "-I", "{}", "-n", "1", "cp", "{}", "/backup/"],
            "xargs -I {} -n 1 cp {} /backup/"
        )
        self.assertIn("Copy", node["summary"])

    def test_skips_simple_flags(self):
        node = parse_single_command(["xargs", "-0", "rm"], "xargs -0 rm")
        self.assertTrue(node["effects"]["deletes_files"])

    def test_bare(self):
        node = parse_single_command(["xargs"], "xargs")
        self.assertIn("echo", node["summary"])
        self.assertEqual(node["intent"], "Batch execute command")

class TestInlineCodeScanning(unittest.TestCase):

    def test_python_os_system(self):
        node = parse_single_command(
            ["python3", "-c", "import os; os.system('rm -rf /')"],
            "python3 -c 'import os; os.system(\"rm -rf /\")'"
        )
        self.assertTrue(any("shell command" in w.lower() for w in node["warnings"]))
        self.assertGreater(node["risk_score"], 20)

    def test_python_subprocess(self):
        node = parse_single_command(
            ["python3", "-c", "import subprocess; subprocess.run(['ls'])"],
            "python3 -c 'import subprocess; subprocess.run([\"ls\"])'"
        )
        self.assertTrue(any("subprocess" in w.lower() for w in node["warnings"]))
        self.assertGreater(node["risk_score"], 20)

    def test_python_shutil_rmtree(self):
        node = parse_single_command(
            ["python3", "-c", "import shutil; shutil.rmtree('/tmp/x')"],
            "python3 -c 'import shutil; shutil.rmtree(\"/tmp/x\")'"
        )
        self.assertTrue(node["effects"]["deletes_files"])
        self.assertTrue(any("directory tree" in w.lower() for w in node["warnings"]))

    def test_python_eval(self):
        node = parse_single_command(
            ["python", "-c", "eval('print(1)')"],
            "python -c 'eval(\"print(1)\")'"
        )
        self.assertTrue(any("dynamic" in w.lower() for w in node["warnings"]))

    def test_python_file_write(self):
        node = parse_single_command(
            ["python3", "-c", "open('x.txt', 'w').write('hi')"],
            "python3 -c 'open(\"x.txt\", \"w\").write(\"hi\")'"
        )
        self.assertTrue(node["effects"]["writes_files"])

    def test_python_network_access(self):
        node = parse_single_command(
            ["python3", "-c", "import socket; s = socket.socket()"],
            "python3 -c 'import socket; s = socket.socket()'"
        )
        self.assertTrue(node["effects"]["network_access"])

    def test_python_safe_code_no_warnings(self):
        node = parse_single_command(
            ["python3", "-c", "print('hello world')"],
            "python3 -c 'print(\"hello world\")'"
        )
        self.assertEqual(len(node["warnings"]), 0)
        self.assertEqual(node["risk_score"], 20)

    def test_python_os_remove(self):
        node = parse_single_command(
            ["python3", "-c", "import os; os.remove('file.txt')"],
            "python3 -c 'import os; os.remove(\"file.txt\")'"
        )
        self.assertTrue(node["effects"]["deletes_files"])

    def test_python_dunder_import(self):
        node = parse_single_command(
            ["python3", "-c", "__import__('os').system('id')"],
            "python3 -c '__import__(\"os\").system(\"id\")'"
        )
        self.assertTrue(any("dynamic" in w.lower() for w in node["warnings"]))

    def test_node_child_process(self):
        node = parse_single_command(
            ["node", "-e", "require('child_process').exec('ls')"],
            "node -e 'require(\"child_process\").exec(\"ls\")'"
        )
        self.assertTrue(any("child process" in w.lower() for w in node["warnings"]))

    def test_node_fs_write(self):
        node = parse_single_command(
            ["node", "-e", "fs.writeFileSync('x', 'y')"],
            "node -e 'fs.writeFileSync(\"x\", \"y\")'"
        )
        self.assertTrue(node["effects"]["writes_files"])

    def test_node_fs_unlink(self):
        node = parse_single_command(
            ["node", "-e", "fs.unlinkSync('file')"],
            "node -e 'fs.unlinkSync(\"file\")'"
        )
        self.assertTrue(node["effects"]["deletes_files"])

    def test_ruby_system(self):
        node = parse_single_command(
            ["ruby", "-e", "system('rm -rf /')"],
            "ruby -e 'system(\"rm -rf /\")'"
        )
        self.assertTrue(any("shell command" in w.lower() for w in node["warnings"]))

    def test_ruby_backtick(self):
        node = parse_single_command(
            ["ruby", "-e", "`rm -rf /tmp`"],
            "ruby -e '`rm -rf /tmp`'"
        )
        self.assertTrue(any("backtick" in w.lower() for w in node["warnings"]))

    def test_ruby_file_delete(self):
        node = parse_single_command(
            ["ruby", "-e", "File.delete('x.txt')"],
            "ruby -e 'File.delete(\"x.txt\")'"
        )
        self.assertTrue(node["effects"]["deletes_files"])

    def test_multiple_patterns_accumulate(self):
        node = parse_single_command(
            ["python3", "-c", "import os; os.system('curl x'); os.remove('y')"],
            "python3 -c 'import os; os.system(\"curl x\"); os.remove(\"y\")'"
        )
        self.assertTrue(len(node["warnings"]) >= 2)
        self.assertTrue(node["effects"]["deletes_files"])


class TestBashInnerCommand(unittest.TestCase):

    def test_bash_c_stores_inner_command(self):
        node = parse_single_command(
            ["bash", "-c", "rm -rf /tmp"],
            "bash -c 'rm -rf /tmp'"
        )
        self.assertEqual(node["inner_command"], "rm -rf /tmp")

    def test_sh_c_stores_inner_command(self):
        node = parse_single_command(
            ["sh", "-c", "echo hello"],
            "sh -c 'echo hello'"
        )
        self.assertEqual(node["inner_command"], "echo hello")

    def test_bash_no_c_no_inner_command(self):
        node = parse_single_command(
            ["bash", "script.sh"],
            "bash script.sh"
        )
        self.assertNotIn("inner_command", node)

    def test_bash_c_without_arg_no_inner_command(self):
        node = parse_single_command(
            ["bash", "-c"],
            "bash -c"
        )
        self.assertNotIn("inner_command", node)


class TestUnknown(unittest.TestCase):

    def test_detects_file_paths(self):
        node = parse_single_command(["mytool", "foo.txt", "/bar/baz"], "mytool foo.txt /bar/baz")
        self.assertIn("foo.txt", node["summary"])
        self.assertIn("/bar/baz", node["summary"])

    def test_many_file_paths_truncated(self):
        node = parse_single_command(
            ["tool", "a.txt", "b.txt", "c.txt", "d.txt"],
            "tool a.txt b.txt c.txt d.txt"
        )
        self.assertIn("+1 more", node["summary"])

    def test_plain_args(self):
        node = parse_single_command(["sometool", "arg1", "arg2"], "sometool arg1 arg2")
        self.assertIn("arg1", node["summary"])

    def test_many_plain_args_truncated(self):
        node = parse_single_command(
            ["tool", "a", "b", "c", "d", "e"],
            "tool a b c d e"
        )
        self.assertIn("...", node["summary"])

    def test_bare_command(self):
        node = parse_single_command(["blah"], "blah")
        self.assertIn("blah", node["summary"])
        self.assertEqual(node["risk_score"], 10)
        self.assertEqual(node["intent"], "Execute system command")


if __name__ == "__main__":
    unittest.main()
