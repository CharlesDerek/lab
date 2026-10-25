"""Exercise the real pre-push hook with a merge-only, later-deleted finding."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class GitleaksHistoryTests(unittest.TestCase):
    def test_hook_rejects_a_finding_added_only_by_merge_then_deleted(self):
        configured = os.environ.get("GITLEAKS_BIN")
        if not configured:
            self.skipTest("Set GITLEAKS_BIN to run the installed-scanner regression")
        scanner = Path(configured).resolve()
        self.assertTrue(scanner.is_file() and os.access(scanner, os.X_OK))
        source = Path(__file__).resolve().parent.parent
        env = dict(os.environ, GITLEAKS_BIN=str(scanner), GIT_CONFIG_NOSYSTEM="1",
                   GIT_CONFIG_GLOBAL=os.devnull)
        with tempfile.TemporaryDirectory(prefix="gitleaks-merge-regression-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()

            def git(*args):
                result = subprocess.run(["git", *args], cwd=repo, env=env,
                                        capture_output=True, text=True)
                # Do not echo arbitrary Git output or synthetic finding values.
                self.assertEqual(result.returncode, 0, "Synthetic Git fixture setup failed")
                return result.stdout.strip()

            def commit(message):
                git("add", "--all")
                git("commit", "--quiet", "-m", message)
                return git("rev-parse", "HEAD")

            git("init", "--quiet", "-b", "main")
            git("config", "user.name", "Synthetic fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "commit.gpgsign", "false")
            (repo / "tools").mkdir()
            shutil.copyfile(source / "tools/check_public_boundary.py",
                            repo / "tools/check_public_boundary.py")
            (repo / ".gitleaks.toml").write_text(
                "title = 'Synthetic merge regression'\n"
                "[[rules]]\nid = 'merge-only-regression'\n"
                "regex = '''SYNTH_MERGE_[a-f0-9]{64}'''\n", encoding="utf-8")
            public_base = commit("public fixture base")
            git("checkout", "--quiet", "-b", "side")
            (repo / "side.txt").write_text("side fixture\n", encoding="utf-8")
            commit("side change")
            git("checkout", "--quiet", "main")
            (repo / "main.txt").write_text("main fixture\n", encoding="utf-8")
            commit("main change")
            git("merge", "--no-commit", "--no-ff", "side")
            value = "SYNTH_MERGE_" + hashlib.sha256(b"noncredential merge regression").hexdigest()
            finding = repo / "merge-only.txt"
            finding.write_text(value + "\n", encoding="utf-8")
            commit("merge with synthetic finding")
            finding.unlink()
            tip = commit("delete synthetic finding")

            # This pinned scanner's default Git diff omits the merge addition.
            default = subprocess.run(
                [str(scanner), "git", ".", "--log-opts=HEAD", "--config", ".gitleaks.toml",
                 "--no-banner", "--no-color", "--redact=100", "--ignore-gitleaks-allow",
                 "--gitleaks-ignore-path", os.devnull, "--max-decode-depth", "2"],
                cwd=repo, env=env, capture_output=True, text=True)
            self.assertEqual(default.returncode, 0, "Default-scan fixture control changed")

            hook = subprocess.run(
                ["bash", str(source / ".githooks/pre-push"), "fixture", "unused"],
                input=f"refs/heads/main {tip} refs/heads/main {public_base}\n",
                cwd=repo, env=env, capture_output=True, text=True)
            output = hook.stdout + hook.stderr
            self.assertEqual(hook.returncode, 1, "Actual hook accepted merge-only finding")
            self.assertTrue("leaks found: 1" in output, "Hook failed without detecting the merge finding")
            self.assertTrue(value not in output, "Scanner output exposed the synthetic detection value")


if __name__ == "__main__":
    unittest.main()
