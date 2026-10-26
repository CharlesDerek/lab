"""Exercise publication trees, including files Git normally ignores."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from check_public_boundary import BoundaryError, check_tree, introduced_commits, remote_public_baselines


class PublicBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args]).decode().strip()

    def write(self, name, data):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)

    def tree(self):
        self.git("add", "--force", ".")
        return self.git("write-tree")

    def commit(self):
        self.git("add", "--force", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "--quiet", "--allow-empty", "-m", "fixture")
        return self.git("rev-parse", "HEAD")

    def run_checker(self, *args):
        return subprocess.run(
            [sys.executable, str(Path(__file__).with_name("check_public_boundary.py")),
             "--repo", str(self.repo), "--tree", "HEAD", *args],
            capture_output=True, text=True,
        )

    def test_uses_selected_tree_instead_of_dirty_or_untracked_content(self):
        self.write("README.md", "Public example\n")
        tree = self.tree()
        self.write("README.md", "/" + "home/private-person/repo\n")
        self.write(".env", "private runtime contents\n")
        self.assertEqual(check_tree(self.repo, tree), (tree, 1, []))

    def test_force_added_private_files_are_rejected(self):
        names = [".env", ".athernex/report.json", "CODEX.md", "nested/signing.key",
                 "nested/release.pk8", "nested/apple.p8", "state.sqlite", ".gitleaksignore"]
        for name in names:
            self.write(name, "local-only contents\n")
        findings = check_tree(self.repo, self.tree())[2]
        self.assertEqual({row[0] for row in findings}, set(names))

    def test_personal_paths_are_reported_without_content(self):
        private = "/" + "home/private-person/repo"
        self.write("settings.json", private + "\n" + "C:" + r"\Users\private-person\repo")
        findings = check_tree(self.repo, self.tree())[2]
        self.assertEqual(len(findings), 2)
        self.assertNotIn("private-person", repr(findings))

    def test_generated_bundle_text_and_provisioning_profiles_are_rejected(self):
        names = ["output/Example.app/Contents/Info.plist",
                 "output/Example.SYSTEMEXTENSION/Contents/Resources/settings.json",
                 "output/profile.mobileprovision", "nested/profile.PROVISIONPROFILE",
                 "output/Empty.app"]
        for name in names:
            self.write(name, "synthetic private deployment metadata\n")
        self.write("src/Info.plist.in", "public source template\n")
        self.write("docs/application.md", "public documentation\n")
        findings = check_tree(self.repo, self.tree())[2]
        self.assertEqual({row[0] for row in findings}, set(names))
        self.assertNotIn("synthetic private deployment metadata", repr(findings))

    def test_fixture_exception_is_bound_to_exact_path_and_file(self):
        fixture = "/" + "home/fixture/test.txt"
        self.write("core-engines/siem/tests/fleet.rs", fixture)
        self.write("deployment.txt", fixture)
        findings = check_tree(self.repo, self.tree())[2]
        self.assertEqual([row[0] for row in findings], ["deployment.txt"])

    def test_symlink_is_not_followed(self):
        (self.repo / "linked").symlink_to("/unavailable-private-file")
        findings = check_tree(self.repo, self.tree())[2]
        self.assertEqual(len(findings), 1)
        self.assertIn("symlink", findings[0][2])

    def test_private_file_deleted_before_tip_is_rejected(self):
        self.write("README.md", "Public fixture\n")
        public = self.commit()
        self.write("CODEX.md", "Private planning notes without credentials\n")
        self.commit()
        (self.repo / "CODEX.md").unlink()
        self.commit()
        self.assertEqual(check_tree(self.repo, "HEAD")[2], [])
        result = self.run_checker("--since", public)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("CODEX.md", result.stdout)
        self.assertNotIn("Private planning notes", result.stdout + result.stderr)

    def test_personal_path_deleted_before_tip_is_rejected(self):
        self.write("settings.txt", "Public fixture\n")
        public = self.commit()
        self.write("settings.txt", "/" + "home/private-person/repo\n")
        self.commit()
        self.write("settings.txt", "Public fixture\n")
        self.commit()
        self.assertEqual(check_tree(self.repo, "HEAD")[2], [])
        result = self.run_checker("--since", public)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("personal workstation path", result.stdout)
        self.assertNotIn("private-person", result.stdout + result.stderr)

    def test_known_public_legacy_history_does_not_block_cleanup(self):
        self.write("CODEX.md", "Previously public legacy notes\n")
        public = self.commit()
        (self.repo / "CODEX.md").unlink()
        self.write("README.md", "Public fixture\n")
        tip = self.commit()
        self.assertEqual(introduced_commits(self.repo, tip, [public]), [tip])
        result = self.run_checker("--since", public)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_new_ref_does_not_trust_local_private_or_tracking_refs(self):
        self.write("README.md", "Public fixture\n")
        public = self.commit()
        remote = Path(self.temp.name) / "public.git"
        subprocess.check_output(["git", "clone", "--bare", "--quiet", str(self.repo), str(remote)])
        self.write("CODEX.md", "Local private planning notes\n")
        private = self.commit()
        self.git("update-ref", "refs/heads/private-work", private)
        self.git("update-ref", "refs/remotes/origin/private-work", private)
        (self.repo / "CODEX.md").unlink()
        tip = self.commit()
        baselines = remote_public_baselines(self.repo, str(remote))
        self.assertEqual(baselines, [public])
        self.assertIn(private, introduced_commits(self.repo, tip, baselines))
        result = self.run_checker("--public-remote", str(remote))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("CODEX.md", result.stdout)

    def test_missing_or_symbolic_baseline_fails_closed(self):
        self.write("README.md", "Public fixture\n")
        self.commit()
        for baseline in ["0" * 40, "1" * 40, "HEAD", "refs/heads/private-work"]:
            with self.subTest(baseline=baseline):
                result = self.run_checker("--since", baseline)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertNotIn(baseline, result.stdout + result.stderr)
        with self.assertRaises(BoundaryError):
            introduced_commits(self.repo, "HEAD", [])

    def test_unknown_empty_or_unfetched_remote_fails_closed(self):
        self.write("README.md", "Public fixture\n")
        public = self.commit()
        empty = Path(self.temp.name) / "empty.git"
        subprocess.check_output(["git", "init", "--bare", "--quiet", str(empty)])
        with self.assertRaises(BoundaryError):
            remote_public_baselines(self.repo, str(empty))
        result = self.run_checker("--public-remote", str(Path(self.temp.name) / "private-missing-remote"))
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("private-missing-remote", result.stdout + result.stderr)
        # Advertise a commit that the publication checkout has not fetched.
        other = Path(self.temp.name) / "other"
        subprocess.check_output(["git", "clone", "--quiet", str(self.repo), str(other)])
        subprocess.check_output(["git", "-C", str(other), "-c", "user.name=Fixture",
                                 "-c", "user.email=fixture@example.invalid", "commit",
                                 "--quiet", "--allow-empty", "-m", "unfetched"])
        self.assertNotEqual(subprocess.check_output(["git", "-C", str(other), "rev-parse", "HEAD"]).decode().strip(), public)
        with self.assertRaises(BoundaryError):
            remote_public_baselines(self.repo, str(other))


if __name__ == "__main__":
    unittest.main()
