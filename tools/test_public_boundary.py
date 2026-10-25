"""Exercise publication trees, including files Git normally ignores."""

from pathlib import Path
import subprocess
import tempfile
import unittest

from check_public_boundary import check_tree


class PublicBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
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

    def test_uses_selected_tree_instead_of_dirty_or_untracked_content(self):
        self.write("README.md", "Public example\n")
        tree = self.tree()
        self.write("README.md", "/" + "home/private-person/repo\n")
        self.write(".env", "private runtime contents\n")
        self.assertEqual(check_tree(self.repo, tree), (tree, 1, []))

    def test_force_added_private_files_are_rejected(self):
        names = [".env", ".athernex/report.json", "CODEX.md", "nested/signing.key",
                 "nested/release.pk8", "nested/apple.p8", "state.sqlite"]
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


if __name__ == "__main__":
    unittest.main()
