#!/usr/bin/env python3
"""Check the exact Git tree being published; never scan private working files.

This complements Gitleaks and human review; it cannot identify all confidential
information. Diagnostics contain paths and line numbers, never matched content.
"""

import argparse
import fnmatch
from pathlib import PurePosixPath
import re
import subprocess


PRIVATE_DIRS = {
    ".athernex", ".paperclip", ".codex", ".cache", ".ssh", ".aws",
    ".terraform", "target", "node_modules", "__pycache__", "logs", "tmp", "temp",
}
PRIVATE_NAMES = {"AGENTS.md", "CODEX.md", "CLAUDE.md", "GEMINI.md", ".mrgi"}
PRIVATE_GLOBS = (
    "*.pem", "*.key", "*.crt", "*.p12", "*.pfx", "*.jks", "*.keystore",
    "*.log", "*.db", "*.db-*", "*.sqlite", "*.sqlite3", "*.sqlite-*",
    "*.tfstate", "*.tfstate.*", "*kubeconfig*", "*.pyc",
    "*.exe", "*.dll", "*.sys", "*.zip", "*.tar", "*.gz", "*.dmp", "*.pcap",
)
PERSONAL_PATH = re.compile(
    r"(?:/(?:home|Users)/[A-Za-z0-9_.-]+(?:/[^\s\"'<>:,;)]+)?"
    r"|[A-Za-z]:[\\/]+Users[\\/]+[A-Za-z0-9_.-]+(?:[\\/][^\s\"'<>;,]+)?)"
)
# Exact synthetic inputs already used by the protocol/fleet tests.
SYNTHETIC_PATHS = {
    "core-engines/endpoint-native/src/tests.rs": {
        "/Users/file", "/Users/state", "/Users/socket",
    },
    "core-engines/endpoint-protocol/src/authentication.rs": {
        "/home/alice/.ssh/authorized_keys",
    },
    "core-engines/siem/tests/fleet.rs": {
        "/home/fixture/test.txt", "/home/fixture/évidence.txt",
    },
}


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def check_tree(repo, ref):
    tree = git(repo, "rev-parse", "--verify", "--end-of-options", ref + "^{tree}").strip().decode()
    findings = []
    entries = git(repo, "ls-tree", "-rz", tree).split(b"\0")
    count = 0
    for entry in filter(None, entries):
        info, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = info.decode().split()
        path = raw_path.decode("utf-8", errors="backslashreplace")
        parts = PurePosixPath(path).parts
        name = parts[-1]
        count += 1
        if (
            any(part in PRIVATE_DIRS for part in parts[:-1])
            or name in PRIVATE_NAMES
            or (name.startswith(".env") and name != ".env.example")
            or any(fnmatch.fnmatch(name.lower(), pattern) for pattern in PRIVATE_GLOBS)
        ):
            findings.append((path, 0, "private state, credential, note, or generated artifact"))
        if kind != "blob" or mode not in {"100644", "100755"}:
            findings.append((path, 0, "symlink or external tree requires explicit publication review"))
            continue
        data = git(repo, "cat-file", "blob", oid)
        if b"\0" in data:
            if not path.startswith("docs/assets/") or not path.endswith(".png"):
                findings.append((path, 0, "unreviewed binary artifact"))
            continue
        for line_number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
            for match in PERSONAL_PATH.finditer(line):
                if match.group() not in SYNTHETIC_PATHS.get(path, set()):
                    # The allowlist declarations must also remain visible to review.
                    if path == "tools/check_public_boundary.py" and match.group() in {
                        value for values in SYNTHETIC_PATHS.values() for value in values
                    }:
                        continue
                    findings.append((path, line_number, "personal workstation path"))
    return tree, count, findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--tree", default="HEAD", help="commit or tree to inspect")
    args = parser.parse_args()
    tree, count, findings = check_tree(args.repo, args.tree)
    for path, line, reason in findings:
        print(f"{path!r}:{line}: {reason}")
    print(f"Public boundary: {count} files, {len(findings)} findings, tree {tree}")
    return bool(findings)


if __name__ == "__main__":
    raise SystemExit(main())
