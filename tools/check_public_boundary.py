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
PRIVATE_NAMES = {"AGENTS.md", "CODEX.md", "CLAUDE.md", "GEMINI.md", ".mrgi", ".gitleaksignore"}
PRIVATE_BUNDLE_SUFFIXES = (".app", ".systemextension")
PRIVATE_GLOBS = (
    "*.pem", "*.key", "*.pk8", "*.p8", "*.crt", "*.p12", "*.pfx", "*.jks", "*.keystore",
    "*.mobileprovision", "*.provisionprofile",
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
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL)


class BoundaryError(ValueError):
    """A publication baseline cannot be verified; messages contain no input data."""


def public_commit(repo, oid):
    # Baselines must be immutable IDs from the remote/event, never local ref names.
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid) or not oid.strip("0"):
        raise BoundaryError("An explicit, nonzero already-public commit ID is required.")
    try:
        resolved = git(repo, "rev-parse", "--verify", "--end-of-options", oid + "^{commit}").strip().decode()
    except subprocess.CalledProcessError:
        raise BoundaryError("An already-public baseline commit is missing locally; fetch it before publishing.") from None
    if resolved != oid:
        raise BoundaryError("The public baseline must identify a commit directly.")
    return resolved


def remote_public_baselines(repo, remote):
    """Trust only currently advertised branch IDs, not local tracking/private refs."""
    try:
        advertised = git(repo, "ls-remote", "--heads", "--", remote).decode().splitlines()
    except (subprocess.CalledProcessError, UnicodeError):
        raise BoundaryError("Cannot read the public remote's advertised branches; refusing publication.") from None
    baselines = []
    for line in advertised:
        fields = line.split()
        if len(fields) != 2 or not fields[1].startswith("refs/heads/"):
            raise BoundaryError("Unexpected public remote advertisement; refusing publication.")
        baselines.append(public_commit(repo, fields[0]))
    if not baselines:
        raise BoundaryError("No public branch baseline exists; initial publication requires separate history review.")
    return sorted(set(baselines))


def introduced_commits(repo, ref, baselines):
    if not baselines:
        raise BoundaryError("An already-public history baseline is required.")
    verified = [public_commit(repo, oid) for oid in baselines]
    tip = git(repo, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}").strip().decode()
    return git(repo, "rev-list", "--reverse", tip, "--not", *verified).decode().splitlines()


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
            or any(part.lower().endswith(PRIVATE_BUNDLE_SUFFIXES) for part in parts)
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
    baseline = parser.add_mutually_exclusive_group()
    baseline.add_argument("--since", action="append", metavar="PUBLIC_COMMIT", help="also check every commit introduced after an already-public commit ID")
    baseline.add_argument("--public-remote", metavar="REMOTE", help="for a new ref, exclude only advertised public branch ancestry")
    args = parser.parse_args()
    try:
        refs = [args.tree]
        if args.since is not None or args.public_remote is not None:
            baselines = args.since if args.since is not None else remote_public_baselines(args.repo, args.public_remote)
            refs.extend(introduced_commits(args.repo, args.tree, baselines))
        seen = set()
        failures = 0
        for ref in refs:
            tree = git(args.repo, "rev-parse", "--verify", "--end-of-options", ref + "^{tree}").strip().decode()
            if tree in seen:
                continue
            seen.add(tree)
            tree, count, findings = check_tree(args.repo, tree)
            for path, line, reason in findings:
                print(f"{path!r}:{line}: {reason}; tree {tree}")
            print(f"Public boundary: {count} files, {len(findings)} findings, tree {tree}")
            failures += len(findings)
        return bool(failures)
    except BoundaryError as error:
        print(f"Public boundary: {error}")
    except (subprocess.CalledProcessError, OSError, UnicodeError):
        print("Public boundary: Git inspection failed; refusing publication.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
