#!/usr/bin/env python3
"""Validate public GitHub workflows keep the expected interview tracks covered."""

from pathlib import Path


CI_WORKFLOW = Path(".github/workflows/ci.yml")
RELEASE_WORKFLOW = Path(".github/workflows/release-promotion.yml")

REQUIRED_CI_SNIPPETS = (
    "Swatinem/rust-cache@v2",
    "cargo fmt --all -- --check",
    "cargo clippy --workspace --all-targets -- -D warnings",
    "cargo install cargo-audit cargo-cyclonedx --locked",
    "cargo audit",
    "cargo cyclonedx --format json --override-filename rust-sbom",
    "make check-automation check-workflows",
    "opentofu/setup-opentofu",
    "run: tofu test",
)

REQUIRED_RELEASE_SNIPPETS = (
    'tags:',
    '"v*"',
    "workflow_dispatch:",
    "promote_production:",
    "Swatinem/rust-cache@v2",
    "cargo install cargo-audit cargo-cyclonedx --locked",
    "make check",
    "cargo audit > dist/evidence/cargo-audit.txt",
    "cargo metadata --locked --format-version 1",
    "rust-sbom.cdx.json",
    "cargo build --workspace --release",
    "tofu -chdir=",
    "actions/upload-artifact@v4",
    "actions/download-artifact@v4",
    "environment:",
    "name: staging",
    "name: production",
    "sha256sum --ignore-missing -c SHA256SUMS",
    "staging-promotion.md",
    "production-promotion.md",
    "gh release create",
    "sha256sum",
)


def validate_workflow(path: Path, required_snippets: tuple[str, ...]) -> None:
    if not path.exists():
        raise SystemExit(f"{path} does not exist")

    content = path.read_text(encoding="utf-8")
    missing = [snippet for snippet in required_snippets if snippet not in content]
    if missing:
        formatted = "\n".join(f"- {snippet}" for snippet in missing)
        raise SystemExit(f"{path} is missing required checks:\n{formatted}")


def main() -> None:
    validate_workflow(CI_WORKFLOW, REQUIRED_CI_SNIPPETS)
    validate_workflow(RELEASE_WORKFLOW, REQUIRED_RELEASE_SNIPPETS)


if __name__ == "__main__":
    main()
