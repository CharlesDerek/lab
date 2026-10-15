# CI/CD Workflow

Project Athernex uses GitHub Actions to show a public-safe promotion path without
publishing private rack topology, credentials, host addresses, or operational
procedures.

## Pull Request and Branch CI

`.github/workflows/ci.yml` validates the public control-plane surface:

- Rust formatting, tests, and clippy warnings.
- SIEM engine/HTTP tests and the bounded standalone Rust encoding experiment.
- The legacy React/TypeScript dashboard build, with locked npm dependencies.
- Rust dependency audit and CycloneDX SBOM generation.
- Shell, Python, Paperclip JSON, and workflow coverage validation.
- OpenTofu formatting, validation, tests, and a Kubernetes contract smoke plan.

## Release Promotion

`.github/workflows/release-promotion.yml` runs on `v*` tags and manual dispatches.
It produces a release evidence bundle with:

- `make check` validation evidence.
- Release binaries for the Rust orchestrator and the interactive SIEM.
- A sanitized OpenTofu plan.
- Rust dependency audit output.
- Cargo dependency metadata and a CycloneDX SBOM for each Rust crate.
- SHA256 checksums for release artifacts and dependency evidence.

Tag runs publish GitHub Releases automatically. Manual runs can publish a release
when `publish_release` is enabled.

The workflow installs the legacy dashboard's dependencies before `make check`.
Checksum paths are relative to the downloaded artifact directory, so staging and
production verification can check both binaries and the evidence archive after
download. Individual evidence-file hashes can also be checked after extracting
the archive. The SIEM runs locally on loopback; these workflows do not expose it
as a hosted or production service.

## Environment Gates

The release promotion workflow also models deployment control:

- `staging` verifies release artifact checksums and uploads a staging promotion
  receipt.
- `production` runs only for version tags or manual runs with
  `promote_production` enabled.
- The `production` job uses the `production` GitHub Environment so repository
  environment protection rules can require approval before the simulation
  completes.

Both environment jobs are public-safe simulations. They record promotion intent
and evidence only; they do not run private rack, network, power, or cluster
operations.
