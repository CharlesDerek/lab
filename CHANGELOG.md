# Changelog

## Unreleased

- Added `make siem-key` and first-run key initialization; foreground SIEM launch targets reuse the saved operator key, use release builds and preserve the installed operational ledger.
- Added an enterprise SIEM overview, integration contract catalog and Project Crustation / Crustacian migration brief, including the durable-acknowledgement gap and endpoint authority boundaries.
- Restyled the Rust console with forest-green surfaces and cyan contours; refreshed eight public-fixture screenshots with reproducible capture provenance and desktop/mobile layout verification.

- Made the Rust SIEM operational by default with a bounded journald adapter, trusted authentication classification, service-failure detection, source-bound API credentials and private systemd user deployment.
- Added source management, independent investigation cases with revision checks, assignments/notes/evidence/export, and real approved case-triage actions. Explicit demo databases retain synthetic exercises.
- Added AXR2 provenance with AXR1 read compatibility, cursor/archive atomic checkpoints, on-demand exact journal-message retrieval, collection readiness and source credential rotation. Runtime state and secrets stay outside the public repository.

- Added a separate operator authentication boundary and a Rust agent hive with task deadlines, exact item/operation capabilities, random expiring tokens, usage budgets, atomic access decisions, completion/revocation and automatic quarantine.
- Moved the hot telemetry window to RAM and added bounded AXR1 + DEFLATE archives, configurable time/capacity/flush controls, checksummed archive drill-down, legacy migration, exclusive ledger ownership and graceful flushing.
- Added agent/task investigation views and new synthetic screenshots; documented measured storage overhead, authorization limits, crash behavior and the next evidence-aware capability experiment.

- Added a Rust SIEM research application with a server-rendered console, event filtering, binary byte inspection, synthetic scenario injection, four temporal/policy detection rules, and a bounded SQLite ledger.
- Added AEF1 event encoding, atomic ingestion/detection/audit commits, conflict-aware idempotency, retained finding evidence, and an evidence-bound review workflow with expiring approvals and response simulations.
- Added an interactive field-retention contract experiment and a dependency-free Rust compression probe with documented compressed-JSON baselines.
- Expanded the README with screenshots, research findings, a staged single-rack roadmap, a demo walkthrough, and defensible public presentation language.
- Extended CI and release evidence to cover the SIEM, both Rust SBOMs, and the legacy frontend; corrected artifact-relative release checksum paths.
- Added staging and production environment-gated promotion simulations to the release workflow, including artifact checksum verification and downloadable promotion receipts.
- Added supply-chain CI coverage with Rust dependency caching, `cargo audit`, CycloneDX SBOM generation, and release evidence checksums for dependency metadata and SBOM artifacts.
- Added a release promotion GitHub Actions workflow that validates the repo, builds the Rust orchestrator, renders a sanitized OpenTofu plan, packages promotion evidence, publishes checksums, uploads artifacts, and can publish GitHub Releases from version tags.
- Added an automation validation target for shell syntax, Python bytecode compilation, Paperclip JSON parsing, and the Neuroplexis runner dry-run path.
- Wired `make check` to validate both the Rust workspace and local automation surfaces.
- Hardened the Neuroplexis maintenance runner so real runs require a positive Codex cycle count, an available Codex CLI, and a concrete repository change from each Codex cycle by default.
- Updated the Paperclip routine payload to run the Neuroplexis maintenance path as a real bounded run with change enforcement enabled.
