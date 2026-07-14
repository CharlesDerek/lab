# Changelog

## Unreleased

- Added an automation validation target for shell syntax, Python bytecode compilation, Paperclip JSON parsing, and the Neuroplexis runner dry-run path.
- Wired `make check` to validate both the Rust workspace and local automation surfaces.
- Hardened the Neuroplexis maintenance runner so real runs require a positive Codex cycle count, an available Codex CLI, and a concrete repository change from each Codex cycle by default.
- Updated the Paperclip routine payload to run the Neuroplexis maintenance path as a real bounded run with change enforcement enabled.
