# Neuroplexis Future Tasks

Public-safe planning backlog for Project Athernex. This document intentionally avoids secrets, credentials, private topology, private network inventories, BMC/IPMI specifics, and destructive power procedures.

## Backlog

### Kafka Broker Power Scheduling

- Define a broker eligibility model for planned power-state changes that accounts for quorum health, partition leadership, replication lag, and maintenance windows.
- Add a dry-run scheduler path that reports proposed broker actions, expected impact, and blocking conditions without changing power state.
- Document operator-facing safety gates for planned broker suspension and restoration, limited to high-level workflow checks.
- Track metrics for broker scheduling decisions, skipped actions, and post-action Kafka recovery health.

### Rust Orchestration

- Design a Rust orchestration crate boundary for scheduling decisions, state reconciliation, policy evaluation, and integration adapters.
- Add typed state models for Kafka broker readiness, node availability, routine status, and scheduling contracts.
- Implement idempotent reconciliation loops with explicit no-op behavior when safety preconditions are not met.
- Provide structured logs and audit events that are useful publicly without exposing private hostnames, addresses, or inventory data.

### Paperclip Routine Integration

- Define a stable routine handoff contract between Neuroplexis orchestration and Paperclip routines.
- Add routine lifecycle states for pending, admitted, running, blocked, complete, and rolled back.
- Support routine preflight checks that can fail closed when Kafka or Kubernetes health signals are incomplete.
- Capture routine outcomes in a sanitized event format suitable for public issue tracking and future documentation.

### Kubernetes Scheduling Contracts

- Draft Kubernetes-facing scheduling contracts for node readiness, workload drain intent, workload return intent, and admission denial reasons.
- Map orchestrator decisions to Kubernetes primitives without embedding cluster-specific names, labels, addresses, or topology.
- Add contract tests for allowed, blocked, and degraded scheduling scenarios.
- Document how Kafka broker safety constraints should override opportunistic workload placement.

### Tests

- Add unit tests for policy evaluation, dry-run output, reconciliation idempotency, and blocked-action explanations.
- Add integration tests with mocked Kafka, Paperclip, and Kubernetes adapters.
- Add regression tests for public/private data redaction in logs, events, plans, and errors.
- Add failure-mode tests for incomplete health signals, stale state, routine timeout, and partial adapter failure.

### Public/Private Boundary Hygiene

- Maintain a public-safe schema for examples, events, plans, and operator-facing summaries.
- Add review checks that reject credentials, private topology, private network inventories, BMC/IPMI identifiers, and destructive power procedures in public docs.
- Keep operational runbooks with environment-specific power details outside public artifacts.
- Add a documentation checklist for future planning updates that confirms sanitized examples, generic identifiers, and non-destructive language.

## Near-Term Acceptance Criteria

- The first implementation plan can be reviewed publicly without exposing private infrastructure details.
- Dry-run scheduling explains what would happen and why an action is blocked or allowed.
- Kafka, Paperclip, and Kubernetes interfaces are represented by typed contracts before environment-specific adapters are added.
- Tests cover safety gates and redaction behavior before any real power-state integration is enabled.
