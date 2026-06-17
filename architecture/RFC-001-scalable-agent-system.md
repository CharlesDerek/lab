# RFC-001: Scalable Agent System Preparation

## Status

Draft for local staging.

## Goal

Prepare a public-safe foundation for coordinating agent workloads across a future server rack without exposing rack internals. The system should support orchestration, review, failure handling, and generative quality controls before physical components are fully available.

## Non-Goals

- Publishing private rack topology, addresses, management-plane details, or credentials.
- Automating power, firmware, IPMI, or storage operations in this public repo.
- Trusting model output as complete or correct without validation.

## Component Model

```text
producer -> Kafka command topic -> Rust orchestrator -> agent worker
                                      |              |
                                      v              v
                              LocalStack state   Paperclip adapter
                                      |
                                      v
                           review / quarantine / audit
```

### Kafka Topics

| Topic | Purpose |
| --- | --- |
| `agent.commands` | Work requested by users, schedulers, or review workflows. |
| `agent.observations` | Worker status, resource pressure, validation findings, and partial results. |
| `agent.results` | Completed outputs that passed required checks. |
| `agent.review` | Outputs that need human or secondary-model review. |
| `agent.deadletter` | Exhausted retries, malformed messages, unsafe requests, or invariant failures. |
| `paperclip.requests` | Sanitized requests bound for the Paperclip adapter. |
| `paperclip.responses` | Sanitized Paperclip responses returned for orchestration. |
| `agent.audit` | Immutable run events suitable for later analysis. |

### LocalStack Resources

| Resource | Local Name | Use |
| --- | --- | --- |
| S3 bucket | `agent-artifacts-local` | Store sanitized artifacts, traces, and generated files. |
| DynamoDB table | `agent-runs-local` | Track run state, idempotency keys, and review decisions. |
| SQS queue | `agent-review-local` | Inspect review work without requiring production services. |
| SQS queue | `agent-deadletter-local` | Inspect exhausted or unsafe work items. |

## Workflow States

```text
received -> validated -> scheduled -> running -> reviewing -> accepted
                                      |             |
                                      v             v
                                  retrying      quarantined
                                      |
                                      v
                                  deadlettered
```

Rules:

- Every command gets a stable `run_id`, `trace_id`, and idempotency key.
- Every agent output records the model/tool identity, evidence references, and validator decisions.
- Retries must be bounded and jittered.
- A hallucination suspicion is routed to review or quarantine, not silently retried as if it were infrastructure failure.
- Dead-lettered messages must retain enough metadata to reproduce the failure in staging.

## Paperclip Integration Boundary

The public contract should include only sanitized envelopes:

```json
{
  "run_id": "local-run-001",
  "capability": "document_review",
  "input_ref": "s3://agent-artifacts-local/input/local-run-001.json",
  "review_policy": "human_required",
  "metadata": {
    "environment": "local",
    "sensitivity": "public-safe"
  }
}
```

Private prompt text, credentials, account IDs, rack metadata, and production endpoints stay outside this repo.

## Acceptance Criteria

- Local dependencies start with `make local-up`.
- LocalStack creates the expected staging resources on boot.
- Rust workspace builds with `make check`.
- Documentation makes the public/private boundary explicit.
