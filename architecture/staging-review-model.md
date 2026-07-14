# Staging Review Model

The orchestration system should assume that both infrastructure and model behavior can fail. Reviews are staged so that failures are classified before promotion.

## Failure Classes

| Class | Examples | Default Action |
| --- | --- | --- |
| Transport | Kafka unavailable, LocalStack unavailable, timeout | Retry with bounded backoff, then dead-letter. |
| Resource pressure | Too many in-flight runs, memory pressure, disk pressure | Throttle scheduling and emit observation events. |
| Capacity lifecycle | Worker group unavailable, node not ready, scheduling constraint unsatisfied | Hold or reschedule without exposing private power or cluster procedures. |
| Validation | Schema mismatch, missing evidence, invalid artifact reference | Reject or send to review. |
| Safety | Secret leakage, private data in output, unsafe command proposal | Quarantine and require human review. |
| Security finding | SIEM, EDR, or policy signal attached to a run | Quarantine affected workflow and require review. |
| Hallucination | Unsupported claim, fabricated tool result, inconsistent reasoning trail | Route to review with evidence requirements. |
| Adapter | Paperclip endpoint error, invalid response, auth failure | Retry only if transient; otherwise dead-letter. |

## Review Gates

1. **Schema gate:** all commands and results match versioned envelopes.
2. **Evidence gate:** claims that depend on files, tools, or external systems include references.
3. **Safety gate:** outputs are scanned for secrets and private operational details.
4. **Security gate:** SIEM, EDR, and policy findings can block promotion.
5. **Determinism gate:** orchestration decisions are based on explicit state, not free-form model output.
6. **Promotion gate:** accepted outputs are copied to durable artifacts and indexed by run metadata.

## Minimum Event Fields

```json
{
  "run_id": "local-run-001",
  "trace_id": "trace-001",
  "event_type": "review_required",
  "state": "reviewing",
  "reason": "missing_evidence",
  "attempt": 1,
  "created_at": "2026-01-01T00:00:00Z"
}
```

## Staging Practice

- Start with local-only flows using LocalStack and Kafka-compatible services.
- Use low concurrency until retry and dead-letter behavior is observable.
- Model dynamic compute capacity through sanitized scheduler events before connecting private node lifecycle automation.
- Promote one capability at a time into the rack environment.
- Capture every failed run as a replayable test fixture after redaction.
