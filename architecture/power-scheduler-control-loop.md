# Power Scheduler Control Loop

Project Athernex uses Kafka as the durable broker between job requests, scheduling decisions, power-module actions, and state capture. The public repo models the control loop and message boundaries; private code owns the real power-module endpoints and device-specific procedures.

## Control Flow

```text
job request
  -> agent.commands
  -> Rust scheduler ruleset
  -> scheduler.capacity
  -> power.commands
  -> power module REST API
  -> power.observations
  -> agent.observations / agent.audit
```

The Rust control plane does not assume a power action succeeded. Every power-on, power-off, drain, or hold decision must produce observations until the requested worker group reaches a known state or the workflow dead-letters.

## Kafka Topics

| Topic | Producer | Consumer | Purpose |
| --- | --- | --- | --- |
| `agent.commands` | User, scheduler, or automation source | Rust orchestrator | Incoming work and requested capability. |
| `scheduler.capacity` | Rust orchestrator | Scheduler adapters, audit consumers | Capacity decisions, holds, dispatches, and lifecycle requests. |
| `power.commands` | Rust orchestrator | Private power-module bridge | Sanitized power intents such as wake, drain, or shutdown. |
| `power.observations` | Private power-module bridge | Rust orchestrator | State transitions and failures from power modules. |
| `agent.observations` | Workers and orchestrator | Review, audit, dashboards | Job progress, capacity pressure, validation, and failure state. |
| `agent.deadletter` | Orchestrator | Review and replay tooling | Exhausted, unsafe, malformed, or unrecoverable workflows. |
| `agent.audit` | Orchestrator | Audit storage | Immutable run and decision records. |

## Power Command Envelope

```json
{
  "schema_version": "athernex.power.v1",
  "run_id": "local-run-001",
  "trace_id": "trace-001",
  "target_group": "worker-group-a",
  "action": "power_on",
  "reason": "capacity_required",
  "requested_slots": 4,
  "deadline_seconds": 600,
  "metadata": {
    "environment": "local",
    "sensitivity": "public-safe"
  }
}
```

Allowed public actions are `power_on`, `power_off`, `drain`, `hold`, and `observe`. Private implementations map those actions to real REST calls and device-specific behavior outside this repository.

## Power Observation Envelope

```json
{
  "schema_version": "athernex.power_observation.v1",
  "run_id": "local-run-001",
  "trace_id": "trace-001",
  "target_group": "worker-group-a",
  "observed_state": "powering_on",
  "available_slots": 0,
  "message": "worker group accepted wake request",
  "created_at": "2026-07-03T00:00:00Z"
}
```

Public observations should describe state transitions without exposing real hostnames, IP addresses, MAC addresses, BMC details, outlet identifiers, credentials, or vendor endpoints.

## Ruleset

The initial Rust scheduler rules are intentionally deterministic:

- Run interactive jobs locally when local slots are available.
- Run any job locally when the required slots fit the always-on control plane capacity.
- Hold maintenance jobs until an explicit promotion window exists.
- Dispatch to remote workers when enough remote slots are already online.
- Request remote power-on when the job allows remote capacity and required slots meet the wake threshold.
- Hold while a remote worker group is already powering on.
- Request remote power-off when remote capacity has been idle longer than the configured idle timeout.

This keeps the public algorithm inspectable while leaving private rack operations behind the power-module bridge.
