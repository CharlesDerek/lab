# Distributed Agentic Infrastructure & Orchestration Lab

Public-safe preparation workspace for a rack-backed agent orchestration system. The repo is aimed at staged integration of Kafka, Rust control services, LocalStack-backed local AWS resources, and Paperclip-facing AI workflows without publishing private rack topology, credentials, addresses, or vendor-specific operational details.

> Experimental infrastructure only. Treat every component here as staging material until it has load tests, failure tests, review gates, and rollback procedures.

## Direction

This lab is being steered toward a Scalable Agent System (SAS): a message-driven control plane that can coordinate local and remote agents, route work through review stages, tolerate partial failures, and keep generative outputs auditable.

Core principles:

- Kafka is the durable coordination backbone for commands, observations, review events, and dead letters.
- Rust services own deterministic orchestration, validation, retries, and backpressure decisions.
- LocalStack provides local AWS-compatible services for staging without touching real cloud accounts.
- Paperclip AI integration stays behind a narrow adapter boundary so public code can show contracts without exposing private prompts, keys, rack metadata, or operational procedures.
- Failures, hallucinations, and review states are first-class workflow outcomes, not afterthoughts.

## Repository Layout

```text
.
├── architecture/
│   ├── RFC-001-scalable-agent-system.md
│   ├── public-boundary.md
│   └── staging-review-model.md
├── core-engines/
│   └── orchestrator/
│       ├── Cargo.toml
│       └── src/main.rs
├── infrastructure/
│   └── local-dev/
│       ├── docker-compose.yml
│       └── localstack/init/ready.d/010-agent-resources.sh
├── .env.example
├── Cargo.toml
└── Makefile
```

## Local Staging

Requirements:

- Docker with Compose support
- Rust toolchain
- `awslocal` is provided inside the LocalStack container; host-side AWS CLI is optional

Start Kafka-compatible messaging and LocalStack:

```bash
make local-up
```

Run the Rust orchestrator preparation stub:

```bash
make run-orchestrator
```

Stop local services:

```bash
make local-down
```

## Integration Tracks

1. **Messaging backbone:** Kafka topics for agent commands, observations, reviews, Paperclip requests, Paperclip responses, and dead letters.
2. **Local AWS staging:** S3 for artifacts, DynamoDB for run metadata, SQS for fallback queues and dead-letter inspection.
3. **Rust orchestration:** typed workflow states, retry policies, idempotency keys, and conservative rate limits before any rack-wide scheduling.
4. **Paperclip adapter:** public-safe request/response envelopes, with secrets and private prompt material kept out of git.
5. **Failure and hallucination controls:** deterministic validation, evidence capture, review queues, quarantine states, and staged promotion.

## Safety Boundary

Do not commit:

- API keys, Paperclip credentials, cloud credentials, SSH keys, IPMI credentials, Tailscale keys, rack hostnames, public IPs, private IPs, MAC addresses, serial numbers, or real topology maps.
- Private system prompts, customer data, unreleased model weights, private datasets, or logs containing secrets.
- Exact power, thermal, wake, firmware, or management-plane procedures for the physical rack.

Use sanitized component names and capability classes instead. See [architecture/public-boundary.md](architecture/public-boundary.md).

## Current Status

- [x] Public-safe architecture direction
- [x] Local Kafka-compatible and LocalStack staging compose file
- [x] Rust orchestrator placeholder with explicit configuration surface
- [x] Failure and hallucination review model
- [ ] Real Kafka consumer and producer implementation
- [ ] Paperclip adapter implementation
- [ ] Load tests for backpressure and retry behavior
- [ ] Rack-specific deployment manifests kept in a private repo or encrypted vault
