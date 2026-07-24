# Project Athernex: Autonomous Infrastructure Datacenter

Public-safe code and architecture workspace for Project Athernex, a modular enterprise-grade homelab that functions as a miniature datacenter for security engineering, distributed systems, and infrastructure automation research.

The real environment combines OpenWrt networking, VLAN-based segmentation, virtualization, centralized logging, layered security controls, and event-driven orchestration. This public repo represents the sanitized control-plane and staging side of that work: Kafka-driven scheduling contracts, Rust orchestration services, LocalStack-backed local resources, review gates, and Paperclip-facing AI workflow boundaries without publishing private rack topology, credentials, addresses, or vendor-specific operational details.

> Experimental infrastructure only. Treat every component here as staging material until it has load tests, failure tests, review gates, and rollback procedures.

## Direction

Project Athernex is being steered toward an autonomous infrastructure control plane: an always-on management layer responsible for routing, automation, observability, security services, and workload scheduling across provisioned compute capacity.

Current development focuses on Kubernetes- and Kafka-driven workload scheduling so compute nodes can be treated as dynamic capacity: provisioned when work requires them, powered only when needed, and coordinated through a dedicated control plane. Public code models those contracts and failure modes without exposing private automation runbooks.

Core principles:

- Kafka is the durable coordination backbone for commands, observations, review events, and dead letters.
- Rust services own deterministic orchestration, validation, retries, backpressure, and scheduling decisions.
- Kubernetes-facing scheduling remains contract-first until private cluster manifests are ready to promote.
- LocalStack provides local AWS-compatible services for staging without touching real cloud accounts.
- Paperclip AI integration stays behind a narrow adapter boundary so public code can show contracts without exposing private prompts, keys, rack metadata, or operational procedures.
- SIEM, EDR, logging, and network segmentation are represented only as sanitized capability classes in this repo.
- Failures, hallucinations, security findings, and review states are first-class workflow outcomes, not afterthoughts.

## Repository Layout

```text
.
├── architecture/
│   ├── athernex-datacenter-model.md
│   ├── power-scheduler-control-loop.md
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

Kafka UI is exposed at `http://127.0.0.1:18080/` to avoid common local port conflicts.

Run the Rust orchestrator preparation stub:

```bash
make run-orchestrator
```

Run the live Kafka round-trip smoke path against the local broker:

```bash
ATHERNEX_KAFKA_INTEGRATION=1 cargo test -p orchestrator live_kafka_broker_round_trips_against_local_kafka_when_enabled
ATHERNEX_LIVE_KAFKA_SMOKE=1 cargo run -p orchestrator
```

Run the full local validation suite:

```bash
make check
```

This validates the Rust workspace, Rust unit tests, GitHub workflow coverage, and the public automation layer: shell syntax, Python bytecode compilation, Paperclip JSON payload parsing, and the Neuroplexis maintenance runner dry-run path. If OpenTofu is installed as `tofu`, it also runs `fmt`, `init -backend=false`, `validate`, and `test` against the Kubernetes scheduler contract in `infrastructure/opentofu/kubernetes-scheduler-contract/`.

Run the OpenTofu/Kubernetes contract checks directly:

```bash
make check-opentofu
```

The OpenTofu module renders sanitized Kubernetes Namespace, ServiceAccount, and ConfigMap contract data without requiring a live cluster or private rack details.

GitHub Actions covers PR validation, release evidence packaging, supply-chain checks, and environment-gated promotion simulations. See [docs/ci-cd-workflow.md](docs/ci-cd-workflow.md).

Run the official Paperclip AI server:

```bash
make run-paperclip
```

The official Paperclip dashboard runs on port `3100` by default. This machine is configured for authenticated private-network access, so use `http://127.0.0.1:3100/`, a LAN address, or a Tailscale address allowed by the host firewall.

Git remotes are split by role:

- `origin`: personal R&D source, `git@github.com:CharlesDerek/lab.git`
- `athernex`: public downstream orchestrator repo, `git@github.com:Athernex/orchestrator.git`

Scheduled routine pushes are guarded by allowlists for both remotes.
The push order is deliberate: push the source branch to `origin` first, then push the same `HEAD` to `athernex/retrospective`.

Manual dual push:

```bash
tools/push_downstream.sh
```

Run the local Codex scheduler bridge:

```bash
make run-codex-scheduler
```

The Codex scheduler bridge is not upstream Paperclip. It is a small local helper that can run Codex in non-interactive bypass mode, capture evidence under `.paperclip/`, verify with `make check`, and optionally commit/push when explicitly enabled. Keep it separate from Paperclip's own agent-management dashboard.

Run the Neuroplexis maintenance routine runner directly:

```bash
tools/neuroplexis_lab_maintenance.sh
```

By default this is a real bounded maintenance run: it creates a task branch, invokes Codex for each cycle, requires every Codex cycle to leave a repository change, verifies with `make check`, and only then proceeds to commit/push when those flags are enabled. Set `DRY_RUN=true` only when you intentionally want a simulation that does not invoke Codex or change branches.

Paperclip routine payload templates live in `paperclip/routines/`. The intended schedule is every 6 hours with `skip_if_active` concurrency so overlapping maintenance cycles do not stack.

After authenticating the Paperclip CLI as a board/admin user, create the live Neuroplexis routine and schedule:

```bash
paperclip/routines/create-neuroplexis-lab-maintenance.sh
```

Run the config-driven planning pipeline in simulation mode:

```bash
python3 tools/neuroplexis_pipeline_runner.py --dry-run
```

Run the same pipeline for one real planning task plus pushed-repo verification:

```bash
python3 tools/neuroplexis_pipeline_runner.py
```

Stop local services:

```bash
make local-down
```

## Integration Tracks

1. **Datacenter control plane:** sanitized always-on control-plane model for routing, automation, observability, SIEM, EDR, and scheduling responsibilities.
2. **Messaging backbone:** Kafka topics for agent commands, observations, reviews, Paperclip requests, Paperclip responses, and dead letters.
3. **Brokered power scheduling:** Kafka topics for capacity decisions, power commands, power observations, state capture, dead letters, and audit trails.
4. **Workload scheduling:** Kubernetes-facing contracts for dynamic capacity and node lifecycle orchestration, with private power and cluster procedures kept outside git.
5. **Local AWS staging:** S3 for artifacts, DynamoDB for run metadata, SQS for fallback queues and dead-letter inspection.
6. **Rust orchestration:** typed workflow states, retry policies, idempotency keys, and conservative rate limits before any rack-wide scheduling.
7. **Paperclip adapter:** public-safe request/response envelopes, with secrets and private prompt material kept out of git.
8. **Failure, security, and hallucination controls:** deterministic validation, evidence capture, review queues, quarantine states, and staged promotion.
9. **Scheduled public improvements:** official Paperclip can manage agents and routines; the local Codex scheduler bridge can run Codex in non-interactive bypass mode, verify with `make check`, and optionally commit/push public-safe changes.
10. **Neuroplexis repo maintenance:** a bounded routine runner creates task branches, runs up to 5 Codex cycles, verifies after each cycle, and records compact handoff notes.

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
- [x] Rust unit tests for scheduler and workflow contracts
- [x] GitHub Actions CI for Rust, automation, and OpenTofu checks
- [x] OpenTofu Kubernetes scheduler contract tests
- [x] Failure and hallucination review model
- [x] Public-safe Athernex datacenter capability model
- [x] Kafka broker and power-scheduler control-loop model
- [x] Official Paperclip run target
- [x] Local Codex scheduler bridge for gated `codex --yolo` improvement runs
- [x] Automation validation wired into `make check`
- [x] Public-safe Kafka producer/consumer contract slice
- [x] Kubernetes scheduler adapter contracts
- [x] Kafka adapter facade for typed producer/consumer records
- [x] Real Kafka consumer and producer implementation
- [ ] Paperclip adapter implementation
- [ ] Load tests for backpressure and retry behavior
- [ ] Rack-specific deployment manifests kept in a private repo or encrypted vault
