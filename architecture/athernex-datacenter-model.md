# Athernex Datacenter Model

Project Athernex is a modular homelab datacenter used for research in security engineering, distributed systems, and infrastructure automation. This document describes the public-safe capability model represented by the repo.

## Public-Safe Capability Map

| Capability | Public Representation | Private Boundary |
| --- | --- | --- |
| Network segmentation | Abstract segments such as `control`, `service`, `worker`, and `lab` | Real VLAN IDs, firewall rules, OpenWrt configuration, addresses, and switch port maps |
| Control plane | Always-on orchestration service with Kafka, local state, review queues, and policy gates | Exact hostnames, access paths, remote management, and production deployment manifests |
| Compute capacity | Worker groups advertised through scheduling contracts | Physical node inventory, power procedures, BMC/IPMI details, serials, and rack topology |
| Kubernetes scheduling | Contract-first adapter for workload placement and lifecycle events | Cluster kubeconfigs, namespaces, manifests, storage classes, and node labels that identify real systems |
| Event backbone | Kafka topics for commands, observations, review events, audit, and dead letters | Production broker endpoints, credentials, retention policies, and operational metrics |
| Power modules | Sanitized `power.commands` and `power.observations` contracts | REST endpoints, outlet maps, BMC/IPMI details, wake procedures, and device credentials |
| Observability | Sanitized events, audit records, run metadata, and local staging artifacts | SIEM indexes, EDR console details, raw logs, alerts, detections, and private incidents |
| Security controls | Review gates, quarantine states, secret-leak prevention, and evidence requirements | Internal detection logic, response playbooks, private tooling credentials, and sensitive findings |

## Control-Plane Responsibilities

The Athernex control plane is modeled as a dedicated always-on layer. In the real environment it is responsible for:

- Routing work and observations across segmented services.
- Coordinating automation workflows through durable events.
- Maintaining audit trails and review states.
- Feeding centralized logging, SIEM, and EDR services.
- Scheduling workloads onto dynamic compute capacity.
- Treating infrastructure failures, security findings, and model-quality issues as explicit workflow states.

## Dynamic Capacity Goal

The target scheduling model is event driven:

```text
work request -> policy validation -> capacity decision -> node lifecycle event -> workload placement -> observation/audit
```

Kafka carries the durable intent and observation stream. Kubernetes is the workload placement boundary. Private automation decides how real nodes are provisioned, powered, joined, drained, or retired; this public repo keeps only the contracts and staging behavior needed to test orchestration safely.

## Staging Interpretation

Local development uses Kafka-compatible messaging and LocalStack resources to exercise the same control-plane behaviors without touching the physical datacenter. A local run should prove message shape, idempotency, review routing, retry behavior, dead-letter handling, and audit capture before anything is promoted into the private rack environment.
