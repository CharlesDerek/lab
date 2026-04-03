# lab

---

# DevSecOps Kubernetes Lab

A living, hands-on lab for rebuilding and advancing my Kubernetes, DevOps, and security engineering skills.

---

## Overview

This repository serves as an active engineering lab focused on:

* Rebuilding Kubernetes proficiency from the ground up
* Applying DevSecOps practices in realistic environments
* Moving from theory to implementation through hands-on work
* Maintaining a public, evolving portfolio of technical capability

This is not a finished project. It is a continuously evolving lab environment.

---

## Current Focus

* Kubernetes fundamentals (pods, deployments, services, networking)
* Rebuilding concepts from ongoing training and practical exercises
* Creating reproducible local cluster environments
* Deploying and testing applications within Kubernetes

---

## Repository Structure

```bash
.
├── k8s/
│   ├── manifests/        # Core Kubernetes YAML (pods, deployments, services)
│   ├── networking/       # Services, ingress, network policies
│   └── security/         # RBAC, policies, secrets handling
│
├── apps/
│   └── sample-app/       # Test applications deployed into the cluster
│
├── infrastructure/
│   └── local-cluster/    # k3d / kind / minikube setups
│
├── devsecops/
│   ├── ci-cd/            # Pipeline configurations (planned)
│   ├── scanning/         # Security scanning tools (planned)
│   └── policies/         # Security enforcement (planned)
│
└── docs/
    └── notes/            # Learning notes, breakdowns, and lessons learned
```

---

## DevSecOps Direction

This lab will progressively incorporate:

* CI/CD pipelines (GitHub Actions)
* Container and dependency scanning
* Kubernetes security (RBAC, NetworkPolicies)
* Secrets management (e.g., Vault, sealed secrets)
* Observability (Prometheus, Grafana, SigNoz)

---

## Approach

* Learn by building, not just consuming material
* Intentionally break and rebuild systems to understand behavior
* Apply production-minded practices where feasible
* Document decisions, failures, and improvements

---

## Purpose

Working in a security-focused role, I identified a need to rebuild hands-on development and infrastructure skills.

This repository exists to:

* Strengthen engineering depth
* Provide visible, demonstrable work
* Bridge Security, DevOps, and Software Engineering

---

## Roadmap

* [ ] Rebuild Kubernetes core concepts
* [ ] Deploy applications with proper networking
* [ ] Introduce CI/CD pipelines
* [ ] Implement container and dependency scanning
* [ ] Add infrastructure as code (Terraform)
* [ ] Integrate observability tooling
* [ ] Simulate real-world DevSecOps scenarios

---

## Tech Stack

* Kubernetes (k3d / kind / minikube)
* Docker
* Helm (planned)
* Terraform (planned)
* GitHub Actions (planned)
* Trivy or similar tools (planned)
* Prometheus / Grafana (planned)
* SigNoz (planned)

---

## Documentation

The `/docs` directory includes:

* Learning notes
* Experiment breakdowns
* Failure analysis and resolutions

---

## Feedback

Suggestions and feedback are welcome.

---

## Disclaimer

This repository is a learning and experimentation environment. Not all configurations are production-hardened.

---

## Personal Note

I focus on building systems that evolve through iteration and refinement. This lab reflects that approach.


