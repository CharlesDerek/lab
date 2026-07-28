import type { KafkaTopic, LabResource, ReviewGate, SecurityFinding } from "../types";

export const resources: LabResource[] = [
  {
    id: "paperclip",
    name: "Paperclip AI",
    role: "Agent and routine management dashboard",
    endpoint: "http://127.0.0.1:3100/",
    status: "healthy",
    telemetry: "Neuroplexis 6h routine, skip-if-active concurrency",
    securityBoundary: "API key never rendered; private prompts stay outside git",
    lastSignal: "2m ago",
    owner: "Paperclip",
  },
  {
    id: "codex-bridge",
    name: "Codex Scheduler Bridge",
    role: "Bounded public-safe repo improvement runner",
    endpoint: "http://127.0.0.1:8090/",
    status: "review",
    telemetry: "Manual trigger, make check evidence under .paperclip/runs",
    securityBoundary: "Autocommit/autopush disabled unless explicitly enabled",
    lastSignal: "7m ago",
    owner: "Athernex",
  },
  {
    id: "kafka-ui",
    name: "Kafka UI",
    role: "Local broker visibility for orchestration topics",
    endpoint: "http://127.0.0.1:18080/",
    status: "healthy",
    telemetry: "10 sanitized topics, bounded drain behavior",
    securityBoundary: "Local-only bind; no production broker details",
    lastSignal: "45s ago",
    owner: "Kafka",
  },
  {
    id: "localstack",
    name: "LocalStack",
    role: "AWS-compatible staging state and queues",
    endpoint: "http://127.0.0.1:4566/",
    status: "healthy",
    telemetry: "S3 artifacts, DynamoDB runs, SQS review and deadletter",
    securityBoundary: "Test credentials only; no cloud account contact",
    lastSignal: "1m ago",
    owner: "LocalStack",
  },
  {
    id: "scheduler-contract",
    name: "Kubernetes Scheduler Contract",
    role: "Sanitized namespace, service account, ConfigMap contract",
    endpoint: "local tofu module",
    status: "degraded",
    telemetry: "OpenTofu validation is optional when tofu is installed",
    securityBoundary: "No rack manifests, kubeconfigs, hostnames, or node labels",
    lastSignal: "last check",
    owner: "Kubernetes",
  },
];

export const topics: KafkaTopic[] = [
  {
    name: "agent.commands",
    purpose: "incoming work requests",
    state: "passing",
    lag: 0,
    quarantined: 0,
  },
  {
    name: "agent.review",
    purpose: "human or secondary review",
    state: "watching",
    lag: 3,
    quarantined: 1,
  },
  {
    name: "agent.deadletter",
    purpose: "exhausted, malformed, or unsafe work",
    state: "watching",
    lag: 1,
    quarantined: 1,
  },
  {
    name: "security.findings",
    purpose: "sanitized SIEM, EDR, and policy signals",
    state: "passing",
    lag: 0,
    quarantined: 0,
  },
  {
    name: "paperclip.requests",
    purpose: "sanitized adapter requests",
    state: "passing",
    lag: 0,
    quarantined: 0,
  },
];

export const reviewGates: ReviewGate[] = [
  {
    name: "Schema",
    state: "passing",
    coverage: 100,
    detail: "Versioned envelopes with idempotency and correlation metadata",
  },
  {
    name: "Evidence",
    state: "watching",
    coverage: 84,
    detail: "Artifacts are referenced by path or S3 URI before acceptance",
  },
  {
    name: "Safety",
    state: "passing",
    coverage: 96,
    detail: "Secret and private topology terms are blocked from display",
  },
  {
    name: "Security",
    state: "watching",
    coverage: 88,
    detail: "Findings can quarantine workflows before promotion",
  },
  {
    name: "Promotion",
    state: "blocked",
    coverage: 62,
    detail: "Private rack promotion remains intentionally outside this repo",
  },
];

export const findings: SecurityFinding[] = [
  {
    id: "finding-001",
    source: "safety-gate",
    level: "medium",
    summary: "Routine output requires evidence reference before merge",
    action: "Route to agent.review",
  },
  {
    id: "finding-002",
    source: "public-boundary",
    level: "low",
    summary: "Endpoint inventory is limited to localhost and sanitized names",
    action: "Continue monitoring",
  },
  {
    id: "finding-003",
    source: "deadletter-policy",
    level: "high",
    summary: "Malformed payloads are dead-lettered without raw payload echo",
    action: "Keep replay fixture redacted",
  },
];
