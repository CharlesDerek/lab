export type HealthState = "healthy" | "degraded" | "review" | "offline";
export type RiskLevel = "low" | "medium" | "high";
export type GateState = "passing" | "watching" | "blocked";

export interface LabResource {
  id: string;
  name: string;
  role: string;
  endpoint: string;
  status: HealthState;
  telemetry: string;
  securityBoundary: string;
  lastSignal: string;
  owner: "Paperclip" | "Athernex" | "LocalStack" | "Kafka" | "Kubernetes";
}

export interface KafkaTopic {
  name: string;
  purpose: string;
  state: GateState;
  lag: number;
  quarantined: number;
}

export interface ReviewGate {
  name: string;
  state: GateState;
  coverage: number;
  detail: string;
}

export interface SecurityFinding {
  id: string;
  source: string;
  level: RiskLevel;
  summary: string;
  action: string;
}

export interface MetricSummary {
  label: string;
  value: string;
  detail: string;
}
