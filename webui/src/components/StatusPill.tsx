import { AlertTriangle, CheckCircle2 } from "lucide-react";
import type { GateState, HealthState } from "../types";

interface StatusPillProps {
  state: HealthState | GateState;
  label: string;
}

export function StatusPill({ state, label }: StatusPillProps) {
  const icon =
    state === "passing" || state === "healthy" ? (
      <CheckCircle2 size={14} />
    ) : (
      <AlertTriangle size={14} />
    );

  return (
    <span className={`dashboard-status dashboard-status--${state}`}>
      {icon}
      {label}
    </span>
  );
}
