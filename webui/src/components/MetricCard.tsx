import type { ReactNode } from "react";
import type { MetricSummary } from "../types";

interface MetricCardProps extends MetricSummary {
  icon: ReactNode;
}

export function MetricCard({ icon, label, value, detail }: MetricCardProps) {
  return (
    <article className="dashboard-metric d-flex align-items-start gap-3">
      <div className="dashboard-metric__icon">{icon}</div>
      <div>
        <span className="dashboard-metric__label">{label}</span>
        <strong className="dashboard-metric__value">{value}</strong>
        <p className="dashboard-metric__detail">{detail}</p>
      </div>
    </article>
  );
}
