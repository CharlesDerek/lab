import type { RiskLevel } from "../types";

export function RiskPill({ level }: { level: RiskLevel }) {
  return (
    <span role="cell" className={`dashboard-risk dashboard-risk--${level}`}>
      {level}
    </span>
  );
}
