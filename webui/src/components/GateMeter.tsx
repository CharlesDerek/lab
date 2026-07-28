import type { ReviewGate } from "../types";
import { StatusPill } from "./StatusPill";

export function GateMeter({ gate }: { gate: ReviewGate }) {
  return (
    <div className="dashboard-gate">
      <div className="dashboard-gate__title d-flex align-items-center justify-content-between gap-3">
        <strong>{gate.name}</strong>
        <StatusPill state={gate.state} label={gate.state} />
      </div>
      <div className="dashboard-gate__track" aria-label={`${gate.name} gate coverage ${gate.coverage}%`}>
        <span className="dashboard-gate__bar" style={{ width: `${gate.coverage}%` }} />
      </div>
      <p className="dashboard-gate__detail">{gate.detail}</p>
    </div>
  );
}
