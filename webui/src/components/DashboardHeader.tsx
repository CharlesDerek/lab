import { Play, RefreshCw, ShieldCheck } from "lucide-react";
import { IconButton } from "./IconButton";

export function DashboardHeader() {
  return (
    <header className="dashboard-shell__header d-flex align-items-center justify-content-between gap-3">
      <div>
        <p className="dashboard-eyebrow">Project Athernex lab control surface</p>
        <h1 className="dashboard-shell__title">Security Operations Dashboard</h1>
        <p className="dashboard-shell__subtitle">
          Public-safe visibility for Paperclip AI, orchestration contracts, local staging, and review gates.
        </p>
      </div>
      <div className="dashboard-shell__actions d-flex align-items-center gap-2">
        <span className="dashboard-shell__badge">
          <ShieldCheck size={14} />
          sanitized mode
        </span>
        <IconButton label="Refresh telemetry" icon={<RefreshCw size={18} />} />
        <IconButton label="Run gated check" icon={<Play size={18} />} />
      </div>
    </header>
  );
}
