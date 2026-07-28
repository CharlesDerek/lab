import { findings, resources, reviewGates, topics } from "./data/labMonitoring";
import { DashboardHeader } from "./components/DashboardHeader";
import { OperationsPanel } from "./components/OperationsPanel";
import { ResourceMonitor } from "./components/ResourceMonitor";
import { SecurityFindings } from "./components/SecurityFindings";
import { SummaryGrid } from "./components/SummaryGrid";

export function App() {
  return (
    <main className="dashboard-shell">
      <aside className="dashboard-shell__rail" aria-hidden="true">
        <span className="dashboard-shell__rail-mark">AX</span>
        <span className="dashboard-shell__rail-line" />
        <span className="dashboard-shell__rail-state">Lab</span>
      </aside>
      <div className="container-fluid dashboard-shell__content">
        <DashboardHeader />
        <SummaryGrid resources={resources} topics={topics} reviewGates={reviewGates} />
        <ResourceMonitor resources={resources} />
        <OperationsPanel topics={topics} reviewGates={reviewGates} />
        <SecurityFindings findings={findings} />
      </div>
    </main>
  );
}
