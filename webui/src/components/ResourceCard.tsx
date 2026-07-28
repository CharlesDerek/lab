import { ClipboardList, Database, Eye, Gauge, Network, TerminalSquare } from "lucide-react";
import type { LabResource } from "../types";
import { safeEndpointLabel, safeLocalHref } from "../security/endpoints";
import { StatusPill } from "./StatusPill";

export function ResourceCard({ resource }: { resource: LabResource }) {
  const endpoint = safeEndpointLabel(resource.endpoint);
  const href = safeLocalHref(resource.endpoint);

  return (
    <article className="dashboard-resource-card h-100 d-flex flex-column">
      <div className="dashboard-resource-card__top d-flex align-items-center justify-content-between gap-2">
        <div className="dashboard-resource-card__icon">{resourceIcon(resource.owner)}</div>
        <StatusPill state={resource.status} label={resource.status} />
      </div>
      <h3 className="dashboard-resource-card__title">{resource.name}</h3>
      <p className="dashboard-resource-card__role">{resource.role}</p>
      <dl className="dashboard-resource-card__facts">
        <div>
          <dt>Endpoint</dt>
          <dd>
            {href ? (
              <a href={href} target="_blank" rel="noreferrer noopener">
                {endpoint}
              </a>
            ) : (
              endpoint
            )}
          </dd>
        </div>
        <div>
          <dt>Telemetry</dt>
          <dd>{resource.telemetry}</dd>
        </div>
        <div>
          <dt>Boundary</dt>
          <dd>{resource.securityBoundary}</dd>
        </div>
      </dl>
      <footer className="dashboard-resource-card__footer d-flex align-items-center gap-2">
        <Eye size={16} aria-hidden="true" />
        <span>Last signal {resource.lastSignal}</span>
      </footer>
    </article>
  );
}

function resourceIcon(owner: LabResource["owner"]) {
  switch (owner) {
    case "Paperclip":
      return <ClipboardList size={20} />;
    case "Kafka":
      return <Network size={20} />;
    case "LocalStack":
      return <Database size={20} />;
    case "Kubernetes":
      return <Gauge size={20} />;
    case "Athernex":
      return <TerminalSquare size={20} />;
  }
}
