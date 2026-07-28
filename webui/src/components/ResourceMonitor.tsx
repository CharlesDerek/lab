import type { LabResource } from "../types";
import { ResourceCard } from "./ResourceCard";
import { SectionHeader } from "./SectionHeader";
import { StatusPill } from "./StatusPill";

export function ResourceMonitor({ resources }: { resources: LabResource[] }) {
  return (
    <section className="dashboard-section">
      <SectionHeader
        eyebrow="Monitored resources"
        title="Paperclip, orchestration, and local staging"
        action={<StatusPill state="healthy" label="local mode" />}
      />
      <div className="row g-3">
        {resources.map((resource) => (
          <div className="col-12 col-md-6 col-xl" key={resource.id}>
            <ResourceCard resource={resource} />
          </div>
        ))}
      </div>
    </section>
  );
}
