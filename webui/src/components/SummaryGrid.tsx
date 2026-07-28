import { Activity, ClipboardList, Lock, ShieldCheck } from "lucide-react";
import type { KafkaTopic, LabResource, ReviewGate } from "../types";
import { MetricCard } from "./MetricCard";

interface SummaryGridProps {
  resources: LabResource[];
  topics: KafkaTopic[];
  reviewGates: ReviewGate[];
}

export function SummaryGrid({ resources, topics, reviewGates }: SummaryGridProps) {
  const healthyCount = resources.filter((resource) => resource.status === "healthy").length;
  const activeReviewItems = topics.reduce((sum, topic) => sum + topic.quarantined, 0);
  const avgCoverage = Math.round(
    reviewGates.reduce((sum, gate) => sum + gate.coverage, 0) / reviewGates.length,
  );

  return (
    <section className="row g-3 dashboard-summary" aria-label="Lab monitoring summary">
      <div className="col-12 col-md-6 col-xl-3">
        <MetricCard
          icon={<Activity size={20} />}
          label="Resource Health"
          value={`${healthyCount}/5`}
          detail="localhost services in expected posture"
        />
      </div>
      <div className="col-12 col-md-6 col-xl-3">
        <MetricCard
          icon={<ShieldCheck size={20} />}
          label="Gate Coverage"
          value={`${avgCoverage}%`}
          detail="schema, evidence, safety, security, promotion"
        />
      </div>
      <div className="col-12 col-md-6 col-xl-3">
        <MetricCard
          icon={<ClipboardList size={20} />}
          label="Review Queue"
          value={`${activeReviewItems}`}
          detail="items requiring human decision"
        />
      </div>
      <div className="col-12 col-md-6 col-xl-3">
        <MetricCard
          icon={<Lock size={20} />}
          label="Boundary"
          value="Public-safe"
          detail="no secrets, topology, or raw private payloads"
        />
      </div>
    </section>
  );
}
