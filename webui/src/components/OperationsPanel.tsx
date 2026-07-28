import { FileCheck2, RadioTower } from "lucide-react";
import type { KafkaTopic, ReviewGate } from "../types";
import { GateMeter } from "./GateMeter";
import { SectionHeader } from "./SectionHeader";
import { TopicRow } from "./TopicRow";

interface OperationsPanelProps {
  topics: KafkaTopic[];
  reviewGates: ReviewGate[];
}

export function OperationsPanel({ topics, reviewGates }: OperationsPanelProps) {
  return (
    <section className="row g-4 dashboard-operations">
      <div className="col-12 col-xl-7">
        <div className="dashboard-section">
          <SectionHeader
            eyebrow="Kafka posture"
            title="Typed workflow topics"
            action={<RadioTower size={22} aria-hidden="true" />}
          />
          <div className="dashboard-topic-list">
            {topics.map((topic) => (
              <TopicRow key={topic.name} topic={topic} />
            ))}
          </div>
        </div>
      </div>

      <div className="col-12 col-xl-5">
        <div className="dashboard-section">
          <SectionHeader
            eyebrow="Review controls"
            title="Promotion gates"
            action={<FileCheck2 size={22} aria-hidden="true" />}
          />
          <div className="dashboard-gate-list">
            {reviewGates.map((gate) => (
              <GateMeter key={gate.name} gate={gate} />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
