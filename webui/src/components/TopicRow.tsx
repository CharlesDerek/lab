import type { KafkaTopic } from "../types";
import { StatusPill } from "./StatusPill";

export function TopicRow({ topic }: { topic: KafkaTopic }) {
  return (
    <div className="dashboard-topic-row">
      <div>
        <strong className="dashboard-topic-row__name">{topic.name}</strong>
        <span className="dashboard-topic-row__purpose">{topic.purpose}</span>
      </div>
      <StatusPill state={topic.state} label={topic.state} />
      <span className="dashboard-topic-row__number" aria-label={`${topic.lag} lagged messages`}>
        <small>lag</small>
        {topic.lag}
      </span>
      <span className="dashboard-topic-row__number" aria-label={`${topic.quarantined} quarantined messages`}>
        <small>hold</small>
        {topic.quarantined}
      </span>
    </div>
  );
}
