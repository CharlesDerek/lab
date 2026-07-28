import { ShieldX } from "lucide-react";
import type { SecurityFinding } from "../types";
import { RiskPill } from "./RiskPill";
import { SectionHeader } from "./SectionHeader";

export function SecurityFindings({ findings }: { findings: SecurityFinding[] }) {
  return (
    <section className="dashboard-section">
      <SectionHeader
        eyebrow="Security measures"
        title="Detection, containment, and evidence handling"
        action={<ShieldX size={22} aria-hidden="true" />}
      />
      <div className="dashboard-findings" role="table" aria-label="Security findings">
        <div className="dashboard-findings__header" role="row">
          <span role="columnheader">Finding</span>
          <span role="columnheader">Source</span>
          <span role="columnheader">Risk</span>
          <span role="columnheader">Action</span>
        </div>
        {findings.map((finding) => (
          <div className="dashboard-findings__row" role="row" key={finding.id}>
            <span role="cell">{finding.summary}</span>
            <span role="cell">{finding.source}</span>
            <RiskPill level={finding.level} />
            <span role="cell">{finding.action}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
