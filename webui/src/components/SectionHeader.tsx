import type { ReactNode } from "react";

interface SectionHeaderProps {
  eyebrow: string;
  title: string;
  action?: ReactNode;
}

export function SectionHeader({ eyebrow, title, action }: SectionHeaderProps) {
  return (
    <div className="dashboard-section__header d-flex align-items-center justify-content-between gap-3">
      <div>
        <p className="dashboard-eyebrow">{eyebrow}</p>
        <h2 className="dashboard-section__title">{title}</h2>
      </div>
      {action}
    </div>
  );
}
