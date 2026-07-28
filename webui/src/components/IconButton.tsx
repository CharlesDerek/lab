import type { ReactNode } from "react";

interface IconButtonProps {
  label: string;
  icon: ReactNode;
}

export function IconButton({ label, icon }: IconButtonProps) {
  return (
    <button type="button" className="btn dashboard-icon-button" title={label} aria-label={label}>
      {icon}
    </button>
  );
}
