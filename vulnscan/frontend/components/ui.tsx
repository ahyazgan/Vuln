import type { Severity } from "@/lib/types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}>{severity}</span>;
}

const OK_STATUSES = new Set(["completed", "accepted", "paid", "succeeded"]);
const BAD_STATUSES = new Set(["failed", "rejected"]);

export function StatusBadge({ status }: { status: string }) {
  const cls = OK_STATUSES.has(status) ? "ok" : BAD_STATUSES.has(status) ? "bad" : "";
  return <span className={`badge status ${cls}`}>{status}</span>;
}

export function ErrorAlert({ message }: { message: string | null }) {
  if (!message) return null;
  return <div className="alert">{message}</div>;
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return <div className="empty">{label}</div>;
}

export function CvssScore({ score }: { score: number }) {
  return <span className="mono">{score.toFixed(1)}</span>;
}
