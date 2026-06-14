"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useState } from "react";
import { Shell } from "@/components/shell";
import { api, downloadReport } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useApi } from "@/lib/useApi";
import { CvssScore, ErrorAlert, SeverityBadge, Spinner, StatusBadge } from "@/components/ui";
import type { ScanFinding } from "@/lib/types";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

function FindingBlock({ f }: { f: ScanFinding }) {
  return (
    <div className="card">
      <div className="row between">
        <div className="row">
          <SeverityBadge severity={f.severity} />
          <strong>{f.title}</strong>
          {f.is_chained && <span className="badge status">chain</span>}
        </div>
        <span className="row">
          <span className="muted">CVSS</span> <CvssScore score={f.cvss_score} />
        </span>
      </div>
      <p style={{ marginBottom: 0 }}>{f.description}</p>
      {f.proof_of_concept && <pre style={{ marginTop: 12 }}>{f.proof_of_concept}</pre>}
      {f.recommendation && (
        <p className="muted" style={{ marginBottom: 0 }}>
          <strong>Fix:</strong> {f.recommendation}
        </p>
      )}
    </div>
  );
}

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const { token } = useAuth();
  const fetcher = useCallback((t: string) => api.getScanReport(t, id), [id]);
  const { data: report, error, loading } = useApi(fetcher);
  const [dlError, setDlError] = useState<string | null>(null);

  async function dl(format: "md" | "html") {
    if (!token) return;
    setDlError(null);
    try {
      await downloadReport(token, id, format);
    } catch {
      setDlError(`Could not download the ${format.toUpperCase()} report.`);
    }
  }

  return (
    <Shell>
      <div className="page-head">
        <h1 style={{ margin: 0 }}>Report</h1>
        <div className="row">
          <Link className="btn secondary small" href={`/scans/${id}`}>
            Back to scan
          </Link>
          <button className="btn secondary small" onClick={() => dl("md")}>
            Download .md
          </button>
          <button className="btn small" onClick={() => dl("html")}>
            Download .html
          </button>
        </div>
      </div>
      <ErrorAlert message={error || dlError} />

      {loading ? (
        <Spinner />
      ) : report ? (
        <>
          <div className="card">
            <div className="row between">
              <span className="mono">{report.summary.target_url}</span>
              <StatusBadge status={report.summary.status} />
            </div>
            <div className="grid cols-3" style={{ marginTop: 16 }}>
              <div>
                <div className="stat">{report.summary.risk_score}/100</div>
                <div className="stat-label">Risk score</div>
              </div>
              <div>
                <div className="stat">{report.summary.total_findings}</div>
                <div className="stat-label">Total findings</div>
              </div>
              <div>
                <div className="stat">
                  {report.summary.max_severity ? (
                    <SeverityBadge severity={report.summary.max_severity} />
                  ) : (
                    "—"
                  )}
                </div>
                <div className="stat-label">Highest severity</div>
              </div>
            </div>
            <div className="row" style={{ flexWrap: "wrap", marginTop: 16 }}>
              {SEVERITIES.map((sev) => (
                <span key={sev} className="badge status">
                  {sev}: {report.summary.by_severity[sev] ?? 0}
                </span>
              ))}
            </div>
          </div>

          <h3 style={{ marginTop: 24 }}>Individual findings ({report.findings.length})</h3>
          {report.findings.length === 0 ? (
            <div className="card empty">None.</div>
          ) : (
            report.findings.map((f) => <FindingBlock key={f.id} f={f} />)
          )}

          {report.chained_findings.length > 0 && (
            <>
              <h3 style={{ marginTop: 24 }}>
                Attack chains ({report.chained_findings.length})
              </h3>
              {report.chained_findings.map((f) => <FindingBlock key={f.id} f={f} />)}
            </>
          )}
        </>
      ) : null}
    </Shell>
  );
}
