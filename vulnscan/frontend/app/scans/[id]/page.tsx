"use client";

import { useParams } from "next/navigation";
import { useCallback, useState } from "react";
import { Shell } from "@/components/shell";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useApi } from "@/lib/useApi";
import { CvssScore, ErrorAlert, SeverityBadge, Spinner, StatusBadge } from "@/components/ui";
import type { ScanFinding } from "@/lib/types";

function FindingCard({ finding }: { finding: ScanFinding }) {
  const { token } = useAuth();
  const [open, setOpen] = useState(false);
  const [companyTenant, setCompanyTenant] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (!token) return;
    setErr(null);
    setMsg(null);
    setBusy(true);
    try {
      await api.createSubmission(token, {
        finding_id: finding.id,
        company_tenant_id: companyTenant.trim(),
      });
      setMsg("Submitted to company for review.");
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Submission failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <div className="row between">
        <div className="row">
          <SeverityBadge severity={finding.severity} />
          <strong>{finding.title}</strong>
          {finding.is_chained && <span className="badge status">chain</span>}
        </div>
        <div className="row">
          <span className="muted">CVSS</span>
          <CvssScore score={finding.cvss_score} />
          <button className="btn small secondary" onClick={() => setOpen((o) => !o)}>
            {open ? "Hide" : "Details"}
          </button>
        </div>
      </div>

      {open && (
        <div style={{ marginTop: 14 }} className="stack">
          <p style={{ margin: 0 }}>{finding.description}</p>
          {finding.proof_of_concept && (
            <>
              <label style={{ marginTop: 8 }}>Proof of concept</label>
              <pre>{finding.proof_of_concept}</pre>
            </>
          )}
          {finding.recommendation && (
            <>
              <label style={{ marginTop: 8 }}>Recommendation</label>
              <p style={{ margin: 0 }}>{finding.recommendation}</p>
            </>
          )}
          {finding.references.length > 0 && (
            <>
              <label style={{ marginTop: 8 }}>References</label>
              <ul style={{ margin: 0 }}>
                {finding.references.map((r) => (
                  <li key={r}>
                    <a href={r} target="_blank" rel="noreferrer">
                      {r}
                    </a>
                  </li>
                ))}
              </ul>
            </>
          )}

          <div style={{ marginTop: 12, borderTop: "1px solid var(--border)", paddingTop: 12 }}>
            <label>Submit to company (tenant ID)</label>
            <div className="row">
              <input
                value={companyTenant}
                onChange={(e) => setCompanyTenant(e.target.value)}
                placeholder="company tenant UUID"
                className="mono"
              />
              <button className="btn small" onClick={submit} disabled={busy || !companyTenant}>
                Submit
              </button>
            </div>
            {msg && (
              <p className="muted" style={{ marginBottom: 0 }}>
                {msg}
              </p>
            )}
            <ErrorAlert message={err} />
          </div>
        </div>
      )}
    </div>
  );
}

export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;

  const scanFetcher = useCallback((t: string) => api.getScan(t, id), [id]);
  const findingsFetcher = useCallback((t: string) => api.getScanFindings(t, id), [id]);
  const { data: scan, error: scanErr, loading } = useApi(scanFetcher);
  const { data: findings, reload } = useApi(findingsFetcher);

  const ordered = [...(findings ?? [])].sort((a, b) => b.cvss_score - a.cvss_score);

  return (
    <Shell>
      <div className="page-head">
        <h1 style={{ margin: 0 }}>Scan detail</h1>
        <button className="btn secondary small" onClick={reload}>
          Refresh
        </button>
      </div>
      <ErrorAlert message={scanErr} />

      {loading ? (
        <Spinner />
      ) : scan ? (
        <>
          <div className="card">
            <div className="stack">
              <div className="row between">
                <span className="mono">{scan.target_url}</span>
                <StatusBadge status={scan.status} />
              </div>
              <div className="muted">
                Level {scan.scan_level} · created {new Date(scan.created_at).toLocaleString()}
              </div>
              {scan.error_message && <div className="alert">{scan.error_message}</div>}
            </div>
          </div>

          <h3 style={{ marginTop: 24 }}>Findings ({ordered.length})</h3>
          {ordered.length === 0 ? (
            <div className="card empty">
              {scan.status === "completed"
                ? "No findings reported."
                : "Findings appear here once the scan completes."}
            </div>
          ) : (
            ordered.map((f) => <FindingCard key={f.id} finding={f} />)
          )}
        </>
      ) : null}
    </Shell>
  );
}
