"use client";

import Link from "next/link";
import { Shell } from "@/components/shell";
import { useApi } from "@/lib/useApi";
import { api } from "@/lib/api";
import { ErrorAlert, SeverityBadge, Spinner } from "@/components/ui";

export default function ProgramsPage() {
  const { data, error, loading } = useApi(api.listPrograms);

  return (
    <Shell>
      <div className="page-head">
        <h1 style={{ margin: 0 }}>Bounty programs</h1>
        <Link className="btn" href="/programs/new">
          New program
        </Link>
      </div>
      <ErrorAlert message={error} />
      {loading ? (
        <Spinner />
      ) : (data ?? []).length === 0 ? (
        <div className="card empty">No programs yet. Define scope and rewards to get started.</div>
      ) : (
        (data ?? []).map((p) => (
          <div className="card" key={p.id}>
            <div className="row between">
              <div className="stack">
                <strong>{p.name}</strong>
                <span className="muted mono">{p.id}</span>
              </div>
              <div className="row">
                <SeverityBadge severity={p.max_severity} />
                <span className={`badge status ${p.is_active ? "ok" : "bad"}`}>
                  {p.is_active ? "active" : "inactive"}
                </span>
              </div>
            </div>
            <div style={{ marginTop: 12 }}>
              <label>Scope</label>
              <div className="row" style={{ flexWrap: "wrap" }}>
                {p.scope_domains.map((d) => (
                  <span key={d} className="badge status">
                    {d}
                  </span>
                ))}
              </div>
            </div>
            {Object.keys(p.reward_table).length > 0 && (
              <div style={{ marginTop: 12 }}>
                <label>Reward table</label>
                <div className="row" style={{ flexWrap: "wrap" }}>
                  {Object.entries(p.reward_table).map(([sev, amt]) => (
                    <span key={sev} className="badge status">
                      {sev}: ${amt}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))
      )}
    </Shell>
  );
}
