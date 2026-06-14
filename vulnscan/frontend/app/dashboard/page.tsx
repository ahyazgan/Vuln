"use client";

import Link from "next/link";
import { Shell } from "@/components/shell";
import { useAuth } from "@/lib/auth";
import { useApi } from "@/lib/useApi";
import { api } from "@/lib/api";
import { Spinner, StatusBadge } from "@/components/ui";

function HackerDashboard() {
  const { data: scans, loading } = useApi(api.listScans);
  if (loading) return <Spinner />;
  const all = scans ?? [];
  const running = all.filter((s) => s.status === "running" || s.status === "queued").length;
  const completed = all.filter((s) => s.status === "completed").length;

  return (
    <>
      <div className="grid cols-3">
        <div className="card">
          <div className="stat">{all.length}</div>
          <div className="stat-label">Total scans</div>
        </div>
        <div className="card">
          <div className="stat">{running}</div>
          <div className="stat-label">Queued / running</div>
        </div>
        <div className="card">
          <div className="stat">{completed}</div>
          <div className="stat-label">Completed</div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="page-head" style={{ marginBottom: 12 }}>
          <h3 style={{ margin: 0 }}>Recent scans</h3>
          <Link className="btn small" href="/scans/new">
            New scan
          </Link>
        </div>
        {all.length === 0 ? (
          <div className="empty">No scans yet. Start one against an in-scope target.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Level</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {all.slice(0, 6).map((s) => (
                <tr key={s.id}>
                  <td>
                    <Link href={`/scans/${s.id}`} className="mono">
                      {s.target_url}
                    </Link>
                  </td>
                  <td>{s.scan_level}</td>
                  <td>
                    <StatusBadge status={s.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

function CompanyDashboard() {
  const { data: programs } = useApi(api.listPrograms);
  const { data: submissions } = useApi(api.listSubmissions);
  const { data: payments } = useApi(api.listPayments);
  const pending = (submissions ?? []).filter((s) => s.status === "pending").length;

  return (
    <>
      <div className="grid cols-3">
        <div className="card">
          <div className="stat">{programs?.length ?? "—"}</div>
          <div className="stat-label">Bounty programs</div>
        </div>
        <div className="card">
          <div className="stat">{pending}</div>
          <div className="stat-label">Submissions awaiting review</div>
        </div>
        <div className="card">
          <div className="stat">{payments?.length ?? "—"}</div>
          <div className="stat-label">Payments</div>
        </div>
      </div>
      <div className="card" style={{ marginTop: 16 }}>
        <div className="row between">
          <h3 style={{ margin: 0 }}>Get started</h3>
          <div className="row">
            <Link className="btn small secondary" href="/submissions">
              Review submissions
            </Link>
            <Link className="btn small" href="/programs/new">
              New program
            </Link>
          </div>
        </div>
      </div>
    </>
  );
}

export default function DashboardPage() {
  const { user } = useAuth();
  return (
    <Shell>
      <div className="page-head">
        <h1 style={{ margin: 0 }}>Dashboard</h1>
      </div>
      {user?.role === "company" ? <CompanyDashboard /> : <HackerDashboard />}
    </Shell>
  );
}
