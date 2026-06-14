"use client";

import Link from "next/link";
import { Shell } from "@/components/shell";
import { useApi } from "@/lib/useApi";
import { api } from "@/lib/api";
import { ErrorAlert, Spinner, StatusBadge } from "@/components/ui";

export default function ScansPage() {
  const { data, error, loading } = useApi(api.listScans);

  return (
    <Shell>
      <div className="page-head">
        <h1 style={{ margin: 0 }}>Scans</h1>
        <Link className="btn" href="/scans/new">
          New scan
        </Link>
      </div>
      <ErrorAlert message={error} />
      <div className="card">
        {loading ? (
          <Spinner />
        ) : (data ?? []).length === 0 ? (
          <div className="empty">No scans yet.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Level</th>
                <th>Status</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {(data ?? []).map((s) => (
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
                  <td className="muted">{new Date(s.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Shell>
  );
}
