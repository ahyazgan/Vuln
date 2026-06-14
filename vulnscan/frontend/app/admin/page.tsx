"use client";

import { useState } from "react";
import { Shell } from "@/components/shell";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useApi } from "@/lib/useApi";
import { ErrorAlert, Spinner } from "@/components/ui";
import type { PlanType, TenantAdmin } from "@/lib/types";

const PLANS: PlanType[] = ["starter", "pro", "enterprise"];

function TenantRow({ tenant, onChanged }: { tenant: TenantAdmin; onChanged: () => void }) {
  const { token } = useAuth();
  const [plan, setPlan] = useState<PlanType>(tenant.plan);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const suspended = tenant.deleted_at !== null;

  async function changePlan(next: PlanType) {
    if (!token) return;
    setPlan(next);
    setBusy(true);
    setErr(null);
    try {
      await api.adminUpdateTenant(token, tenant.id, { plan: next });
      onChanged();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Update failed");
    } finally {
      setBusy(false);
    }
  }

  async function suspend() {
    if (!token) return;
    setBusy(true);
    setErr(null);
    try {
      await api.adminSuspendTenant(token, tenant.id);
      onChanged();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Suspend failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <tr style={suspended ? { opacity: 0.55 } : undefined}>
      <td>
        <div className="stack">
          <strong>{tenant.name}</strong>
          <span className="muted mono">{tenant.id.slice(0, 8)}…</span>
        </div>
      </td>
      <td>{tenant.user_count}</td>
      <td>{tenant.scan_count}</td>
      <td>
        <select
          value={plan}
          disabled={busy || suspended}
          onChange={(e) => changePlan(e.target.value as PlanType)}
          style={{ width: 130 }}
        >
          {PLANS.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
      </td>
      <td>
        {suspended ? (
          <span className="badge status bad">suspended</span>
        ) : (
          <button className="btn small secondary" disabled={busy} onClick={suspend}>
            Suspend
          </button>
        )}
        <ErrorAlert message={err} />
      </td>
    </tr>
  );
}

export default function AdminPage() {
  const { data: stats } = useApi(api.adminStats);
  const { data: tenants, loading, error, reload } = useApi(api.adminTenants);
  const { data: audit } = useApi(api.adminAudit);

  const cards: [string, number | undefined][] = [
    ["Tenants", stats?.tenants],
    ["Users", stats?.users],
    ["Scans", stats?.scans],
    ["Findings", stats?.findings],
    ["Submissions", stats?.submissions],
    ["Payments", stats?.payments],
  ];

  return (
    <Shell>
      <div className="page-head">
        <h1 style={{ margin: 0 }}>Admin</h1>
      </div>

      <div className="grid cols-3">
        {cards.map(([label, value]) => (
          <div className="card" key={label}>
            <div className="stat">{value ?? "—"}</div>
            <div className="stat-label">{label}</div>
          </div>
        ))}
      </div>

      <h3 style={{ marginTop: 24 }}>Tenants</h3>
      <ErrorAlert message={error} />
      <div className="card">
        {loading ? (
          <Spinner />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Tenant</th>
                <th>Users</th>
                <th>Scans</th>
                <th>Plan</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {(tenants ?? []).map((t) => (
                <TenantRow key={t.id} tenant={t} onChanged={reload} />
              ))}
            </tbody>
          </table>
        )}
      </div>

      <h3 style={{ marginTop: 24 }}>Recent audit activity</h3>
      <div className="card">
        {(audit ?? []).length === 0 ? (
          <div className="empty">No audit records.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Action</th>
                <th>Target</th>
              </tr>
            </thead>
            <tbody>
              {(audit ?? []).slice(0, 25).map((a) => (
                <tr key={a.id}>
                  <td className="muted">{new Date(a.created_at).toLocaleString()}</td>
                  <td className="mono">{a.action}</td>
                  <td className="mono muted">{a.target ? a.target.slice(0, 16) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Shell>
  );
}
