"use client";

import { Shell } from "@/components/shell";
import { useApi } from "@/lib/useApi";
import { api } from "@/lib/api";
import { ErrorAlert, Spinner, StatusBadge } from "@/components/ui";

export default function PaymentsPage() {
  const { data, error, loading } = useApi(api.listPayments);

  return (
    <Shell>
      <div className="page-head">
        <h1 style={{ margin: 0 }}>Payments</h1>
      </div>
      <ErrorAlert message={error} />
      <div className="card">
        {loading ? (
          <Spinner />
        ) : (data ?? []).length === 0 ? (
          <div className="empty">
            No payments yet. Accept a submission and pay its bounty to see it here.
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Submission</th>
                <th>Amount</th>
                <th>Status</th>
                <th>Provider ref</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {(data ?? []).map((p) => (
                <tr key={p.id}>
                  <td className="mono">{p.submission_id.slice(0, 8)}…</td>
                  <td className="mono">
                    {p.amount} {p.currency.toUpperCase()}
                  </td>
                  <td>
                    <StatusBadge status={p.status} />
                  </td>
                  <td className="mono muted">{p.provider_payment_id ?? "—"}</td>
                  <td className="muted">{new Date(p.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Shell>
  );
}
