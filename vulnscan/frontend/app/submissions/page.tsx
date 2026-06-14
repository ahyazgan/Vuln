"use client";

import { useState } from "react";
import { Shell } from "@/components/shell";
import { useApi } from "@/lib/useApi";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { ErrorAlert, Spinner, StatusBadge } from "@/components/ui";
import type { BountySubmission } from "@/lib/types";

function CompanyRow({
  submission,
  onChanged,
}: {
  submission: BountySubmission;
  onChanged: () => void;
}) {
  const { token } = useAuth();
  const [reward, setReward] = useState(submission.reward_amount ?? "");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function review(status: "accepted" | "rejected") {
    if (!token) return;
    setErr(null);
    setBusy(true);
    try {
      await api.reviewSubmission(token, submission.id, {
        status,
        reward_amount: status === "accepted" ? reward || undefined : undefined,
      });
      onChanged();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Review failed");
    } finally {
      setBusy(false);
    }
  }

  async function pay() {
    if (!token) return;
    setErr(null);
    setBusy(true);
    try {
      await api.paySubmission(token, submission.id, {});
      onChanged();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Payment failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <tr>
      <td className="mono">{submission.finding_id.slice(0, 8)}…</td>
      <td>
        <StatusBadge status={submission.status} />
      </td>
      <td>
        {submission.status === "pending" ? (
          <input
            value={reward}
            onChange={(e) => setReward(e.target.value)}
            placeholder="reward"
            style={{ width: 110 }}
          />
        ) : (
          <span className="mono">{submission.reward_amount ?? "—"}</span>
        )}
      </td>
      <td>
        <div className="row">
          {submission.status === "pending" && (
            <>
              <button className="btn small" disabled={busy} onClick={() => review("accepted")}>
                Accept
              </button>
              <button
                className="btn small secondary"
                disabled={busy}
                onClick={() => review("rejected")}
              >
                Reject
              </button>
            </>
          )}
          {submission.status === "accepted" && (
            <button className="btn small" disabled={busy} onClick={pay}>
              Pay bounty
            </button>
          )}
          {submission.status === "paid" && <span className="muted">Paid ✓</span>}
        </div>
        <ErrorAlert message={err} />
      </td>
    </tr>
  );
}

export default function SubmissionsPage() {
  const { user } = useAuth();
  const { data, error, loading, reload } = useApi(api.listSubmissions);
  const isCompany = user?.role === "company";

  return (
    <Shell>
      <div className="page-head">
        <h1 style={{ margin: 0 }}>Submissions</h1>
      </div>
      <ErrorAlert message={error} />
      <div className="card">
        {loading ? (
          <Spinner />
        ) : (data ?? []).length === 0 ? (
          <div className="empty">
            {isCompany ? "No submissions received yet." : "You haven't submitted any findings."}
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Finding</th>
                <th>Status</th>
                <th>Reward</th>
                <th>{isCompany ? "Actions" : "Submitted"}</th>
              </tr>
            </thead>
            <tbody>
              {(data ?? []).map((s) =>
                isCompany ? (
                  <CompanyRow key={s.id} submission={s} onChanged={reload} />
                ) : (
                  <tr key={s.id}>
                    <td className="mono">{s.finding_id.slice(0, 8)}…</td>
                    <td>
                      <StatusBadge status={s.status} />
                    </td>
                    <td className="mono">{s.reward_amount ?? "—"}</td>
                    <td className="muted">{new Date(s.submitted_at).toLocaleString()}</td>
                  </tr>
                ),
              )}
            </tbody>
          </table>
        )}
      </div>
    </Shell>
  );
}
