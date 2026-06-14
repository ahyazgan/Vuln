"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Shell } from "@/components/shell";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { ErrorAlert } from "@/components/ui";
import type { Severity } from "@/lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export default function NewProgramPage() {
  const router = useRouter();
  const { token } = useAuth();
  const [name, setName] = useState("");
  const [scope, setScope] = useState("");
  const [maxSeverity, setMaxSeverity] = useState<Severity>("critical");
  const [rewards, setRewards] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function parseRewards(): Record<string, number> {
    const out: Record<string, number> = {};
    for (const part of rewards.split(",").map((s) => s.trim()).filter(Boolean)) {
      const [sev, amt] = part.split(":").map((s) => s.trim());
      if (sev && amt && !Number.isNaN(Number(amt))) out[sev.toLowerCase()] = Number(amt);
    }
    return out;
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!token) return;
    setError(null);
    setBusy(true);
    try {
      await api.createProgram(token, {
        name,
        scope_domains: scope
          .split(/[\n,]/)
          .map((s) => s.trim())
          .filter(Boolean),
        max_severity: maxSeverity,
        reward_table: parseRewards(),
      });
      router.replace("/programs");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to create program");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell>
      <div className="page-head">
        <h1 style={{ margin: 0 }}>New bounty program</h1>
      </div>
      <div className="card" style={{ maxWidth: 620 }}>
        <form onSubmit={onSubmit}>
          <div className="field">
            <label>Program name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <div className="field">
            <label>Scope domains (comma or newline separated)</label>
            <textarea
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              rows={3}
              placeholder={"example.com\napi.example.com"}
              required
            />
          </div>
          <div className="field">
            <label>Maximum severity in scope</label>
            <select
              value={maxSeverity}
              onChange={(e) => setMaxSeverity(e.target.value as Severity)}
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label>Reward table (e.g. critical: 5000, high: 1500)</label>
            <input
              value={rewards}
              onChange={(e) => setRewards(e.target.value)}
              placeholder="critical: 5000, high: 1500, medium: 500"
            />
          </div>
          <div style={{ marginTop: 16 }}>
            <ErrorAlert message={error} />
          </div>
          <button className="btn" style={{ marginTop: 16 }} disabled={busy}>
            {busy ? "Creating…" : "Create program"}
          </button>
        </form>
      </div>
    </Shell>
  );
}
