"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Shell } from "@/components/shell";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { ErrorAlert } from "@/components/ui";

const LEVELS = [
  { value: 1, label: "1 — Recon only" },
  { value: 2, label: "2 — + Surface mapping" },
  { value: 3, label: "3 — + Active testing" },
  { value: 4, label: "4 — + Claude analysis" },
  { value: 5, label: "5 — + Chain analysis" },
  { value: 6, label: "6 — Full report" },
];

export default function NewScanPage() {
  const router = useRouter();
  const { token } = useAuth();
  const [targetUrl, setTargetUrl] = useState("");
  const [programId, setProgramId] = useState("");
  const [scanLevel, setScanLevel] = useState(6);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!token) return;
    setError(null);
    setBusy(true);
    try {
      await api.createScan(token, {
        target_url: targetUrl,
        program_id: programId.trim(),
        scan_level: scanLevel,
      });
      router.replace("/scans");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to start scan");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell>
      <div className="page-head">
        <h1 style={{ margin: 0 }}>New scan</h1>
      </div>
      <div className="card" style={{ maxWidth: 560 }}>
        <p className="muted" style={{ marginTop: 0 }}>
          The target must be within the scope whitelist of the program you reference, or the
          scan is refused before any request is made.
        </p>
        <form onSubmit={onSubmit}>
          <div className="field">
            <label>Target URL</label>
            <input
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com/login"
              required
            />
          </div>
          <div className="field">
            <label>Program ID</label>
            <input
              value={programId}
              onChange={(e) => setProgramId(e.target.value)}
              placeholder="UUID of an active bounty program"
              className="mono"
              required
            />
          </div>
          <div className="field">
            <label>Scan depth</label>
            <select
              value={scanLevel}
              onChange={(e) => setScanLevel(Number(e.target.value))}
            >
              {LEVELS.map((l) => (
                <option key={l.value} value={l.value}>
                  {l.label}
                </option>
              ))}
            </select>
          </div>
          <div style={{ marginTop: 16 }}>
            <ErrorAlert message={error} />
          </div>
          <button className="btn" style={{ marginTop: 16 }} disabled={busy}>
            {busy ? "Starting…" : "Start scan"}
          </button>
        </form>
      </div>
    </Shell>
  );
}
