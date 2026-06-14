"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useAuth } from "@/lib/auth";
import { ApiError } from "@/lib/api";
import { ErrorAlert } from "@/components/ui";
import type { UserRole } from "@/lib/types";

export default function RegisterPage() {
  const { register } = useAuth();
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [tenantName, setTenantName] = useState("");
  const [role, setRole] = useState<UserRole>("hacker");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await register(email, password, role, tenantName);
      router.replace("/dashboard");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Registration failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="center-screen">
      <div className="card" style={{ width: 380 }}>
        <h1 style={{ marginTop: 0 }}>Create your account</h1>
        <p className="muted" style={{ marginTop: -8 }}>
          A new organization (tenant) is created for you.
        </p>
        <form onSubmit={onSubmit}>
          <div className="field">
            <label>Organization name</label>
            <input value={tenantName} onChange={(e) => setTenantName(e.target.value)} required />
          </div>
          <div className="field">
            <label>Account type</label>
            <select value={role} onChange={(e) => setRole(e.target.value as UserRole)}>
              <option value="hacker">Hacker — run scans, submit findings</option>
              <option value="company">Company — define programs, pay bounties</option>
            </select>
          </div>
          <div className="field">
            <label>Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
            />
          </div>
          <div className="field">
            <label>Password (min 8 characters)</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
              autoComplete="new-password"
            />
          </div>
          <div style={{ marginTop: 16 }}>
            <ErrorAlert message={error} />
          </div>
          <button className="btn" style={{ width: "100%", marginTop: 16 }} disabled={busy}>
            {busy ? "Creating…" : "Create account"}
          </button>
        </form>
        <p className="muted" style={{ marginTop: 16, fontSize: 14 }}>
          Already have an account? <Link href="/login">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
