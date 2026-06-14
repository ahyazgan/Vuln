// Typed fetch client for the VulnScan AI backend.
//
// All calls go through `request`, which prefixes the API base URL, attaches the
// bearer token when present, and raises a typed `ApiError` on non-2xx so callers
// can render `err.message` directly.

import type {
  AccessToken,
  BountyProgram,
  BountySubmission,
  Payment,
  PaymentInitiated,
  ScanCreated,
  ScanFinding,
  ScanJob,
  SubmissionStatus,
  TokenPair,
  User,
  UserRole,
} from "./types";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") ?? "http://localhost:8000";

const PREFIX = "/api/v1";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  options: { method?: string; body?: unknown; token?: string | null } = {},
): Promise<T> {
  const { method = "GET", body, token } = options;
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;

  let res: Response;
  try {
    res = await fetch(`${API_BASE}${PREFIX}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      cache: "no-store",
    });
  } catch {
    throw new ApiError(0, "Network error — is the backend reachable?");
  }

  if (res.status === 204) return undefined as T;

  const text = await res.text();
  const data = text ? JSON.parse(text) : undefined;

  if (!res.ok) {
    const detail =
      (data && (data.detail ?? data.message)) || `Request failed (${res.status})`;
    throw new ApiError(res.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data as T;
}

// --- Auth --------------------------------------------------------------------
export const api = {
  register: (body: {
    email: string;
    password: string;
    role: UserRole;
    tenant_name: string;
  }) => request<TokenPair>("/auth/register", { method: "POST", body }),

  login: (body: { email: string; password: string; tenant_id?: string }) =>
    request<TokenPair>("/auth/login", { method: "POST", body }),

  refresh: (refresh_token: string) =>
    request<AccessToken>("/auth/refresh", { method: "POST", body: { refresh_token } }),

  me: (token: string) => request<User>("/auth/me", { token }),

  // --- Programs (company) ----------------------------------------------------
  listPrograms: (token: string) => request<BountyProgram[]>("/programs", { token }),

  createProgram: (
    token: string,
    body: {
      name: string;
      scope_domains: string[];
      max_severity?: string;
      reward_table?: Record<string, number>;
    },
  ) => request<BountyProgram>("/programs", { method: "POST", body, token }),

  // --- Scans (hacker) --------------------------------------------------------
  listScans: (token: string) => request<ScanJob[]>("/scans", { token }),

  getScan: (token: string, id: string) => request<ScanJob>(`/scans/${id}`, { token }),

  getScanFindings: (token: string, id: string) =>
    request<ScanFinding[]>(`/scans/${id}/findings`, { token }),

  createScan: (
    token: string,
    body: { target_url: string; program_id: string; scan_level: number },
  ) => request<ScanCreated>("/scans", { method: "POST", body, token }),

  // --- Submissions -----------------------------------------------------------
  listSubmissions: (token: string) => request<BountySubmission[]>("/submissions", { token }),

  createSubmission: (token: string, body: { finding_id: string; company_tenant_id: string }) =>
    request<BountySubmission>("/submissions", { method: "POST", body, token }),

  reviewSubmission: (
    token: string,
    id: string,
    body: { status: SubmissionStatus; reward_amount?: string; reason?: string },
  ) => request<BountySubmission>(`/submissions/${id}/review`, { method: "POST", body, token }),

  // --- Payments (company) ----------------------------------------------------
  listPayments: (token: string) => request<Payment[]>("/payments", { token }),

  paySubmission: (
    token: string,
    submissionId: string,
    body: { amount?: string; currency?: string },
  ) =>
    request<PaymentInitiated>(`/payments/submissions/${submissionId}/pay`, {
      method: "POST",
      body,
      token,
    }),
};
