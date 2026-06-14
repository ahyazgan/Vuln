// Shared types mirroring the VulnScan AI backend schemas (vulnscan/domain/schemas.py).

export type UserRole = "hacker" | "company" | "admin";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ScanStatus = "queued" | "running" | "completed" | "failed";

export type SubmissionStatus = "pending" | "accepted" | "rejected" | "paid";

export type PaymentStatus = "pending" | "succeeded" | "failed" | "refunded";

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface AccessToken {
  access_token: string;
  token_type: string;
}

export interface User {
  id: string;
  tenant_id: string;
  email: string;
  role: UserRole;
  created_at: string;
  updated_at: string;
}

export interface BountyProgram {
  id: string;
  tenant_id: string;
  name: string;
  scope_domains: string[];
  max_severity: Severity;
  reward_table: Record<string, number>;
  is_active: boolean;
  created_at: string;
}

export interface ScanJob {
  id: string;
  tenant_id: string;
  user_id: string;
  program_id: string | null;
  target_url: string;
  scan_level: number;
  status: ScanStatus;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  created_at: string;
}

export interface ScanFinding {
  id: string;
  tenant_id: string;
  scan_job_id: string;
  title: string;
  severity: Severity;
  cvss_score: number;
  description: string;
  proof_of_concept: string | null;
  recommendation: string | null;
  references: string[];
  is_chained: boolean;
  chain_parent_ids: string[];
  created_at: string;
}

export interface ScanCreated {
  scan_id: string;
  status: ScanStatus;
}

export interface BountySubmission {
  id: string;
  tenant_id: string;
  finding_id: string;
  hacker_user_id: string;
  company_tenant_id: string;
  status: SubmissionStatus;
  reward_amount: string | null;
  submitted_at: string;
  reviewed_at: string | null;
}

export interface Payment {
  id: string;
  tenant_id: string;
  submission_id: string;
  amount: string;
  currency: string;
  status: PaymentStatus;
  provider: string;
  provider_payment_id: string | null;
  error_message: string | null;
  created_at: string;
}

export interface PaymentInitiated extends Payment {
  client_secret: string | null;
}
