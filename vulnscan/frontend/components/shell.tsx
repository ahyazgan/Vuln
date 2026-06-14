"use client";

// Authenticated app shell: top nav (role-aware links) + a guard that redirects
// unauthenticated visitors to /login. Wrap every protected page in <Shell>.

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";
import { useAuth } from "@/lib/auth";
import type { UserRole } from "@/lib/types";

interface NavItem {
  href: string;
  label: string;
  roles: UserRole[];
}

const NAV: NavItem[] = [
  { href: "/dashboard", label: "Dashboard", roles: ["hacker", "company", "admin"] },
  { href: "/scans", label: "Scans", roles: ["hacker", "admin"] },
  { href: "/programs", label: "Programs", roles: ["company", "admin"] },
  { href: "/submissions", label: "Submissions", roles: ["hacker", "company"] },
  { href: "/payments", label: "Payments", roles: ["company", "admin"] },
  { href: "/admin", label: "Admin", roles: ["admin"] },
];

export function Shell({ children }: { children: React.ReactNode }) {
  const { user, loading, logout } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (!loading && !user) router.replace("/login");
  }, [loading, user, router]);

  if (loading) return <div className="center-screen muted">Loading…</div>;
  if (!user) return null;

  const links = NAV.filter((n) => n.roles.includes(user.role));

  return (
    <>
      <nav className="nav">
        <div className="nav-inner">
          <Link href="/dashboard" className="brand">
            Vuln<span>Scan</span> AI
          </Link>
          {links.map((n) => (
            <Link
              key={n.href}
              href={n.href}
              className={pathname.startsWith(n.href) ? "active" : ""}
            >
              {n.label}
            </Link>
          ))}
          <div className="nav-spacer" />
          <span className="nav-user">
            {user.email} · {user.role}
          </span>
          <button
            className="btn secondary small"
            onClick={() => {
              logout();
              router.replace("/login");
            }}
          >
            Sign out
          </button>
        </div>
      </nav>
      <div className="container">{children}</div>
    </>
  );
}
