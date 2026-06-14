"use client";

// Client-side auth context: holds the JWT pair + current user, persists tokens
// to localStorage, and exposes login / register / logout. On a 401 the access
// token is silently refreshed once using the refresh token before giving up.

import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { api, ApiError } from "./api";
import type { User, UserRole } from "./types";

const ACCESS_KEY = "vulnscan.access";
const REFRESH_KEY = "vulnscan.refresh";

interface AuthState {
  user: User | null;
  token: string | null;
  loading: boolean;
  login: (email: string, password: string, tenantId?: string) => Promise<void>;
  register: (
    email: string,
    password: string,
    role: UserRole,
    tenantName: string,
  ) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Restore a session from localStorage on first mount.
  useEffect(() => {
    const access = localStorage.getItem(ACCESS_KEY);
    const refresh = localStorage.getItem(REFRESH_KEY);
    if (!access) {
      setLoading(false);
      return;
    }
    (async () => {
      try {
        const me = await api.me(access);
        setUser(me);
        setToken(access);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401 && refresh) {
          try {
            const refreshed = await api.refresh(refresh);
            const me = await api.me(refreshed.access_token);
            localStorage.setItem(ACCESS_KEY, refreshed.access_token);
            setUser(me);
            setToken(refreshed.access_token);
          } catch {
            clearSession();
          }
        } else {
          clearSession();
        }
      } finally {
        setLoading(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function clearSession() {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
    setUser(null);
    setToken(null);
  }

  async function persistAndLoad(access: string, refresh: string) {
    localStorage.setItem(ACCESS_KEY, access);
    localStorage.setItem(REFRESH_KEY, refresh);
    const me = await api.me(access);
    setUser(me);
    setToken(access);
  }

  async function login(email: string, password: string, tenantId?: string) {
    const tokens = await api.login({ email, password, tenant_id: tenantId });
    await persistAndLoad(tokens.access_token, tokens.refresh_token);
  }

  async function register(
    email: string,
    password: string,
    role: UserRole,
    tenantName: string,
  ) {
    const tokens = await api.register({ email, password, role, tenant_name: tenantName });
    await persistAndLoad(tokens.access_token, tokens.refresh_token);
  }

  function logout() {
    clearSession();
  }

  const value = useMemo<AuthState>(
    () => ({ user, token, loading, login, register, logout }),
    // login/register/logout are stable closures over setState; only state drives value.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [user, token, loading],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
