import { computed, ref } from "vue";
import { defineStore } from "pinia";
import { bootstrapAdmin, fetchBootstrapStatus } from "~/services/bootstrap.api";
import * as authApi from "~/services/auth.api";
import type { AccountRole, SessionKind } from "~/services/auth.api";
import {
  onSessionExpired,
  onUnauthorized,
  registerCsrfProvider,
} from "~/services/http.client";

export interface AdminSession {
  adminId: string;
  email: string;
  sessionKind: SessionKind;
  /** True when the password was confirmed within the last ten minutes. */
  recentAuthentication: boolean;
  role: AccountRole;
  lastLoginAt?: string | null;
}

export type BootstrapState = "unknown" | "setupRequired" | "ready";

const CSRF_STORAGE_KEY = "dopbase.csrf";
const CSRF_COOKIE_NAME = "dopbase_csrf";

/**
 * Persist the CSRF token alongside the long-lived HttpOnly session cookie so
 * reopening the desktop app does not leave an authenticated but unusable UI.
 * The token is not a credential on its own; the server stores only its hash.
 */
function restoreCsrf(): string | null {
  try {
    return localStorage.getItem(CSRF_STORAGE_KEY);
  } catch {
    return null;
  }
}

function persistCsrf(token: string | null): void {
  try {
    if (token) localStorage.setItem(CSRF_STORAGE_KEY, token);
    else localStorage.removeItem(CSRF_STORAGE_KEY);
  } catch {
    // Storage is unavailable, so keep the token in memory only.
  }
}

function persistCsrfCookie(token: string | null): void {
  if (typeof document === "undefined") return;
  const secure = location.protocol === "https:" ? "; Secure" : "";
  if (!token) {
    document.cookie = `${CSRF_COOKIE_NAME}=; Path=/; SameSite=Strict; Max-Age=0${secure}`;
    return;
  }
  document.cookie = `${CSRF_COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; SameSite=Strict; Max-Age=2147483647${secure}`;
}

/**
 * Single-admin session state for the whole Admin UI.
 *
 * Owns the browser session object, the CSRF token backing the
 * `X-Dopbase-CSRF` header, and the public bootstrap state that decides
 * whether new visitors land on `/setup` or `/login`. Registering the CSRF
 * provider and session listeners here keeps `services/` store-free.
 */
export const useAuthStore = defineStore("auth", () => {
  const session = ref<AdminSession | null>(null);
  const bootstrapState = ref<BootstrapState>("unknown");
  const csrfToken = ref<string | null>(restoreCsrf());
  const sessionExpired = ref(false);

  registerCsrfProvider(() => csrfToken.value);
  function expireSession(): void {
    session.value = null;
    setCsrf(null);
    sessionExpired.value = true;
  }
  onUnauthorized(expireSession);
  onSessionExpired(expireSession);

  const isAuthenticated = computed(() => session.value !== null);
  const isRoot = computed(() => session.value?.role === "root");
  const isAdmin = computed(
    () => session.value?.role === "root" || session.value?.role === "admin",
  );

  function setCsrf(token: string | null): void {
    csrfToken.value = token;
    persistCsrf(token);
    persistCsrfCookie(token);
  }

  // Mirror the existing browser CSRF token into the WebView cookie jar so
  // the local CLI broker can reuse an already-authenticated desktop session.
  persistCsrfCookie(csrfToken.value);

  /**
   * Resolves the public bootstrap status once. Network failures leave the
   * state `"unknown"` so guards can retry instead of hard-redirecting.
   */
  async function loadBootstrapStatus(): Promise<BootstrapState> {
    try {
      const status = await fetchBootstrapStatus();
      bootstrapState.value =
        status.state === "setupRequired" ? "setupRequired" : "ready";
    } catch {
      bootstrapState.value = "unknown";
    }
    return bootstrapState.value;
  }

  /** Claims an uninitialized server with the one-time setup token. */
  async function bootstrap(request: {
    setupToken: string;
    email: string;
    password: string;
  }): Promise<void> {
    const response = await bootstrapAdmin(request);
    session.value = {
      adminId: response.adminId,
      email: response.email,
      sessionKind: "browser",
      recentAuthentication: true,
      role: response.role ?? "root",
      lastLoginAt: response.lastLoginAt ?? null,
    };
    setCsrf(response.csrfToken);
    sessionExpired.value = false;
    bootstrapState.value = "ready";
  }

  /** Signs in with email + password and stores the browser session. */
  async function login(email: string, password: string): Promise<void> {
    const response = await authApi.login({
      email,
      password,
      sessionKind: "browser",
    });
    session.value = {
      adminId: response.adminId,
      email: response.email,
      sessionKind: response.sessionKind,
      recentAuthentication: true,
      role: response.role ?? "admin",
      lastLoginAt: response.lastLoginAt ?? null,
    };
    if (response.csrfToken) setCsrf(response.csrfToken);
    sessionExpired.value = false;
  }

  /** Re-checks the cookie session and throws ApiError(401) when absent. */
  async function fetchSession(): Promise<void> {
    const response = await authApi.fetchSession();
    session.value = {
      adminId: response.adminId,
      email: response.email,
      sessionKind: response.sessionKind,
      recentAuthentication: response.recentAuthentication,
      role: response.role ?? "admin",
      lastLoginAt: response.lastLoginAt ?? null,
    };
    sessionExpired.value = false;
  }

  /** Revokes the session server-side and clears all local state. */
  async function logout(): Promise<void> {
    try {
      await authApi.logout();
    } finally {
      session.value = null;
      setCsrf(null);
      sessionExpired.value = false;
    }
  }

  function clearLocalSession(): void {
    session.value = null;
    setCsrf(null);
    bootstrapState.value = "unknown";
    sessionExpired.value = false;
  }

  /** Confirms the password, enabling reveal/export for ten minutes. */
  async function reauthenticate(password: string): Promise<void> {
    await authApi.reauthenticate(password);
    if (session.value) {
      session.value = { ...session.value, recentAuthentication: true };
    }
  }

  /**
   * Rotates the password. The server revokes every human session, so the
   * local session and CSRF token are cleared and the admin must sign in
   * again.
   */
  async function changePassword(
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    await authApi.changePassword(currentPassword, newPassword);
    session.value = null;
    setCsrf(null);
    sessionExpired.value = false;
  }

  return {
    session,
    bootstrapState,
    csrfToken,
    sessionExpired,
    isAuthenticated,
    isRoot,
    isAdmin,
    setCsrf,
    loadBootstrapStatus,
    bootstrap,
    login,
    fetchSession,
    logout,
    clearLocalSession,
    reauthenticate,
    changePassword,
  };
});
