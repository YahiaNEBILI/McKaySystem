"use client";

import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

import { ApiError } from "@/lib/api/client";
import { getStoredScope } from "@/lib/scope";
import { useAuth } from "@/hooks/useAuth";

function loginErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    const code = error.code ? ` (${error.code})` : "";
    return `Login failed [${error.status}${code}]: ${error.message}`;
  }
  if (error instanceof Error) {
    return `Login failed: ${error.message}`;
  }
  return "Login failed.";
}

export default function LoginPage() {
  const router = useRouter();
  const { login, isLoading } = useAuth();
  const savedScope = getStoredScope();
  const [tenantId, setTenantId] = useState(savedScope?.tenantId ?? "");
  const [workspace, setWorkspace] = useState(savedScope?.workspace ?? "");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitError(null);
    setIsSubmitting(true);
    try {
      await login({
        tenantId,
        workspace,
        email,
        password,
      });
      router.push("/findings");
    } catch (error) {
      setSubmitError(loginErrorMessage(error));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <main className="login-shell relative overflow-hidden">
      <div className="login-orb login-orb--one" />
      <div className="login-orb login-orb--two" />
      <div className="login-orb login-orb--three" />

      <div className="relative z-10 mx-auto grid min-h-screen w-full max-w-6xl items-center gap-8 px-6 py-10 lg:grid-cols-[1.08fr_0.92fr]">
        <section className="login-reveal text-white">
          <p className="mb-3 inline-flex items-center rounded-full border border-cyan-300/35 bg-cyan-300/10 px-3 py-1 text-xs uppercase tracking-[0.24em] text-cyan-100">
            McKay System 1.0
          </p>
          <h1 className="max-w-xl text-4xl font-semibold leading-tight md:text-5xl">
            SaaS FinOps Platform, in real time.
          </h1>
          <p className="mt-4 max-w-lg text-sm text-cyan-100/85 md:text-base">
            Detect waste, enforce policy, and execute remediations with deterministic,
            tenant-safe operations.
          </p>

          <div className="mt-8 grid max-w-lg gap-3 sm:grid-cols-2">
            <article className="rounded-lg border border-white/20 bg-white/8 p-3 backdrop-blur-sm">
              <p className="text-xs uppercase tracking-[0.22em] text-cyan-100/90">Detect</p>
              <p className="mt-2 text-2xl font-semibold">Scans AWS assets & cost signals</p>
              <p className="mt-1 text-xs text-cyan-100/80">Produces consistent, explainable findings</p>
            </article>
            <article className="rounded-lg border border-white/20 bg-white/8 p-3 backdrop-blur-sm">
              <p className="text-xs uppercase tracking-[0.22em] text-cyan-100/90">Prioritize</p>
              <p className="mt-2 text-2xl font-semibold">Correlates & ranks by impact & risk</p>
              <p className="mt-1 text-xs text-cyan-100/80">Provide the tool you need for FinOps</p>
            </article>
            <article className="rounded-lg border border-white/20 bg-white/8 p-3 backdrop-blur-sm sm:col-span-2">
              <p className="text-xs uppercase tracking-[0.22em] text-cyan-100/90">Governance & Audit</p>
              <p className="mt-2 text-sm text-cyan-50/95">
                Ownership routing, SLA aging, audit trail (immutable findings + state history) — built for real ops teams
              </p>
            </article>
          </div>
        </section>

        <form className="login-panel login-reveal w-full rounded-2xl p-7 md:p-8" onSubmit={handleSubmit}>
          <div>
            <h2 className="text-2xl font-semibold text-slate-900">Sign in</h2>
            <p className="mt-1 text-sm text-slate-600">
              Enter your tenant/workspace and account credentials.
            </p>
          </div>

          <div className="mt-6 space-y-4">
            <label className="block text-sm">
              <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">
                Tenant ID
              </span>
              <input
                className="w-full rounded-md border border-slate-300 bg-white px-3 py-2.5 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
                value={tenantId}
                onChange={(event) => setTenantId(event.target.value)}
                autoComplete="organization"
                required
              />
            </label>
            <label className="block text-sm">
              <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">
                Workspace
              </span>
              <input
                className="w-full rounded-md border border-slate-300 bg-white px-3 py-2.5 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
                value={workspace}
                onChange={(event) => setWorkspace(event.target.value)}
                autoComplete="off"
                required
              />
            </label>
            <label className="block text-sm">
              <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">
                Email
              </span>
              <input
                className="w-full rounded-md border border-slate-300 bg-white px-3 py-2.5 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                autoComplete="username"
                required
              />
            </label>
            <label className="block text-sm">
              <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">
                Password
              </span>
              <input
                className="w-full rounded-md border border-slate-300 bg-white px-3 py-2.5 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
                required
              />
            </label>
          </div>

          {submitError ? (
            <p className="mt-4 rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700">
              {submitError}
            </p>
          ) : null}

          <button
            type="submit"
            className="mt-5 w-full rounded-md bg-gradient-to-r from-cyan-500 to-sky-600 px-3 py-2.5 text-sm font-semibold text-white shadow-lg shadow-cyan-900/20 transition hover:brightness-105 disabled:opacity-50"
            disabled={isSubmitting || isLoading}
          >
            {isSubmitting ? "Signing in..." : "Sign in"}
          </button>

          <p className="mt-3 text-xs text-slate-500">
            Secure session cookie authentication with scoped tenant/workspace validation.
          </p>
        </form>
      </div>
    </main>
  );
}
