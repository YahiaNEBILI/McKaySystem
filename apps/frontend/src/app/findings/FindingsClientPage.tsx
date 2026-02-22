"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";

import { useAuth } from "@/hooks/useAuth";
import { useFindingLifecycle } from "@/hooks/useFindingLifecycle";
import { FindingItem, findingsQueryKey, useFindings } from "@/hooks/useFindings";
import { ApiError } from "@/lib/api/client";
import { getStoredScope } from "@/lib/scope";

function formatMoney(value: number | null): string {
  if (value === null || Number.isNaN(value)) {
    return "-";
  }
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 2,
  }).format(value);
}

function findingsErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    const code = error.code ? ` (${error.code})` : "";
    return `Failed to load findings [${error.status}${code}]: ${error.message}`;
  }
  if (error instanceof Error) {
    return `Failed to load findings: ${error.message}`;
  }
  return "Failed to load findings.";
}

function parsePositiveInt(value: string | null, fallback: number): number {
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return fallback;
  }
  return parsed;
}

function formatDateTime(value: string | null): string {
  if (!value) {
    return "-";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
}

function lifecycleErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    const code = error.code ? ` (${error.code})` : "";
    return `Action failed [${error.status}${code}]: ${error.message}`;
  }
  if (error instanceof Error) {
    return `Action failed: ${error.message}`;
  }
  return "Action failed.";
}

export function FindingsClientPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const scope = getStoredScope();
  const auth = useAuth();
  const stateFilter = searchParams.get("state") ?? "";
  const severityFilter = searchParams.get("severity") ?? "";
  const orderFilter =
    searchParams.get("order") === "detected_desc"
      ? "detected_desc"
      : "savings_desc";
  const queryFilter = searchParams.get("q") ?? "";
  const limitFilter = parsePositiveInt(searchParams.get("limit"), 50);
  const page = parsePositiveInt(searchParams.get("page"), 1);
  const offset = (page - 1) * limitFilter;
  const [searchInput, setSearchInput] = useState(queryFilter);
  const [selectedFingerprint, setSelectedFingerprint] = useState<string | null>(null);
  const [actionReason, setActionReason] = useState("");
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    setSearchInput(queryFilter);
  }, [queryFilter]);

  const queryKey = findingsQueryKey(
    { tenantId: scope?.tenantId, workspace: scope?.workspace },
    {
      limit: limitFilter,
      offset,
      state: stateFilter,
      severity: severityFilter,
      q: queryFilter,
      order: orderFilter,
    },
  );

  const findings = useFindings({
    limit: limitFilter,
    offset,
    state: stateFilter,
    severity: severityFilter,
    order: orderFilter,
    q: queryFilter,
  });
  const lifecycle = useFindingLifecycle({ queryKey });

  useEffect(() => {
    if (!scope) {
      router.replace("/login");
      return;
    }
    if (!auth.isLoading && !auth.isAuthenticated) {
      router.replace("/login");
    }
  }, [auth.isAuthenticated, auth.isLoading, router, scope]);

  useEffect(() => {
    if (!selectedFingerprint) {
      return;
    }
    const exists = findings.data?.items.some((item) => item.fingerprint === selectedFingerprint);
    if (!exists) {
      setSelectedFingerprint(null);
      setActionReason("");
      setActionError(null);
      setActionFeedback(null);
    }
  }, [findings.data?.items, selectedFingerprint]);

  if (!scope) {
    return null;
  }

  const activeScope = scope;
  const selectedFinding =
    findings.data?.items.find((item) => item.fingerprint === selectedFingerprint) ?? null;
  const permissions = new Set(auth.user?.permissions ?? []);
  const canTriage = permissions.has("admin:full") || permissions.has("findings:update");
  const total = findings.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / limitFilter));
  const canPrev = page > 1;
  const canNext = page < totalPages;
  const pageStart = total === 0 ? 0 : offset + 1;
  const pageEnd = total === 0 ? 0 : Math.min(offset + (findings.data?.items.length ?? 0), total);

  function pushWithParams(updates: Record<string, string | null>) {
    const params = new URLSearchParams(searchParams.toString());
    for (const [key, value] of Object.entries(updates)) {
      if (!value) {
        params.delete(key);
      } else {
        params.set(key, value);
      }
    }
    const query = params.toString();
    router.push(query ? `/findings?${query}` : "/findings");
  }

  function setPage(nextPage: number) {
    const safePage = String(Math.max(1, nextPage));
    pushWithParams({ page: safePage });
  }

  async function runAction(
    input: { action: "ignore" | "resolve"; label: string } | { action: "snooze"; label: string; snoozeDays: 7 | 14 | 30 },
  ) {
    if (!selectedFinding || !canTriage) {
      return;
    }
    setActionError(null);
    setActionFeedback(null);
    try {
      await lifecycle.mutateAsync({
        action: input.action,
        fingerprint: selectedFinding.fingerprint,
        reason: actionReason.trim() || undefined,
        snoozeDays: input.action === "snooze" ? input.snoozeDays : undefined,
        tenantId: activeScope.tenantId,
        workspace: activeScope.workspace,
        updatedBy: auth.user?.email || auth.user?.user_id || undefined,
      });
      setActionFeedback(
        input.action === "snooze"
          ? `Finding snoozed for ${input.snoozeDays} days.`
          : `Finding set to ${input.label.toLowerCase()}.`,
      );
    } catch (error) {
      setActionError(lifecycleErrorMessage(error));
    }
  }

  function openFinding(item: FindingItem) {
    setSelectedFingerprint(item.fingerprint);
    setActionReason(item.reason ?? "");
    setActionError(null);
    setActionFeedback(null);
  }

  return (
    <main className="mx-auto min-h-screen w-full max-w-6xl px-6 py-8">
      <header className="mb-6 flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Findings</h1>
          <p className="text-sm text-zinc-600">
            Tenant: <span className="font-medium">{activeScope.tenantId}</span> | Workspace:{" "}
            <span className="font-medium">{activeScope.workspace}</span>
          </p>
        </div>
        <button
          type="button"
          className="rounded border border-zinc-300 px-3 py-2 text-sm"
          onClick={async () => {
            await auth.logout();
            router.push("/login");
          }}
        >
          Logout
        </button>
      </header>

      <section className="mb-4 rounded border border-zinc-200 bg-zinc-50 p-3 text-sm">
        <div className="grid gap-3 md:grid-cols-5">
          <label className="block">
            <span className="mb-1 block text-xs font-medium uppercase text-zinc-600">State</span>
            <select
              className="w-full rounded border border-zinc-300 bg-white px-2 py-1.5"
              value={stateFilter}
              onChange={(event) => {
                pushWithParams({ state: event.target.value || null, page: "1" });
              }}
            >
              <option value="">All</option>
              <option value="open">Open</option>
              <option value="snoozed">Snoozed</option>
              <option value="resolved">Resolved</option>
              <option value="ignored">Ignored</option>
            </select>
          </label>

          <label className="block">
            <span className="mb-1 block text-xs font-medium uppercase text-zinc-600">Severity</span>
            <select
              className="w-full rounded border border-zinc-300 bg-white px-2 py-1.5"
              value={severityFilter}
              onChange={(event) => {
                pushWithParams({ severity: event.target.value || null, page: "1" });
              }}
            >
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </label>

          <label className="block">
            <span className="mb-1 block text-xs font-medium uppercase text-zinc-600">Sort</span>
            <select
              className="w-full rounded border border-zinc-300 bg-white px-2 py-1.5"
              value={orderFilter}
              onChange={(event) => {
                pushWithParams({ order: event.target.value || null, page: "1" });
              }}
            >
              <option value="savings_desc">Savings desc</option>
              <option value="detected_desc">Detected desc</option>
            </select>
          </label>

          <label className="block">
            <span className="mb-1 block text-xs font-medium uppercase text-zinc-600">Page size</span>
            <select
              className="w-full rounded border border-zinc-300 bg-white px-2 py-1.5"
              value={String(limitFilter)}
              onChange={(event) => {
                pushWithParams({
                  limit: event.target.value,
                  page: "1",
                });
              }}
            >
              <option value="25">25</option>
              <option value="50">50</option>
              <option value="100">100</option>
            </select>
          </label>

          <form
            className="block"
            onSubmit={(event) => {
              event.preventDefault();
              pushWithParams({ q: searchInput.trim() || null, page: "1" });
            }}
          >
            <span className="mb-1 block text-xs font-medium uppercase text-zinc-600">Search</span>
            <div className="flex gap-2">
              <input
                className="w-full rounded border border-zinc-300 px-2 py-1.5"
                value={searchInput}
                onChange={(event) => {
                  setSearchInput(event.target.value);
                }}
                placeholder="Title contains..."
              />
              <button
                type="submit"
                className="rounded border border-zinc-300 bg-white px-2 py-1.5 text-xs"
              >
                Apply
              </button>
            </div>
          </form>
        </div>
      </section>

      {findings.isLoading ? <p>Loading findings...</p> : null}
      {findings.error ? (
        <div className="mb-4 rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          <p>{findingsErrorMessage(findings.error)}</p>
          <button
            type="button"
            className="mt-2 rounded border border-red-300 px-2 py-1 text-xs"
            onClick={() => {
              void findings.refetch();
            }}
          >
            Retry
          </button>
        </div>
      ) : null}

      {!findings.isLoading && findings.data ? (
        <>
          <div className="overflow-x-auto rounded border border-zinc-200">
            <table className="min-w-full text-left text-sm">
              <thead className="bg-zinc-50 text-xs uppercase tracking-wide text-zinc-600">
                <tr>
                  <th className="px-3 py-2">Severity</th>
                  <th className="px-3 py-2">Service</th>
                  <th className="px-3 py-2">Title</th>
                  <th className="px-3 py-2">Savings</th>
                  <th className="px-3 py-2">State</th>
                  <th className="px-3 py-2">Region</th>
                </tr>
              </thead>
              <tbody>
                {findings.data.items.map((item) => (
                  <tr
                    key={item.fingerprint}
                    className={`border-t border-zinc-100 ${selectedFingerprint === item.fingerprint ? "bg-cyan-50" : ""}`}
                  >
                    <td className="px-3 py-2">{item.severity}</td>
                    <td className="px-3 py-2">{item.service}</td>
                    <td className="px-3 py-2">
                      <button
                        type="button"
                        className="text-left text-cyan-700 underline-offset-2 hover:underline"
                        onClick={() => {
                          openFinding(item);
                        }}
                      >
                        {item.title}
                      </button>
                    </td>
                    <td className="px-3 py-2">{formatMoney(item.estimated_monthly_savings)}</td>
                    <td className="px-3 py-2">{item.effective_state}</td>
                    <td className="px-3 py-2">{item.region ?? "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {findings.data.items.length === 0 ? (
            <p className="mt-3 text-sm text-zinc-600">No findings match the current filters.</p>
          ) : null}

          <div className="mt-4 flex items-center justify-between text-sm">
            <p className="text-zinc-600">
              Showing {pageStart}-{pageEnd} of {total}
            </p>
            <div className="flex items-center gap-2">
              <button
                type="button"
                className="rounded border border-zinc-300 px-2 py-1 disabled:opacity-50"
                onClick={() => {
                  setPage(page - 1);
                }}
                disabled={!canPrev}
              >
                Previous
              </button>
              <span className="text-zinc-700">
                Page {page} / {totalPages}
              </span>
              <button
                type="button"
                className="rounded border border-zinc-300 px-2 py-1 disabled:opacity-50"
                onClick={() => {
                  setPage(page + 1);
                }}
                disabled={!canNext}
              >
                Next
              </button>
            </div>
          </div>
        </>
      ) : null}

      {selectedFinding ? (
        <div className="fixed inset-0 z-50 flex">
          <button
            type="button"
            className="h-full flex-1 bg-black/40"
            aria-label="Close detail drawer"
            onClick={() => {
              setSelectedFingerprint(null);
              setActionError(null);
              setActionFeedback(null);
            }}
          />
          <aside className="h-full w-full max-w-2xl overflow-y-auto border-l border-zinc-200 bg-white p-6 shadow-2xl">
            <div className="mb-4 flex items-start justify-between gap-4">
              <div>
                <h2 className="text-xl font-semibold">{selectedFinding.title}</h2>
                <p className="mt-1 text-xs text-zinc-600">{selectedFinding.fingerprint}</p>
              </div>
              <button
                type="button"
                className="rounded border border-zinc-300 px-2 py-1 text-xs"
                onClick={() => {
                  setSelectedFingerprint(null);
                  setActionError(null);
                  setActionFeedback(null);
                }}
              >
                Close
              </button>
            </div>

            <div className="grid gap-3 text-sm md:grid-cols-2">
              <p><span className="font-medium">Check:</span> {selectedFinding.check_id}</p>
              <p><span className="font-medium">Category:</span> {selectedFinding.category ?? "-"}</p>
              <p><span className="font-medium">Service:</span> {selectedFinding.service}</p>
              <p><span className="font-medium">Severity:</span> {selectedFinding.severity}</p>
              <p><span className="font-medium">State:</span> {selectedFinding.effective_state}</p>
              <p><span className="font-medium">Savings:</span> {formatMoney(selectedFinding.estimated_monthly_savings)}</p>
              <p><span className="font-medium">Account:</span> {selectedFinding.account_id ?? "-"}</p>
              <p><span className="font-medium">Region:</span> {selectedFinding.region ?? "-"}</p>
              <p><span className="font-medium">Detected:</span> {formatDateTime(selectedFinding.detected_at)}</p>
              <p><span className="font-medium">Opened:</span> {formatDateTime(selectedFinding.first_opened_at)}</p>
              <p><span className="font-medium">Snooze Until:</span> {formatDateTime(selectedFinding.snooze_until)}</p>
              <p><span className="font-medium">Owner:</span> {selectedFinding.owner_email ?? "-"}</p>
            </div>

            <section className="mt-5 rounded border border-zinc-200 bg-zinc-50 p-3">
              <h3 className="text-sm font-semibold">Lifecycle Actions</h3>
              <p className="mt-1 text-xs text-zinc-600">
                {canTriage
                  ? "State updates are applied optimistically and synced with backend."
                  : "Missing permission: findings:update"}
              </p>

              <label className="mt-3 block text-xs font-medium uppercase tracking-wide text-zinc-600">
                Reason (optional)
                <textarea
                  className="mt-1 h-20 w-full rounded border border-zinc-300 bg-white px-2 py-1.5 text-sm"
                  value={actionReason}
                  onChange={(event) => {
                    setActionReason(event.target.value);
                  }}
                  disabled={!canTriage || lifecycle.isPending}
                />
              </label>

              {actionError ? (
                <p className="mt-2 rounded border border-red-300 bg-red-50 px-2 py-1 text-xs text-red-700">
                  {actionError}
                </p>
              ) : null}
              {actionFeedback ? (
                <p className="mt-2 rounded border border-emerald-300 bg-emerald-50 px-2 py-1 text-xs text-emerald-700">
                  {actionFeedback}
                </p>
              ) : null}

              <div className="mt-3 flex flex-wrap gap-2">
                <button
                  type="button"
                  className="rounded border border-zinc-300 bg-white px-3 py-1.5 text-xs disabled:opacity-50"
                  disabled={!canTriage || lifecycle.isPending}
                  onClick={() => {
                    void runAction({ action: "resolve", label: "Resolved" });
                  }}
                >
                  Resolve
                </button>
                <button
                  type="button"
                  className="rounded border border-zinc-300 bg-white px-3 py-1.5 text-xs disabled:opacity-50"
                  disabled={!canTriage || lifecycle.isPending}
                  onClick={() => {
                    void runAction({ action: "ignore", label: "Ignored" });
                  }}
                >
                  Ignore
                </button>
                <button
                  type="button"
                  className="rounded border border-zinc-300 bg-white px-3 py-1.5 text-xs disabled:opacity-50"
                  disabled={!canTriage || lifecycle.isPending}
                  onClick={() => {
                    void runAction({ action: "snooze", label: "Snoozed", snoozeDays: 7 });
                  }}
                >
                  Snooze 7d
                </button>
                <button
                  type="button"
                  className="rounded border border-zinc-300 bg-white px-3 py-1.5 text-xs disabled:opacity-50"
                  disabled={!canTriage || lifecycle.isPending}
                  onClick={() => {
                    void runAction({ action: "snooze", label: "Snoozed", snoozeDays: 14 });
                  }}
                >
                  Snooze 14d
                </button>
                <button
                  type="button"
                  className="rounded border border-zinc-300 bg-white px-3 py-1.5 text-xs disabled:opacity-50"
                  disabled={!canTriage || lifecycle.isPending}
                  onClick={() => {
                    void runAction({ action: "snooze", label: "Snoozed", snoozeDays: 30 });
                  }}
                >
                  Snooze 30d
                </button>
              </div>
            </section>

            <section className="mt-5">
              <h3 className="mb-2 text-sm font-semibold">Raw Payload</h3>
              <pre className="max-h-72 overflow-auto rounded border border-zinc-200 bg-zinc-950 p-3 text-xs text-zinc-100">
                {JSON.stringify(selectedFinding.payload ?? {}, null, 2)}
              </pre>
            </section>
          </aside>
        </div>
      ) : null}
    </main>
  );
}
