"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

import { useAuth } from "@/hooks/useAuth";
import { RecommendationItem, useRecommendations } from "@/hooks/useRecommendations";
import { ApiError } from "@/lib/api/client";
import { getStoredScope } from "@/lib/scope";

const ALL_STATE_FILTER = "open,snoozed,resolved,ignored";

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

function parseNonNegativeFloat(value: string | null): number | null {
  if (!value) {
    return null;
  }
  const parsed = Number.parseFloat(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return null;
  }
  return parsed;
}

function recommendationsErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    const code = error.code ? ` (${error.code})` : "";
    return `Failed to load recommendations [${error.status}${code}]: ${error.message}`;
  }
  if (error instanceof Error) {
    return `Failed to load recommendations: ${error.message}`;
  }
  return "Failed to load recommendations.";
}

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

function priorityBadgeClass(priority: string): string {
  const key = priority.trim().toLowerCase();
  if (key === "p1") {
    return "border-red-300 bg-red-50 text-red-800";
  }
  if (key === "p2") {
    return "border-amber-300 bg-amber-50 text-amber-800";
  }
  return "border-zinc-300 bg-zinc-100 text-zinc-700";
}

function confidenceBadgeClass(label: string): string {
  const key = label.trim().toLowerCase();
  if (key === "high") {
    return "border-emerald-300 bg-emerald-50 text-emerald-800";
  }
  if (key === "medium") {
    return "border-amber-300 bg-amber-50 text-amber-800";
  }
  return "border-zinc-300 bg-zinc-100 text-zinc-700";
}

function stateBadgeClass(value: string): string {
  const key = value.trim().toLowerCase();
  if (key === "open") {
    return "border-cyan-300 bg-cyan-50 text-cyan-800";
  }
  if (key === "snoozed") {
    return "border-amber-300 bg-amber-50 text-amber-800";
  }
  if (key === "resolved") {
    return "border-emerald-300 bg-emerald-50 text-emerald-800";
  }
  if (key === "ignored") {
    return "border-zinc-300 bg-zinc-100 text-zinc-700";
  }
  return "border-zinc-300 bg-zinc-100 text-zinc-700";
}

export function RecommendationsClientPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const scope = getStoredScope();
  const auth = useAuth();
  const stateFilter = searchParams.get("state")?.trim() || "open";
  const severityFilter = searchParams.get("severity") ?? "";
  const orderFilter = searchParams.get("order") === "detected_desc" ? "detected_desc" : "savings_desc";
  const serviceFilter = searchParams.get("service") ?? "";
  const checkIdFilter = searchParams.get("check_id") ?? "";
  const queryFilter = searchParams.get("q") ?? "";
  const minSavingsRaw = searchParams.get("min_savings") ?? "";
  const minSavingsFilter = parseNonNegativeFloat(minSavingsRaw);
  const limitFilter = parsePositiveInt(searchParams.get("limit"), 50);
  const page = parsePositiveInt(searchParams.get("page"), 1);
  const offset = (page - 1) * limitFilter;
  const [searchInput, setSearchInput] = useState(queryFilter);
  const [serviceInput, setServiceInput] = useState(serviceFilter);
  const [checkIdInput, setCheckIdInput] = useState(checkIdFilter);
  const [minSavingsInput, setMinSavingsInput] = useState(minSavingsRaw);
  const [selectedFingerprint, setSelectedFingerprint] = useState<string | null>(null);

  useEffect(() => {
    setSearchInput(queryFilter);
  }, [queryFilter]);

  useEffect(() => {
    setServiceInput(serviceFilter);
  }, [serviceFilter]);

  useEffect(() => {
    setCheckIdInput(checkIdFilter);
  }, [checkIdFilter]);

  useEffect(() => {
    setMinSavingsInput(minSavingsRaw);
  }, [minSavingsRaw]);

  const recommendations = useRecommendations({
    limit: limitFilter,
    offset,
    state: stateFilter,
    severity: severityFilter,
    service: serviceFilter,
    checkId: checkIdFilter,
    q: queryFilter,
    minSavings: minSavingsFilter,
    order: orderFilter,
  });

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
    const exists = recommendations.data?.items.some((item) => item.fingerprint === selectedFingerprint);
    if (!exists) {
      setSelectedFingerprint(null);
    }
  }, [recommendations.data?.items, selectedFingerprint]);

  const permissions = useMemo(() => new Set(auth.user?.permissions ?? []), [auth.user?.permissions]);
  const canReadUsers = permissions.has("admin:full") || permissions.has("users:read");
  const canReadFindings = permissions.has("admin:full") || permissions.has("findings:read");

  if (!scope) {
    return null;
  }

  const activeScope = scope;
  const selectedRecommendation =
    recommendations.data?.items.find((item) => item.fingerprint === selectedFingerprint) ?? null;
  const total = recommendations.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / limitFilter));
  const canPrev = page > 1;
  const canNext = page < totalPages;
  const pageStart = total === 0 ? 0 : offset + 1;
  const pageEnd = total === 0 ? 0 : Math.min(offset + (recommendations.data?.items.length ?? 0), total);
  const pageSavings = (recommendations.data?.items ?? []).reduce(
    (acc, item) => acc + (item.estimated_monthly_savings ?? 0),
    0,
  );
  const approvalRequiredCount = (recommendations.data?.items ?? []).filter(
    (item) => item.requires_approval,
  ).length;

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
    router.push(query ? `/recommendations?${query}` : "/recommendations");
  }

  function applySearchFilters() {
    const nextMinSavings = parseNonNegativeFloat(minSavingsInput);
    pushWithParams({
      q: searchInput.trim() || null,
      service: serviceInput.trim() || null,
      check_id: checkIdInput.trim() || null,
      min_savings: nextMinSavings === null ? null : String(nextMinSavings),
      page: "1",
    });
  }

  function openRecommendation(item: RecommendationItem) {
    setSelectedFingerprint(item.fingerprint);
  }

  return (
    <main className="finops-shell relative overflow-hidden">
      <div className="finops-orb finops-orb--one" />
      <div className="finops-orb finops-orb--two" />
      <div className="finops-orb finops-orb--three" />

      <div className="relative z-10 mx-auto min-h-screen w-full max-w-7xl px-6 py-6">
      <header className="finops-panel mb-4 flex flex-wrap items-start justify-between gap-3 rounded-2xl p-4">
        <div>
          <p className="inline-flex rounded-full border border-cyan-300/70 bg-cyan-50 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-cyan-700">
            FinOps Actions
          </p>
          <h1 className="font-display mt-2 text-2xl font-semibold tracking-tight text-slate-900 md:text-3xl">
            Recommendations Studio
          </h1>
          <p className="mt-1 text-sm text-slate-600">
            Tenant: <span className="font-medium">{activeScope.tenantId}</span> | Workspace:{" "}
            <span className="font-medium">{activeScope.workspace}</span>
          </p>
        </div>
        <div className="flex items-center gap-2 self-start">
          {canReadFindings ? (
            <button
              type="button"
              className="finops-toolbar-btn rounded-lg px-3 py-2 text-sm font-medium transition"
              onClick={() => {
                router.push("/findings");
              }}
            >
              Findings
            </button>
          ) : null}
          {canReadUsers ? (
            <button
              type="button"
              className="finops-toolbar-btn rounded-lg px-3 py-2 text-sm font-medium transition"
              onClick={() => {
                router.push("/users");
              }}
            >
              Users
            </button>
          ) : null}
          <button
            type="button"
            className="rounded-lg border border-rose-300 bg-rose-50 px-3 py-2 text-sm font-medium text-rose-700 transition hover:border-rose-400 hover:bg-rose-100"
            onClick={async () => {
              await auth.logout();
              router.push("/login");
            }}
          >
            Logout
          </button>
        </div>
      </header>

      <section className="mb-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        <article className="rounded-xl border border-cyan-300/35 bg-slate-900/45 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-100/85">Total</p>
          <p className="font-display mt-1 text-2xl font-semibold text-white">{total}</p>
        </article>
        <article className="rounded-xl border border-cyan-300/35 bg-slate-900/45 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-100/85">Current Page</p>
          <p className="font-display mt-1 text-2xl font-semibold text-white">{pageStart}-{pageEnd}</p>
        </article>
        <article className="rounded-xl border border-cyan-300/35 bg-slate-900/45 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-100/85">Page Savings</p>
          <p className="font-display mt-1 text-2xl font-semibold text-white">{formatMoney(pageSavings)}</p>
        </article>
        <article className="rounded-xl border border-cyan-300/35 bg-slate-900/45 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-100/85">Needs Approval</p>
          <p className="font-display mt-1 text-2xl font-semibold text-white">{approvalRequiredCount}</p>
        </article>
      </section>

      <section className="finops-panel mb-3 rounded-2xl p-4 text-sm">
        <div className="grid gap-3 md:grid-cols-4">
          <label className="block">
            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">State</span>
            <select
              className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
              value={stateFilter}
              onChange={(event) => {
                pushWithParams({ state: event.target.value, page: "1" });
              }}
            >
              <option value="open">Open</option>
              <option value={ALL_STATE_FILTER}>All states</option>
              <option value="snoozed">Snoozed</option>
              <option value="resolved">Resolved</option>
              <option value="ignored">Ignored</option>
            </select>
          </label>

          <label className="block">
            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">Severity</span>
            <select
              className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
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
            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">Sort</span>
            <select
              className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
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
            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">Page size</span>
            <select
              className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
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
        </div>

        <form
          className="mt-3 grid gap-3 md:grid-cols-4"
          onSubmit={(event) => {
            event.preventDefault();
            applySearchFilters();
          }}
        >
          <label className="block">
            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">Search title</span>
            <input
              className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
              value={searchInput}
              onChange={(event) => {
                setSearchInput(event.target.value);
              }}
              placeholder="Find title..."
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">Service</span>
            <input
              className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
              value={serviceInput}
              onChange={(event) => {
                setServiceInput(event.target.value);
              }}
              placeholder="ec2, rds, s3..."
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">Check ID</span>
            <input
              className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
              value={checkIdInput}
              onChange={(event) => {
                setCheckIdInput(event.target.value);
              }}
              placeholder="aws.ec2..."
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium uppercase text-zinc-600">
              Min monthly savings
            </span>
            <input
              className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
              inputMode="decimal"
              value={minSavingsInput}
              onChange={(event) => {
                setMinSavingsInput(event.target.value);
              }}
              placeholder="25"
            />
          </label>
          <div className="md:col-span-4 flex flex-wrap items-center gap-2">
            <button type="submit" className="rounded-lg border border-cyan-300 bg-cyan-50 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-cyan-800 transition hover:border-cyan-400 hover:bg-cyan-100">
              Apply
            </button>
            <button
              type="button"
              className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-700 transition hover:bg-slate-100"
              onClick={() => {
                setSearchInput("");
                setServiceInput("");
                setCheckIdInput("");
                setMinSavingsInput("");
                pushWithParams({
                  q: null,
                  service: null,
                  check_id: null,
                  min_savings: null,
                  page: "1",
                });
              }}
            >
              Clear
            </button>
          </div>
        </form>
      </section>

      {recommendations.isLoading ? <p className="rounded-xl bg-white/80 px-3 py-2 text-sm text-slate-700">Loading recommendations...</p> : null}
      {recommendations.error ? (
        <div className="mb-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          <p>{recommendationsErrorMessage(recommendations.error)}</p>
          <button
            type="button"
            className="mt-2 rounded-lg border border-red-300 bg-white px-2.5 py-1.5 text-xs font-medium"
            onClick={() => {
              void recommendations.refetch();
            }}
          >
            Retry
          </button>
        </div>
      ) : null}

      {!recommendations.isLoading && recommendations.data ? (
        <>
          <div className="finops-panel overflow-x-auto rounded-2xl">
            <table className="min-w-full text-left text-sm text-slate-700">
              <thead className="finops-table-head text-xs uppercase tracking-wide text-slate-600">
                <tr>
                  <th className="px-3 py-2">Priority</th>
                  <th className="px-3 py-2">Recommendation</th>
                  <th className="px-3 py-2">Action Type</th>
                  <th className="px-3 py-2">Savings / month</th>
                  <th className="px-3 py-2">Confidence</th>
                  <th className="px-3 py-2">Approval</th>
                  <th className="px-3 py-2">State</th>
                </tr>
              </thead>
              <tbody>
                {recommendations.data.items.map((item) => (
                  <tr
                    key={item.fingerprint}
                    className={`border-t border-slate-100 transition ${selectedFingerprint === item.fingerprint ? "bg-cyan-50/70" : "hover:bg-slate-50/70"}`}
                  >
                    <td className="px-3 py-2">
                      <span
                        className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium ${priorityBadgeClass(item.priority)}`}
                      >
                        {item.priority.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <button
                        type="button"
                        className="text-left font-medium text-cyan-700 underline-offset-2 transition hover:text-cyan-900 hover:underline"
                        onClick={() => {
                          openRecommendation(item);
                        }}
                      >
                        {item.title}
                      </button>
                      <p className="mt-0.5 text-xs text-zinc-600">
                        {item.recommendation_type} | {item.service} | {item.check_id}
                      </p>
                    </td>
                    <td className="px-3 py-2">
                      <span className="inline-flex items-center rounded border border-zinc-300 bg-zinc-100 px-2 py-0.5 text-xs">
                        {item.action_type}
                      </span>
                    </td>
                    <td className="px-3 py-2">{formatMoney(item.estimated_monthly_savings)}</td>
                    <td className="px-3 py-2">
                      <span
                        className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium ${confidenceBadgeClass(item.confidence_label)}`}
                      >
                        {item.confidence}% ({item.confidence_label})
                      </span>
                    </td>
                    <td className="px-3 py-2">{item.requires_approval ? "Required" : "No"}</td>
                    <td className="px-3 py-2">
                      <span className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium ${stateBadgeClass(item.effective_state)}`}>
                        {item.effective_state}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {recommendations.data.items.length === 0 ? (
            <p className="mt-3 rounded-xl bg-white/80 px-3 py-2 text-sm text-slate-600">
              No recommendations match the current filters.
            </p>
          ) : null}

          <div className="mt-4 flex items-center justify-between text-sm">
            <p className="text-cyan-50/95">
              Showing {pageStart}-{pageEnd} of {total}
            </p>
            <div className="flex items-center gap-2">
              <button
                type="button"
                className="rounded-lg border border-sky-200/80 bg-white/90 px-3 py-1.5 font-medium text-slate-800 transition hover:bg-white disabled:opacity-50"
                onClick={() => {
                  pushWithParams({ page: String(Math.max(1, page - 1)) });
                }}
                disabled={!canPrev}
              >
                Previous
              </button>
              <span className="rounded-md bg-slate-900/25 px-2 py-1 text-cyan-50">
                Page {page} / {totalPages}
              </span>
              <button
                type="button"
                className="rounded-lg border border-sky-200/80 bg-white/90 px-3 py-1.5 font-medium text-slate-800 transition hover:bg-white disabled:opacity-50"
                onClick={() => {
                  pushWithParams({ page: String(page + 1) });
                }}
                disabled={!canNext}
              >
                Next
              </button>
            </div>
          </div>
        </>
      ) : null}

      {selectedRecommendation ? (
        <div className="fixed inset-0 z-50 flex">
          <button
            type="button"
            className="h-full flex-1 bg-slate-950/55"
            aria-label="Close recommendation drawer"
            onClick={() => {
              setSelectedFingerprint(null);
            }}
          />
          <aside className="h-full w-full max-w-2xl overflow-y-auto border-l border-slate-200 bg-white/95 p-6 shadow-2xl backdrop-blur">
            <div className="mb-4 flex items-start justify-between gap-4">
              <div>
                <h2 className="text-xl font-semibold text-slate-900">{selectedRecommendation.title}</h2>
                <p className="mt-1 text-xs text-slate-600">{selectedRecommendation.fingerprint}</p>
              </div>
              <button
                type="button"
                className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700"
                onClick={() => {
                  setSelectedFingerprint(null);
                }}
              >
                Close
              </button>
            </div>

            <div className="grid gap-3 text-sm text-slate-700 md:grid-cols-2">
              <p><span className="font-medium">Type:</span> {selectedRecommendation.recommendation_type}</p>
              <p><span className="font-medium">Priority:</span> {selectedRecommendation.priority.toUpperCase()}</p>
              <p><span className="font-medium">Action Type:</span> {selectedRecommendation.action_type}</p>
              <p><span className="font-medium">State:</span> {selectedRecommendation.effective_state}</p>
              <p><span className="font-medium">Service:</span> {selectedRecommendation.service}</p>
              <p><span className="font-medium">Severity:</span> {selectedRecommendation.severity}</p>
              <p><span className="font-medium">Category:</span> {selectedRecommendation.category ?? "-"}</p>
              <p><span className="font-medium">Detected:</span> {formatDateTime(selectedRecommendation.detected_at)}</p>
              <p><span className="font-medium">Region:</span> {selectedRecommendation.region ?? "-"}</p>
              <p><span className="font-medium">Account:</span> {selectedRecommendation.account_id ?? "-"}</p>
              <p><span className="font-medium">Monthly Savings:</span> {formatMoney(selectedRecommendation.estimated_monthly_savings)}</p>
              <p><span className="font-medium">Annual Savings:</span> {formatMoney(selectedRecommendation.estimated_annual_savings)}</p>
              <p><span className="font-medium">Confidence:</span> {selectedRecommendation.confidence}% ({selectedRecommendation.confidence_label})</p>
              <p><span className="font-medium">Approval:</span> {selectedRecommendation.requires_approval ? "Required" : "Not required"}</p>
            </div>

            <section className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3">
              <h3 className="text-sm font-semibold text-slate-900">Why This Recommendation</h3>
              <p className="mt-1 text-sm text-slate-700">
                {selectedRecommendation.checker_advice || "-"}
              </p>
            </section>

            <section className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3">
              <h3 className="text-sm font-semibold text-slate-900">Normalized Action Plan</h3>
              <p className="mt-1 text-sm text-slate-700">{selectedRecommendation.action}</p>
              <div className="mt-3 grid gap-2 text-sm md:grid-cols-2">
                <p>
                  <span className="font-medium">Current:</span>{" "}
                  {selectedRecommendation.current.kind} = {selectedRecommendation.current.value}
                </p>
                <p>
                  <span className="font-medium">Target:</span>{" "}
                  {selectedRecommendation.target.kind} = {selectedRecommendation.target.value}
                </p>
                <p>
                  <span className="font-medium">Pricing Source:</span>{" "}
                  {selectedRecommendation.pricing_source}
                </p>
                <p>
                  <span className="font-medium">Pricing Version:</span>{" "}
                  {selectedRecommendation.pricing_version ?? "unknown"}
                </p>
              </div>
            </section>
          </aside>
        </div>
      ) : null}
      </div>
    </main>
  );
}
