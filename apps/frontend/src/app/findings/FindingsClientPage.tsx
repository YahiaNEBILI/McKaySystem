"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Fragment, useEffect, useMemo, useState } from "react";

import { useAuth } from "@/hooks/useAuth";
import { useFindingLifecycle } from "@/hooks/useFindingLifecycle";
import {
  FindingItem,
  findingsQueryKey,
  groupedFindingsCategoryQueryKey,
  useFindings,
  useFindingsGroupedCategory,
} from "@/hooks/useFindings";
import { RunLatestItem, useRunsLatest } from "@/hooks/useRunsLatest";
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

function findingAdvice(payload: Record<string, unknown> | null): string | null {
  if (!payload) {
    return null;
  }
  const advice = String(payload.advice ?? "").trim();
  if (advice) {
    return advice;
  }
  const legacy = String(payload.recommendation ?? "").trim();
  return legacy || null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function firstNonEmptyText(...values: unknown[]): string | null {
  for (const value of values) {
    const normalized = String(value ?? "").trim();
    if (normalized) {
      return normalized;
    }
  }
  return null;
}

function impactedResourceName(payload: Record<string, unknown> | null): string | null {
  if (!payload) {
    return null;
  }
  const scope = asRecord(payload.scope);
  const dimensions = asRecord(payload.dimensions);
  return firstNonEmptyText(
    payload.resource_name,
    payload.resource_id,
    payload.resource_arn,
    scope?.resource_name,
    scope?.resource_id,
    scope?.resource_arn,
    dimensions?.resource_name,
    dimensions?.resource_id,
    dimensions?.resource_arn,
    dimensions?.instance_id,
    dimensions?.bucket,
    dimensions?.bucket_name,
    dimensions?.db_instance_identifier,
    dimensions?.db_cluster_identifier,
    dimensions?.nat_gateway_id,
    dimensions?.function_name,
    dimensions?.load_balancer_name,
    dimensions?.load_balancer_arn,
    dimensions?.distribution_id,
    dimensions?.volume_id,
    dimensions?.snapshot_id,
    dimensions?.file_system_id,
    dimensions?.vault_name,
    dimensions?.plan_name,
    dimensions?.cluster_name,
    dimensions?.service_name,
  );
}

function runDateSummary(items: FindingItem[], latestRun: RunLatestItem | null): {
  runIdLabel: string;
  runDateLabel: string;
  sourceLabel: string;
} {
  if (latestRun?.run_id) {
    return {
      runIdLabel: latestRun.run_id,
      runDateLabel: formatDateTime(latestRun.run_ts),
      sourceLabel: "latest run metadata",
    };
  }

  const runIds = new Set<string>();
  let latestDetectedMs = Number.NEGATIVE_INFINITY;
  let latestDetectedValue: string | null = null;

  for (const item of items) {
    const runId = String(item.run_id ?? "").trim();
    if (runId) {
      runIds.add(runId);
    }
    const detectedAt = String(item.detected_at ?? "").trim();
    if (!detectedAt) {
      continue;
    }
    const ms = new Date(detectedAt).getTime();
    if (!Number.isNaN(ms) && ms >= latestDetectedMs) {
      latestDetectedMs = ms;
      latestDetectedValue = detectedAt;
    }
  }

  let runIdLabel = "-";
  if (runIds.size === 1) {
    runIdLabel = Array.from(runIds)[0];
  } else if (runIds.size > 1) {
    runIdLabel = `${runIds.size} runs (mixed)`;
  }

  return {
    runIdLabel,
    runDateLabel: latestDetectedValue ? formatDateTime(latestDetectedValue) : "-",
    sourceLabel: "derived from findings",
  };
}

function severityBadgeClass(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (normalized === "critical") {
    return "border-rose-300 bg-rose-50 text-rose-800";
  }
  if (normalized === "high") {
    return "border-orange-300 bg-orange-50 text-orange-800";
  }
  if (normalized === "medium") {
    return "border-amber-300 bg-amber-50 text-amber-800";
  }
  if (normalized === "low") {
    return "border-emerald-300 bg-emerald-50 text-emerald-800";
  }
  return "border-zinc-300 bg-zinc-100 text-zinc-700";
}

function stateBadgeClass(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (normalized === "open") {
    return "border-cyan-300 bg-cyan-50 text-cyan-800";
  }
  if (normalized === "snoozed") {
    return "border-amber-300 bg-amber-50 text-amber-800";
  }
  if (normalized === "resolved") {
    return "border-emerald-300 bg-emerald-50 text-emerald-800";
  }
  if (normalized === "ignored") {
    return "border-zinc-300 bg-zinc-100 text-zinc-700";
  }
  return "border-zinc-300 bg-zinc-100 text-zinc-700";
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
  const groupByFilter = searchParams.get("group_by") === "category" ? "category" : "none";
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

  const findingsListQueryKey = findingsQueryKey(
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
  const groupedCategoryQueryKey = groupedFindingsCategoryQueryKey(
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
    enabled: groupByFilter !== "category",
  });
  const groupedFindings = useFindingsGroupedCategory({
    limit: limitFilter,
    offset,
    state: stateFilter,
    severity: severityFilter,
    order: orderFilter,
    q: queryFilter,
    enabled: groupByFilter === "category",
  });
  const activeFindings = groupByFilter === "category" ? groupedFindings : findings;
  const lifecycleQueryKey =
    groupByFilter === "category" ? groupedCategoryQueryKey : findingsListQueryKey;
  const lifecycle = useFindingLifecycle({ queryKey: lifecycleQueryKey });
  const permissions = useMemo(() => new Set(auth.user?.permissions ?? []), [auth.user?.permissions]);
  const canReadRuns = permissions.has("admin:full") || permissions.has("runs:read");
  const latestRun = useRunsLatest(canReadRuns);

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
    const exists = activeFindings.data?.items.some((item) => item.fingerprint === selectedFingerprint);
    if (!exists) {
      setSelectedFingerprint(null);
      setActionReason("");
      setActionError(null);
      setActionFeedback(null);
    }
  }, [activeFindings.data?.items, selectedFingerprint]);

  const runSummary = useMemo(
    () => runDateSummary(activeFindings.data?.items ?? [], latestRun.data ?? null),
    [activeFindings.data?.items, latestRun.data],
  );

  const groupedItems = useMemo(() => {
    if (groupByFilter !== "category") {
      return [];
    }
    const buckets = new Map<string, FindingItem[]>();
    for (const item of activeFindings.data?.items ?? []) {
      const key = String(item.category ?? "").trim() || "uncategorized";
      const current = buckets.get(key);
      if (current) {
        current.push(item);
      } else {
        buckets.set(key, [item]);
      }
    }
    return Array.from(buckets.entries()).map(([category, items]) => ({ category, items }));
  }, [activeFindings.data?.items, groupByFilter]);

  const categoryCountsByName = useMemo(() => {
    const out = new Map<string, number>();
    for (const item of groupedFindings.data?.category_totals ?? []) {
      const key = String(item.category ?? "").trim() || "uncategorized";
      out.set(key, Number(item.finding_count ?? 0));
    }
    return out;
  }, [groupedFindings.data?.category_totals]);
  const pageSavings = useMemo(
    () =>
      (activeFindings.data?.items ?? []).reduce(
        (acc, item) => acc + (item.estimated_monthly_savings ?? 0),
        0,
      ),
    [activeFindings.data?.items],
  );
  const visibleCategoryCount = useMemo(() => {
    const categories = new Set<string>();
    for (const item of activeFindings.data?.items ?? []) {
      categories.add(String(item.category ?? "").trim() || "uncategorized");
    }
    return categories.size;
  }, [activeFindings.data?.items]);

  if (!scope) {
    return null;
  }

  const activeScope = scope;
  const selectedFinding =
    activeFindings.data?.items.find((item) => item.fingerprint === selectedFingerprint) ?? null;
  const canTriage = permissions.has("admin:full") || permissions.has("findings:update");
  const canReadRecommendations = permissions.has("admin:full") || permissions.has("findings:read");
  const canReadUsers = permissions.has("admin:full") || permissions.has("users:read");
  const total = activeFindings.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / limitFilter));
  const canPrev = page > 1;
  const canNext = page < totalPages;
  const pageStart = total === 0 ? 0 : offset + 1;
  const pageEnd = total === 0 ? 0 : Math.min(offset + (activeFindings.data?.items.length ?? 0), total);
  const categoryCount =
    groupByFilter === "category"
      ? groupedFindings.data?.category_totals?.length ?? visibleCategoryCount
      : visibleCategoryCount;

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

  function renderFindingRow(item: FindingItem) {
    const resource = impactedResourceName(item.payload) ?? "-";
    return (
      <tr
        key={item.fingerprint}
        className={`border-t border-slate-100 transition ${selectedFingerprint === item.fingerprint ? "bg-cyan-50/70" : "hover:bg-slate-50/70"}`}
      >
        <td className="px-3 py-2">
          <span className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-semibold uppercase ${severityBadgeClass(item.severity)}`}>
            {item.severity}
          </span>
        </td>
        <td className="px-3 py-2 text-slate-700">{item.category ?? "-"}</td>
        <td className="px-3 py-2 text-slate-700">{item.service}</td>
        <td className="px-3 py-2">
          <span className="block max-w-[16rem] truncate font-medium text-slate-700" title={resource}>
            {resource}
          </span>
        </td>
        <td className="px-3 py-2">
          <button
            type="button"
            className="text-left font-medium text-cyan-700 underline-offset-2 transition hover:text-cyan-900 hover:underline"
            onClick={() => {
              openFinding(item);
            }}
          >
            {item.title}
          </button>
        </td>
        <td className="px-3 py-2 font-medium text-slate-700">{formatMoney(item.estimated_monthly_savings)}</td>
        <td className="px-3 py-2">
          <span className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium ${stateBadgeClass(item.effective_state)}`}>
            {item.effective_state}
          </span>
        </td>
        <td className="px-3 py-2 text-slate-700">{item.region ?? "-"}</td>
      </tr>
    );
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
            FinOps Findings
          </p>
          <h1 className="font-display mt-2 text-2xl font-semibold tracking-tight text-slate-900 md:text-3xl">
            Findings Control Center
          </h1>
          <p className="mt-1 text-sm text-slate-600">
            Tenant: <span className="font-medium">{activeScope.tenantId}</span> | Workspace:{" "}
            <span className="font-medium">{activeScope.workspace}</span>
          </p>
          <p className="text-sm text-slate-600">
            Run date: <span className="font-medium">{runSummary.runDateLabel}</span> | Run ID:{" "}
            <span className="font-medium">{runSummary.runIdLabel}</span>{" "}
            <span className="text-xs text-slate-500">({runSummary.sourceLabel})</span>
          </p>
        </div>
        <div className="flex items-center gap-2 self-start">
          {canReadRecommendations ? (
            <button
              type="button"
              className="finops-toolbar-btn rounded-lg px-3 py-2 text-sm font-medium transition"
              onClick={() => {
                router.push("/recommendations");
              }}
            >
              Recommendations
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
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-100/85">Total Findings</p>
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
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-100/85">Categories</p>
          <p className="font-display mt-1 text-2xl font-semibold text-white">{categoryCount}</p>
        </article>
      </section>

      <section className="finops-panel mb-3 rounded-2xl p-4 text-sm">
        <div className="grid gap-3 md:grid-cols-6">
          <label className="block">
            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">State</span>
            <select
              className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
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
            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">Group by</span>
            <select
              className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
              value={groupByFilter}
              onChange={(event) => {
                pushWithParams({ group_by: event.target.value === "category" ? "category" : null, page: "1" });
              }}
            >
              <option value="none">None</option>
              <option value="category">Category (server-side)</option>
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

          <form
            className="block"
            onSubmit={(event) => {
              event.preventDefault();
              pushWithParams({ q: searchInput.trim() || null, page: "1" });
            }}
          >
            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">Search</span>
            <div className="flex gap-2">
              <input
                className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
                value={searchInput}
                onChange={(event) => {
                  setSearchInput(event.target.value);
                }}
                placeholder="Title contains..."
              />
              <button
                type="submit"
                className="rounded-lg border border-cyan-300 bg-cyan-50 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-cyan-800 transition hover:border-cyan-400 hover:bg-cyan-100"
              >
                Apply
              </button>
            </div>
          </form>
        </div>
      </section>

      {activeFindings.isLoading ? <p className="rounded-xl bg-white/80 px-3 py-2 text-sm text-slate-700">Loading findings...</p> : null}
      {activeFindings.error ? (
        <div className="mb-4 rounded-xl border border-red-200 bg-red-50/95 p-3 text-sm text-red-700">
          <p>{findingsErrorMessage(activeFindings.error)}</p>
          <button
            type="button"
            className="mt-2 rounded-lg border border-red-300 bg-white px-2.5 py-1.5 text-xs font-medium"
            onClick={() => {
              void activeFindings.refetch();
            }}
          >
            Retry
          </button>
        </div>
      ) : null}

      {!activeFindings.isLoading && activeFindings.data ? (
        <>
          <div className="finops-panel overflow-x-auto rounded-2xl">
            <table className="min-w-full text-left text-sm text-slate-700">
              <thead className="finops-table-head text-xs uppercase tracking-wide text-slate-600">
                <tr>
                  <th className="px-3 py-2">Severity</th>
                  <th className="px-3 py-2">Category</th>
                  <th className="px-3 py-2">Service</th>
                  <th className="px-3 py-2">Resource</th>
                  <th className="px-3 py-2">Title</th>
                  <th className="px-3 py-2">Savings</th>
                  <th className="px-3 py-2">State</th>
                  <th className="px-3 py-2">Region</th>
                </tr>
              </thead>
              <tbody>
                {groupByFilter === "category"
                  ? groupedItems.map((group) => (
                      <Fragment key={`group:${group.category}`}>
                        <tr className="border-t border-slate-200 bg-slate-100/75">
                          <td className="px-3 py-2 text-xs font-semibold uppercase tracking-wide text-slate-700" colSpan={8}>
                            Category: {group.category} ({categoryCountsByName.get(group.category) ?? group.items.length})
                          </td>
                        </tr>
                        {group.items.map((item) => renderFindingRow(item))}
                      </Fragment>
                    ))
                  : activeFindings.data.items.map((item) => renderFindingRow(item))}
              </tbody>
            </table>
          </div>

          {activeFindings.data.items.length === 0 ? (
            <p className="mt-3 rounded-xl bg-white/80 px-3 py-2 text-sm text-slate-600">No findings match the current filters.</p>
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
                  setPage(page - 1);
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
            className="h-full flex-1 bg-slate-950/55"
            aria-label="Close detail drawer"
            onClick={() => {
              setSelectedFingerprint(null);
              setActionError(null);
              setActionFeedback(null);
            }}
          />
          <aside className="h-full w-full max-w-2xl overflow-y-auto border-l border-slate-200 bg-white/95 p-6 shadow-2xl backdrop-blur">
            <div className="mb-4 flex items-start justify-between gap-4">
              <div>
                <h2 className="text-xl font-semibold text-slate-900">{selectedFinding.title}</h2>
                <p className="mt-1 text-xs text-slate-600">{selectedFinding.fingerprint}</p>
              </div>
              <button
                type="button"
                className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700"
                onClick={() => {
                  setSelectedFingerprint(null);
                  setActionError(null);
                  setActionFeedback(null);
                }}
              >
                Close
              </button>
            </div>

            <div className="grid gap-3 text-sm text-slate-700 md:grid-cols-2">
              <p><span className="font-medium">Check:</span> {selectedFinding.check_id}</p>
              <p><span className="font-medium">Category:</span> {selectedFinding.category ?? "-"}</p>
              <p><span className="font-medium">Run ID:</span> {selectedFinding.run_id ?? "-"}</p>
              <p><span className="font-medium">Resource:</span> {impactedResourceName(selectedFinding.payload) ?? "-"}</p>
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

            <section className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3">
              <h3 className="text-sm font-semibold text-slate-900">Checker Advice</h3>
              <p className="mt-1 text-sm text-slate-700">
                {findingAdvice(selectedFinding.payload) ?? "-"}
              </p>
            </section>

            <section className="mt-5 rounded-xl border border-slate-200 bg-slate-50 p-3">
              <h3 className="text-sm font-semibold text-slate-900">Lifecycle Actions</h3>
              <p className="mt-1 text-xs text-slate-600">
                {canTriage
                  ? "State updates are applied optimistically and synced with backend."
                  : "Missing permission: findings:update"}
              </p>

              <label className="mt-3 block text-xs font-medium uppercase tracking-wide text-slate-600">
                Reason (optional)
                <textarea
                  className="mt-1 h-20 w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-sm text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
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
                  className="rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-emerald-800 transition hover:bg-emerald-100 disabled:opacity-50"
                  disabled={!canTriage || lifecycle.isPending}
                  onClick={() => {
                    void runAction({ action: "resolve", label: "Resolved" });
                  }}
                >
                  Resolve
                </button>
                <button
                  type="button"
                  className="rounded-lg border border-slate-300 bg-slate-100 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-800 transition hover:bg-slate-200 disabled:opacity-50"
                  disabled={!canTriage || lifecycle.isPending}
                  onClick={() => {
                    void runAction({ action: "ignore", label: "Ignored" });
                  }}
                >
                  Ignore
                </button>
                <button
                  type="button"
                  className="rounded-lg border border-cyan-300 bg-cyan-50 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-cyan-800 transition hover:bg-cyan-100 disabled:opacity-50"
                  disabled={!canTriage || lifecycle.isPending}
                  onClick={() => {
                    void runAction({ action: "snooze", label: "Snoozed", snoozeDays: 7 });
                  }}
                >
                  Snooze 7d
                </button>
                <button
                  type="button"
                  className="rounded-lg border border-cyan-300 bg-cyan-50 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-cyan-800 transition hover:bg-cyan-100 disabled:opacity-50"
                  disabled={!canTriage || lifecycle.isPending}
                  onClick={() => {
                    void runAction({ action: "snooze", label: "Snoozed", snoozeDays: 14 });
                  }}
                >
                  Snooze 14d
                </button>
                <button
                  type="button"
                  className="rounded-lg border border-cyan-300 bg-cyan-50 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-cyan-800 transition hover:bg-cyan-100 disabled:opacity-50"
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
              <h3 className="mb-2 text-sm font-semibold text-slate-900">Raw Payload</h3>
              <pre className="max-h-72 overflow-auto rounded-xl border border-slate-900/30 bg-slate-950 p-3 text-xs text-slate-100">
                {JSON.stringify(selectedFinding.payload ?? {}, null, 2)}
              </pre>
            </section>
          </aside>
        </div>
      ) : null}
      </div>
    </main>
  );
}

