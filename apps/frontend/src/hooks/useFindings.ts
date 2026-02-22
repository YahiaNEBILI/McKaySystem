"use client";

import { useQuery } from "@tanstack/react-query";

import { apiClient } from "@/lib/api/client";
import { getStoredScope } from "@/lib/scope";

export interface FindingItem {
  tenant_id: string;
  workspace: string;
  fingerprint: string;
  run_id: string | null;
  check_id: string;
  service: string;
  severity: string;
  title: string;
  estimated_monthly_savings: number | null;
  account_id: string | null;
  region: string | null;
  category: string | null;
  group_key: string | null;
  state: string | null;
  snooze_until: string | null;
  reason: string | null;
  effective_state: string;
  first_detected_at: string | null;
  first_opened_at: string | null;
  detected_at: string | null;
  owner_id: string | null;
  owner_email: string | null;
  owner_name: string | null;
  team_id: string | null;
  sla_deadline: string | null;
  sla_status: string | null;
  payload: Record<string, unknown> | null;
}

export interface FindingsResponse {
  ok: true;
  tenant_id: string;
  workspace: string;
  limit: number;
  offset: number;
  total: number;
  items: FindingItem[];
}

interface UseFindingsOptions {
  limit?: number;
  offset?: number;
  state?: string;
  severity?: string;
  q?: string;
  order?: "savings_desc" | "detected_desc";
}

export function findingsQueryKey(
  scope: { tenantId?: string; workspace?: string },
  options: UseFindingsOptions,
) {
  return [
    "findings",
    scope.tenantId,
    scope.workspace,
    options.limit ?? 50,
    options.offset ?? 0,
    options.state ?? "",
    options.severity ?? "",
    options.q ?? "",
    options.order ?? "savings_desc",
  ] as const;
}

/**
 * Query scoped findings from the Flask API read model.
 */
export function useFindings(options: UseFindingsOptions = {}) {
  const scope = getStoredScope();
  const limit = options.limit ?? 50;
  const offset = options.offset ?? 0;
  const state = options.state ?? "";
  const severity = options.severity ?? "";
  const q = options.q ?? "";
  const order = options.order ?? "savings_desc";

  return useQuery({
    queryKey: findingsQueryKey(
      { tenantId: scope?.tenantId, workspace: scope?.workspace },
      { limit, offset, state, severity, q, order },
    ),
    enabled: Boolean(scope?.tenantId && scope?.workspace),
    queryFn: async () => {
      return apiClient.get<FindingsResponse>("/findings", {
        query: {
          limit,
          offset,
          state,
          severity,
          q,
          order,
        },
      });
    },
  });
}
