"use client";

import { useQuery } from "@tanstack/react-query";

import { apiClient } from "@/lib/api/client";
import { getStoredScope } from "@/lib/scope";

export interface FindingItem {
  fingerprint: string;
  check_id: string;
  service: string;
  severity: string;
  title: string;
  estimated_monthly_savings: number | null;
  account_id: string | null;
  region: string | null;
  effective_state: string;
  detected_at: string | null;
}

interface FindingsResponse {
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
    queryKey: [
      "findings",
      scope?.tenantId,
      scope?.workspace,
      limit,
      offset,
      state,
      severity,
      q,
      order,
    ],
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
