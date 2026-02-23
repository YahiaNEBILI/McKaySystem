"use client";

import { useQuery } from "@tanstack/react-query";

import { apiClient } from "@/lib/api/client";
import { getStoredScope } from "@/lib/scope";

export interface RecommendationValue {
  kind: string;
  value: string;
}

export interface RecommendationItem {
  fingerprint: string;
  check_id: string;
  service: string;
  severity: string;
  category: string | null;
  title: string;
  recommendation_type: string;
  action: string;
  priority: string;
  action_type: string;
  target: RecommendationValue;
  checker_advice: string;
  current: RecommendationValue;
  estimated_monthly_savings: number;
  estimated_annual_savings: number;
  confidence: number;
  confidence_label: string;
  pricing_source: string;
  pricing_version: string | null;
  requires_approval: boolean;
  region: string | null;
  account_id: string | null;
  detected_at: string | null;
  effective_state: string;
}

export interface RecommendationsResponse {
  ok: true;
  tenant_id: string;
  workspace: string;
  limit: number;
  offset: number;
  total: number;
  items: RecommendationItem[];
}

interface UseRecommendationsOptions {
  limit?: number;
  offset?: number;
  state?: string;
  severity?: string;
  service?: string;
  checkId?: string;
  q?: string;
  minSavings?: number | null;
  order?: "savings_desc" | "detected_desc";
}

export function recommendationsQueryKey(
  scope: { tenantId?: string; workspace?: string },
  options: {
    limit: number;
    offset: number;
    state: string;
    severity: string;
    service: string;
    checkId: string;
    q: string;
    minSavings: string;
    order: "savings_desc" | "detected_desc";
  },
) {
  return [
    "recommendations",
    scope.tenantId,
    scope.workspace,
    options.limit,
    options.offset,
    options.state,
    options.severity,
    options.service,
    options.checkId,
    options.q,
    options.minSavings,
    options.order,
  ] as const;
}

/**
 * Query scoped recommendations derived from current findings.
 */
export function useRecommendations(options: UseRecommendationsOptions = {}) {
  const scope = getStoredScope();
  const limit = options.limit ?? 50;
  const offset = options.offset ?? 0;
  const state = options.state ?? "open";
  const severity = options.severity ?? "";
  const service = options.service ?? "";
  const checkId = options.checkId ?? "";
  const q = options.q ?? "";
  const minSavings = options.minSavings ?? null;
  const order = options.order ?? "savings_desc";

  return useQuery({
    queryKey: recommendationsQueryKey(
      { tenantId: scope?.tenantId, workspace: scope?.workspace },
      {
        limit,
        offset,
        state,
        severity,
        service,
        checkId,
        q,
        minSavings: minSavings === null ? "" : String(minSavings),
        order,
      },
    ),
    enabled: Boolean(scope?.tenantId && scope?.workspace),
    queryFn: async () => {
      return apiClient.get<RecommendationsResponse>("/recommendations", {
        query: {
          limit,
          offset,
          state,
          severity,
          service,
          check_id: checkId,
          q,
          min_savings: minSavings,
          order,
        },
      });
    },
  });
}
