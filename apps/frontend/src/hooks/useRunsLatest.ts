"use client";

import { useQuery } from "@tanstack/react-query";

import { ApiError, apiClient } from "@/lib/api/client";
import { getStoredScope } from "@/lib/scope";

export interface RunLatestItem {
  tenant_id: string;
  workspace: string;
  run_id: string;
  run_ts: string;
  status: string | null;
  artifact_prefix: string | null;
  ingested_at: string | null;
  engine_version: string | null;
  pricing_version: string | null;
  pricing_source: string | null;
  raw_present: boolean | null;
  correlated_present: boolean | null;
  enriched_present: boolean | null;
}

interface RunLatestResponse {
  tenant_id: string;
  workspace: string;
  run: RunLatestItem | null;
}

/**
 * Resolve latest run metadata for current tenant/workspace.
 */
export function useRunsLatest(enabled = true) {
  const scope = getStoredScope();

  return useQuery({
    queryKey: ["runs", "latest", scope?.tenantId, scope?.workspace],
    enabled: Boolean(scope?.tenantId && scope?.workspace && enabled),
    retry: false,
    queryFn: async () => {
      try {
        const response = await apiClient.get<RunLatestResponse>("/runs/latest");
        return response.run;
      } catch (error) {
        if (error instanceof ApiError && (error.status === 403 || error.status === 404)) {
          return null;
        }
        throw error;
      }
    },
  });
}
