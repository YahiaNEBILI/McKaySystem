"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";

import { apiClient } from "@/lib/api/client";
import { FindingsResponse } from "@/hooks/useFindings";

type LifecycleAction = "ignore" | "resolve" | "snooze";

interface LifecycleMutationInput {
  action: LifecycleAction;
  fingerprint: string;
  reason?: string;
  snoozeDays?: 7 | 14 | 30;
  tenantId: string;
  workspace: string;
  updatedBy?: string;
}

interface LifecycleContext {
  previous: FindingsResponse | undefined;
}

interface UseFindingLifecycleOptions {
  queryKey: readonly unknown[];
}

function snoozeUntilIso(days: 7 | 14 | 30): string {
  const now = new Date();
  now.setUTCDate(now.getUTCDate() + days);
  return now.toISOString();
}

function optimisticState(
  input: LifecycleMutationInput,
): { effectiveState: string; state: string; snoozeUntil: string | null } {
  if (input.action === "resolve") {
    return { effectiveState: "resolved", state: "resolved", snoozeUntil: null };
  }
  if (input.action === "ignore") {
    return { effectiveState: "ignored", state: "ignored", snoozeUntil: null };
  }
  return {
    effectiveState: "snoozed",
    state: "snoozed",
    snoozeUntil: snoozeUntilIso(input.snoozeDays ?? 7),
  };
}

/**
 * Execute finding lifecycle actions with optimistic cache update + rollback.
 */
export function useFindingLifecycle(options: UseFindingLifecycleOptions) {
  const queryClient = useQueryClient();

  return useMutation<void, Error, LifecycleMutationInput, LifecycleContext>({
    mutationFn: async (input) => {
      const body: Record<string, unknown> = {
        tenant_id: input.tenantId,
        workspace: input.workspace,
        fingerprint: input.fingerprint,
        reason: input.reason?.trim() || undefined,
        updated_by: input.updatedBy || "frontend-ui",
      };

      if (input.action === "snooze") {
        body.snooze_until = snoozeUntilIso(input.snoozeDays ?? 7);
      }

      await apiClient.post(`/lifecycle/${input.action}`, body);
    },
    onMutate: async (input) => {
      await queryClient.cancelQueries({ queryKey: options.queryKey });
      const previous = queryClient.getQueryData<FindingsResponse>(options.queryKey);
      if (!previous) {
        return { previous: undefined };
      }

      const next = optimisticState(input);
      queryClient.setQueryData<FindingsResponse>(options.queryKey, {
        ...previous,
        items: previous.items.map((item) =>
          item.fingerprint === input.fingerprint
            ? {
                ...item,
                state: next.state,
                effective_state: next.effectiveState,
                snooze_until: next.snoozeUntil,
                reason: input.reason?.trim() || item.reason,
              }
            : item,
        ),
      });
      return { previous };
    },
    onError: (_error, _input, context) => {
      if (context?.previous) {
        queryClient.setQueryData(options.queryKey, context.previous);
      }
    },
    onSettled: async () => {
      await queryClient.invalidateQueries({ queryKey: options.queryKey });
    },
  });
}
