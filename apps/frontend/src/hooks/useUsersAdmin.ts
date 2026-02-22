"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiClient } from "@/lib/api/client";
import { getStoredScope } from "@/lib/scope";

export interface UserItem {
  tenant_id: string;
  workspace: string;
  user_id: string;
  email: string;
  full_name: string | null;
  external_id: string | null;
  auth_provider: string | null;
  is_active: boolean;
  is_superadmin: boolean;
  last_login_at: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface UsersResponse {
  ok: true;
  tenant_id: string;
  workspace: string;
  limit: number;
  offset: number;
  total: number;
  items: UserItem[];
}

export interface UserRole {
  role_id: string;
  name: string | null;
  description: string | null;
  is_system: boolean;
  granted_by: string | null;
  granted_at: string | null;
  permissions: string[];
}

export interface UserRoleResponse {
  ok: true;
  tenant_id: string;
  workspace: string;
  user_id: string;
  role: UserRole | null;
}

interface UseUsersOptions {
  limit?: number;
  offset?: number;
  q?: string;
  includeInactive?: boolean;
  enabled?: boolean;
}

interface CreateUserPayload {
  tenant_id: string;
  workspace: string;
  user_id: string;
  email: string;
  password?: string;
  full_name?: string;
  external_id?: string;
  auth_provider?: string;
  is_active?: boolean;
  is_superadmin?: boolean;
}

interface SetUserRolePayload {
  tenant_id: string;
  workspace: string;
  role_id: string;
  granted_by?: string;
}

export function usersQueryKey(
  scope: { tenantId?: string; workspace?: string },
  options: { limit: number; offset: number; q: string; includeInactive: boolean },
) {
  return [
    "users",
    scope.tenantId,
    scope.workspace,
    options.limit,
    options.offset,
    options.q,
    options.includeInactive,
  ] as const;
}

export function userRoleQueryKey(
  scope: { tenantId?: string; workspace?: string },
  userId: string | null,
) {
  return ["users", "role", scope.tenantId, scope.workspace, userId ?? ""] as const;
}

/**
 * Query scoped users with paging and search.
 */
export function useUsers(options: UseUsersOptions = {}) {
  const scope = getStoredScope();
  const limit = options.limit ?? 25;
  const offset = options.offset ?? 0;
  const q = options.q ?? "";
  const includeInactive = options.includeInactive ?? false;
  const enabled = options.enabled ?? true;

  return useQuery({
    queryKey: usersQueryKey(
      { tenantId: scope?.tenantId, workspace: scope?.workspace },
      { limit, offset, q, includeInactive },
    ),
    enabled: Boolean(scope?.tenantId && scope?.workspace && enabled),
    queryFn: async () => {
      return apiClient.get<UsersResponse>("/users", {
        query: {
          limit,
          offset,
          q,
          include_inactive: includeInactive,
        },
      });
    },
  });
}

/**
 * Query one user's workspace role assignment.
 */
export function useUserRole(userId: string | null, enabled = true) {
  const scope = getStoredScope();

  return useQuery({
    queryKey: userRoleQueryKey({ tenantId: scope?.tenantId, workspace: scope?.workspace }, userId),
    enabled: Boolean(scope?.tenantId && scope?.workspace && userId && enabled),
    queryFn: async () => {
      return apiClient.get<UserRoleResponse>(`/users/${encodeURIComponent(String(userId))}/role`);
    },
  });
}

/**
 * Mutations for users and role assignments.
 */
export function useUsersAdminMutations() {
  const queryClient = useQueryClient();
  const scope = getStoredScope();

  const invalidateUsers = async () => {
    await queryClient.invalidateQueries({
      queryKey: ["users", scope?.tenantId, scope?.workspace],
    });
  };

  const createUser = useMutation({
    mutationFn: async (payload: CreateUserPayload) => {
      return apiClient.post<{ ok: true; user: UserItem }>("/users", payload);
    },
    onSuccess: invalidateUsers,
  });

  const deactivateUser = useMutation({
    mutationFn: async (params: { userId: string }) => {
      return apiClient.del<{ ok: true }>(`/users/${encodeURIComponent(params.userId)}`);
    },
    onSuccess: invalidateUsers,
  });

  const setUserRole = useMutation({
    mutationFn: async (params: { userId: string; payload: SetUserRolePayload }) => {
      return apiClient.put<UserRoleResponse>(
        `/users/${encodeURIComponent(params.userId)}/role`,
        params.payload,
      );
    },
    onSuccess: async (_data, params) => {
      await invalidateUsers();
      await queryClient.invalidateQueries({
        queryKey: userRoleQueryKey(
          { tenantId: scope?.tenantId, workspace: scope?.workspace },
          params.userId,
        ),
      });
    },
  });

  const setTenantRole = useMutation({
    mutationFn: async (params: { userId: string; payload: SetUserRolePayload }) => {
      return apiClient.put<{
        ok: true;
        summary: { targeted: number; assigned: number; skipped: number };
      }>(`/users/${encodeURIComponent(params.userId)}/role/tenant`, params.payload);
    },
    onSuccess: invalidateUsers,
  });

  return {
    createUser,
    deactivateUser,
    setUserRole,
    setTenantRole,
  };
}
