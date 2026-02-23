"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";

import { apiClient } from "@/lib/api/client";
import {
  clearStoredScope,
  getStoredScope,
  setStoredScope,
  TenantScope,
} from "@/lib/scope";

interface AuthUser {
  tenant_id: string;
  workspace: string;
  user_id: string;
  email: string;
  full_name: string;
  permissions: string[];
}

interface AuthMeResponse {
  ok: true;
  user: AuthUser;
}

interface LoginPayload extends TenantScope {
  email: string;
  password: string;
}

interface LoginResponse {
  ok: true;
  user: AuthUser;
  session_token: string;
  expires_at: string;
}

/**
 * Resolve current user and provide login/logout actions.
 */
export function useAuth() {
  const queryClient = useQueryClient();
  const scope = getStoredScope();

  const query = useQuery({
    queryKey: ["auth", "me", scope?.tenantId, scope?.workspace],
    enabled: Boolean(scope?.tenantId && scope?.workspace),
    queryFn: async () => {
      const response = await apiClient.get<AuthMeResponse>("/auth/me");
      return response.user;
    },
    retry: false,
  });

  async function login(payload: LoginPayload): Promise<void> {
    setStoredScope({
      tenantId: payload.tenantId,
      workspace: payload.workspace,
    });
    try {
      await apiClient.post<LoginResponse>("/auth/login", {
        tenant_id: payload.tenantId,
        workspace: payload.workspace,
        email: payload.email,
        password: payload.password,
      });
      await queryClient.invalidateQueries({ queryKey: ["auth"] });
    } catch (error) {
      clearStoredScope();
      throw error;
    }
  }

  async function logout(): Promise<void> {
    try {
      await apiClient.post("/auth/logout", {});
    } finally {
      clearStoredScope();
      queryClient.clear();
    }
  }

  return {
    user: query.data ?? null,
    isLoading: query.isLoading,
    isFetching: query.isFetching,
    isAuthenticated: Boolean(query.data),
    error: query.error,
    login,
    logout,
  };
}
