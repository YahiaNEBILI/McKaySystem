export interface TenantScope {
  tenantId: string;
  workspace: string;
}

const SCOPE_STORAGE_KEY = "mckay.tenant_scope";

/**
 * Read tenant scope from session storage.
 */
export function getStoredScope(): TenantScope | null {
  if (typeof window === "undefined") {
    return null;
  }
  const raw = window.sessionStorage.getItem(SCOPE_STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<TenantScope>;
    const tenantId = String(parsed.tenantId ?? "").trim();
    const workspace = String(parsed.workspace ?? "").trim();
    if (!tenantId || !workspace) {
      return null;
    }
    return { tenantId, workspace };
  } catch {
    return null;
  }
}

/**
 * Persist tenant scope in session storage.
 */
export function setStoredScope(scope: TenantScope): void {
  if (typeof window === "undefined") {
    return;
  }
  const payload: TenantScope = {
    tenantId: scope.tenantId.trim(),
    workspace: scope.workspace.trim(),
  };
  window.sessionStorage.setItem(SCOPE_STORAGE_KEY, JSON.stringify(payload));
}

/**
 * Remove tenant scope from session storage.
 */
export function clearStoredScope(): void {
  if (typeof window === "undefined") {
    return;
  }
  window.sessionStorage.removeItem(SCOPE_STORAGE_KEY);
}
