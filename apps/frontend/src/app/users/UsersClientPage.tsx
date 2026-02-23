"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { FormEvent, useEffect, useMemo, useState } from "react";

import { useAuth } from "@/hooks/useAuth";
import {
  UserItem,
  useRolesCatalog,
  useUserRole,
  useUsers,
  useUsersAdminMutations,
} from "@/hooks/useUsersAdmin";
import { ApiError } from "@/lib/api/client";
import { getStoredScope } from "@/lib/scope";

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

function apiErrorMessage(prefix: string, error: unknown): string {
  if (error instanceof ApiError) {
    const code = error.code ? ` (${error.code})` : "";
    return `${prefix} [${error.status}${code}]: ${error.message}`;
  }
  if (error instanceof Error) {
    return `${prefix}: ${error.message}`;
  }
  return prefix;
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

function userStatusBadgeClass(user: UserItem): string {
  if (user.is_superadmin) {
    return "border-fuchsia-300 bg-fuchsia-50 text-fuchsia-800";
  }
  if (user.is_active) {
    return "border-emerald-300 bg-emerald-50 text-emerald-800";
  }
  return "border-zinc-300 bg-zinc-100 text-zinc-700";
}

export function UsersClientPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const scope = getStoredScope();
  const auth = useAuth();
  const qFilter = searchParams.get("q") ?? "";
  const includeInactive = searchParams.get("include_inactive") === "true";
  const limit = parsePositiveInt(searchParams.get("limit"), 25);
  const page = parsePositiveInt(searchParams.get("page"), 1);
  const offset = (page - 1) * limit;
  const [searchInput, setSearchInput] = useState(qFilter);
  const [showCreate, setShowCreate] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [createFeedback, setCreateFeedback] = useState<string | null>(null);
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [roleIdInput, setRoleIdInput] = useState("viewer");
  const [grantedByInput, setGrantedByInput] = useState("");
  const [applyTenantWide, setApplyTenantWide] = useState(false);
  const [roleError, setRoleError] = useState<string | null>(null);
  const [roleFeedback, setRoleFeedback] = useState<string | null>(null);

  const permissions = useMemo(() => new Set(auth.user?.permissions ?? []), [auth.user?.permissions]);
  const isAdminFull = permissions.has("admin:full");
  const canReadFindings = isAdminFull || permissions.has("findings:read");
  const canReadUsers = isAdminFull || permissions.has("users:read");
  const canCreateUsers = isAdminFull || permissions.has("users:create");
  const canManageRoles = isAdminFull || permissions.has("users:manage_roles");
  const canDeleteUsers = isAdminFull || permissions.has("users:delete");

  useEffect(() => {
    setSearchInput(qFilter);
  }, [qFilter]);

  useEffect(() => {
    if (!scope) {
      router.replace("/login");
      return;
    }
    if (!auth.isLoading && !auth.isAuthenticated) {
      router.replace("/login");
    }
  }, [auth.isAuthenticated, auth.isLoading, router, scope]);

  const users = useUsers({
    limit,
    offset,
    q: qFilter,
    includeInactive,
    enabled: canReadUsers,
  });
  const rolesCatalog = useRolesCatalog(canManageRoles);
  const role = useUserRole(selectedUserId, canManageRoles);
  const mutations = useUsersAdminMutations();

  useEffect(() => {
    if (!selectedUserId) {
      return;
    }
    setGrantedByInput(auth.user?.email ?? "");
  }, [auth.user?.email, selectedUserId]);

  useEffect(() => {
    const currentRoleId = role.data?.role?.role_id;
    if (currentRoleId) {
      setRoleIdInput(currentRoleId);
      return;
    }
    const selectedUserRoleId = selectedUserId
      ? users.data?.items.find((item) => item.user_id === selectedUserId)?.role_id
      : null;
    if (selectedUserRoleId) {
      setRoleIdInput(selectedUserRoleId);
      return;
    }
    if (!role.data || role.data.role === null) {
      setRoleIdInput("viewer");
    }
  }, [role.data, selectedUserId, users.data?.items]);

  useEffect(() => {
    const catalogItems = rolesCatalog.data?.items ?? [];
    if (catalogItems.length === 0) {
      return;
    }
    const exists = catalogItems.some((item) => item.role_id === roleIdInput);
    if (!exists) {
      setRoleIdInput(catalogItems[0].role_id);
    }
  }, [roleIdInput, rolesCatalog.data?.items]);

  if (!scope) {
    return null;
  }
  const activeScope = scope;

  const selectedUser =
    users.data?.items.find((item) => item.user_id === selectedUserId) ?? null;
  const total = users.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const canPrev = page > 1;
  const canNext = page < totalPages;
  const pageStart = total === 0 ? 0 : offset + 1;
  const pageEnd = total === 0 ? 0 : Math.min(offset + (users.data?.items.length ?? 0), total);
  const activeCount = (users.data?.items ?? []).filter((item) => item.is_active).length;
  const superadminCount = (users.data?.items ?? []).filter((item) => item.is_superadmin).length;
  const assignedRoleCount = (users.data?.items ?? []).filter((item) => Boolean(item.role_id)).length;

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
    router.push(query ? `/users?${query}` : "/users");
  }

  async function submitCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canCreateUsers) {
      return;
    }
    const formData = new FormData(event.currentTarget);
    const userId = String(formData.get("user_id") ?? "").trim();
    const email = String(formData.get("email") ?? "").trim();
    const fullName = String(formData.get("full_name") ?? "").trim();
    const password = String(formData.get("password") ?? "").trim();
    const isSuperadmin = formData.get("is_superadmin") === "on";
    if (!userId || !email) {
      setCreateError("User ID and email are required.");
      return;
    }
    setCreateError(null);
    setCreateFeedback(null);
    try {
      await mutations.createUser.mutateAsync({
        tenant_id: activeScope.tenantId,
        workspace: activeScope.workspace,
        user_id: userId,
        email,
        full_name: fullName || undefined,
        password: password || undefined,
        is_superadmin: isSuperadmin,
      });
      setCreateFeedback("User created.");
      event.currentTarget.reset();
      setShowCreate(false);
    } catch (error) {
      setCreateError(apiErrorMessage("Failed to create user", error));
    }
  }

  async function deactivateUser(user: UserItem) {
    if (!canDeleteUsers || !user.is_active) {
      return;
    }
    const confirmed = window.confirm(`Deactivate user ${user.email}?`);
    if (!confirmed) {
      return;
    }
    try {
      await mutations.deactivateUser.mutateAsync({ userId: user.user_id });
    } catch (error) {
      setRoleError(apiErrorMessage("Failed to deactivate user", error));
    }
  }

  async function saveRole() {
    if (!selectedUser || !canManageRoles) {
      return;
    }
    const roleId = roleIdInput.trim();
    if (!roleId) {
      setRoleError("Role ID is required.");
      return;
    }

    setRoleError(null);
    setRoleFeedback(null);
    const payload = {
      tenant_id: activeScope.tenantId,
      workspace: activeScope.workspace,
      role_id: roleId,
      granted_by: grantedByInput.trim() || undefined,
    };

    try {
      if (applyTenantWide) {
        const result = await mutations.setTenantRole.mutateAsync({
          userId: selectedUser.user_id,
          payload,
        });
        const summary = result.summary;
        setRoleFeedback(
          `Tenant role updated: ${summary.assigned}/${summary.targeted} assigned, ${summary.skipped} skipped.`,
        );
      } else {
        await mutations.setUserRole.mutateAsync({
          userId: selectedUser.user_id,
          payload,
        });
        await role.refetch();
        setRoleFeedback("Workspace role updated.");
      }
    } catch (error) {
      setRoleError(apiErrorMessage("Failed to update role", error));
    }
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
              Access Governance
            </p>
            <h1 className="font-display mt-2 text-2xl font-semibold tracking-tight text-slate-900 md:text-3xl">
              Users and Roles
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
            {canReadFindings ? (
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
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-100/85">Total Users</p>
          <p className="font-display mt-1 text-2xl font-semibold text-white">{total}</p>
        </article>
        <article className="rounded-xl border border-cyan-300/35 bg-slate-900/45 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-100/85">Active (page)</p>
          <p className="font-display mt-1 text-2xl font-semibold text-white">{activeCount}</p>
        </article>
        <article className="rounded-xl border border-cyan-300/35 bg-slate-900/45 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-100/85">Assigned Role</p>
          <p className="font-display mt-1 text-2xl font-semibold text-white">{assignedRoleCount}</p>
        </article>
        <article className="rounded-xl border border-cyan-300/35 bg-slate-900/45 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-100/85">Superadmins</p>
          <p className="font-display mt-1 text-2xl font-semibold text-white">{superadminCount}</p>
        </article>
      </section>

      {!canReadUsers ? (
        <div className="mb-4 rounded-xl border border-amber-300 bg-amber-50 p-3 text-sm text-amber-800">
          Missing permission `users:read` to list users in this workspace.
        </div>
      ) : null}

      {canReadUsers ? (
        <>
          <section className="finops-panel mb-3 rounded-2xl p-4 text-sm">
            <div className="grid gap-3 md:grid-cols-4">
              <label className="block md:col-span-2">
                <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">
                  Search users
                </span>
                <form
                  className="flex gap-2"
                  onSubmit={(event) => {
                    event.preventDefault();
                    pushWithParams({ q: searchInput.trim() || null, page: "1" });
                  }}
                >
                  <input
                    className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
                    value={searchInput}
                    onChange={(event) => {
                      setSearchInput(event.target.value);
                    }}
                    placeholder="email, user_id, full name"
                  />
                  <button
                    type="submit"
                    className="rounded-lg border border-cyan-300 bg-cyan-50 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-cyan-800 transition hover:border-cyan-400 hover:bg-cyan-100"
                  >
                    Apply
                  </button>
                </form>
              </label>

              <label className="block">
                <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">
                  Page size
                </span>
                <select
                  className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
                  value={String(limit)}
                  onChange={(event) => {
                    pushWithParams({ limit: event.target.value, page: "1" });
                  }}
                >
                  <option value="10">10</option>
                  <option value="25">25</option>
                  <option value="50">50</option>
                  <option value="100">100</option>
                </select>
              </label>

              <label className="flex items-end">
                <input
                  type="checkbox"
                  checked={includeInactive}
                  onChange={(event) => {
                    pushWithParams({
                      include_inactive: event.target.checked ? "true" : null,
                      page: "1",
                    });
                  }}
                />
                <span className="ml-2 text-sm text-slate-700">Include inactive users</span>
              </label>
            </div>
          </section>

          <section className="finops-panel mb-4 rounded-2xl p-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-700">
                User Management
              </h2>
              {canCreateUsers ? (
                <button
                  type="button"
                  className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-700 transition hover:bg-slate-100"
                  onClick={() => {
                    setShowCreate((prev) => !prev);
                    setCreateError(null);
                    setCreateFeedback(null);
                  }}
                >
                  {showCreate ? "Close" : "Create User"}
                </button>
              ) : null}
            </div>

            {showCreate ? (
              <form className="mt-3 grid gap-3 md:grid-cols-2" onSubmit={submitCreate}>
                <label className="block text-sm">
                  <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">
                    User ID
                  </span>
                  <input
                    name="user_id"
                    className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
                    required
                  />
                </label>
                <label className="block text-sm">
                  <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">
                    Email
                  </span>
                  <input
                    type="email"
                    name="email"
                    className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
                    required
                  />
                </label>
                <label className="block text-sm">
                  <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">
                    Full name
                  </span>
                  <input name="full_name" className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200" />
                </label>
                <label className="block text-sm">
                  <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">
                    Password (optional)
                  </span>
                  <input
                    type="password"
                    name="password"
                    className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
                  />
                </label>
                <label className="flex items-center text-sm">
                  <input type="checkbox" name="is_superadmin" />
                  <span className="ml-2 text-slate-700">Superadmin</span>
                </label>
                <div className="flex items-center justify-end">
                  <button
                    type="submit"
                    disabled={mutations.createUser.isPending}
                    className="rounded-lg border border-cyan-300 bg-cyan-50 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-cyan-800 transition hover:bg-cyan-100 disabled:opacity-50"
                  >
                    {mutations.createUser.isPending ? "Creating..." : "Create"}
                  </button>
                </div>
              </form>
            ) : null}

            {createError ? (
              <p className="mt-2 rounded border border-red-300 bg-red-50 px-2 py-1 text-xs text-red-700">
                {createError}
              </p>
            ) : null}
            {createFeedback ? (
              <p className="mt-2 rounded border border-emerald-300 bg-emerald-50 px-2 py-1 text-xs text-emerald-700">
                {createFeedback}
              </p>
            ) : null}
          </section>

          {users.isLoading ? <p className="rounded-xl bg-white/80 px-3 py-2 text-sm text-slate-700">Loading users...</p> : null}
          {users.error ? (
            <div className="mb-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-700">
              <p>{apiErrorMessage("Failed to load users", users.error)}</p>
              <button
                type="button"
                className="mt-2 rounded-lg border border-red-300 bg-white px-2.5 py-1.5 text-xs font-medium"
                onClick={() => {
                  void users.refetch();
                }}
              >
                Retry
              </button>
            </div>
          ) : null}

          {!users.isLoading && users.data ? (
            <>
              <div className="finops-panel overflow-x-auto rounded-2xl">
                <table className="min-w-full text-left text-sm text-slate-700">
                  <thead className="finops-table-head text-xs uppercase tracking-wide text-slate-600">
                    <tr>
                      <th className="px-3 py-2">Email</th>
                      <th className="px-3 py-2">User ID</th>
                      <th className="px-3 py-2">Full name</th>
                      <th className="px-3 py-2">Provider</th>
                      <th className="px-3 py-2">Role</th>
                      <th className="px-3 py-2">Last login</th>
                      <th className="px-3 py-2">Status</th>
                      <th className="px-3 py-2">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.data.items.map((user) => (
                      <tr
                        key={user.user_id}
                        className={`border-t border-slate-100 transition ${selectedUserId === user.user_id ? "bg-cyan-50/70" : "hover:bg-slate-50/70"}`}
                      >
                        <td className="px-3 py-2">{user.email}</td>
                        <td className="px-3 py-2">{user.user_id}</td>
                        <td className="px-3 py-2">{user.full_name ?? "-"}</td>
                        <td className="px-3 py-2">{user.auth_provider ?? "-"}</td>
                        <td className="px-3 py-2">
                          {user.role_id ? (
                            <span className="inline-flex items-center rounded border border-cyan-300 bg-cyan-50 px-2 py-0.5 text-xs font-medium text-cyan-800">
                              {user.role_name ? `${user.role_name} (${user.role_id})` : user.role_id}
                            </span>
                          ) : (
                            <span className="inline-flex items-center rounded border border-zinc-300 bg-zinc-100 px-2 py-0.5 text-xs text-zinc-600">
                              Unassigned
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-2">{formatDateTime(user.last_login_at)}</td>
                        <td className="px-3 py-2">
                          <span className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium ${userStatusBadgeClass(user)}`}>
                            {user.is_active ? "Active" : "Inactive"}
                            {user.is_superadmin ? " / Superadmin" : ""}
                          </span>
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex flex-wrap gap-2">
                            {canManageRoles ? (
                              <button
                                type="button"
                                className="rounded-lg border border-cyan-300 bg-cyan-50 px-2.5 py-1 text-xs font-semibold uppercase tracking-wide text-cyan-800 transition hover:bg-cyan-100"
                                onClick={() => {
                                  setSelectedUserId(user.user_id);
                                  setRoleError(null);
                                  setRoleFeedback(null);
                                  setApplyTenantWide(false);
                                }}
                              >
                                Manage Role
                              </button>
                            ) : null}
                            {canDeleteUsers && user.is_active ? (
                              <button
                                type="button"
                                className="rounded-lg border border-rose-300 bg-rose-50 px-2.5 py-1 text-xs font-semibold uppercase tracking-wide text-rose-700 transition hover:bg-rose-100"
                                onClick={() => {
                                  void deactivateUser(user);
                                }}
                              >
                                Deactivate
                              </button>
                            ) : null}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {users.data.items.length === 0 ? (
                <p className="mt-3 rounded-xl bg-white/80 px-3 py-2 text-sm text-slate-600">No users match the current filters.</p>
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
        </>
      ) : null}

      {selectedUser ? (
        <div className="fixed inset-0 z-50 flex">
          <button
            type="button"
            className="h-full flex-1 bg-slate-950/55"
            aria-label="Close role drawer"
            onClick={() => {
              setSelectedUserId(null);
              setRoleError(null);
              setRoleFeedback(null);
            }}
          />
          <aside className="h-full w-full max-w-xl overflow-y-auto border-l border-slate-200 bg-white/95 p-6 shadow-2xl backdrop-blur">
            <div className="mb-4 flex items-start justify-between gap-4">
              <div>
                <h2 className="text-xl font-semibold text-slate-900">Manage Role</h2>
                <p className="mt-1 text-sm text-slate-600">
                  {selectedUser.email} ({selectedUser.user_id})
                </p>
              </div>
              <button
                type="button"
                className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700"
                onClick={() => {
                  setSelectedUserId(null);
                  setRoleError(null);
                  setRoleFeedback(null);
                }}
              >
                Close
              </button>
            </div>

            {role.isLoading ? <p className="text-sm text-slate-700">Loading role...</p> : null}
            {role.error ? (
              <p className="rounded border border-red-300 bg-red-50 px-2 py-1 text-xs text-red-700">
                {apiErrorMessage("Failed to load role", role.error)}
              </p>
            ) : null}

            <div className="mt-3 space-y-3 text-slate-700">
              <label className="block text-sm">
                <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">
                  Role ID
                </span>
                {rolesCatalog.data?.items && rolesCatalog.data.items.length > 0 ? (
                  <select
                    value={roleIdInput}
                    onChange={(event) => {
                      setRoleIdInput(event.target.value);
                    }}
                    className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
                    disabled={!canManageRoles}
                  >
                    {rolesCatalog.data.items.map((item) => (
                      <option key={item.role_id} value={item.role_id}>
                        {item.name ? `${item.name} (${item.role_id})` : item.role_id}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    value={roleIdInput}
                    onChange={(event) => {
                      setRoleIdInput(event.target.value);
                    }}
                    className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
                    disabled={!canManageRoles}
                    placeholder="viewer"
                  />
                )}
              </label>
              {rolesCatalog.error ? (
                <p className="rounded border border-amber-300 bg-amber-50 px-2 py-1 text-xs text-amber-800">
                  {apiErrorMessage("Failed to load roles catalog", rolesCatalog.error)}
                </p>
              ) : null}

              <label className="block text-sm">
                <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-600">
                  Granted by (optional)
                </span>
                <input
                  value={grantedByInput}
                  onChange={(event) => {
                    setGrantedByInput(event.target.value);
                  }}
                  className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200"
                  disabled={!canManageRoles}
                  placeholder={auth.user?.email ?? "admin@tenant.io"}
                />
              </label>

              <label className="flex items-center text-sm">
                <input
                  type="checkbox"
                  checked={applyTenantWide}
                  onChange={(event) => {
                    setApplyTenantWide(event.target.checked);
                  }}
                  disabled={!canManageRoles || !isAdminFull}
                />
                <span className="ml-2">
                  Apply role to all existing tenant workspaces (requires `admin:full`)
                </span>
              </label>

              {role.data?.role ? (
                <section className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                  <h3 className="text-sm font-semibold text-slate-900">Current Role</h3>
                  <p className="mt-1 text-xs text-slate-700">
                    {role.data.role.role_id} {role.data.role.name ? `(${role.data.role.name})` : ""}
                  </p>
                  <p className="mt-1 text-xs text-slate-600">
                    Granted by: {role.data.role.granted_by ?? "-"} | Granted at:{" "}
                    {formatDateTime(role.data.role.granted_at)}
                  </p>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {role.data.role.permissions.length > 0 ? (
                      role.data.role.permissions.map((permission) => (
                        <span
                          key={permission}
                          className="rounded border border-slate-300 bg-white px-2 py-0.5 text-[11px]"
                        >
                          {permission}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-slate-500">No permissions returned.</span>
                    )}
                  </div>
                </section>
              ) : (
                <p className="text-xs text-slate-600">No role assignment in this workspace.</p>
              )}

              {roleError ? (
                <p className="rounded border border-red-300 bg-red-50 px-2 py-1 text-xs text-red-700">
                  {roleError}
                </p>
              ) : null}
              {roleFeedback ? (
                <p className="rounded border border-emerald-300 bg-emerald-50 px-2 py-1 text-xs text-emerald-700">
                  {roleFeedback}
                </p>
              ) : null}

              <div className="flex items-center justify-end">
                <button
                  type="button"
                  className="rounded-lg border border-cyan-300 bg-cyan-50 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-cyan-800 transition hover:border-cyan-400 hover:bg-cyan-100 disabled:opacity-50"
                  disabled={
                    !canManageRoles || mutations.setUserRole.isPending || mutations.setTenantRole.isPending
                  }
                  onClick={() => {
                    void saveRole();
                  }}
                >
                  {mutations.setUserRole.isPending || mutations.setTenantRole.isPending
                    ? "Saving..."
                    : "Save Role"}
                </button>
              </div>
            </div>
          </aside>
        </div>
      ) : null}
      </div>
    </main>
  );
}
