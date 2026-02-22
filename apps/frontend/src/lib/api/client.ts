import { getStoredScope } from "@/lib/scope";

type QueryValue = string | number | boolean | null | undefined;

export interface RequestOptions extends Omit<RequestInit, "body"> {
  query?: Record<string, QueryValue>;
  body?: unknown;
}

interface ApiErrorPayload {
  ok?: boolean;
  error?: string;
  message?: string;
}

/**
 * Typed error for API failures.
 */
export class ApiError extends Error {
  status: number;

  code: string | null;

  constructor(params: { status: number; code?: string | null; message: string }) {
    super(params.message);
    this.name = "ApiError";
    this.status = params.status;
    this.code = params.code ?? null;
  }
}

function getApiBaseUrl(): string {
  const baseUrl = process.env.NEXT_PUBLIC_API_URL;
  if (!baseUrl) {
    throw new Error("NEXT_PUBLIC_API_URL is not configured");
  }
  return baseUrl.replace(/\/+$/, "");
}

function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const url = new URL(`${getApiBaseUrl()}${normalizedPath}`);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") {
        continue;
      }
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

async function parseApiError(response: Response): Promise<ApiError> {
  let payload: ApiErrorPayload | null = null;
  try {
    payload = (await response.json()) as ApiErrorPayload;
  } catch {
    payload = null;
  }

  return new ApiError({
    status: response.status,
    code: payload?.error ?? null,
    message: payload?.message ?? `Request failed with status ${response.status}`,
  });
}

/**
 * Shared API client configured for cookie-based auth.
 */
export const apiClient = {
  async request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const scope = getStoredScope();
    const scopedQuery = {
      ...options.query,
      tenant_id: options.query?.tenant_id ?? scope?.tenantId,
      workspace: options.query?.workspace ?? scope?.workspace,
    };

    const headers = new Headers(options.headers ?? {});
    const hasBody = options.body !== undefined;
    if (hasBody && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }

    const response = await fetch(buildUrl(path, scopedQuery), {
      ...options,
      credentials: "include",
      headers,
      body: hasBody ? JSON.stringify(options.body) : undefined,
    });

    if (!response.ok) {
      throw await parseApiError(response);
    }

    const payload = (await response.json()) as ApiErrorPayload & T;
    if (payload.ok === false) {
      throw new ApiError({
        status: response.status,
        code: payload.error ?? null,
        message: payload.message ?? "Request failed",
      });
    }
    return payload as T;
  },

  get<T>(path: string, options: Omit<RequestOptions, "method" | "body"> = {}) {
    return this.request<T>(path, {
      ...options,
      method: "GET",
    });
  },

  post<T>(path: string, body?: unknown, options: Omit<RequestOptions, "method" | "body"> = {}) {
    return this.request<T>(path, {
      ...options,
      method: "POST",
      body,
    });
  },

  put<T>(path: string, body?: unknown, options: Omit<RequestOptions, "method" | "body"> = {}) {
    return this.request<T>(path, {
      ...options,
      method: "PUT",
      body,
    });
  },

  del<T>(path: string, options: Omit<RequestOptions, "method"> = {}) {
    return this.request<T>(path, {
      ...options,
      method: "DELETE",
    });
  },
};
