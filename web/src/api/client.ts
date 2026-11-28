import type {
  AuditLogItem,
  AuditVerifyResponse,
  CveFeedImportRequest,
  CveFeedImportResponse,
  CveSearchResponse,
  DriftResponse,
  DryRunOutcomeInput,
  EnrollmentTokenCreateRequest,
  EnrollmentTokenResponse,
  FindingItem,
  FleetRescanResponse,
  HostDetailResponse,
  HostListItem,
  PackageRecord,
  PaginatedResponse,
  PatchPlanCreateRequest,
  PatchPlanItem,
  SnapshotCreatedResponse,
  SnapshotSummary,
  TokenResponse,
  ToolBundleManifestResponse,
  ToolBundleRegisterInput,
  UserCreateRequest,
  UserProfile,
  UserUpdateRequest,
  WaveHealthReportInput,
} from "../types/api";

const TOKEN_STORAGE_KEY = "hostgrid_access_token";
let unauthorizedListener: (() => void) | null = null;

export function registerUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedListener = handler;
}

export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

export function getStoredToken(): string | null {
  try {
    return window.sessionStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setStoredToken(token: string | null): void {
  try {
    if (token === null) {
      window.sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    } else {
      window.sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
    }
  } catch {
    // Ignore storage unavailability in restricted contexts.
  }
}

async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getStoredToken();
  const headers = new Headers(init.headers);
  if (token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const resp = await fetch(path, { ...init, headers });
  if (!resp.ok) {
    if (resp.status === 401 && path !== "/api/v1/auth/login" && unauthorizedListener) {
      unauthorizedListener();
    }
    let detail = `Error HTTP ${resp.status}`;
    try {
      const problem = (await resp.json()) as { detail?: string; title?: string };
      detail = problem.detail || problem.title || detail;
    } catch {
      // Non-JSON error body.
    }
    throw new ApiError(resp.status, detail);
  }
  return (await resp.json()) as T;
}

async function apiTextRequest(path: string, init: RequestInit = {}): Promise<string> {
  const token = getStoredToken();
  const headers = new Headers(init.headers);
  if (token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const resp = await fetch(path, { ...init, headers });
  if (!resp.ok) {
    if (resp.status === 401 && unauthorizedListener) {
      unauthorizedListener();
    }
    let detail = `Error HTTP ${resp.status}`;
    try {
      const problem = (await resp.json()) as { detail?: string; title?: string };
      detail = problem.detail || problem.title || detail;
    } catch {
      // Non-JSON error body.
    }
    throw new ApiError(resp.status, detail);
  }
  return await resp.text();
}

export interface HostFilters {
  readonly search?: string;
  readonly os_family?: string;
  readonly eol_status?: string;
  readonly connectivity_mode?: string;
  readonly repo_access_ok?: string;
}

function createIdempotencyKey(): string {
  if (typeof globalThis.crypto?.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  if (typeof globalThis.crypto?.getRandomValues === "function") {
    globalThis.crypto.getRandomValues(bytes);
  }
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export const hostGridApi = {
  login(username: string, password: string): Promise<TokenResponse> {
    return apiRequest<TokenResponse>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
  },

  me(): Promise<UserProfile> {
    return apiRequest<UserProfile>("/api/v1/auth/me");
  },

  listHosts(filters: HostFilters = {}): Promise<PaginatedResponse<HostListItem>> {
    const params = new URLSearchParams();
    params.set("limit", "100");
    if (filters.search) params.set("search", filters.search);
    if (filters.os_family) params.set("os_family", filters.os_family);
    if (filters.eol_status) params.set("eol_status", filters.eol_status);
    if (filters.connectivity_mode) params.set("connectivity_mode", filters.connectivity_mode);
    if (filters.repo_access_ok === "true" || filters.repo_access_ok === "false") {
      params.set("repo_access_ok", filters.repo_access_ok);
    }
    return apiRequest<PaginatedResponse<HostListItem>>(`/api/v1/hosts?${params.toString()}`);
  },

  getHost(hostId: string): Promise<HostDetailResponse> {
    return apiRequest<HostDetailResponse>(`/api/v1/hosts/${encodeURIComponent(hostId)}`);
  },

  listHostSnapshots(hostId: string): Promise<PaginatedResponse<SnapshotSummary>> {
    return apiRequest<PaginatedResponse<SnapshotSummary>>(
      `/api/v1/hosts/${encodeURIComponent(hostId)}/snapshots?limit=50`
    );
  },

  listHostPackages(hostId: string, search?: string): Promise<PaginatedResponse<PackageRecord>> {
    const params = new URLSearchParams({ limit: "100" });
    if (search) params.set("search", search);
    return apiRequest<PaginatedResponse<PackageRecord>>(
      `/api/v1/hosts/${encodeURIComponent(hostId)}/packages?${params.toString()}`
    );
  },

  listSnapshotFindings(
    snapshotId: string,
    severity?: string,
    category?: string
  ): Promise<PaginatedResponse<FindingItem>> {
    const params = new URLSearchParams({ limit: "100" });
    if (severity) params.set("severity", severity);
    if (category) params.set("category", category);
    return apiRequest<PaginatedResponse<FindingItem>>(
      `/api/v1/snapshots/${encodeURIComponent(snapshotId)}/findings?${params.toString()}`
    );
  },

  getSnapshotDrift(snapshotId: string): Promise<DriftResponse> {
    return apiRequest<DriftResponse>(
      `/api/v1/snapshots/${encodeURIComponent(snapshotId)}/drift`
    );
  },

  searchCves(query: string): Promise<CveSearchResponse> {
    const params = new URLSearchParams({ q: query });
    return apiRequest<CveSearchResponse>(`/api/v1/cves/search?${params.toString()}`);
  },

  importBundle(file: File): Promise<SnapshotCreatedResponse> {
    const form = new FormData();
    form.append("file", file);
    return apiRequest<SnapshotCreatedResponse>("/api/v1/snapshots/import-bundle", {
      method: "POST",
      body: form,
    });
  },

  importAgentless(payloadJson: string): Promise<SnapshotCreatedResponse> {
    return apiRequest<SnapshotCreatedResponse>("/api/v1/snapshots/import-agentless", {
      method: "POST",
      body: payloadJson,
    });
  },

  exportHostReport(hostId: string, format: "json" | "sarif"): Promise<Record<string, unknown>> {
    return apiRequest<Record<string, unknown>>(
      `/api/v1/reports/hosts/${encodeURIComponent(hostId)}?format=${format}`
    );
  },

  exportHostTextReport(hostId: string, format: "markdown" | "html"): Promise<string> {
    return apiTextRequest(
      `/api/v1/reports/hosts/${encodeURIComponent(hostId)}?format=${format}`
    );
  },

  importCveFeed(payload: CveFeedImportRequest): Promise<CveFeedImportResponse> {
    return apiRequest<CveFeedImportResponse>("/api/v1/cves/import-feed", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  rescanFleetCves(): Promise<FleetRescanResponse> {
    return apiRequest<FleetRescanResponse>("/api/v1/cves/rescan-fleet", {
      method: "POST",
    });
  },

  listAuditLogs(limit = 50): Promise<PaginatedResponse<AuditLogItem>> {
    return apiRequest<PaginatedResponse<AuditLogItem>>(`/api/v1/audit/logs?limit=${limit}`);
  },

  verifyWormAudit(): Promise<AuditVerifyResponse> {
    return apiRequest<AuditVerifyResponse>("/api/v1/audit/verify");
  },

  listPatchPlans(statusFilter?: string): Promise<PaginatedResponse<PatchPlanItem>> {
    const params = new URLSearchParams({ limit: "50" });
    if (statusFilter) params.set("status", statusFilter);
    return apiRequest<PaginatedResponse<PatchPlanItem>>(
      `/api/v1/patching/plans?${params.toString()}`
    );
  },

  createPatchPlan(payload: PatchPlanCreateRequest, idempotencyKey?: string): Promise<PatchPlanItem> {
    return apiRequest<PatchPlanItem>("/api/v1/patching/plans", {
      method: "POST",
      headers: { "Idempotency-Key": idempotencyKey ?? createIdempotencyKey() },
      body: JSON.stringify(payload),
    });
  },

  submitPatchDryRun(
    planId: string,
    outcomes: readonly DryRunOutcomeInput[]
  ): Promise<PatchPlanItem> {
    return apiRequest<PatchPlanItem>(
      `/api/v1/patching/plans/${encodeURIComponent(planId)}/dry-run`,
      {
        method: "POST",
        body: JSON.stringify({ outcomes }),
      }
    );
  },

  decidePatchPlan(
    planId: string,
    decision: "approved" | "rejected",
    rationale: string
  ): Promise<PatchPlanItem> {
    return apiRequest<PatchPlanItem>(
      `/api/v1/patching/plans/${encodeURIComponent(planId)}/decision`,
      {
        method: "POST",
        body: JSON.stringify({ decision, rationale }),
      }
    );
  },

  startCanaryExecution(planId: string): Promise<PatchPlanItem> {
    return apiRequest<PatchPlanItem>(
      `/api/v1/patching/plans/${encodeURIComponent(planId)}/execute`,
      { method: "POST" }
    );
  },

  reportWaveHealth(planId: string, payload: WaveHealthReportInput): Promise<PatchPlanItem> {
    return apiRequest<PatchPlanItem>(
      `/api/v1/patching/plans/${encodeURIComponent(planId)}/wave-report`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      }
    );
  },

  listUsers(limit = 50, offset = 0): Promise<PaginatedResponse<UserProfile>> {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    return apiRequest<PaginatedResponse<UserProfile>>(`/api/v1/users?${params.toString()}`);
  },

  createUser(payload: UserCreateRequest): Promise<UserProfile> {
    return apiRequest<UserProfile>("/api/v1/users", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  updateUser(userId: string, payload: UserUpdateRequest): Promise<UserProfile> {
    return apiRequest<UserProfile>(`/api/v1/users/${encodeURIComponent(userId)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  },

  createEnrollmentToken(
    payload: EnrollmentTokenCreateRequest
  ): Promise<EnrollmentTokenResponse> {
    return apiRequest<EnrollmentTokenResponse>("/api/v1/enrollments/tokens", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  registerToolBundle(input: ToolBundleRegisterInput): Promise<ToolBundleManifestResponse> {
    const form = new FormData();
    form.append("tool_name", input.tool_name);
    form.append("version", input.version);
    form.append("arch", input.arch);
    form.append("file", input.file);
    if (input.signature_b64 && input.signature_b64.trim()) {
      form.append("signature_b64", input.signature_b64.trim());
    }
    return apiRequest<ToolBundleManifestResponse>("/api/v1/bundles/register", {
      method: "POST",
      body: form,
    });
  },
};
