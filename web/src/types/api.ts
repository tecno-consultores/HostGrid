export type UserRole = "admin" | "approver" | "operator" | "viewer";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type EolStatus = "supported" | "approaching_eol" | "eol" | "unknown";
export type ConnectivityMode = "lan" | "relay" | "airgapped" | "agentless";
export type EnvironmentType = "prod" | "staging" | "dev" | "dmz";
export type ToolBundleArch = "noarch" | "amd64" | "arm64" | "386";

export interface UserProfile {
  readonly id: string;
  readonly username: string;
  readonly email: string;
  readonly role: UserRole;
  readonly is_active: boolean;
}

export interface TokenResponse {
  readonly access_token: string;
  readonly token_type: "bearer";
  readonly expires_at: string;
  readonly user: UserProfile;
}

export interface PaginatedResponse<T> {
  readonly items: readonly T[];
  readonly total: number;
  readonly limit: number;
  readonly offset: number;
}

export interface CapabilityItem {
  readonly status: "supported" | "not_supported_on_os" | "error";
  readonly binary?: string | null;
  readonly reason?: string | null;
  readonly fallback_used: boolean;
}

export interface HostListItem {
  readonly id: string;
  readonly hostname: string;
  readonly os_family: string;
  readonly os_name: string;
  readonly os_version: string;
  readonly kernel_version: string;
  readonly arch: string;
  readonly init_system: string;
  readonly connectivity_mode: ConnectivityMode;
  readonly environment: string;
  readonly eol_status: EolStatus;
  readonly eol_date: string | null;
  readonly repo_access_ok: boolean | null;
  readonly last_hardening_index: number | null;
  readonly last_hardening_delta: number | null;
  readonly last_lynis_version: string | null;
  readonly critical_cves_count: number;
  readonly high_cves_count: number;
  readonly last_seen_at: string | null;
}

export interface HostDetailResponse extends HostListItem {
  readonly machine_id_hash: string;
  readonly capabilities: Readonly<Record<string, CapabilityItem>>;
  readonly latest_snapshot_id: string | null;
  readonly latest_snapshot_at: string | null;
  readonly total_snapshots: number;
}

export interface SnapshotSummary {
  readonly id: string;
  readonly host_id: string;
  readonly previous_snapshot_id: string | null;
  readonly ingestion_source: string;
  readonly agent_version: string;
  readonly collected_at: string;
  readonly ingested_at: string;
  readonly hardening_index: number | null;
  readonly lynis_version: string | null;
  readonly tests_executed: number;
  readonly tests_skipped: number;
  readonly warnings_count: number;
  readonly suggestions_count: number;
  readonly critical_cves_count: number;
  readonly high_cves_count: number;
  readonly bundle_sha256: string | null;
}

export interface FindingItem {
  readonly id: string;
  readonly snapshot_id: string;
  readonly host_id: string;
  readonly fingerprint: string;
  readonly rule_id: string;
  readonly source_tool: string;
  readonly category: string;
  readonly severity: Severity;
  readonly base_severity: Severity;
  readonly confidence: string;
  readonly title: string;
  readonly description: string;
  readonly evidence: Readonly<Record<string, unknown>>;
  readonly remediation: string;
  readonly reference_ids: readonly string[];
  readonly contextual_score: number;
  readonly contextual_factors: readonly string[];
}

export interface DriftItem {
  readonly fingerprint: string;
  readonly status: "new" | "resolved" | "persisted";
  readonly severity: Severity;
  readonly previous_severity: Severity | null;
  readonly category: string;
  readonly title: string;
}

export interface DriftResponse {
  readonly snapshot_id: string;
  readonly previous_snapshot_id: string | null;
  readonly hardening_index_current: number | null;
  readonly hardening_index_previous: number | null;
  readonly hardening_index_delta: number | null;
  readonly summary: Readonly<{
    new: number;
    resolved: number;
    persisted: number;
  }>;
  readonly items: readonly DriftItem[];
}

export interface PackageRecord {
  readonly package_manager: string;
  readonly name: string;
  readonly source_package: string | null;
  readonly epoch: string | null;
  readonly version: string;
  readonly release: string | null;
  readonly arch: string;
}

export interface CveSearchItem {
  readonly host_id: string;
  readonly hostname: string;
  readonly os: string;
  readonly eol_status: EolStatus;
  readonly cve_id: string | null;
  readonly package_name: string;
  readonly installed_version: string;
  readonly fixed_version: string | null;
  readonly effective_severity: Severity;
  readonly exposed_network: boolean;
  readonly exposed_ports: readonly string[];
  readonly last_snapshot_at: string | null;
}

export interface CveSearchResponse {
  readonly query: string;
  readonly total: number;
  readonly items: readonly CveSearchItem[];
}

export interface SnapshotCreatedResponse {
  readonly snapshot_id: string;
  readonly host_id: string;
  readonly previous_snapshot_id: string | null;
  readonly ingestion_source: string;
  readonly hardening_index: number | null;
  readonly eol_status: EolStatus;
  readonly findings_total: number;
  readonly critical_cves_count: number;
  readonly high_cves_count: number;
  readonly drift_summary: Readonly<Record<string, number>>;
  readonly bundle_sha256: string | null;
}

export interface AuditVerifyResponse {
  readonly valid: boolean;
  readonly checked_records: number;
  readonly first_seq_num: number | null;
  readonly last_seq_num: number | null;
  readonly last_record_hash: string | null;
  readonly broken_at_seq_num: number | null;
}

export interface AuditLogItem {
  readonly seq_num: number;
  readonly id: string;
  readonly occurred_at: string;
  readonly actor_id: string | null;
  readonly actor_username: string;
  readonly action: string;
  readonly resource_type: string;
  readonly resource_id: string;
  readonly details: Readonly<Record<string, unknown>>;
  readonly prev_record_hash: string;
  readonly record_hash: string;
}

export type CveFeedFormat = "osv" | "trivy" | "oval";

export interface CveFeedImportRequest {
  readonly feed_format: CveFeedFormat;
  readonly ecosystem?: string | null;
  readonly payload: string;
  readonly rescan_fleet: boolean;
}

export interface CveFeedImportResponse {
  readonly feed_format: CveFeedFormat;
  readonly parsed: number;
  readonly upserted: number;
  readonly hosts_rescanned: number;
  readonly total_cve_matches: number;
}

export interface FleetRescanResponse {
  readonly hosts_rescanned: number;
  readonly total_cve_matches: number;
  readonly critical_matches: number;
  readonly high_matches: number;
}

export type PatchPlanStatus =
  | "DRAFT"
  | "REPO_PRECHECK"
  | "FAILED_PRECHECK"
  | "DRY_RUN_READY"
  | "PENDING_APPROVAL"
  | "APPROVED"
  | "REJECTED"
  | "CANARY_WAVE"
  | "ROLLOUT_IN_PROGRESS"
  | "COMPLETED"
  | "ROLLED_BACK";

export interface PatchApprovalItem {
  readonly id: string;
  readonly patch_plan_id: string;
  readonly approver_id: string;
  readonly approver_username: string;
  readonly decision: "approved" | "rejected";
  readonly rationale: string;
  readonly decided_at: string;
}

export interface CanaryWaveItem {
  readonly wave_number: number;
  readonly is_canary: boolean;
  readonly host_ids: readonly string[];
}

export interface PatchPlanItem {
  readonly id: string;
  readonly title: string;
  readonly target_host_ids: readonly string[];
  readonly packages: readonly string[];
  readonly canary_percent: number;
  readonly status: PatchPlanStatus;
  readonly created_by: string;
  readonly created_by_username: string;
  readonly created_at: string;
  readonly updated_at: string;
  readonly precheck: Readonly<{
    passed?: boolean;
    eligible_host_ids?: readonly string[];
    blocked_host_ids?: readonly string[];
  }>;
  readonly policy: Readonly<{
    canary_percent?: number;
    max_wave_percent?: number;
    safe_mode_enabled?: boolean;
    max_failed_hosts?: number;
    rollback_on_unreachable?: boolean;
  }>;
  readonly waves: readonly CanaryWaveItem[];
  readonly active_wave_number: number | null;
  readonly dry_run_report: Readonly<Record<string, unknown>> | null;
  readonly wave_reports: readonly Readonly<Record<string, unknown>>[];
  readonly approvals: readonly PatchApprovalItem[];
}

export interface PatchPlanCreateRequest {
  readonly title: string;
  readonly target_host_ids: readonly string[];
  readonly packages: readonly string[];
  readonly canary_percent: number;
  readonly max_wave_percent: number;
  readonly safe_mode_enabled: boolean;
  readonly max_failed_hosts: number;
  readonly rollback_on_unreachable: boolean;
}

export interface DryRunOutcomeInput {
  readonly host_id: string;
  readonly succeeded: boolean;
  readonly repo_verified: boolean;
  readonly planned_changes_count: number;
}

export interface WaveHealthReportInput {
  readonly wave_number: number;
  readonly healthy_hosts: number;
  readonly failed_hosts: number;
  readonly unreachable_hosts: number;
}

export interface UserCreateRequest {
  readonly username: string;
  readonly email: string;
  readonly password: string;
  readonly role: UserRole;
}

export interface UserUpdateRequest {
  readonly role?: UserRole;
  readonly is_active?: boolean;
  readonly unlock?: boolean;
}

export interface EnrollmentTokenCreateRequest {
  readonly label: string;
  readonly environment: EnvironmentType;
  readonly ttl_minutes: number;
}

export interface EnrollmentTokenResponse {
  readonly id: string;
  readonly enrollment_token: string;
  readonly label: string;
  readonly environment: EnvironmentType;
  readonly expires_at: string;
}

export interface ToolBundleRegisterInput {
  readonly tool_name: string;
  readonly version: string;
  readonly arch: ToolBundleArch;
  readonly file: File;
  readonly signature_b64?: string;
}

export interface ToolBundleManifestResponse {
  readonly tool_name: string;
  readonly version: string;
  readonly arch: string;
  readonly filename: string;
  readonly sha256: string;
  readonly size_bytes: number;
  readonly manifest_canonical_json: string;
  readonly signature_b64: string;
  readonly download_url: string;
}
