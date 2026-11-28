"""Host, finding, drift, CVE, tool bundle, and audit log schemas."""

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator

from app.schemas.common import StrictBaseModel, sanitize_single_line


class HostListItem(StrictBaseModel):
    """Fleet table host summary row."""

    id: UUID
    hostname: str
    os_family: str
    os_name: str
    os_version: str
    kernel_version: str
    arch: str
    init_system: str
    connectivity_mode: str
    environment: str
    eol_status: str
    eol_date: str | None
    repo_access_ok: bool | None
    last_hardening_index: int | None
    last_hardening_delta: int | None
    last_lynis_version: str | None
    critical_cves_count: int
    high_cves_count: int
    last_seen_at: str | None


class HostDetailResponse(HostListItem):
    """Full host detail including Capability Probe and latest snapshot summary."""

    machine_id_hash: str
    capabilities: dict[str, Any]
    latest_snapshot_id: UUID | None
    latest_snapshot_at: str | None
    total_snapshots: int


class FindingResponse(StrictBaseModel):
    """Unified normalized finding DTO."""

    id: UUID
    snapshot_id: UUID
    host_id: UUID
    fingerprint: str
    rule_id: str
    source_tool: str
    category: str
    severity: str
    base_severity: str
    confidence: str
    title: str
    description: str
    evidence: dict[str, Any]
    remediation: str
    reference_ids: list[str]
    contextual_score: float
    contextual_factors: list[str]


class DriftItemResponse(StrictBaseModel):
    """Single diff entry between consecutive snapshots."""

    fingerprint: str
    status: Literal["new", "resolved", "persisted"]
    severity: str
    previous_severity: str | None
    category: str
    title: str


class DriftResponse(StrictBaseModel):
    """Drift comparison response matching SPEC.md section 6.2."""

    snapshot_id: UUID
    previous_snapshot_id: UUID | None
    hardening_index_current: int | None
    hardening_index_previous: int | None
    hardening_index_delta: int | None
    summary: dict[str, int]
    items: list[DriftItemResponse]


class CveAdvisoryIn(StrictBaseModel):
    """Single advisory record in offline CVE sync feed."""

    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    ecosystem: str = Field(min_length=2, max_length=64)
    package_name: str = Field(min_length=1, max_length=255)
    fixed_version: str | None = Field(default=None, max_length=128)
    advisory_status: Literal["affected", "fixed", "not_affected", "wontfix"] = "affected"
    base_severity: Literal["critical", "high", "medium", "low"] = "high"
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    source_feed: Literal["osv", "oval", "trivy"] = "osv"
    summary: str = Field(default="", max_length=2000)
    references: list[str] = Field(default_factory=list)

    @field_validator("ecosystem", "package_name", "summary")
    @classmethod
    def _clean_cve_text(cls, value: str) -> str:
        return sanitize_single_line(value).strip()


class CveSyncRequest(StrictBaseModel):
    """Offline CVE feed sync payload."""

    advisories: list[CveAdvisoryIn] = Field(min_length=1, max_length=5000)


class CveSyncResponse(StrictBaseModel):
    """Summary of offline CVE sync."""

    upserted: int


class CveFeedImportRequest(StrictBaseModel):
    """Offline raw feed import request for OSV JSON, Trivy JSON, or OVAL XML (Phase 2)."""

    feed_format: Literal["osv", "trivy", "oval"]
    ecosystem: str | None = Field(default=None, max_length=64)
    payload: str = Field(min_length=2, max_length=2_000_000)
    rescan_fleet: bool = False

    @field_validator("ecosystem")
    @classmethod
    def _clean_ecosystem(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return sanitize_single_line(value).strip() or None


class CveFeedImportResponse(StrictBaseModel):
    """Summary of offline CVE feed parsing, upsert, and optional fleet rescan."""

    feed_format: Literal["osv", "trivy", "oval"]
    parsed: int
    upserted: int
    hosts_rescanned: int = 0
    total_cve_matches: int = 0


class FleetRescanResponse(StrictBaseModel):
    """Summary of offline fleet CVE re-evaluation against latest host snapshots."""

    hosts_rescanned: int
    total_cve_matches: int
    critical_matches: int
    high_matches: int


class CveSearchItem(StrictBaseModel):
    """Reverse CVE / package fleet impact record."""

    host_id: UUID
    hostname: str
    os: str
    eol_status: str
    cve_id: str | None
    package_name: str
    installed_version: str
    fixed_version: str | None
    effective_severity: str
    exposed_network: bool
    exposed_ports: list[str]
    last_snapshot_at: str | None


class CveSearchResponse(StrictBaseModel):
    """Reverse CVE search response matching SPEC.md section 6.2."""

    query: str
    total: int
    items: list[CveSearchItem]


class ToolBundleManifestResponse(StrictBaseModel):
    """Signed portable tool bundle manifest."""

    tool_name: str
    version: str
    arch: str
    filename: str
    sha256: str
    size_bytes: int
    manifest_canonical_json: str
    signature_b64: str
    download_url: str


class AuditLogItem(StrictBaseModel):
    """WORM audit log entry."""

    seq_num: int
    id: UUID
    occurred_at: str
    actor_id: UUID | None
    actor_username: str
    action: str
    resource_type: str
    resource_id: str
    details: dict[str, Any]
    prev_record_hash: str
    record_hash: str


class AuditVerifyResponse(StrictBaseModel):
    """WORM audit hash-chain verification report."""

    valid: bool
    checked_records: int
    first_seq_num: int | None
    last_seq_num: int | None
    last_record_hash: str | None
    broken_at_seq_num: int | None
