"""Snapshot ingestion, agentless payload, and air-gapped bundle schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator

from app.schemas.common import StrictBaseModel, sanitize_multiline, sanitize_single_line
from app.schemas.enrollment import (
    ArchType,
    ConnectivityMode,
    EnvironmentType,
    InitSystemType,
    OsFamilyType,
)


class CapabilityItem(StrictBaseModel):
    """Single Capability Probe feature status."""

    status: Literal["supported", "not_supported_on_os", "error"]
    binary: str | None = Field(default=None, max_length=128)
    reason: str | None = Field(default=None, max_length=255)
    fallback_used: bool = False

    @field_validator("binary", "reason")
    @classmethod
    def _clean_optional(cls, value: str | None) -> str | None:
        return sanitize_single_line(value) if value is not None else None


class ProbePayload(StrictBaseModel):
    """Host operating system, init, and capability detection output."""

    os_family: OsFamilyType = "other"
    os_name: str = Field(min_length=1, max_length=128)
    os_version: str = Field(min_length=1, max_length=64)
    kernel_version: str = Field(min_length=1, max_length=128)
    arch: ArchType = "amd64"
    init_system: InitSystemType = "unknown"
    capabilities: dict[str, CapabilityItem] = Field(default_factory=dict)

    @field_validator("os_name", "os_version", "kernel_version")
    @classmethod
    def _clean_probe_text(cls, value: str) -> str:
        return sanitize_single_line(value).strip()


class PackageItem(StrictBaseModel):
    """Single installed software package from dpkg, rpm, or apk."""

    package_manager: Literal["dpkg", "rpm", "apk"]
    name: str = Field(min_length=1, max_length=255)
    source_package: str | None = Field(default=None, max_length=255)
    epoch: str = Field(default="", max_length=16)
    version: str = Field(min_length=1, max_length=128)
    release: str = Field(default="", max_length=128)
    arch: str = Field(default="unknown", max_length=32)

    @field_validator("name", "version", "arch")
    @classmethod
    def _clean_required(cls, value: str) -> str:
        return sanitize_single_line(value).strip()


class ListeningSocket(StrictBaseModel):
    """Active listening socket detected on the host."""

    proto: Literal["tcp", "tcp6", "udp", "udp6"] = "tcp"
    local_addr: str = Field(min_length=1, max_length=64)
    port: int = Field(ge=0, le=65535)
    process: str = Field(default="", max_length=128)
    pid: int | None = Field(default=None, ge=0)

    @field_validator("local_addr", "process")
    @classmethod
    def _clean_socket_text(cls, value: str) -> str:
        return sanitize_single_line(value).strip()


class NetworkPayload(StrictBaseModel):
    """Host network collector output."""

    listening_sockets: list[ListeningSocket] = Field(default_factory=list)


class ServiceItem(StrictBaseModel):
    """Running or configured service detected by init collector."""

    name: str = Field(min_length=1, max_length=128)
    state: str = Field(min_length=1, max_length=32)
    init_system: str = Field(default="unknown", max_length=32)

    @field_validator("name", "state", "init_system")
    @classmethod
    def _clean_service(cls, value: str) -> str:
        return sanitize_single_line(value).strip()


class ReposPayload(StrictBaseModel):
    """Repository reachability and configured sources."""

    access_ok: bool | None = None
    configured_sources: list[str] = Field(default_factory=list)
    check_detail: str = Field(default="", max_length=255)

    @field_validator("check_detail")
    @classmethod
    def _clean_detail(cls, value: str) -> str:
        return sanitize_single_line(value)


class LynisPayload(StrictBaseModel):
    """Portable Lynis execution result and raw report data."""

    executed: bool = False
    lynis_version: str | None = Field(default=None, max_length=32)
    report_dat: str = Field(default="")

    @field_validator("report_dat")
    @classmethod
    def _clean_report(cls, value: str) -> str:
        return sanitize_multiline(value)


class SnapshotIngestRequest(StrictBaseModel):
    """Snapshot payload submitted by enrolled agent or inside .bundle."""

    host_id: UUID | None = None
    hostname: str | None = Field(default=None, max_length=255)
    machine_id_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    environment: EnvironmentType = "prod"
    collected_at: datetime
    agent_version: str = Field(min_length=1, max_length=32)
    connectivity_mode: ConnectivityMode = "lan"
    probe: ProbePayload
    packages: list[PackageItem] = Field(default_factory=list)
    network: NetworkPayload = Field(default_factory=NetworkPayload)
    services: list[ServiceItem] = Field(default_factory=list)
    sysctl: dict[str, str] = Field(default_factory=dict)
    repos: ReposPayload = Field(default_factory=ReposPayload)
    lynis: LynisPayload = Field(default_factory=LynisPayload)

    @field_validator("agent_version")
    @classmethod
    def _clean_version(cls, value: str) -> str:
        return sanitize_single_line(value).strip()


class AgentlessIngestRequest(StrictBaseModel):
    """Snapshot payload generated by agentless/collect_posix.sh."""

    hostname: str = Field(min_length=1, max_length=255)
    machine_id_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment: EnvironmentType = "prod"
    collected_at: datetime
    agent_version: str = Field(default="agentless-posix-1.0", max_length=32)
    connectivity_mode: Literal["agentless"] = "agentless"
    probe: ProbePayload
    packages: list[PackageItem] = Field(default_factory=list)
    network: NetworkPayload = Field(default_factory=NetworkPayload)
    services: list[ServiceItem] = Field(default_factory=list)
    sysctl: dict[str, str] = Field(default_factory=dict)
    repos: ReposPayload = Field(default_factory=ReposPayload)
    lynis: LynisPayload = Field(default_factory=LynisPayload)

    @field_validator("hostname", "agent_version")
    @classmethod
    def _clean_agentless_text(cls, value: str) -> str:
        return sanitize_single_line(value).strip()


class BundleManifestFile(StrictBaseModel):
    """Single file integrity entry inside air-gapped .bundle manifest."""

    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)


class BundleManifest(StrictBaseModel):
    """Strict schema for manifest.json inside an air-gapped .bundle archive."""

    bundle_format_version: Literal["1.0"]
    bundle_id: UUID
    created_at: datetime
    hostname: str = Field(min_length=1, max_length=255)
    machine_id_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    agent_version: str = Field(min_length=1, max_length=32)
    signature_mode: Literal["ed25519", "hmac_host", "sha256_integrity_only"]
    files: dict[str, BundleManifestFile]

    @field_validator("hostname", "agent_version")
    @classmethod
    def _clean_manifest_text(cls, value: str) -> str:
        return sanitize_single_line(value).strip()


class SnapshotCreatedResponse(StrictBaseModel):
    """Summary returned when a snapshot is ingested."""

    snapshot_id: UUID
    host_id: UUID
    previous_snapshot_id: UUID | None
    ingestion_source: str
    hardening_index: int | None
    eol_status: str
    findings_total: int
    critical_cves_count: int
    high_cves_count: int
    drift_summary: dict[str, int]
    bundle_sha256: str | None = None


class SnapshotSummaryResponse(StrictBaseModel):
    """Historical snapshot entry for host timeline charts."""

    id: UUID
    host_id: UUID
    previous_snapshot_id: UUID | None
    ingestion_source: str
    agent_version: str
    collected_at: str
    ingested_at: str
    hardening_index: int | None
    lynis_version: str | None
    tests_executed: int
    tests_skipped: int
    warnings_count: int
    suggestions_count: int
    critical_cves_count: int
    high_cves_count: int
    bundle_sha256: str | None


class PackageRecordResponse(StrictBaseModel):
    """Stored package row returned for a host snapshot."""

    package_manager: str
    name: str
    source_package: str | None
    epoch: str | None
    version: str
    release: str | None
    arch: str
    extra: dict[str, Any] | None = None
