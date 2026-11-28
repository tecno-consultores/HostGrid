"""SQLAlchemy 2.0 ORM models matching SPEC.md section 2.2."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.security import utc_now
from app.db.base import Base


class User(Base):
    """Human operator / auditor / approver / admin account."""

    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )


class EnrollmentToken(Base):
    """Single-use expiring enrollment token issued by operators/admins."""

    __tablename__ = "enrollment_tokens"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(16), nullable=False, default="prod")
    created_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    used_by_host_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class Host(Base):
    """Monitored Linux server inventory entry."""

    __tablename__ = "hosts"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    machine_id_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    os_family: Mapped[str] = mapped_column(String(32), nullable=False, default="other")
    os_name: Mapped[str] = mapped_column(String(128), nullable=False, default="Unknown Linux")
    os_version: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    kernel_version: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    arch: Mapped[str] = mapped_column(String(16), nullable=False, default="amd64")
    init_system: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    connectivity_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="lan")
    environment: Mapped[str] = mapped_column(String(16), nullable=False, default="prod")
    eol_status: Mapped[str] = mapped_column(String(24), nullable=False, default="unknown")
    eol_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    repo_access_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_hardening_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_hardening_delta: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_lynis_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    critical_cves_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_cves_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    credential_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    capabilities_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )


class Snapshot(Base):
    """Immutable point-in-time audit snapshot for a host."""

    __tablename__ = "snapshots"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    host_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("hosts.id"), nullable=False, index=True
    )
    previous_snapshot_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("snapshots.id"), nullable=True
    )
    ingestion_source: Mapped[str] = mapped_column(String(24), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(32), nullable=False, default="0.0.0")
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    hardening_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    lynis_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tests_executed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tests_skipped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    warnings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suggestions_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_cves_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_cves_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    raw_probe_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    raw_network_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    raw_services_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    raw_sysctl_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    raw_repos_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    bundle_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)


class SnapshotPackage(Base):
    """Installed package entry captured in a snapshot SBOM."""

    __tablename__ = "snapshot_packages"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    snapshot_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("snapshots.id"), nullable=False, index=True
    )
    package_manager: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_package: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    epoch: Mapped[str | None] = mapped_column(String(16), nullable=True)
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    release: Mapped[str | None] = mapped_column(String(128), nullable=True)
    arch: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")


class Finding(Base):
    """Normalized, deduplicated security finding compatible with SARIF 2.1.0."""

    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("snapshot_id", "fingerprint", name="uq_finding_snap_fp"),)

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    snapshot_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("snapshots.id"), nullable=False, index=True
    )
    host_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("hosts.id"), nullable=False, index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_tool: Mapped[str] = mapped_column(String(32), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    base_severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    reference_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    contextual_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    contextual_factors_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class SnapshotDriftItem(Base):
    """Drift comparison entry between Snapshot N and Snapshot N-1."""

    __tablename__ = "snapshot_drift_items"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    snapshot_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("snapshots.id"), nullable=False, index=True
    )
    previous_snapshot_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("snapshots.id"), nullable=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    previous_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class CveAdvisory(Base):
    """Offline distro-aware vulnerability advisory."""

    __tablename__ = "cve_advisories"
    __table_args__ = (
        Index("ix_cve_ecosystem_pkg_id", "ecosystem", "package_name", "cve_id"),
        UniqueConstraint("ecosystem", "package_name", "cve_id", name="uq_cve_eco_pkg_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    ecosystem: Mapped[str] = mapped_column(String(64), nullable=False)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    fixed_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    advisory_status: Mapped[str] = mapped_column(String(24), nullable=False, default="affected")
    base_severity: Mapped[str] = mapped_column(String(16), nullable=False)
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(4, 1), nullable=True)
    source_feed: Mapped[str] = mapped_column(String(16), nullable=False, default="osv")
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    references_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )


class HostCveMatch(Base):
    """Active CVE match correlated with a host snapshot and network exposure."""

    __tablename__ = "host_cve_matches"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    host_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("hosts.id"), nullable=False, index=True
    )
    snapshot_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("snapshots.id"), nullable=False, index=True
    )
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    installed_version: Mapped[str] = mapped_column(String(128), nullable=False)
    fixed_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    effective_severity: Mapped[str] = mapped_column(String(16), nullable=False)
    exposed_network: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    exposed_ports_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    contextual_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class EolCatalog(Base):
    """Offline End-of-Life reference table per Linux distribution and version."""

    __tablename__ = "eol_catalog"
    __table_args__ = (UniqueConstraint("os_family", "os_version", name="uq_eol_os_ver"),)

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    os_family: Mapped[str] = mapped_column(String(32), nullable=False)
    os_version: Mapped[str] = mapped_column(String(64), nullable=False)
    codename: Mapped[str | None] = mapped_column(String(64), nullable=True)
    release_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    standard_eol_date: Mapped[date] = mapped_column(Date, nullable=False)
    extended_eol_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class ToolBundle(Base):
    """Cryptographically signed portable tool bundle metadata (e.g., Lynis)."""

    __tablename__ = "tool_bundles"
    __table_args__ = (UniqueConstraint("tool_name", "version", "arch", name="uq_tool_ver_arch"),)

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    arch: Mapped[str] = mapped_column(String(32), nullable=False, default="noarch")
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_b64: Mapped[str] = mapped_column(Text, nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    published_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class AuditLog(Base):
    """Immutable WORM audit log chained by SHA-256 hashes."""

    __tablename__ = "audit_logs"

    seq_num: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), unique=True, nullable=False, default=uuid4)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    actor_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    actor_username: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    prev_record_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)


class PatchPlan(Base):
    """Governed patching plan schema (execution workflow completed in Phase 3)."""

    __tablename__ = "patch_plans"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    target_host_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    packages_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    canary_percent: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="DRAFT")
    dry_run_report_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_by: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )


class PatchApproval(Base):
    """Maker-Checker decision record for governed patch plans (Phase 3)."""

    __tablename__ = "patch_approvals"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    patch_plan_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("patch_plans.id"), nullable=False
    )
    approver_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class IdempotencyRecord(Base):
    """Idempotency key cache preventing duplicate mutations on network retries (SPEC.md 1.1)."""

    __tablename__ = "idempotency_records"
    __table_args__ = (
        UniqueConstraint(
            "idempotency_key",
            "endpoint",
            "actor_scope",
            name="uq_idempotency_key_scope",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    endpoint: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_scope: Mapped[str] = mapped_column(String(128), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False, default=201)
    response_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
