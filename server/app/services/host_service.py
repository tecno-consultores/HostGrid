"""Read-side fleet, host detail, snapshots, findings, packages, reports, and audit services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import DomainError
from app.core.rbac import ALL_USER_ROLES, ActorContext, require_roles
from app.core.security import format_rfc3339
from app.db.models import AuditLog, Finding, Host, Snapshot, SnapshotPackage
from app.schemas.common import PaginatedResponse
from app.schemas.host import AuditLogItem, FindingResponse, HostDetailResponse, HostListItem
from app.schemas.snapshot import PackageRecordResponse, SnapshotSummaryResponse
from app.services.drift.engine import get_snapshot_drift
from app.services.normalizer.scoring import build_sarif_report
from app.services.reporting import render_html_report, render_markdown_report
from app.services.worm import serialize_audit_log


@dataclass(frozen=True)
class HostFilterParams:
    """Bounded fleet query filter parameters."""

    search: str | None = None
    os_family: str | None = None
    eol_status: str | None = None
    connectivity_mode: str | None = None
    repo_access_ok: bool | None = None
    limit: int = 50
    offset: int = 0


def _serialize_host_list_item(host: Host) -> HostListItem:
    return HostListItem(
        id=host.id,
        hostname=host.hostname,
        os_family=host.os_family,
        os_name=host.os_name,
        os_version=host.os_version,
        kernel_version=host.kernel_version,
        arch=host.arch,
        init_system=host.init_system,
        connectivity_mode=host.connectivity_mode,
        environment=host.environment,
        eol_status=host.eol_status,
        eol_date=host.eol_date.isoformat() if host.eol_date is not None else None,
        repo_access_ok=host.repo_access_ok,
        last_hardening_index=host.last_hardening_index,
        last_hardening_delta=host.last_hardening_delta,
        last_lynis_version=host.last_lynis_version,
        critical_cves_count=host.critical_cves_count,
        high_cves_count=host.high_cves_count,
        last_seen_at=format_rfc3339(host.last_seen_at) if host.last_seen_at is not None else None,
    )


def _serialize_finding(row: Finding) -> FindingResponse:
    return FindingResponse(
        id=row.id,
        snapshot_id=row.snapshot_id,
        host_id=row.host_id,
        fingerprint=row.fingerprint,
        rule_id=row.rule_id,
        source_tool=row.source_tool,
        category=row.category,
        severity=row.severity,
        base_severity=row.base_severity,
        confidence=row.confidence,
        title=row.title,
        description=row.description,
        evidence=row.evidence_json,
        remediation=row.remediation,
        reference_ids=row.reference_ids_json,
        contextual_score=float(row.contextual_score),
        contextual_factors=row.contextual_factors_json,
    )


def _build_host_filters(filters: HostFilterParams) -> list[Any]:
    exact_pairs: tuple[tuple[str | None, Any], ...] = (
        (filters.os_family, Host.os_family),
        (filters.eol_status, Host.eol_status),
        (filters.connectivity_mode, Host.connectivity_mode),
    )
    clauses: list[Any] = [
        column == value.strip().lower() for value, column in exact_pairs if value
    ]
    if filters.search:
        clauses.append(Host.hostname.ilike(f"%{filters.search.strip()}%"))
    if filters.repo_access_ok is not None:
        clauses.append(Host.repo_access_ok.is_(filters.repo_access_ok))
    return clauses


async def list_hosts(
    session: AsyncSession,
    *,
    actor: ActorContext,
    filters: HostFilterParams,
) -> PaginatedResponse[HostListItem]:
    """List monitored hosts with optional filtering and pagination."""
    require_roles(actor, ALL_USER_ROLES)
    clauses = _build_host_filters(filters)
    total = int(
        (await session.execute(select(func.count(Host.id)).where(*clauses))).scalar_one()
    )
    rows = (
        await session.execute(
            select(Host)
            .where(*clauses)
            .order_by(desc(Host.critical_cves_count), Host.hostname.asc())
            .limit(filters.limit)
            .offset(filters.offset)
        )
    ).scalars().all()
    return PaginatedResponse(
        items=[_serialize_host_list_item(host) for host in rows],
        total=total,
        limit=filters.limit,
        offset=filters.offset,
    )


async def get_host_detail(
    session: AsyncSession,
    *,
    actor: ActorContext,
    host_id: UUID,
) -> HostDetailResponse:
    """Fetch full host metadata, Capability Probe, and latest snapshot pointers."""
    require_roles(actor, ALL_USER_ROLES)
    host = (await session.execute(select(Host).where(Host.id == host_id))).scalar_one_or_none()
    if host is None:
        raise DomainError(
            status_code=404,
            title="Not Found",
            detail="Host not found.",
            error_type="urn:hostgrid:error:not_found",
        )

    latest = (
        await session.execute(
            select(Snapshot)
            .where(Snapshot.host_id == host.id)
            .order_by(desc(Snapshot.ingested_at), desc(Snapshot.id))
            .limit(1)
        )
    ).scalar_one_or_none()
    snap_count = int(
        (
            await session.execute(
                select(func.count(Snapshot.id)).where(Snapshot.host_id == host.id)
            )
        ).scalar_one()
    )
    base_item = _serialize_host_list_item(host)
    return HostDetailResponse(
        **base_item.model_dump(),
        machine_id_hash=host.machine_id_hash,
        capabilities=host.capabilities_json,
        latest_snapshot_id=latest.id if latest is not None else None,
        latest_snapshot_at=format_rfc3339(latest.collected_at) if latest is not None else None,
        total_snapshots=snap_count,
    )


async def list_host_snapshots(
    session: AsyncSession,
    *,
    actor: ActorContext,
    host_id: UUID,
    limit: int = 50,
    offset: int = 0,
) -> PaginatedResponse[SnapshotSummaryResponse]:
    """List historical snapshots for a host ordered newest first."""
    require_roles(actor, ALL_USER_ROLES)
    total = int(
        (
            await session.execute(
                select(func.count(Snapshot.id)).where(Snapshot.host_id == host_id)
            )
        ).scalar_one()
    )
    rows = (
        await session.execute(
            select(Snapshot)
            .where(Snapshot.host_id == host_id)
            .order_by(desc(Snapshot.ingested_at), desc(Snapshot.id))
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    items = [
        SnapshotSummaryResponse(
            id=row.id,
            host_id=row.host_id,
            previous_snapshot_id=row.previous_snapshot_id,
            ingestion_source=row.ingestion_source,
            agent_version=row.agent_version,
            collected_at=format_rfc3339(row.collected_at),
            ingested_at=format_rfc3339(row.ingested_at),
            hardening_index=row.hardening_index,
            lynis_version=row.lynis_version,
            tests_executed=row.tests_executed,
            tests_skipped=row.tests_skipped,
            warnings_count=row.warnings_count,
            suggestions_count=row.suggestions_count,
            critical_cves_count=row.critical_cves_count,
            high_cves_count=row.high_cves_count,
            bundle_sha256=row.bundle_sha256,
        )
        for row in rows
    ]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


async def list_snapshot_findings(
    session: AsyncSession,
    *,
    actor: ActorContext,
    snapshot_id: UUID,
    severity: str | None = None,
    category: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> PaginatedResponse[FindingResponse]:
    """List deduplicated findings for a snapshot with optional severity/category filters."""
    require_roles(actor, ALL_USER_ROLES)
    clauses: list[Any] = [Finding.snapshot_id == snapshot_id]
    if severity:
        clauses.append(Finding.severity == severity.strip().lower())
    if category:
        clauses.append(Finding.category == category.strip().lower())
    total = int(
        (await session.execute(select(func.count(Finding.id)).where(*clauses))).scalar_one()
    )
    rows = (
        await session.execute(
            select(Finding)
            .where(*clauses)
            .order_by(desc(Finding.contextual_score), Finding.fingerprint.asc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    return PaginatedResponse(
        items=[_serialize_finding(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


async def list_snapshot_packages(
    session: AsyncSession,
    *,
    actor: ActorContext,
    snapshot_id: UUID,
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> PaginatedResponse[PackageRecordResponse]:
    """List installed packages captured in a snapshot SBOM."""
    require_roles(actor, ALL_USER_ROLES)
    clauses: list[Any] = [SnapshotPackage.snapshot_id == snapshot_id]
    if search:
        clauses.append(SnapshotPackage.name.ilike(f"%{search.strip()}%"))
    total = int(
        (
            await session.execute(select(func.count(SnapshotPackage.id)).where(*clauses))
        ).scalar_one()
    )
    rows = (
        await session.execute(
            select(SnapshotPackage)
            .where(*clauses)
            .order_by(SnapshotPackage.name.asc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    items = [
        PackageRecordResponse(
            package_manager=row.package_manager,
            name=row.name,
            source_package=row.source_package,
            epoch=row.epoch,
            version=row.version,
            release=row.release,
            arch=row.arch,
        )
        for row in rows
    ]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


async def export_host_report(
    session: AsyncSession,
    *,
    actor: ActorContext,
    host_id: UUID,
    report_format: str = "json",
) -> dict[str, Any] | str:
    """Export latest host posture report in JSON, SARIF 2.1.0, Markdown, or HTML format."""
    detail = await get_host_detail(session, actor=actor, host_id=host_id)
    if detail.latest_snapshot_id is None:
        raise DomainError(
            status_code=404,
            title="No Snapshots",
            detail="Host has no snapshots available for export.",
            error_type="urn:hostgrid:error:no_snapshots",
        )
    finding_rows = (
        await session.execute(
            select(Finding)
            .where(Finding.snapshot_id == detail.latest_snapshot_id)
            .order_by(desc(Finding.contextual_score), Finding.fingerprint.asc())
        )
    ).scalars().all()
    findings_dicts = [_serialize_finding(row).model_dump(mode="json") for row in finding_rows]
    if report_format == "sarif":
        return build_sarif_report(
            host_name=detail.hostname,
            snapshot_id=str(detail.latest_snapshot_id),
            findings=findings_dicts,
        )
    if report_format in {"markdown", "html"}:
        drift = await get_snapshot_drift(
            session,
            actor=actor,
            snapshot_id=detail.latest_snapshot_id,
        )
        renderer = render_markdown_report if report_format == "markdown" else render_html_report
        return renderer(
            detail=detail,
            snapshot_id=str(detail.latest_snapshot_id),
            findings=findings_dicts,
            drift=drift,
        )
    return {
        "host": detail.model_dump(mode="json"),
        "snapshot_id": str(detail.latest_snapshot_id),
        "findings": findings_dicts,
    }


async def list_audit_logs(
    session: AsyncSession,
    *,
    actor: ActorContext,
    limit: int = 50,
    offset: int = 0,
) -> PaginatedResponse[AuditLogItem]:
    """Return paginated WORM audit log records newest first."""
    require_roles(actor, ALL_USER_ROLES)
    total = int((await session.execute(select(func.count(AuditLog.seq_num)))).scalar_one())
    rows = (
        await session.execute(
            select(AuditLog).order_by(desc(AuditLog.seq_num)).limit(limit).offset(offset)
        )
    ).scalars().all()
    return PaginatedResponse(
        items=[serialize_audit_log(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )
