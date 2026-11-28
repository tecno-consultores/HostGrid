"""Drift engine computing new, resolved, and persisted findings between snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import DomainError
from app.core.rbac import ALL_USER_ROLES, ActorContext, require_roles
from app.db.models import Finding, Snapshot, SnapshotDriftItem
from app.schemas.host import DriftItemResponse, DriftResponse


@dataclass(frozen=True)
class FindingDigest:
    """Minimal immutable representation of a finding for drift comparison."""

    fingerprint: str
    severity: str
    category: str
    title: str


@dataclass(frozen=True)
class DriftComputation:
    """Result of comparing current findings against previous snapshot findings."""

    items: list[SnapshotDriftItem]
    summary: dict[str, int]


def compute_drift_items(
    *,
    snapshot_id: UUID,
    previous_snapshot_id: UUID | None,
    current_findings: list[FindingDigest],
    previous_findings: list[FindingDigest],
) -> DriftComputation:
    """Compare current and previous finding sets by deterministic fingerprint."""
    prev_map = {item.fingerprint: item for item in previous_findings}
    curr_map = {item.fingerprint: item for item in current_findings}
    drift_rows: list[SnapshotDriftItem] = []
    counts = {"new": 0, "resolved": 0, "persisted": 0}

    for fp, curr in curr_map.items():
        prev = prev_map.get(fp)
        status: Literal["new", "persisted"] = "new" if prev is None else "persisted"
        counts[status] += 1
        drift_rows.append(
            SnapshotDriftItem(
                snapshot_id=snapshot_id,
                previous_snapshot_id=previous_snapshot_id,
                fingerprint=fp,
                status=status,
                severity=curr.severity,
                previous_severity=prev.severity if prev is not None else None,
                title=curr.title,
                category=curr.category,
            )
        )

    for fp, prev in prev_map.items():
        if fp in curr_map:
            continue
        counts["resolved"] += 1
        drift_rows.append(
            SnapshotDriftItem(
                snapshot_id=snapshot_id,
                previous_snapshot_id=previous_snapshot_id,
                fingerprint=fp,
                status="resolved",
                severity=prev.severity,
                previous_severity=prev.severity,
                title=prev.title,
                category=prev.category,
            )
        )

    return DriftComputation(items=drift_rows, summary=counts)


def compute_hardening_delta(current: int | None, previous: int | None) -> int | None:
    """Compute signed delta of Lynis hardening index when both snapshots have values."""
    if current is None or previous is None:
        return None
    return current - previous


def _to_drift_status(value: str) -> Literal["new", "resolved", "persisted"]:
    if value == "new":
        return "new"
    if value == "resolved":
        return "resolved"
    return "persisted"


async def load_previous_finding_digests(
    session: AsyncSession,
    previous_snapshot_id: UUID | None,
) -> list[FindingDigest]:
    """Load finding digests for the immediately preceding snapshot."""
    if previous_snapshot_id is None:
        return []
    rows = (
        await session.execute(select(Finding).where(Finding.snapshot_id == previous_snapshot_id))
    ).scalars().all()
    return [
        FindingDigest(
            fingerprint=row.fingerprint,
            severity=row.severity,
            category=row.category,
            title=row.title,
        )
        for row in rows
    ]


async def get_snapshot_drift(
    session: AsyncSession,
    *,
    actor: ActorContext,
    snapshot_id: UUID,
) -> DriftResponse:
    """Fetch stored drift comparison for a snapshot."""
    require_roles(actor, ALL_USER_ROLES)
    snap = (
        await session.execute(select(Snapshot).where(Snapshot.id == snapshot_id))
    ).scalar_one_or_none()
    if snap is None:
        raise DomainError(
            status_code=404,
            title="Not Found",
            detail="Snapshot not found.",
            error_type="urn:hostgrid:error:not_found",
        )

    prev_snap: Snapshot | None = None
    if snap.previous_snapshot_id is not None:
        prev_snap = (
            await session.execute(
                select(Snapshot).where(Snapshot.id == snap.previous_snapshot_id)
            )
        ).scalar_one_or_none()

    rows = (
        await session.execute(
            select(SnapshotDriftItem).where(SnapshotDriftItem.snapshot_id == snapshot_id)
        )
    ).scalars().all()

    summary = {"new": 0, "resolved": 0, "persisted": 0}
    items: list[DriftItemResponse] = []
    for row in rows:
        status = _to_drift_status(row.status)
        summary[status] += 1
        items.append(
            DriftItemResponse(
                fingerprint=row.fingerprint,
                status=status,
                severity=row.severity,
                previous_severity=row.previous_severity,
                category=row.category,
                title=row.title,
            )
        )

    prev_idx = prev_snap.hardening_index if prev_snap is not None else None
    return DriftResponse(
        snapshot_id=snap.id,
        previous_snapshot_id=snap.previous_snapshot_id,
        hardening_index_current=snap.hardening_index,
        hardening_index_previous=prev_idx,
        hardening_index_delta=compute_hardening_delta(snap.hardening_index, prev_idx),
        summary=summary,
        items=items,
    )
