"""WORM immutable audit log service with SHA-256 hash chaining."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import ALL_USER_ROLES, ActorContext, require_roles
from app.core.security import canonical_json_bytes, format_rfc3339, sha256_hex, utc_now
from app.db.models import AuditLog
from app.schemas.host import AuditLogItem, AuditVerifyResponse

GENESIS_HASH = "0" * 64


def compute_audit_record_hash(
    *,
    seq_num: int,
    prev_record_hash: str,
    occurred_at: datetime,
    actor_username: str,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict[str, Any],
) -> str:
    """Compute deterministic SHA-256 hash for an audit log record."""
    payload = {
        "seq_num": seq_num,
        "prev_record_hash": prev_record_hash,
        "occurred_at": format_rfc3339(occurred_at),
        "actor_username": actor_username,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details,
    }
    return sha256_hex(canonical_json_bytes(payload))


async def _acquire_worm_lock(session: AsyncSession) -> None:
    bind = session.get_bind()
    if bind.dialect.name == "postgresql":
        await session.execute(text("SELECT pg_advisory_xact_lock(hashtext('hostgrid_worm_audit'))"))


async def append_audit_log(
    session: AsyncSession,
    *,
    actor_id: UUID | None,
    actor_username: str,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Append an immutable hash-chained record to audit_logs."""
    await _acquire_worm_lock(session)
    latest_result = await session.execute(
        select(AuditLog).order_by(desc(AuditLog.seq_num)).limit(1)
    )
    latest = latest_result.scalar_one_or_none()
    seq_num = 1 if latest is None else latest.seq_num + 1
    prev_hash = GENESIS_HASH if latest is None else latest.record_hash
    occurred_at = utc_now()
    safe_details = details or {}
    record_hash = compute_audit_record_hash(
        seq_num=seq_num,
        prev_record_hash=prev_hash,
        occurred_at=occurred_at,
        actor_username=actor_username,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=safe_details,
    )
    entry = AuditLog(
        seq_num=seq_num,
        id=uuid4(),
        occurred_at=occurred_at,
        actor_id=actor_id,
        actor_username=actor_username,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details_json=safe_details,
        prev_record_hash=prev_hash,
        record_hash=record_hash,
    )
    session.add(entry)
    await session.flush()
    return entry


def _is_record_valid(entry: AuditLog, expected_seq: int, expected_prev: str) -> bool:
    if entry.seq_num != expected_seq or entry.prev_record_hash != expected_prev:
        return False
    expected_hash = compute_audit_record_hash(
        seq_num=entry.seq_num,
        prev_record_hash=entry.prev_record_hash,
        occurred_at=entry.occurred_at,
        actor_username=entry.actor_username,
        action=entry.action,
        resource_type=entry.resource_type,
        resource_id=entry.resource_id,
        details=entry.details_json,
    )
    return entry.record_hash == expected_hash


async def verify_audit_chain(
    session: AsyncSession,
    *,
    actor: ActorContext | None = None,
) -> AuditVerifyResponse:
    """Verify full monotonic sequence and SHA-256 chain integrity."""
    if actor is not None:
        require_roles(actor, ALL_USER_ROLES)
    result = await session.execute(select(AuditLog).order_by(AuditLog.seq_num.asc()))
    records = list(result.scalars().all())
    if not records:
        return AuditVerifyResponse(
            valid=True,
            checked_records=0,
            first_seq_num=None,
            last_seq_num=None,
            last_record_hash=None,
            broken_at_seq_num=None,
        )

    expected_prev = GENESIS_HASH
    for idx, entry in enumerate(records, start=1):
        if not _is_record_valid(entry, idx, expected_prev):
            return AuditVerifyResponse(
                valid=False,
                checked_records=idx,
                first_seq_num=records[0].seq_num,
                last_seq_num=records[-1].seq_num,
                last_record_hash=records[-1].record_hash,
                broken_at_seq_num=entry.seq_num,
            )
        expected_prev = entry.record_hash

    return AuditVerifyResponse(
        valid=True,
        checked_records=len(records),
        first_seq_num=records[0].seq_num,
        last_seq_num=records[-1].seq_num,
        last_record_hash=records[-1].record_hash,
        broken_at_seq_num=None,
    )


def serialize_audit_log(entry: AuditLog) -> AuditLogItem:
    """Convert ORM AuditLog row into API response schema."""
    return AuditLogItem(
        seq_num=entry.seq_num,
        id=entry.id,
        occurred_at=format_rfc3339(entry.occurred_at),
        actor_id=entry.actor_id,
        actor_username=entry.actor_username,
        action=entry.action,
        resource_type=entry.resource_type,
        resource_id=entry.resource_id,
        details=entry.details_json,
        prev_record_hash=entry.prev_record_hash,
        record_hash=entry.record_hash,
    )
