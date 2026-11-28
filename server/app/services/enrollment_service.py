"""Agent enrollment token issuance, host registration, and heartbeat services."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import DomainError
from app.core.rbac import (
    OPERATOR_OR_ADMIN,
    ActorContext,
    require_agent_host,
    require_roles,
)
from app.core.security import (
    format_rfc3339,
    generate_prefixed_token,
    sha256_hex,
    utc_now,
)
from app.db.models import EnrollmentToken, Host
from app.schemas.enrollment import (
    EnrollmentRegisterRequest,
    EnrollmentRegisterResponse,
    EnrollmentTokenCreateRequest,
    EnrollmentTokenResponse,
    HeartbeatRequest,
    HeartbeatResponse,
)
from app.services.eol.detector import evaluate_host_eol
from app.services.worm import append_audit_log


def _is_expired(expires_at_dt: datetime) -> bool:
    normalized = (
        expires_at_dt.astimezone(UTC)
        if expires_at_dt.tzinfo is not None
        else expires_at_dt.replace(tzinfo=UTC)
    )
    return normalized <= utc_now()


async def create_enrollment_token(
    session: AsyncSession,
    *,
    actor: ActorContext,
    payload: EnrollmentTokenCreateRequest,
) -> EnrollmentTokenResponse:
    """Issue a single-use expiring enrollment token (operator/admin only)."""
    require_roles(actor, OPERATOR_OR_ADMIN)
    if actor.actor_id is None:
        raise DomainError(
            status_code=403,
            title="Forbidden",
            detail="Human actor required to create enrollment token.",
            error_type="urn:hostgrid:error:forbidden",
        )

    plaintext = generate_prefixed_token("hg_enroll_")
    expires_at = utc_now() + timedelta(minutes=payload.ttl_minutes)
    record = EnrollmentToken(
        token_hash=sha256_hex(plaintext),
        label=payload.label,
        environment=payload.environment,
        created_by=actor.actor_id,
        expires_at=expires_at,
    )
    session.add(record)
    await session.flush()
    await append_audit_log(
        session,
        actor_id=actor.actor_id,
        actor_username=actor.username,
        action="enrollment_token.created",
        resource_type="enrollment_token",
        resource_id=str(record.id),
        details={"label": payload.label, "environment": payload.environment},
    )
    await session.commit()
    return EnrollmentTokenResponse(
        id=record.id,
        enrollment_token=plaintext,
        label=record.label,
        environment=payload.environment,
        expires_at=format_rfc3339(expires_at),
    )


async def _upsert_enrolled_host(
    session: AsyncSession,
    *,
    payload: EnrollmentRegisterRequest,
    environment: str,
    credential_hash: str,
) -> Host:
    eol = await evaluate_host_eol(
        session,
        os_family=payload.os_family,
        os_version=payload.os_version,
    )
    existing = (
        await session.execute(
            select(Host).where(Host.machine_id_hash == payload.machine_id_hash)
        )
    ).scalar_one_or_none()
    now = utc_now()
    if existing is None:
        host = Host(
            hostname=payload.hostname,
            machine_id_hash=payload.machine_id_hash,
            os_family=payload.os_family,
            os_name=payload.os_name,
            os_version=payload.os_version,
            kernel_version=payload.kernel_version,
            arch=payload.arch,
            init_system=payload.init_system,
            connectivity_mode=payload.connectivity_mode,
            environment=environment,
            eol_status=eol.status,
            eol_date=eol.eol_date,
            credential_hash=credential_hash,
            last_seen_at=now,
        )
        session.add(host)
        await session.flush()
        return host

    existing.hostname = payload.hostname
    existing.os_family = payload.os_family
    existing.os_name = payload.os_name
    existing.os_version = payload.os_version
    existing.kernel_version = payload.kernel_version
    existing.arch = payload.arch
    existing.init_system = payload.init_system
    existing.connectivity_mode = payload.connectivity_mode
    existing.environment = environment
    existing.eol_status = eol.status
    existing.eol_date = eol.eol_date
    existing.credential_hash = credential_hash
    existing.last_seen_at = now
    await session.flush()
    return existing


async def register_agent(
    session: AsyncSession,
    *,
    settings: Settings,
    payload: EnrollmentRegisterRequest,
) -> EnrollmentRegisterResponse:
    """Validate and consume single-use token, enroll host, and issue rotating agent credential."""
    token_hash = sha256_hex(payload.enrollment_token)
    token = (
        await session.execute(
            select(EnrollmentToken).where(EnrollmentToken.token_hash == token_hash)
        )
    ).scalar_one_or_none()
    if token is None or token.used_at is not None or _is_expired(token.expires_at):
        raise DomainError(
            status_code=401,
            title="Invalid Enrollment Token",
            detail="Enrollment token is invalid, expired, or already used.",
            error_type="urn:hostgrid:error:enrollment_invalid",
        )

    now = utc_now()
    claim_res = await session.execute(
        update(EnrollmentToken)
        .where(
            EnrollmentToken.id == token.id,
            EnrollmentToken.used_at.is_(None),
        )
        .values(used_at=now)
    )
    if not isinstance(claim_res, CursorResult) or claim_res.rowcount != 1:
        raise DomainError(
            status_code=401,
            title="Invalid Enrollment Token",
            detail="Enrollment token is invalid, expired, or already used.",
            error_type="urn:hostgrid:error:enrollment_invalid",
        )

    agent_cred = generate_prefixed_token("hg_agent_")
    environment = payload.environment or token.environment
    host = await _upsert_enrolled_host(
        session,
        payload=payload,
        environment=environment,
        credential_hash=sha256_hex(agent_cred),
    )
    await session.execute(
        update(EnrollmentToken)
        .where(EnrollmentToken.id == token.id)
        .values(used_by_host_id=host.id)
    )
    await append_audit_log(
        session,
        actor_id=None,
        actor_username=f"agent:{host.hostname}",
        action="host.enrolled",
        resource_type="host",
        resource_id=str(host.id),
        details={
            "hostname": host.hostname,
            "os": f"{host.os_family}:{host.os_version}",
            "connectivity_mode": host.connectivity_mode,
        },
    )
    await session.commit()
    return EnrollmentRegisterResponse(
        host_id=host.id,
        agent_credential=agent_cred,
        bundle_signing_pubkey_b64=settings.hostgrid_bundle_signing_pubkey_b64,
    )


async def record_heartbeat(
    session: AsyncSession,
    *,
    actor: ActorContext,
    host_id: UUID,
    payload: HeartbeatRequest,
) -> HeartbeatResponse:
    """Update host liveness, repo reachability, and installed Lynis version."""
    require_agent_host(actor, host_id)
    host = (await session.execute(select(Host).where(Host.id == host_id))).scalar_one_or_none()
    if host is None:
        raise DomainError(
            status_code=404,
            title="Not Found",
            detail="Host not found.",
            error_type="urn:hostgrid:error:not_found",
        )

    now = utc_now()
    host.last_seen_at = now
    if payload.repo_access_ok is not None:
        host.repo_access_ok = payload.repo_access_ok
    if payload.lynis_version:
        host.last_lynis_version = payload.lynis_version
    await session.commit()
    return HeartbeatResponse(host_id=host.id, server_time=format_rfc3339(now))
