"""Admin-only user lifecycle management service with WORM audit logging (SPEC.md 1.2)."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import DomainError
from app.core.rbac import ADMIN_ONLY, ActorContext, require_roles
from app.core.security import hash_password
from app.db.models import User
from app.schemas.auth import UserCreateRequest, UserProfile, UserUpdateRequest
from app.schemas.common import PaginatedResponse
from app.services.auth_service import to_user_profile
from app.services.worm import append_audit_log


async def list_users(
    session: AsyncSession,
    *,
    actor: ActorContext,
    limit: int = 50,
    offset: int = 0,
) -> PaginatedResponse[UserProfile]:
    """List user accounts (admin only)."""
    require_roles(actor, ADMIN_ONLY)
    total = int((await session.execute(select(func.count(User.id)))).scalar_one())
    rows = (
        await session.execute(
            select(User).order_by(User.username.asc()).limit(limit).offset(offset)
        )
    ).scalars().all()
    return PaginatedResponse(
        items=[to_user_profile(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


async def create_user(
    session: AsyncSession,
    *,
    actor: ActorContext,
    payload: UserCreateRequest,
) -> UserProfile:
    """Provision a new RBAC user account with Argon2id hashing and WORM audit entry."""
    require_roles(actor, ADMIN_ONLY)
    duplicate = (
        await session.execute(
            select(User).where(
                or_(User.username == payload.username, User.email == payload.email.lower())
            )
        )
    ).scalar_one_or_none()
    if duplicate is not None:
        raise DomainError(
            status_code=409,
            title="Conflict",
            detail="Username or email already exists.",
            error_type="urn:hostgrid:error:duplicate_user",
        )
    user = User(
        username=payload.username,
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    session.add(user)
    await session.flush()
    await append_audit_log(
        session,
        actor_id=actor.actor_id,
        actor_username=actor.username,
        action="user.created",
        resource_type="user",
        resource_id=str(user.id),
        details={"username": user.username, "role": user.role},
    )
    await session.commit()
    return to_user_profile(user)


def _guard_self_lockout(actor: ActorContext, target: User, payload: UserUpdateRequest) -> None:
    if actor.actor_id != target.id:
        return
    if payload.is_active is False or (payload.role is not None and payload.role != "admin"):
        raise DomainError(
            status_code=409,
            title="Conflict",
            detail="Administrators cannot deactivate or demote their own account.",
            error_type="urn:hostgrid:error:self_lockout",
        )


async def update_user(
    session: AsyncSession,
    *,
    actor: ActorContext,
    user_id: UUID,
    payload: UserUpdateRequest,
) -> UserProfile:
    """Update user role, active status, or unlock failed-login lockout (admin only)."""
    require_roles(actor, ADMIN_ONLY)
    user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise DomainError(
            status_code=404,
            title="Not Found",
            detail="User not found.",
            error_type="urn:hostgrid:error:not_found",
        )
    _guard_self_lockout(actor, user, payload)
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.unlock:
        user.failed_attempts = 0
        user.locked_until = None
    await append_audit_log(
        session,
        actor_id=actor.actor_id,
        actor_username=actor.username,
        action="user.updated",
        resource_type="user",
        resource_id=str(user.id),
        details={
            "role": user.role,
            "is_active": user.is_active,
            "unlocked": payload.unlock,
        },
    )
    await session.commit()
    return to_user_profile(user)
