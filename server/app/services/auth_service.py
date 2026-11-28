"""Authentication, lockout enforcement, and bootstrap admin provisioning."""

from __future__ import annotations

from datetime import UTC, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import DomainError
from app.core.security import (
    create_access_token,
    format_rfc3339,
    hash_password,
    utc_now,
    verify_password,
)
from app.db.models import User
from app.schemas.auth import TokenResponse, UserProfile
from app.services.worm import append_audit_log

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def to_user_profile(user: User) -> UserProfile:
    """Serialize ORM User to UserProfile schema."""
    return UserProfile(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,  # type: ignore[arg-type]
        is_active=user.is_active,
    )


def _is_locked(user: User) -> bool:
    if user.locked_until is None:
        return False
    locked_utc = (
        user.locked_until.astimezone(UTC)
        if user.locked_until.tzinfo is not None
        else user.locked_until.replace(tzinfo=UTC)
    )
    return locked_utc > utc_now()


async def _record_failed_attempt(session: AsyncSession, user: User) -> None:
    user.failed_attempts += 1
    if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
        user.locked_until = utc_now() + timedelta(minutes=LOCKOUT_MINUTES)
    await session.commit()


async def authenticate_user(
    session: AsyncSession,
    *,
    settings: Settings,
    username: str,
    password: str,
) -> TokenResponse:
    """Authenticate human user via Argon2id and issue JWT access token."""
    user = (
        await session.execute(select(User).where(User.username == username))
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        raise DomainError(
            status_code=401,
            title="Unauthorized",
            detail="Invalid username or password.",
            error_type="urn:hostgrid:error:auth",
        )
    if _is_locked(user):
        raise DomainError(
            status_code=423,
            title="Account Locked",
            detail="Account is temporarily locked due to repeated failed logins.",
            error_type="urn:hostgrid:error:account_locked",
        )
    if not verify_password(password, user.password_hash):
        await _record_failed_attempt(session, user)
        raise DomainError(
            status_code=401,
            title="Unauthorized",
            detail="Invalid username or password.",
            error_type="urn:hostgrid:error:auth",
        )

    user.failed_attempts = 0
    user.locked_until = None
    token, expires_at = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
        secret=settings.hostgrid_jwt_secret,
        expire_minutes=settings.hostgrid_jwt_expire_minutes,
    )
    await append_audit_log(
        session,
        actor_id=user.id,
        actor_username=user.username,
        action="auth.login_success",
        resource_type="user",
        resource_id=str(user.id),
        details={"role": user.role},
    )
    await session.commit()
    return TokenResponse(
        access_token=token,
        expires_at=format_rfc3339(expires_at),
        user=to_user_profile(user),
    )


async def ensure_bootstrap_admin(session: AsyncSession, settings: Settings) -> bool:
    """Create initial admin strictly from environment variables if configured and absent."""
    username = settings.hostgrid_bootstrap_admin_username.strip()
    password = settings.hostgrid_bootstrap_admin_password
    email = settings.hostgrid_bootstrap_admin_email.strip()
    if not username or not password or not email:
        return False

    existing = (
        await session.execute(select(User).where(User.username == username))
    ).scalar_one_or_none()
    if existing is not None:
        return False

    admin = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role="admin",
        is_active=True,
    )
    session.add(admin)
    await session.flush()
    await append_audit_log(
        session,
        actor_id=admin.id,
        actor_username=admin.username,
        action="user.bootstrap_admin_created",
        resource_type="user",
        resource_id=str(admin.id),
        details={"role": "admin"},
    )
    await session.commit()
    return True
