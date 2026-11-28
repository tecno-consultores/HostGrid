"""FastAPI dependency injection adapters for DB sessions, settings, and authentication."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.errors import DomainError
from app.core.rbac import ActorContext, Role
from app.core.security import decode_access_token, sha256_hex
from app.db.models import Host, User

_BEARER = HTTPBearer(auto_error=False)
BearerCreds = Annotated[HTTPAuthorizationCredentials | None, Depends(_BEARER)]


def get_app_settings(request: Request) -> Settings:
    """Retrieve bound Settings instance from FastAPI app state."""
    settings: Settings = request.app.state.settings
    return settings


async def get_db_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Yield request-scoped AsyncSession from app state."""
    factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    async with factory() as session:
        yield session


DbSession = Annotated[AsyncSession, Depends(get_db_session)]
AppSettings = Annotated[Settings, Depends(get_app_settings)]


def _extract_bearer(credentials: HTTPAuthorizationCredentials | None) -> str:
    if credentials is None or not credentials.credentials:
        raise DomainError(
            status_code=401,
            title="Unauthorized",
            detail="Missing Bearer authentication token.",
            error_type="urn:hostgrid:error:auth",
        )
    return credentials.credentials


async def _resolve_user_from_jwt(
    token: str,
    session: AsyncSession,
    settings: Settings,
) -> tuple[User, ActorContext]:
    claims = decode_access_token(token, settings.hostgrid_jwt_secret)
    try:
        user_id = UUID(str(claims["sub"]))
    except (KeyError, ValueError) as exc:
        raise DomainError(
            status_code=401,
            title="Unauthorized",
            detail="Malformed authentication subject.",
            error_type="urn:hostgrid:error:auth",
        ) from exc

    user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None or not user.is_active:
        raise DomainError(
            status_code=401,
            title="Unauthorized",
            detail="User account is inactive or does not exist.",
            error_type="urn:hostgrid:error:auth",
        )
    actor = ActorContext(
        actor_id=user.id,
        username=user.username,
        role=Role(user.role),
        is_agent=False,
    )
    return user, actor


async def _resolve_agent_from_token(token: str, session: AsyncSession) -> ActorContext:
    cred_hash = sha256_hex(token)
    host = (
        await session.execute(select(Host).where(Host.credential_hash == cred_hash))
    ).scalar_one_or_none()
    if host is None:
        raise DomainError(
            status_code=401,
            title="Unauthorized",
            detail="Invalid agent credential.",
            error_type="urn:hostgrid:error:agent_auth",
        )
    return ActorContext(
        actor_id=None,
        username=f"agent:{host.hostname}",
        role=None,
        is_agent=True,
        host_id=host.id,
    )


async def get_current_user(
    credentials: BearerCreds,
    session: DbSession,
    settings: AppSettings,
) -> tuple[User, ActorContext]:
    """Authenticate a human user JWT."""
    token = _extract_bearer(credentials)
    return await _resolve_user_from_jwt(token, session, settings)


CurrentUserPair = Annotated[tuple[User, ActorContext], Depends(get_current_user)]


async def get_user_actor(user_and_actor: CurrentUserPair) -> ActorContext:
    """Return ActorContext for an authenticated human user."""
    return user_and_actor[1]


async def get_agent_actor(
    credentials: BearerCreds,
    session: DbSession,
) -> ActorContext:
    """Authenticate an enrolled hostgrid-agent credential."""
    token = _extract_bearer(credentials)
    return await _resolve_agent_from_token(token, session)


async def get_user_or_agent_actor(
    credentials: BearerCreds,
    session: DbSession,
    settings: AppSettings,
) -> ActorContext:
    """Authenticate either an enrolled agent credential or a human user JWT."""
    token = _extract_bearer(credentials)
    if token.startswith("hg_agent_"):
        return await _resolve_agent_from_token(token, session)
    _, actor = await _resolve_user_from_jwt(token, session, settings)
    return actor


UserActor = Annotated[ActorContext, Depends(get_user_actor)]
AgentActor = Annotated[ActorContext, Depends(get_agent_actor)]
UserOrAgentActor = Annotated[ActorContext, Depends(get_user_or_agent_actor)]
