"""Admin-only user and role management endpoints (/api/v1/users, SPEC.md 1.2)."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, status

from app.api.deps import DbSession, UserActor
from app.schemas.auth import UserCreateRequest, UserProfile, UserUpdateRequest
from app.schemas.common import PaginatedResponse
from app.services.user_service import create_user, list_users, update_user

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=PaginatedResponse[UserProfile])
async def get_users(
    actor: UserActor,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedResponse[UserProfile]:
    """List registered HostGrid users (admin only)."""
    return await list_users(session, actor=actor, limit=limit, offset=offset)


@router.post("", response_model=UserProfile, status_code=status.HTTP_201_CREATED)
async def register_user(
    payload: UserCreateRequest,
    actor: UserActor,
    session: DbSession,
) -> UserProfile:
    """Create a new HostGrid user with explicit RBAC role (admin only)."""
    return await create_user(session, actor=actor, payload=payload)


@router.patch("/{user_id}", response_model=UserProfile)
async def modify_user(
    user_id: UUID,
    payload: UserUpdateRequest,
    actor: UserActor,
    session: DbSession,
) -> UserProfile:
    """Update a user's RBAC role, active state, or unlock lockout (admin only)."""
    return await update_user(session, actor=actor, user_id=user_id, payload=payload)
