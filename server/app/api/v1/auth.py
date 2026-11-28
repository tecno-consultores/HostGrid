"""Authentication endpoints (/api/v1/auth)."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import AppSettings, CurrentUserPair, DbSession
from app.schemas.auth import LoginRequest, TokenResponse, UserProfile
from app.services.auth_service import authenticate_user, to_user_profile

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    session: DbSession,
    settings: AppSettings,
) -> TokenResponse:
    """Authenticate user credentials and return JWT access token."""
    return await authenticate_user(
        session,
        settings=settings,
        username=payload.username,
        password=payload.password,
    )


@router.get("/me", response_model=UserProfile)
async def me(user_and_actor: CurrentUserPair) -> UserProfile:
    """Return profile and role of current authenticated user."""
    return to_user_profile(user_and_actor[0])
