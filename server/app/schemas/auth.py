"""Authentication and user profile schemas."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator

from app.schemas.common import StrictBaseModel, sanitize_single_line


class LoginRequest(StrictBaseModel):
    """Human user login payload."""

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("username")
    @classmethod
    def _clean_username(cls, value: str) -> str:
        return sanitize_single_line(value).strip()


class TokenResponse(StrictBaseModel):
    """JWT access token response."""

    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105
    expires_at: str
    user: UserProfile


class UserProfile(StrictBaseModel):
    """Authenticated user profile."""

    id: UUID
    username: str
    email: str
    role: Literal["admin", "approver", "operator", "viewer"]
    is_active: bool


class UserCreateRequest(StrictBaseModel):
    """Admin-only user provisioning payload (SPEC.md 1.2)."""

    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    email: str = Field(min_length=5, max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=12, max_length=256)
    role: Literal["admin", "approver", "operator", "viewer"] = "viewer"

    @field_validator("username", "email")
    @classmethod
    def _clean_user_fields(cls, value: str) -> str:
        return sanitize_single_line(value).strip()


class UserUpdateRequest(StrictBaseModel):
    """Admin-only user role, status, or lockout reset update payload."""

    role: Literal["admin", "approver", "operator", "viewer"] | None = None
    is_active: bool | None = None
    unlock: bool = False
