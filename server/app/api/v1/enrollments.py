"""Enrollment endpoints (/api/v1/enrollments)."""

from __future__ import annotations

from fastapi import APIRouter, status

from app.api.deps import AppSettings, DbSession, UserActor
from app.schemas.enrollment import (
    EnrollmentRegisterRequest,
    EnrollmentRegisterResponse,
    EnrollmentTokenCreateRequest,
    EnrollmentTokenResponse,
)
from app.services.enrollment_service import create_enrollment_token, register_agent

router = APIRouter(prefix="/enrollments", tags=["enrollments"])


@router.post(
    "/tokens",
    response_model=EnrollmentTokenResponse,
    status_code=status.HTTP_201_CREATED,
)
async def issue_token(
    payload: EnrollmentTokenCreateRequest,
    actor: UserActor,
    session: DbSession,
) -> EnrollmentTokenResponse:
    """Issue a single-use expiring enrollment token."""
    return await create_enrollment_token(session, actor=actor, payload=payload)


@router.post(
    "/register",
    response_model=EnrollmentRegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    payload: EnrollmentRegisterRequest,
    session: DbSession,
    settings: AppSettings,
) -> EnrollmentRegisterResponse:
    """Enroll a hostgrid-agent node using a single-use token."""
    return await register_agent(session, settings=settings, payload=payload)
