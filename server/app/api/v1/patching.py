"""Governed patching plan endpoints (/api/v1/patching, Phase 3)."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Header, Query, status

from app.api.deps import DbSession, UserActor
from app.schemas.common import PaginatedResponse
from app.schemas.patching import (
    PatchDecisionRequest,
    PatchDryRunSubmitRequest,
    PatchPlanCreateRequest,
    PatchPlanResponse,
    WaveHealthReportRequest,
)
from app.services.patching.service import (
    create_patch_plan,
    decide_patch_plan,
    get_patch_plan,
    list_patch_plans,
    report_wave_health,
    start_canary_execution,
    submit_dry_run,
)

router = APIRouter(prefix="/patching", tags=["patching"])


@router.get("/plans", response_model=PaginatedResponse[PatchPlanResponse])
async def get_patch_plans(
    actor: UserActor,
    session: DbSession,
    status_filter: Annotated[str | None, Query(alias="status", max_length=32)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedResponse[PatchPlanResponse]:
    """List governed patch plans with optional status filtering."""
    return await list_patch_plans(
        session,
        actor=actor,
        status_filter=status_filter,
        limit=limit,
        offset=offset,
    )


@router.get("/plans/{plan_id}", response_model=PatchPlanResponse)
async def fetch_patch_plan(
    plan_id: UUID,
    actor: UserActor,
    session: DbSession,
) -> PatchPlanResponse:
    """Get governed patch plan details, canary waves, dry-run report, and Maker-Checker trail."""
    return await get_patch_plan(session, actor=actor, plan_id=plan_id)


@router.post("/plans", response_model=PatchPlanResponse, status_code=status.HTTP_201_CREATED)
async def new_patch_plan(
    payload: PatchPlanCreateRequest,
    actor: UserActor,
    session: DbSession,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", max_length=64)] = None,
) -> PatchPlanResponse:
    """Create a governed patch plan and execute repository pre-verification (operator/admin)."""
    return await create_patch_plan(
        session,
        actor=actor,
        payload=payload,
        idempotency_key=idempotency_key,
    )


@router.post("/plans/{plan_id}/dry-run", response_model=PatchPlanResponse)
async def record_dry_run(
    plan_id: UUID,
    payload: PatchDryRunSubmitRequest,
    actor: UserActor,
    session: DbSession,
) -> PatchPlanResponse:
    """Submit per-host dry-run outcomes to transition DRY_RUN_READY -> PENDING_APPROVAL."""
    return await submit_dry_run(session, actor=actor, plan_id=plan_id, payload=payload)


@router.post("/plans/{plan_id}/decision", response_model=PatchPlanResponse)
async def plan_decision(
    plan_id: UUID,
    payload: PatchDecisionRequest,
    actor: UserActor,
    session: DbSession,
) -> PatchPlanResponse:
    """Approve or reject a patch plan enforcing Maker-Checker (approver != creator)."""
    return await decide_patch_plan(session, actor=actor, plan_id=plan_id, payload=payload)


@router.post("/plans/{plan_id}/execute", response_model=PatchPlanResponse)
async def execute_canary(
    plan_id: UUID,
    actor: UserActor,
    session: DbSession,
) -> PatchPlanResponse:
    """Start progressive canary rollout (APPROVED -> CANARY_WAVE)."""
    return await start_canary_execution(session, actor=actor, plan_id=plan_id)


@router.post("/plans/{plan_id}/wave-report", response_model=PatchPlanResponse)
async def wave_report(
    plan_id: UUID,
    payload: WaveHealthReportRequest,
    actor: UserActor,
    session: DbSession,
) -> PatchPlanResponse:
    """Record wave health telemetry to advance waves or trigger Safe Mode rollback."""
    return await report_wave_health(session, actor=actor, plan_id=plan_id, payload=payload)
