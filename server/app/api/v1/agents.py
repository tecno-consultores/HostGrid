"""Agent heartbeat and pull-based patch job endpoints (/api/v1/agents)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter

from app.api.deps import AgentActor, DbSession
from app.schemas.enrollment import HeartbeatRequest, HeartbeatResponse
from app.schemas.patching import (
    AgentPatchJobResponse,
    AgentPatchJobResultRequest,
    PatchPlanResponse,
)
from app.services.enrollment_service import record_heartbeat
from app.services.patching.service import get_agent_patch_jobs, report_agent_patch_job_result

router = APIRouter(prefix="/agents", tags=["agents"])


@router.post("/{host_id}/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    host_id: UUID,
    payload: HeartbeatRequest,
    actor: AgentActor,
    session: DbSession,
) -> HeartbeatResponse:
    """Record periodic liveness heartbeat from an enrolled agent."""
    return await record_heartbeat(session, actor=actor, host_id=host_id, payload=payload)


@router.get("/{host_id}/patch-jobs", response_model=list[AgentPatchJobResponse])
async def agent_patch_jobs(
    host_id: UUID,
    actor: AgentActor,
    session: DbSession,
) -> list[AgentPatchJobResponse]:
    """Pull pending governed dry-run or active-wave patch jobs assigned to this host."""
    return await get_agent_patch_jobs(session, actor=actor, host_id=host_id)


@router.post("/{host_id}/patch-jobs/{plan_id}/result", response_model=PatchPlanResponse)
async def agent_patch_job_result(
    host_id: UUID,
    plan_id: UUID,
    payload: AgentPatchJobResultRequest,
    actor: AgentActor,
    session: DbSession,
) -> PatchPlanResponse:
    """Report dry-run simulation or wave execution Safe Mode result from an enrolled agent."""
    return await report_agent_patch_job_result(
        session,
        actor=actor,
        host_id=host_id,
        plan_id=plan_id,
        payload=payload,
    )
