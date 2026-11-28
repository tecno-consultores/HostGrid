"""WORM immutable audit log endpoints (/api/v1/audit)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import DbSession, UserActor
from app.schemas.common import PaginatedResponse
from app.schemas.host import AuditLogItem, AuditVerifyResponse
from app.services.host_service import list_audit_logs
from app.services.worm import verify_audit_chain

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/logs", response_model=PaginatedResponse[AuditLogItem])
async def audit_logs(
    actor: UserActor,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedResponse[AuditLogItem]:
    """Query paginated WORM audit log entries."""
    return await list_audit_logs(session, actor=actor, limit=limit, offset=offset)


@router.get("/verify", response_model=AuditVerifyResponse)
async def verify_audit(
    actor: UserActor,
    session: DbSession,
) -> AuditVerifyResponse:
    """Verify integrity of the entire SHA-256 hash-chained WORM audit log."""
    return await verify_audit_chain(session, actor=actor)
