"""Fleet and host detail endpoints (/api/v1/hosts)."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from app.api.deps import DbSession, UserActor
from app.schemas.common import PaginatedResponse
from app.schemas.host import HostDetailResponse, HostListItem
from app.schemas.snapshot import PackageRecordResponse, SnapshotSummaryResponse
from app.services.host_service import (
    HostFilterParams,
    get_host_detail,
    list_host_snapshots,
    list_hosts,
    list_snapshot_packages,
)

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("", response_model=PaginatedResponse[HostListItem])
async def get_hosts(
    actor: UserActor,
    session: DbSession,
    search: Annotated[str | None, Query(max_length=128)] = None,
    os_family: Annotated[str | None, Query(max_length=32)] = None,
    eol_status: Annotated[str | None, Query(max_length=24)] = None,
    connectivity_mode: Annotated[str | None, Query(max_length=16)] = None,
    repo_access_ok: Annotated[bool | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedResponse[HostListItem]:
    """List fleet servers with optional filtering."""
    filters = HostFilterParams(
        search=search,
        os_family=os_family,
        eol_status=eol_status,
        connectivity_mode=connectivity_mode,
        repo_access_ok=repo_access_ok,
        limit=limit,
        offset=offset,
    )
    return await list_hosts(session, actor=actor, filters=filters)


@router.get("/{host_id}", response_model=HostDetailResponse)
async def host_detail(
    host_id: UUID,
    actor: UserActor,
    session: DbSession,
) -> HostDetailResponse:
    """Get single host details including Capability Probe."""
    return await get_host_detail(session, actor=actor, host_id=host_id)


@router.get("/{host_id}/snapshots", response_model=PaginatedResponse[SnapshotSummaryResponse])
async def host_snapshots(
    host_id: UUID,
    actor: UserActor,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedResponse[SnapshotSummaryResponse]:
    """Get snapshot timeline for a host."""
    return await list_host_snapshots(
        session,
        actor=actor,
        host_id=host_id,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{host_id}/packages",
    response_model=PaginatedResponse[PackageRecordResponse],
)
async def host_latest_packages(
    host_id: UUID,
    actor: UserActor,
    session: DbSession,
    search: Annotated[str | None, Query(max_length=128)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedResponse[PackageRecordResponse]:
    """Get SBOM packages from the host's latest snapshot."""
    detail = await get_host_detail(session, actor=actor, host_id=host_id)
    if detail.latest_snapshot_id is None:
        return PaginatedResponse(items=[], total=0, limit=limit, offset=offset)
    return await list_snapshot_packages(
        session,
        actor=actor,
        snapshot_id=detail.latest_snapshot_id,
        search=search,
        limit=limit,
        offset=offset,
    )
