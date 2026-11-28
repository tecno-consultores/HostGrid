"""Snapshot ingestion, air-gapped bundle import, drift, and findings endpoints."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, File, Header, Query, UploadFile, status

from app.api.deps import AgentActor, AppSettings, DbSession, UserActor
from app.core.errors import DomainError
from app.schemas.common import PaginatedResponse
from app.schemas.host import DriftResponse, FindingResponse
from app.schemas.snapshot import (
    AgentlessIngestRequest,
    SnapshotCreatedResponse,
    SnapshotIngestRequest,
)
from app.services.drift.engine import get_snapshot_drift
from app.services.host_service import list_snapshot_findings
from app.services.ingestion import (
    ingest_agent_snapshot,
    ingest_agentless_snapshot,
    ingest_airgapped_bundle,
)

router = APIRouter(prefix="/snapshots", tags=["snapshots"])


async def _read_upload_bounded(upload: UploadFile, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await upload.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise DomainError(
                status_code=413,
                title="Payload Too Large",
                detail="Uploaded bundle exceeds maximum configured size.",
                error_type="urn:hostgrid:error:bundle_too_large",
            )
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("", response_model=SnapshotCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_snapshot(
    payload: SnapshotIngestRequest,
    actor: AgentActor,
    session: DbSession,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", max_length=64)] = None,
) -> SnapshotCreatedResponse:
    """Ingest a snapshot pushed by an enrolled agent."""
    return await ingest_agent_snapshot(
        session,
        actor=actor,
        payload=payload,
        idempotency_key=idempotency_key,
    )


@router.post(
    "/import-bundle",
    response_model=SnapshotCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
async def import_bundle(
    file: Annotated[UploadFile, File(...)],
    actor: UserActor,
    session: DbSession,
    settings: AppSettings,
) -> SnapshotCreatedResponse:
    """Upload, cryptographically verify, and ingest an air-gapped .bundle archive."""
    raw = await _read_upload_bounded(file, settings.max_bundle_bytes)
    return await ingest_airgapped_bundle(
        session,
        settings=settings,
        actor=actor,
        raw_bytes=raw,
    )


@router.post(
    "/import-agentless",
    response_model=SnapshotCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
async def import_agentless(
    payload: AgentlessIngestRequest,
    actor: UserActor,
    session: DbSession,
) -> SnapshotCreatedResponse:
    """Ingest JSON output from agentless/collect_posix.sh."""
    return await ingest_agentless_snapshot(session, actor=actor, payload=payload)


@router.get("/{snapshot_id}/drift", response_model=DriftResponse)
async def snapshot_drift(
    snapshot_id: UUID,
    actor: UserActor,
    session: DbSession,
) -> DriftResponse:
    """Retrieve diff between snapshot and its predecessor."""
    return await get_snapshot_drift(session, actor=actor, snapshot_id=snapshot_id)


@router.get("/{snapshot_id}/findings", response_model=PaginatedResponse[FindingResponse])
async def snapshot_findings(
    snapshot_id: UUID,
    actor: UserActor,
    session: DbSession,
    severity: Annotated[str | None, Query(max_length=16)] = None,
    category: Annotated[str | None, Query(max_length=32)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedResponse[FindingResponse]:
    """Retrieve normalized deduplicated findings for a snapshot."""
    return await list_snapshot_findings(
        session,
        actor=actor,
        snapshot_id=snapshot_id,
        severity=severity,
        category=category,
        limit=limit,
        offset=offset,
    )
