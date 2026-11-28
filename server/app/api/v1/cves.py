"""Offline CVE sync, feed import, fleet rescan, and reverse search endpoints (/api/v1/cves)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import DbSession, UserActor
from app.schemas.host import (
    CveFeedImportRequest,
    CveFeedImportResponse,
    CveSearchResponse,
    CveSyncRequest,
    CveSyncResponse,
    FleetRescanResponse,
)
from app.services.cve.matcher import (
    import_offline_cve_feed,
    rescan_fleet_cves,
    search_cves_across_fleet,
    sync_cve_advisories,
)

router = APIRouter(prefix="/cves", tags=["cves"])


@router.get("/search", response_model=CveSearchResponse)
async def search_cves(
    actor: UserActor,
    session: DbSession,
    q: Annotated[str, Query(max_length=128)] = "",
) -> CveSearchResponse:
    """Global reverse search by CVE ID or package name across fleet."""
    return await search_cves_across_fleet(session, actor=actor, query=q)


@router.post("/sync-feed", response_model=CveSyncResponse)
async def sync_feed(
    payload: CveSyncRequest,
    actor: UserActor,
    session: DbSession,
) -> CveSyncResponse:
    """Load offline distro-aware CVE advisories into local database (admin only)."""
    return await sync_cve_advisories(session, actor=actor, payload=payload)


@router.post("/import-feed", response_model=CveFeedImportResponse)
async def import_feed(
    payload: CveFeedImportRequest,
    actor: UserActor,
    session: DbSession,
) -> CveFeedImportResponse:
    """Import raw offline OSV JSON, Trivy JSON, or OVAL XML vulnerability feeds (admin only)."""
    return await import_offline_cve_feed(session, actor=actor, payload=payload)


@router.post("/rescan-fleet", response_model=FleetRescanResponse)
async def rescan_fleet(
    actor: UserActor,
    session: DbSession,
) -> FleetRescanResponse:
    """Re-evaluate all hosts' latest snapshots against the local offline CVE database."""
    return await rescan_fleet_cves(session, actor=actor)
