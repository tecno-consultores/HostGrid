"""API v1 router aggregator."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    agents,
    audit,
    auth,
    bundles,
    cves,
    enrollments,
    hosts,
    patching,
    reports,
    snapshots,
    users,
)

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(auth.router)
api_v1_router.include_router(users.router)
api_v1_router.include_router(enrollments.router)
api_v1_router.include_router(agents.router)
api_v1_router.include_router(hosts.router)
api_v1_router.include_router(snapshots.router)
api_v1_router.include_router(cves.router)
api_v1_router.include_router(bundles.router)
api_v1_router.include_router(reports.router)
api_v1_router.include_router(audit.router)
api_v1_router.include_router(patching.router)
