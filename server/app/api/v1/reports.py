"""Report export endpoints (/api/v1/reports)."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Query, Response
from fastapi.responses import JSONResponse

from app.api.deps import DbSession, UserActor
from app.services.host_service import export_host_report

router = APIRouter(prefix="/reports", tags=["reports"])

_TEXT_MEDIA_TYPES: dict[str, tuple[str, str]] = {
    "markdown": ("text/markdown; charset=utf-8", "md"),
    "html": ("text/html; charset=utf-8", "html"),
}


@router.get("/hosts/{host_id}")
async def host_report(
    host_id: UUID,
    actor: UserActor,
    session: DbSession,
    report_format: Annotated[
        Literal["json", "sarif", "markdown", "html"],
        Query(alias="format"),
    ] = "json",
) -> Response:
    """Export host security report as JSON, SARIF 2.1.0, Markdown, or print-ready HTML."""
    result = await export_host_report(
        session,
        actor=actor,
        host_id=host_id,
        report_format=report_format,
    )
    if isinstance(result, str):
        media_type, ext = _TEXT_MEDIA_TYPES[report_format]
        headers = {
            "Content-Disposition": f'attachment; filename="hostgrid-{host_id}.{ext}"',
            "X-Content-Type-Options": "nosniff",
        }
        if report_format == "html":
            headers["Content-Security-Policy"] = (
                "default-src 'none'; style-src 'unsafe-inline'; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            )
        return Response(
            content=result,
            media_type=media_type,
            headers=headers,
        )
    return JSONResponse(content=result)
