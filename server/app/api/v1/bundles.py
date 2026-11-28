"""Signed portable tool bundle endpoints (/api/v1/bundles)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, File, Form, Query, UploadFile, status
from fastapi.responses import FileResponse

from app.api.deps import AppSettings, DbSession, UserActor, UserOrAgentActor
from app.core.errors import DomainError
from app.schemas.host import ToolBundleManifestResponse
from app.services.artifacts.tool_bundles import (
    MAX_TOOL_BUNDLE_BYTES,
    get_tool_bundle_file,
    get_tool_bundle_manifest,
    register_tool_bundle,
)

router = APIRouter(prefix="/bundles", tags=["bundles"])


async def _read_tool_upload_bounded(upload: UploadFile, max_bytes: int) -> bytes:
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
                detail="Uploaded tool bundle exceeds maximum allowed size.",
                error_type="urn:hostgrid:error:tool_bundle_too_large",
            )
        chunks.append(chunk)
    return b"".join(chunks)


@router.post(
    "/register",
    response_model=ToolBundleManifestResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_tool_bundle(
    tool_name: Annotated[str, Form(...)],
    version: Annotated[str, Form(...)],
    file: Annotated[UploadFile, File(...)],
    actor: UserActor,
    session: DbSession,
    settings: AppSettings,
    arch: Annotated[str, Form()] = "noarch",
    signature_b64: Annotated[str | None, Form()] = None,
) -> ToolBundleManifestResponse:
    """Register and sign a portable tool tarball (e.g., Lynis portable)."""
    content = await _read_tool_upload_bounded(file, MAX_TOOL_BUNDLE_BYTES)
    filename = file.filename or f"{tool_name}-{version}-portable.tar.gz"
    return await register_tool_bundle(
        session,
        settings=settings,
        actor=actor,
        tool_name=tool_name,
        version=version,
        arch=arch,
        filename=filename,
        tarball_bytes=content,
        signature_b64=signature_b64,
    )


@router.get("/{tool}/{version}/manifest", response_model=ToolBundleManifestResponse)
async def tool_manifest(
    tool: str,
    version: str,
    actor: UserOrAgentActor,
    session: DbSession,
    arch: Annotated[str | None, Query(max_length=32)] = None,
) -> ToolBundleManifestResponse:
    """Fetch Ed25519-signed manifest for a portable tool bundle."""
    return await get_tool_bundle_manifest(
        session,
        actor=actor,
        tool_name=tool,
        version=version,
        arch=arch,
    )


@router.get("/{tool}/{version}/download")
async def tool_download(
    tool: str,
    version: str,
    actor: UserOrAgentActor,
    session: DbSession,
    settings: AppSettings,
    arch: Annotated[str | None, Query(max_length=32)] = None,
) -> FileResponse:
    """Download signed portable tool tarball."""
    path, bundle = await get_tool_bundle_file(
        session,
        settings=settings,
        actor=actor,
        tool_name=tool,
        version=version,
        arch=arch,
    )
    return FileResponse(
        path=path,
        media_type="application/gzip",
        filename=bundle.filename,
        headers={"X-HostGrid-SHA256": bundle.sha256},
    )
