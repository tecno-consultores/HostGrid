"""Signed portable tool bundle registry, manifest signing, and safe streaming download."""

from __future__ import annotations

import asyncio
import base64
import os
import re
import tempfile
from pathlib import Path

from sqlalchemy import Select, case, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import DomainError
from app.core.rbac import ALL_USER_ROLES, OPERATOR_OR_ADMIN, ActorContext, require_roles
from app.core.security import (
    canonical_json_bytes,
    sha256_hex,
    sign_ed25519_b64,
    utc_now,
    verify_ed25519_b64,
)
from app.db.models import ToolBundle
from app.schemas.host import ToolBundleManifestResponse
from app.services.worm import append_audit_log

_SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")
ALLOWED_BUNDLE_ARCHES = frozenset({"noarch", "amd64", "arm64", "386"})
MAX_TOOL_NAME_LEN = 64
MAX_TOOL_VERSION_LEN = 32
MAX_TOOL_BUNDLE_BYTES = 50 * 1024 * 1024


def validate_safe_segment(value: str, field_name: str, *, max_length: int = 128) -> str:
    """Reject path traversal, overlong values, or illegal characters in bundle identifiers."""
    if not value or len(value) > max_length or not _SAFE_NAME_RE.match(value) or ".." in value:
        raise DomainError(
            status_code=400,
            title="Bad Request",
            detail=f"Invalid {field_name} identifier.",
            error_type="urn:hostgrid:error:invalid_path_segment",
        )
    return value


def validate_bundle_arch(value: str) -> str:
    """Enforce SPEC.md section 2.2.11 architecture allow-list (noarch|amd64|arm64|386)."""
    cleaned = validate_safe_segment(value, "arch", max_length=32)
    if cleaned not in ALLOWED_BUNDLE_ARCHES:
        raise DomainError(
            status_code=400,
            title="Bad Request",
            detail="Unsupported bundle architecture (allowed: noarch, amd64, arm64, 386).",
            error_type="urn:hostgrid:error:invalid_arch",
        )
    return cleaned


def build_manifest_canonical_json(bundle: ToolBundle) -> str:
    """Construct the exact sorted-key canonical JSON signed with Ed25519."""
    payload = {
        "arch": bundle.arch,
        "filename": bundle.filename,
        "sha256": bundle.sha256,
        "size_bytes": bundle.size_bytes,
        "tool_name": bundle.tool_name,
        "version": bundle.version,
    }
    return canonical_json_bytes(payload).decode("utf-8")


def resolve_safe_bundle_path(bundles_dir: str, filename: str) -> Path:
    """Resolve legacy flat bundle path strictly within bundles_dir preventing path traversal."""
    validate_safe_segment(filename, "filename")
    base = Path(os.path.realpath(bundles_dir))
    candidate = Path(os.path.realpath(base / filename))
    if candidate.parent != base:
        raise DomainError(
            status_code=400,
            title="Bad Request",
            detail="Bundle path escapes configured artifact root.",
            error_type="urn:hostgrid:error:path_traversal",
        )
    return candidate


def resolve_bundle_storage_path(
    bundles_dir: str,
    tool_name: str,
    version: str,
    arch: str,
    filename: str,
) -> Path:
    """Resolve isolated per-(tool, version, arch) path inside bundles_dir preventing collisions."""
    clean_tool = validate_safe_segment(tool_name, "tool_name", max_length=MAX_TOOL_NAME_LEN)
    clean_ver = validate_safe_segment(version, "version", max_length=MAX_TOOL_VERSION_LEN)
    clean_arch = validate_bundle_arch(arch)
    clean_file = validate_safe_segment(filename, "filename")
    base = Path(os.path.realpath(bundles_dir))
    subdir = Path(os.path.realpath(base / clean_tool / clean_ver / clean_arch))
    candidate = Path(os.path.realpath(subdir / clean_file))
    if candidate.parent != subdir or not candidate.is_relative_to(base):
        raise DomainError(
            status_code=400,
            title="Bad Request",
            detail="Bundle path escapes configured artifact root.",
            error_type="urn:hostgrid:error:path_traversal",
        )
    return candidate


def _write_bundle_file_sync(
    bundles_dir: str,
    tool_name: str,
    version: str,
    arch: str,
    filename: str,
    tarball_bytes: bytes,
) -> None:
    target_path = resolve_bundle_storage_path(bundles_dir, tool_name, version, arch, filename)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".bundle-", suffix=".tmp", dir=str(target_path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(tarball_bytes)
        os.replace(tmp_name, target_path)
    except Exception:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def _validate_provided_signature(
    settings: Settings,
    canonical_bytes: bytes,
    clean_sig: str,
) -> str:
    try:
        raw_sig = base64.b64decode(clean_sig, validate=True)
    except ValueError as exc:
        raise DomainError(
            status_code=422,
            title="Invalid Bundle Signature",
            detail="Provided signature_b64 is not valid Base64.",
            error_type="urn:hostgrid:error:invalid_signature",
        ) from exc
    if len(raw_sig) != 64:
        raise DomainError(
            status_code=422,
            title="Invalid Bundle Signature",
            detail="Ed25519 signature_b64 must decode to exactly 64 bytes.",
            error_type="urn:hostgrid:error:invalid_signature",
        )
    if settings.hostgrid_bundle_signing_pubkey_b64 and not verify_ed25519_b64(
        settings.hostgrid_bundle_signing_pubkey_b64,
        canonical_bytes,
        clean_sig,
    ):
        raise DomainError(
            status_code=422,
            title="Invalid Bundle Signature",
            detail="Provided Ed25519 signature failed verification against signing public key.",
            error_type="urn:hostgrid:error:invalid_signature",
        )
    return clean_sig


async def register_tool_bundle(
    session: AsyncSession,
    *,
    settings: Settings,
    actor: ActorContext,
    tool_name: str,
    version: str,
    arch: str,
    filename: str,
    tarball_bytes: bytes,
    signature_b64: str | None = None,
) -> ToolBundleManifestResponse:
    """Store and sign (or verify provided signature of) a portable tool bundle."""
    require_roles(actor, OPERATOR_OR_ADMIN)
    clean_tool = validate_safe_segment(tool_name, "tool_name", max_length=MAX_TOOL_NAME_LEN)
    clean_ver = validate_safe_segment(version, "version", max_length=MAX_TOOL_VERSION_LEN)
    clean_arch = validate_bundle_arch(arch)
    clean_file = validate_safe_segment(filename, "filename")

    digest = sha256_hex(tarball_bytes)
    size_bytes = len(tarball_bytes)
    temp_bundle = ToolBundle(
        tool_name=clean_tool,
        version=clean_ver,
        arch=clean_arch,
        filename=clean_file,
        sha256=digest,
        signature_b64="",
        size_bytes=size_bytes,
    )
    canonical = build_manifest_canonical_json(temp_bundle)
    resolved_sig = _resolve_signature(settings, canonical.encode("utf-8"), signature_b64)

    await asyncio.to_thread(
        _write_bundle_file_sync,
        settings.hostgrid_bundles_dir,
        clean_tool,
        clean_ver,
        clean_arch,
        clean_file,
        tarball_bytes,
    )

    existing = (
        await session.execute(
            select(ToolBundle).where(
                ToolBundle.tool_name == clean_tool,
                ToolBundle.version == clean_ver,
                ToolBundle.arch == clean_arch,
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        bundle = ToolBundle(
            tool_name=clean_tool,
            version=clean_ver,
            arch=clean_arch,
            filename=clean_file,
            sha256=digest,
            signature_b64=resolved_sig,
            size_bytes=size_bytes,
            is_active=True,
        )
        session.add(bundle)
    else:
        existing.filename = clean_file
        existing.sha256 = digest
        existing.signature_b64 = resolved_sig
        existing.size_bytes = size_bytes
        existing.is_active = True
        existing.published_at = utc_now()
        bundle = existing

    await append_audit_log(
        session,
        actor_id=actor.actor_id,
        actor_username=actor.username,
        action="tool_bundle.registered",
        resource_type="tool_bundle",
        resource_id=f"{clean_tool}:{clean_ver}:{clean_arch}",
        details={"filename": clean_file, "sha256": digest, "size_bytes": size_bytes},
    )
    await session.commit()
    return _to_manifest_response(bundle)


def _resolve_signature(
    settings: Settings,
    canonical_bytes: bytes,
    provided_sig: str | None,
) -> str:
    if provided_sig and provided_sig.strip():
        return _validate_provided_signature(settings, canonical_bytes, provided_sig.strip())
    if settings.hostgrid_bundle_signing_privkey_b64:
        return sign_ed25519_b64(settings.hostgrid_bundle_signing_privkey_b64, canonical_bytes)
    raise DomainError(
        status_code=422,
        title="Missing Signature",
        detail="Provide Ed25519 signature_b64 or configure HOSTGRID_BUNDLE_SIGNING_PRIVKEY_B64.",
        error_type="urn:hostgrid:error:missing_signature",
    )


def _build_bundle_lookup_stmt(
    clean_tool: str,
    version: str,
    clean_arch: str | None,
) -> Select[ToolBundle]:
    stmt = select(ToolBundle).where(
        ToolBundle.tool_name == clean_tool,
        ToolBundle.is_active.is_(True),
    )
    if clean_arch is not None:
        stmt = stmt.where(ToolBundle.arch == clean_arch)
    noarch_first = case((ToolBundle.arch == "noarch", 0), else_=1)
    if version == "latest":
        return stmt.order_by(
            desc(ToolBundle.published_at),
            noarch_first,
            ToolBundle.arch.asc(),
            ToolBundle.id.asc(),
        ).limit(1)
    clean_ver = validate_safe_segment(version, "version", max_length=MAX_TOOL_VERSION_LEN)
    return (
        stmt.where(ToolBundle.version == clean_ver)
        .order_by(
            noarch_first,
            desc(ToolBundle.published_at),
            ToolBundle.arch.asc(),
            ToolBundle.id.asc(),
        )
        .limit(1)
    )


async def _find_tool_bundle(
    session: AsyncSession,
    tool_name: str,
    version: str,
    arch: str | None = None,
) -> ToolBundle:
    clean_tool = validate_safe_segment(tool_name, "tool_name", max_length=MAX_TOOL_NAME_LEN)
    stripped_arch = arch.strip() if arch is not None else ""
    clean_arch = validate_bundle_arch(stripped_arch) if stripped_arch else None
    stmt = _build_bundle_lookup_stmt(clean_tool, version, clean_arch)
    bundle = (await session.execute(stmt)).scalar_one_or_none()
    if bundle is None:
        raise DomainError(
            status_code=404,
            title="Not Found",
            detail="Requested tool bundle was not found.",
            error_type="urn:hostgrid:error:not_found",
        )
    return bundle


def _to_manifest_response(bundle: ToolBundle) -> ToolBundleManifestResponse:
    base_url = f"/api/v1/bundles/{bundle.tool_name}/{bundle.version}/download"
    download_url = base_url if bundle.arch == "noarch" else f"{base_url}?arch={bundle.arch}"
    return ToolBundleManifestResponse(
        tool_name=bundle.tool_name,
        version=bundle.version,
        arch=bundle.arch,
        filename=bundle.filename,
        sha256=bundle.sha256,
        size_bytes=bundle.size_bytes,
        manifest_canonical_json=build_manifest_canonical_json(bundle),
        signature_b64=bundle.signature_b64,
        download_url=download_url,
    )


async def get_tool_bundle_manifest(
    session: AsyncSession,
    *,
    actor: ActorContext,
    tool_name: str,
    version: str,
    arch: str | None = None,
) -> ToolBundleManifestResponse:
    """Return signed manifest metadata for a portable tool bundle."""
    if not actor.is_agent:
        require_roles(actor, ALL_USER_ROLES)
    bundle = await _find_tool_bundle(session, tool_name, version, arch=arch)
    return _to_manifest_response(bundle)


async def get_tool_bundle_file(
    session: AsyncSession,
    *,
    settings: Settings,
    actor: ActorContext,
    tool_name: str,
    version: str,
    arch: str | None = None,
) -> tuple[Path, ToolBundle]:
    """Resolve and verify on-disk bundle tarball for download."""
    if not actor.is_agent:
        require_roles(actor, OPERATOR_OR_ADMIN)
    bundle = await _find_tool_bundle(session, tool_name, version, arch=arch)
    path = resolve_bundle_storage_path(
        settings.hostgrid_bundles_dir,
        bundle.tool_name,
        bundle.version,
        bundle.arch,
        bundle.filename,
    )
    if not path.is_file():
        legacy_path = resolve_safe_bundle_path(settings.hostgrid_bundles_dir, bundle.filename)
        if legacy_path.is_file():
            path = legacy_path
        else:
            raise DomainError(
                status_code=404,
                title="Not Found",
                detail="Bundle archive file missing on storage.",
                error_type="urn:hostgrid:error:bundle_missing",
            )
    return path, bundle
