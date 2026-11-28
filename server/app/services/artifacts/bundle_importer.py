"""Strict 7-step validator and extractor for air-gapped .bundle archives."""

from __future__ import annotations

import io
import json
import re
import tarfile
from dataclasses import dataclass

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import DomainError
from app.core.rbac import ActorContext
from app.core.security import (
    sha256_hex,
    verify_ed25519_b64,
    verify_hmac_sha256_b64,
)
from app.db.models import Host
from app.schemas.snapshot import BundleManifest, SnapshotIngestRequest
from app.services.worm import append_audit_log

MAX_TAR_ENTRIES = 16
CHUNK_SIZE = 65536
_ENTRY_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")


@dataclass(frozen=True)
class ValidatedBundle:
    """Validated air-gapped bundle ready for snapshot ingestion."""

    manifest: BundleManifest
    snapshot: SnapshotIngestRequest
    bundle_sha256: str


def _validate_member_safety(member: tarfile.TarInfo) -> str:
    name = member.name.removeprefix("./")
    if (
        not member.isfile()
        or member.issym()
        or member.islnk()
        or "/" in name
        or "\\" in name
        or ".." in name
        or not _ENTRY_NAME_RE.match(name)
    ):
        raise DomainError(
            status_code=422,
            title="Unsafe Archive Entry",
            detail=f"Rejected unsafe archive member '{member.name}'.",
            error_type="urn:hostgrid:error:unsafe_bundle",
        )
    return name


def _raise_zip_bomb() -> None:
    raise DomainError(
        status_code=413,
        title="Payload Too Large",
        detail="Uncompressed bundle exceeds maximum allowed size (zip-bomb protection).",
        error_type="urn:hostgrid:error:zip_bomb",
    )


def _read_member_bounded(
    tf: tarfile.TarFile,
    member: tarfile.TarInfo,
    remaining_budget: int,
) -> bytes:
    extracted = tf.extractfile(member)
    if extracted is None:
        raise DomainError(
            status_code=422,
            title="Invalid Archive",
            detail="Failed to read regular file from archive.",
            error_type="urn:hostgrid:error:invalid_bundle",
        )
    chunks: list[bytes] = []
    total = 0
    while (block := extracted.read(CHUNK_SIZE)):
        total += len(block)
        if total > remaining_budget:
            _raise_zip_bomb()
        chunks.append(block)
    return b"".join(chunks)


def _extract_single_member(
    tf: tarfile.TarFile,
    member: tarfile.TarInfo,
    entries: dict[str, bytes],
    remaining_budget: int,
) -> int:
    clean_name = _validate_member_safety(member)
    if clean_name in entries:
        raise DomainError(
            status_code=422,
            title="Duplicate Archive Entry",
            detail=f"Duplicate archive member '{clean_name}' is not allowed.",
            error_type="urn:hostgrid:error:duplicate_entry",
        )
    if member.size > remaining_budget:
        _raise_zip_bomb()
    data = _read_member_bounded(tf, member, remaining_budget)
    entries[clean_name] = data
    return len(data)


def _extract_bundle_entries(raw_bytes: bytes, max_uncompressed: int) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    used_bytes = 0
    member_count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:gz") as tf:
            while (member := tf.next()) is not None:
                member_count += 1
                if member_count > MAX_TAR_ENTRIES:
                    raise DomainError(
                        status_code=422,
                        title="Too Many Archive Entries",
                        detail=f"Archive exceeds maximum entry count ({MAX_TAR_ENTRIES}).",
                        error_type="urn:hostgrid:error:too_many_entries",
                    )
                used_bytes += _extract_single_member(
                    tf,
                    member,
                    entries,
                    max_uncompressed - used_bytes,
                )
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise DomainError(
            status_code=422,
            title="Corrupt Bundle Archive",
            detail="Uploaded file is not a valid gzip-compressed tar .bundle archive.",
            error_type="urn:hostgrid:error:invalid_archive",
        ) from exc
    return entries


def _parse_manifest(entries: dict[str, bytes]) -> tuple[BundleManifest, bytes]:
    manifest_bytes = entries.get("manifest.json")
    if manifest_bytes is None:
        raise DomainError(
            status_code=422,
            title="Missing Manifest",
            detail="Bundle archive is missing required manifest.json.",
            error_type="urn:hostgrid:error:missing_manifest",
        )
    try:
        manifest = BundleManifest.model_validate_json(manifest_bytes)
    except ValidationError as exc:
        raise DomainError(
            status_code=422,
            title="Invalid Manifest",
            detail=f"Bundle manifest.json failed strict validation: {exc.error_count()} errors.",
            error_type="urn:hostgrid:error:invalid_manifest",
        ) from exc
    return manifest, manifest_bytes


def _reject_unlisted_entries(manifest: BundleManifest, entries: dict[str, bytes]) -> None:
    allowed = {"manifest.json", "manifest.sig", *manifest.files.keys()}
    extra = sorted(set(entries.keys()) - allowed)
    if extra:
        raise DomainError(
            status_code=422,
            title="Unexpected Archive Entry",
            detail=f"Unlisted archive entries not covered by manifest.json: {', '.join(extra)}.",
            error_type="urn:hostgrid:error:unlisted_entry",
        )


def _verify_manifest_files(manifest: BundleManifest, entries: dict[str, bytes]) -> None:
    if "snapshot.json" not in manifest.files:
        raise DomainError(
            status_code=422,
            title="Invalid Manifest",
            detail="manifest.json must declare snapshot.json integrity metadata.",
            error_type="urn:hostgrid:error:missing_snapshot_manifest",
        )
    _reject_unlisted_entries(manifest, entries)
    for filename, meta in manifest.files.items():
        data = entries.get(filename)
        if data is None:
            raise DomainError(
                status_code=422,
                title="Missing File",
                detail=f"File '{filename}' listed in manifest.json is missing from archive.",
                error_type="urn:hostgrid:error:missing_file",
            )
        if len(data) != meta.size_bytes or sha256_hex(data) != meta.sha256:
            raise DomainError(
                status_code=422,
                title="Integrity Check Failed",
                detail=f"SHA-256 or byte size mismatch for '{filename}'.",
                error_type="urn:hostgrid:error:integrity_mismatch",
            )


async def _check_signature_valid(
    session: AsyncSession,
    *,
    settings: Settings,
    manifest: BundleManifest,
    manifest_bytes: bytes,
    sig_text: str,
) -> bool:
    if manifest.signature_mode == "ed25519":
        if not settings.hostgrid_bundle_signing_pubkey_b64:
            return False
        return verify_ed25519_b64(
            settings.hostgrid_bundle_signing_pubkey_b64,
            manifest_bytes,
            sig_text,
        )
    host = (
        await session.execute(
            select(Host).where(Host.machine_id_hash == manifest.machine_id_hash)
        )
    ).scalar_one_or_none()
    if host is None or not host.credential_hash:
        return False
    return verify_hmac_sha256_b64(host.credential_hash, manifest_bytes, sig_text)


async def _verify_bundle_signature(
    session: AsyncSession,
    *,
    settings: Settings,
    actor: ActorContext,
    manifest: BundleManifest,
    manifest_bytes: bytes,
    sig_bytes: bytes | None,
) -> None:
    if manifest.signature_mode == "sha256_integrity_only":
        return

    sig_text = sig_bytes.decode("utf-8", errors="replace").strip() if sig_bytes else ""
    valid = await _check_signature_valid(
        session,
        settings=settings,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        sig_text=sig_text,
    )
    if valid:
        return

    await append_audit_log(
        session,
        actor_id=actor.actor_id,
        actor_username=actor.username,
        action="bundle.signature_rejected",
        resource_type="offline_bundle",
        resource_id=str(manifest.bundle_id),
        details={
            "hostname": manifest.hostname,
            "signature_mode": manifest.signature_mode,
        },
    )
    await session.commit()
    raise DomainError(
        status_code=422,
        title="Invalid Bundle Signature",
        detail="Cryptographic signature verification failed for air-gapped bundle.",
        error_type="urn:hostgrid:error:invalid_signature",
    )


def _attach_lynis_entry(raw_obj: dict[str, object], entries: dict[str, bytes]) -> None:
    lynis_bytes = entries.get("lynis-report.dat")
    if lynis_bytes is None:
        return
    lynis_obj = raw_obj.setdefault("lynis", {})
    if isinstance(lynis_obj, dict) and not lynis_obj.get("report_dat"):
        lynis_obj["executed"] = True
        lynis_obj["report_dat"] = lynis_bytes.decode("utf-8", errors="replace")


def _enforce_manifest_identity(raw_obj: dict[str, object], manifest: BundleManifest) -> None:
    raw_mid = raw_obj.get("machine_id_hash")
    if raw_mid is not None and raw_mid != manifest.machine_id_hash:
        raise DomainError(
            status_code=422,
            title="Bundle Identity Mismatch",
            detail="snapshot.json machine_id_hash does not match signed manifest.json.",
            error_type="urn:hostgrid:error:bundle_identity_mismatch",
        )
    raw_host = raw_obj.get("hostname")
    if raw_host is not None and str(raw_host).strip() != manifest.hostname:
        raise DomainError(
            status_code=422,
            title="Bundle Identity Mismatch",
            detail="snapshot.json hostname does not match signed manifest.json.",
            error_type="urn:hostgrid:error:bundle_identity_mismatch",
        )
    raw_obj["hostname"] = manifest.hostname
    raw_obj["machine_id_hash"] = manifest.machine_id_hash
    raw_obj["host_id"] = None
    raw_obj["connectivity_mode"] = "airgapped"


def _assemble_snapshot(
    manifest: BundleManifest,
    entries: dict[str, bytes],
) -> SnapshotIngestRequest:
    try:
        raw_obj = json.loads(entries["snapshot.json"].decode("utf-8"))
        if not isinstance(raw_obj, dict):
            raise ValueError("snapshot.json root must be a JSON object")
    except (ValueError, UnicodeDecodeError) as exc:
        raise DomainError(
            status_code=422,
            title="Invalid Snapshot JSON",
            detail="snapshot.json inside bundle is not valid UTF-8 JSON.",
            error_type="urn:hostgrid:error:invalid_snapshot_json",
        ) from exc

    _enforce_manifest_identity(raw_obj, manifest)
    _attach_lynis_entry(raw_obj, entries)

    try:
        return SnapshotIngestRequest.model_validate(raw_obj)
    except ValidationError as exc:
        raise DomainError(
            status_code=422,
            title="Invalid Snapshot Payload",
            detail=f"snapshot.json failed schema validation ({exc.error_count()} errors).",
            error_type="urn:hostgrid:error:invalid_snapshot",
        ) from exc


async def validate_airgapped_bundle(
    session: AsyncSession,
    *,
    settings: Settings,
    actor: ActorContext,
    raw_bytes: bytes,
) -> ValidatedBundle:
    """Execute all 7 SPEC.md section 5.1 security checks on an uploaded .bundle."""
    if len(raw_bytes) > settings.max_bundle_bytes:
        raise DomainError(
            status_code=413,
            title="Payload Too Large",
            detail=f"Compressed bundle exceeds limit of {settings.hostgrid_max_bundle_size_mb} MB.",
            error_type="urn:hostgrid:error:bundle_too_large",
        )

    entries = _extract_bundle_entries(raw_bytes, settings.max_bundle_uncompressed_bytes)
    manifest, manifest_bytes = _parse_manifest(entries)
    _verify_manifest_files(manifest, entries)
    await _verify_bundle_signature(
        session,
        settings=settings,
        actor=actor,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        sig_bytes=entries.get("manifest.sig"),
    )
    snapshot = _assemble_snapshot(manifest, entries)
    return ValidatedBundle(
        manifest=manifest,
        snapshot=snapshot,
        bundle_sha256=sha256_hex(raw_bytes),
    )
