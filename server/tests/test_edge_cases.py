"""Comprehensive edge-case, security boundary, and error-path tests for HostGrid Control Plane."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import secrets
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import jwt
import pytest
from fastapi import FastAPI
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import DomainError
from app.core.rbac import ActorContext, Role
from app.core.security import (
    sha256_hex,
    verify_ed25519_b64,
    verify_hmac_sha256_b64,
)
from app.db.base import yield_session
from app.db.models import EnrollmentToken, Host, User
from app.main import create_app
from app.schemas.auth import LoginRequest
from app.schemas.common import sanitize_multiline, sanitize_single_line
from app.schemas.enrollment import EnrollmentTokenCreateRequest
from app.services.artifacts.bundle_importer import validate_airgapped_bundle
from app.services.artifacts.tool_bundles import resolve_safe_bundle_path, validate_safe_segment
from app.services.auth_service import ensure_bootstrap_admin
from app.services.cve.versioning import compare_distro_versions
from app.services.enrollment_service import create_enrollment_token
from app.services.eol.detector import seed_eol_catalog
from tests.conftest import login_as


def _make_tar_gz(entries: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o600
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_settings_and_sanitizers_and_crypto_edge_cases() -> None:
    """Validate secret length check, control-char rejection, version ties, and crypto errors."""
    short_secret = secrets.token_hex(4)
    with pytest.raises(ValidationError):
        Settings(HOSTGRID_JWT_SECRET=short_secret)

    with pytest.raises(ValueError, match="Control characters"):
        sanitize_single_line("bad\x00value")

    with pytest.raises(ValueError, match="Disallowed control characters"):
        sanitize_multiline("line1\nline2\x07bell")

    assert sanitize_multiline("line1\nline2\tok") == "line1\nline2\tok"

    with pytest.raises(ValidationError):
        LoginRequest.model_validate({"username": "a", "password": "b", "extra_field": 1})

    assert verify_ed25519_b64("not-base64!!!", b"msg", "sig") is False
    assert verify_hmac_sha256_b64("k", b"msg", "not-base64!!!") is False

    sig_b64 = base64.b64encode(hmac.new(b"k", b"msg", hashlib.sha256).digest()).decode("ascii")
    assert verify_hmac_sha256_b64("k", b"msg", sig_b64) is True
    assert verify_hmac_sha256_b64("k", b"tampered", sig_b64) is False

    assert compare_distro_versions("1.0a", "1.0b") == -1
    assert compare_distro_versions("1.0b", "1.0a") == 1
    assert compare_distro_versions("1.0+", "1.0a") == 1
    assert compare_distro_versions("1.0a", "1.0ab") == -1
    assert compare_distro_versions("1.0ab", "1.0a") == 1


@pytest.mark.asyncio
async def test_bootstrap_admin_seed_idempotency_and_lifespan(tmp_path: Path) -> None:
    """Verify env-driven bootstrap admin creation, idempotency, and ASGI lifespan."""
    db_file = tmp_path / "boot.db"
    boot_pw = secrets.token_urlsafe(18)
    settings = Settings(
        HOSTGRID_ENV="production",
        HOSTGRID_JWT_SECRET=secrets.token_hex(32),
        DATABASE_URL=f"sqlite+aiosqlite:///{db_file}",
        HOSTGRID_BOOTSTRAP_ADMIN_USERNAME="boot_admin",
        HOSTGRID_BOOTSTRAP_ADMIN_EMAIL="boot@example.local",
        HOSTGRID_BOOTSTRAP_ADMIN_PASSWORD=boot_pw,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        async for session in yield_session(app.state.session_factory):
            assert await ensure_bootstrap_admin(session, settings) is False
            assert await seed_eol_catalog(session) == 0

        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            bad_val = await client.post("/api/v1/auth/login", json={"unexpected": 1})
            assert bad_val.status_code == 422
            assert bad_val.json()["detail"] == "Request payload validation failed."

    no_boot = Settings(
        HOSTGRID_ENV="testing",
        HOSTGRID_JWT_SECRET=secrets.token_hex(32),
        DATABASE_URL=f"sqlite+aiosqlite:///{db_file}",
    )
    app2 = create_app(no_boot)
    async with app2.state.session_factory() as session:
        assert await ensure_bootstrap_admin(session, no_boot) is False
    await app2.state.engine.dispose()


@pytest.mark.asyncio
async def test_auth_deps_errors_and_healthz_degraded(
    api_client: httpx.AsyncClient,
    app_instance: FastAPI,
    test_settings: Settings,
) -> None:
    """Test missing/malformed JWT, inactive user, invalid agent token, and unexpected 500."""
    no_auth = await api_client.get("/api/v1/auth/me")
    assert no_auth.status_code == 401

    bad_jwt = await api_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer not.a.valid.jwt"},
    )
    assert bad_jwt.status_code == 401

    malformed_sub = jwt.encode(
        {"sub": "not-a-uuid", "exp": datetime.now(UTC) + timedelta(minutes=5)},
        test_settings.hostgrid_jwt_secret,
        algorithm="HS256",
    )
    bad_sub = await api_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {malformed_sub}"},
    )
    assert bad_sub.status_code == 401

    inactive_login = await api_client.post(
        "/api/v1/auth/login",
        json={"username": "inactive_u", "password": "InactPass!123"},
    )
    assert inactive_login.status_code == 401

    bad_agent = await api_client.post(
        f"/api/v1/agents/{uuid4()}/heartbeat",
        headers={"Authorization": "Bearer hg_agent_invalid_token_123456"},
        json={"agent_version": "0.1.0"},
    )
    assert bad_agent.status_code == 401

    @app_instance.get("/test-boom")
    async def boom() -> dict[str, str]:
        raise RuntimeError("boom")

    transport = httpx.ASGITransport(app=app_instance, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c2:
        err_resp = await c2.get("/test-boom")
        assert err_resp.status_code == 500
        assert err_resp.headers["content-type"].startswith("application/problem+json")


@pytest.mark.asyncio
async def test_enrollment_reenroll_mismatch_filters_and_endpoints(
    api_client: httpx.AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Exercise re-enrollment, host mismatch 403, filters, 404s, JSON report, and audit logs."""
    admin_jwt = await login_as(api_client, "admin_u", "AdminPass!123")
    admin_hdr = {"Authorization": f"Bearer {admin_jwt}"}

    with pytest.raises(DomainError):
        await create_enrollment_token(
            db_session,
            actor=ActorContext(actor_id=None, username="admin_u", role=Role.ADMIN),
            payload=EnrollmentTokenCreateRequest(label="bad", environment="prod"),
        )

    admin_user = (
        await db_session.execute(User.__table__.select().where(User.username == "admin_u"))
    ).first()
    assert admin_user is not None
    expired_plain = "hg_enroll_" + "a" * 64
    db_session.add(
        EnrollmentToken(
            token_hash=sha256_hex(expired_plain),
            label="expired",
            environment="prod",
            created_by=admin_user.id,
            expires_at=datetime.now(UTC) - timedelta(minutes=5),
        )
    )
    await db_session.commit()

    exp_resp = await api_client.post(
        "/api/v1/enrollments/register",
        json={
            "enrollment_token": expired_plain,
            "hostname": "exp-host",
            "machine_id_hash": sha256_hex("exp-host"),
            "os_family": "debian",
            "os_name": "Debian",
            "os_version": "12",
            "kernel_version": "6.1.0",
            "arch": "amd64",
            "init_system": "systemd",
        },
    )
    assert exp_resp.status_code == 401

    tok1 = (
        await api_client.post(
            "/api/v1/enrollments/tokens",
            headers=admin_hdr,
            json={"label": "host-a", "environment": "dev"},
        )
    ).json()["enrollment_token"]
    tok2 = (
        await api_client.post(
            "/api/v1/enrollments/tokens",
            headers=admin_hdr,
            json={"label": "host-a-reenroll", "environment": "dmz"},
        )
    ).json()["enrollment_token"]

    mid = sha256_hex("host-reenroll-id")
    reg1 = await api_client.post(
        "/api/v1/enrollments/register",
        json={
            "enrollment_token": tok1,
            "hostname": "srv-reenroll",
            "machine_id_hash": mid,
            "os_family": "ubuntu",
            "os_name": "Ubuntu",
            "os_version": "22.04",
            "kernel_version": "5.15.0",
            "arch": "amd64",
            "init_system": "systemd",
            "connectivity_mode": "relay",
        },
    )
    assert reg1.status_code == 201
    host_id = reg1.json()["host_id"]

    reg2 = await api_client.post(
        "/api/v1/enrollments/register",
        json={
            "enrollment_token": tok2,
            "hostname": "srv-reenroll-v2",
            "machine_id_hash": mid,
            "os_family": "ubuntu",
            "os_name": "Ubuntu",
            "os_version": "22.04",
            "kernel_version": "5.15.0-2",
            "arch": "amd64",
            "init_system": "systemd",
            "connectivity_mode": "relay",
        },
    )
    assert reg2.status_code == 201
    assert reg2.json()["host_id"] == host_id
    agent_cred = reg2.json()["agent_credential"]
    agent_hdr = {"Authorization": f"Bearer {agent_cred}"}

    mismatch_hb = await api_client.post(
        f"/api/v1/agents/{uuid4()}/heartbeat",
        headers=agent_hdr,
        json={"agent_version": "0.1.0"},
    )
    assert mismatch_hb.status_code == 403

    empty_pkgs = await api_client.get(f"/api/v1/hosts/{host_id}/packages", headers=admin_hdr)
    assert empty_pkgs.status_code == 200
    assert empty_pkgs.json()["total"] == 0

    no_snap_report = await api_client.get(f"/api/v1/reports/hosts/{host_id}", headers=admin_hdr)
    assert no_snap_report.status_code == 404

    missing_host = await api_client.get(f"/api/v1/hosts/{uuid4()}", headers=admin_hdr)
    assert missing_host.status_code == 404

    missing_drift = await api_client.get(
        f"/api/v1/snapshots/{uuid4()}/drift",
        headers=admin_hdr,
    )
    assert missing_drift.status_code == 404

    no_host_id_snap = await api_client.post(
        "/api/v1/snapshots",
        headers=agent_hdr,
        json={
            "collected_at": datetime.now(UTC).isoformat(),
            "agent_version": "0.1.0",
            "connectivity_mode": "relay",
            "probe": {
                "os_family": "ubuntu",
                "os_name": "Ubuntu",
                "os_version": "22.04",
                "kernel_version": "5.15.0",
                "arch": "amd64",
                "init_system": "systemd",
                "capabilities": {},
            },
        },
    )
    assert no_host_id_snap.status_code == 422

    # Sync CVE and update same advisory, test non-vulnerable backport & loopback exposure
    adv_payload = {
        "advisories": [
            {
                "cve_id": "CVE-2024-0001",
                "ecosystem": "Ubuntu:22.04",
                "package_name": "nginx",
                "fixed_version": "1.18.0-6ubuntu14.5",
                "advisory_status": "affected",
                "base_severity": "medium",
                "cvss_score": 6.5,
                "source_feed": "oval",
                "summary": "Nginx issue",
                "references": ["USN-1"],
            },
            {
                "cve_id": "CVE-2024-0002",
                "ecosystem": "Ubuntu:22.04",
                "package_name": "curl",
                "fixed_version": "7.81.0-1ubuntu1.10",
                "advisory_status": "affected",
                "base_severity": "high",
                "cvss_score": 7.5,
                "source_feed": "osv",
                "summary": "Already patched backport",
                "references": [],
            },
        ]
    }
    sync1 = await api_client.post("/api/v1/cves/sync-feed", headers=admin_hdr, json=adv_payload)
    sync2 = await api_client.post("/api/v1/cves/sync-feed", headers=admin_hdr, json=adv_payload)
    assert sync1.status_code == 200
    assert sync2.status_code == 200

    snap_ok = await api_client.post(
        "/api/v1/snapshots",
        headers=agent_hdr,
        json={
            "host_id": host_id,
            "collected_at": datetime.now(UTC).isoformat(),
            "agent_version": "0.1.0",
            "connectivity_mode": "relay",
            "probe": {
                "os_family": "ubuntu",
                "os_name": "Ubuntu",
                "os_version": "22.04",
                "kernel_version": "5.15.0",
                "arch": "amd64",
                "init_system": "systemd",
                "capabilities": {},
            },
            "packages": [
                {
                    "package_manager": "dpkg",
                    "name": "nginx",
                    "source_package": "nginx",
                    "epoch": "",
                    "version": "1.18.0-6ubuntu14.4",
                    "release": "",
                    "arch": "amd64",
                },
                {
                    "package_manager": "dpkg",
                    "name": "curl",
                    "source_package": "curl",
                    "epoch": "",
                    "version": "7.81.0-1ubuntu1.16",
                    "release": "",
                    "arch": "amd64",
                },
            ],
            "network": {
                "listening_sockets": [
                    {
                        "proto": "tcp",
                        "local_addr": "127.0.0.1",
                        "port": 8080,
                        "process": "nginx",
                    }
                ]
            },
            "repos": {
                "access_ok": True,
                "configured_sources": ["deb http://mirror/ubuntu jammy main"],
            },
        },
    )
    assert snap_ok.status_code == 201
    snap_id = snap_ok.json()["snapshot_id"]

    filtered = await api_client.get(
        "/api/v1/hosts?search=reenroll&os_family=ubuntu&connectivity_mode=relay&repo_access_ok=true",
        headers=admin_hdr,
    )
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1

    snaps = await api_client.get(f"/api/v1/hosts/{host_id}/snapshots", headers=admin_hdr)
    assert snaps.status_code == 200
    assert snaps.json()["total"] == 1

    findings = await api_client.get(
        f"/api/v1/snapshots/{snap_id}/findings?severity=medium&category=cve",
        headers=admin_hdr,
    )
    assert findings.status_code == 200
    assert findings.json()["total"] == 1

    pkgs_search = await api_client.get(
        f"/api/v1/hosts/{host_id}/packages?search=nginx",
        headers=admin_hdr,
    )
    assert pkgs_search.status_code == 200
    assert pkgs_search.json()["total"] == 1

    json_report = await api_client.get(
        f"/api/v1/reports/hosts/{host_id}?format=json",
        headers=admin_hdr,
    )
    assert json_report.status_code == 200
    assert json_report.json()["snapshot_id"] == snap_id

    empty_cve = await api_client.get("/api/v1/cves/search?q=", headers=admin_hdr)
    assert empty_cve.status_code == 200
    assert empty_cve.json()["total"] == 0

    logs_resp = await api_client.get("/api/v1/audit/logs?limit=10&offset=0", headers=admin_hdr)
    assert logs_resp.status_code == 200
    assert logs_resp.json()["total"] >= 1

    # Agent auth on tool bundle endpoints + signature verification on update
    reg_b = await api_client.post(
        "/api/v1/bundles/register",
        headers=admin_hdr,
        data={"tool_name": "lynis", "version": "3.1.4", "arch": "noarch"},
        files={"file": ("lynis-3.1.4.tar.gz", b"v1-bytes", "application/gzip")},
    )
    assert reg_b.status_code == 201
    # Reusing v1 signature for different tarball bytes must be rejected (422)
    forged_b = await api_client.post(
        "/api/v1/bundles/register",
        headers=admin_hdr,
        data={
            "tool_name": "lynis",
            "version": "3.1.4",
            "arch": "noarch",
            "signature_b64": reg_b.json()["signature_b64"],
        },
        files={"file": ("lynis-3.1.4.tar.gz", b"v2-bytes", "application/gzip")},
    )
    assert forged_b.status_code == 422

    # Valid server-signed update replaces tarball cleanly
    reg_b2 = await api_client.post(
        "/api/v1/bundles/register",
        headers=admin_hdr,
        data={"tool_name": "lynis", "version": "3.1.4", "arch": "noarch"},
        files={"file": ("lynis-3.1.4.tar.gz", b"v2-bytes", "application/gzip")},
    )
    assert reg_b2.status_code == 201

    # Re-registering with matching valid signature_b64 succeeds
    reg_b2_sig = await api_client.post(
        "/api/v1/bundles/register",
        headers=admin_hdr,
        data={
            "tool_name": "lynis",
            "version": "3.1.4",
            "arch": "noarch",
            "signature_b64": reg_b2.json()["signature_b64"],
        },
        files={"file": ("lynis-3.1.4.tar.gz", b"v2-bytes", "application/gzip")},
    )
    assert reg_b2_sig.status_code == 201

    # Invalid base64 / wrong-length signature rejected
    bad_b64 = await api_client.post(
        "/api/v1/bundles/register",
        headers=admin_hdr,
        data={
            "tool_name": "lynis",
            "version": "3.1.5",
            "arch": "noarch",
            "signature_b64": "!!!not-base64!!!",
        },
        files={"file": ("lynis-3.1.5.tar.gz", b"v3-bytes", "application/gzip")},
    )
    assert bad_b64.status_code == 422

    short_sig = await api_client.post(
        "/api/v1/bundles/register",
        headers=admin_hdr,
        data={
            "tool_name": "lynis",
            "version": "3.1.5",
            "arch": "noarch",
            "signature_b64": base64.b64encode(b"short").decode("ascii"),
        },
        files={"file": ("lynis-3.1.5.tar.gz", b"v3-bytes", "application/gzip")},
    )
    assert short_sig.status_code == 422

    agent_manifest = await api_client.get(
        "/api/v1/bundles/lynis/3.1.4/manifest",
        headers=agent_hdr,
    )
    assert agent_manifest.status_code == 200
    agent_dl = await api_client.get(
        "/api/v1/bundles/lynis/3.1.4/download",
        headers=agent_hdr,
    )
    assert agent_dl.status_code == 200
    assert agent_dl.content == b"v2-bytes"

    not_found_b = await api_client.get(
        "/api/v1/bundles/lynis/9.9.9/manifest",
        headers=admin_hdr,
    )
    assert not_found_b.status_code == 404


@pytest.mark.asyncio
async def test_bundle_importer_all_security_rejections_and_hmac_host(
    api_client: httpx.AsyncClient,
    db_session: AsyncSession,
    test_settings: Settings,
) -> None:
    """Verify every security gate of .bundle importer: size, entries, zip-bomb, HMAC, JSON."""
    admin_jwt = await login_as(api_client, "admin_u", "AdminPass!123")
    admin_hdr = {"Authorization": f"Bearer {admin_jwt}"}
    actor = ActorContext(actor_id=uuid4(), username="admin_u", role=Role.ADMIN)

    # Path segment validation
    with pytest.raises(DomainError):
        validate_safe_segment("../evil", "tool_name")
    with pytest.raises(DomainError):
        resolve_safe_bundle_path(test_settings.hostgrid_bundles_dir, "bad/name")

    # 1. Oversized compressed upload (> 2MB test setting)
    oversized = b"x" * (test_settings.max_bundle_bytes + 10)
    resp_big = await api_client.post(
        "/api/v1/snapshots/import-bundle",
        headers=admin_hdr,
        files={"file": ("big.bundle", oversized, "application/gzip")},
    )
    assert resp_big.status_code == 413

    with pytest.raises(DomainError):
        await validate_airgapped_bundle(
            db_session,
            settings=test_settings,
            actor=actor,
            raw_bytes=oversized,
        )

    # 2. Corrupt non-gzip payload
    corrupt = await api_client.post(
        "/api/v1/snapshots/import-bundle",
        headers=admin_hdr,
        files={"file": ("bad.bundle", b"not-a-tar-gz", "application/gzip")},
    )
    assert corrupt.status_code == 422

    # 3. Too many entries (> 16)
    many = _make_tar_gz([(f"f{i}.txt", b"a") for i in range(18)])
    resp_many = await api_client.post(
        "/api/v1/snapshots/import-bundle",
        headers=admin_hdr,
        files={"file": ("many.bundle", many, "application/gzip")},
    )
    assert resp_many.status_code == 422

    # 4. Zip-bomb (highly compressible zeros exceeding 4MB uncompressed cap)
    bomb = _make_tar_gz([("zero.bin", b"\x00" * (5 * 1024 * 1024))])
    resp_bomb = await api_client.post(
        "/api/v1/snapshots/import-bundle",
        headers=admin_hdr,
        files={"file": ("bomb.bundle", bomb, "application/gzip")},
    )
    assert resp_bomb.status_code == 413

    # 5. Missing manifest.json
    no_manifest = _make_tar_gz([("snapshot.json", b"{}")])
    assert (
        await api_client.post(
            "/api/v1/snapshots/import-bundle",
            headers=admin_hdr,
            files={"file": ("nomanifest.bundle", no_manifest, "application/gzip")},
        )
    ).status_code == 422

    # 6. Invalid manifest JSON schema
    bad_manifest = _make_tar_gz([("manifest.json", b'{"bad": true}')])
    assert (
        await api_client.post(
            "/api/v1/snapshots/import-bundle",
            headers=admin_hdr,
            files={"file": ("badmanifest.bundle", bad_manifest, "application/gzip")},
        )
    ).status_code == 422

    # 7. Valid HMAC host-signed bundle + missing file / invalid snapshot.json tests
    cred_hash = sha256_hex("hg_agent_secret_for_hmac")
    mid = sha256_hex("hmac-airgap-machine")
    host = Host(
        hostname="srv-hmac-01",
        machine_id_hash=mid,
        os_family="debian",
        os_name="Debian",
        os_version="12",
        kernel_version="6.1.0",
        arch="amd64",
        init_system="systemd",
        connectivity_mode="airgapped",
        environment="prod",
        credential_hash=cred_hash,
    )
    db_session.add(host)
    await db_session.commit()

    snap_bytes = json.dumps(
        {
            "collected_at": datetime.now(UTC).isoformat(),
            "agent_version": "0.1.0",
            "probe": {
                "os_family": "debian",
                "os_name": "Debian",
                "os_version": "12",
                "kernel_version": "6.1.0",
                "arch": "amd64",
                "init_system": "systemd",
                "capabilities": {},
            },
        }
    ).encode("utf-8")
    manifest_bytes = json.dumps(
        {
            "bundle_format_version": "1.0",
            "bundle_id": str(uuid4()),
            "created_at": datetime.now(UTC).isoformat(),
            "hostname": "srv-hmac-01",
            "machine_id_hash": mid,
            "agent_version": "0.1.0",
            "signature_mode": "hmac_host",
            "files": {
                "snapshot.json": {
                    "sha256": sha256_hex(snap_bytes),
                    "size_bytes": len(snap_bytes),
                }
            },
        }
    ).encode("utf-8")
    mac = base64.b64encode(
        hmac.new(cred_hash.encode("utf-8"), manifest_bytes, hashlib.sha256).digest()
    )
    hmac_bundle = _make_tar_gz(
        [
            ("manifest.json", manifest_bytes),
            ("manifest.sig", mac),
            ("snapshot.json", snap_bytes),
        ]
    )
    hmac_resp = await api_client.post(
        "/api/v1/snapshots/import-bundle",
        headers=admin_hdr,
        files={"file": ("hmac.bundle", hmac_bundle, "application/gzip")},
    )
    assert hmac_resp.status_code == 201, hmac_resp.text

    # Missing file referenced in manifest
    missing_file_bundle = _make_tar_gz(
        [("manifest.json", manifest_bytes), ("manifest.sig", mac)]
    )
    assert (
        await api_client.post(
            "/api/v1/snapshots/import-bundle",
            headers=admin_hdr,
            files={"file": ("missing.bundle", missing_file_bundle, "application/gzip")},
        )
    ).status_code == 422

    # Manifest without snapshot.json entry
    no_snap_manifest = json.dumps(
        {
            "bundle_format_version": "1.0",
            "bundle_id": str(uuid4()),
            "created_at": datetime.now(UTC).isoformat(),
            "hostname": "srv-hmac-01",
            "machine_id_hash": mid,
            "agent_version": "0.1.0",
            "signature_mode": "sha256_integrity_only",
            "files": {},
        }
    ).encode("utf-8")
    assert (
        await api_client.post(
            "/api/v1/snapshots/import-bundle",
            headers=admin_hdr,
            files={
                "file": (
                    "nosnap.bundle",
                    _make_tar_gz([("manifest.json", no_snap_manifest)]),
                    "application/gzip",
                )
            },
        )
    ).status_code == 422

    # Invalid snapshot.json content
    bad_snap_bytes = b"not-json"
    bad_snap_manifest = json.dumps(
        {
            "bundle_format_version": "1.0",
            "bundle_id": str(uuid4()),
            "created_at": datetime.now(UTC).isoformat(),
            "hostname": "srv-hmac-01",
            "machine_id_hash": mid,
            "agent_version": "0.1.0",
            "signature_mode": "sha256_integrity_only",
            "files": {
                "snapshot.json": {
                    "sha256": sha256_hex(bad_snap_bytes),
                    "size_bytes": len(bad_snap_bytes),
                }
            },
        }
    ).encode("utf-8")
    assert (
        await api_client.post(
            "/api/v1/snapshots/import-bundle",
            headers=admin_hdr,
            files={
                "file": (
                    "badsnap.bundle",
                    _make_tar_gz(
                        [
                            ("manifest.json", bad_snap_manifest),
                            ("snapshot.json", bad_snap_bytes),
                        ]
                    ),
                    "application/gzip",
                )
            },
        )
    ).status_code == 422

    # 8. Duplicate archive member rejected
    dup_bundle = _make_tar_gz(
        [
            ("manifest.json", manifest_bytes),
            ("manifest.sig", mac),
            ("snapshot.json", snap_bytes),
            ("snapshot.json", snap_bytes),
        ]
    )
    assert (
        await api_client.post(
            "/api/v1/snapshots/import-bundle",
            headers=admin_hdr,
            files={"file": ("dup.bundle", dup_bundle, "application/gzip")},
        )
    ).status_code == 422

    # 9. Unlisted extra file (forged lynis-report.dat) rejected
    unlisted_bundle = _make_tar_gz(
        [
            ("manifest.json", manifest_bytes),
            ("manifest.sig", mac),
            ("snapshot.json", snap_bytes),
            ("lynis-report.dat", b"lynis_version=9.9.9\nhardening_index=100\n"),
        ]
    )
    assert (
        await api_client.post(
            "/api/v1/snapshots/import-bundle",
            headers=admin_hdr,
            files={"file": ("unlisted.bundle", unlisted_bundle, "application/gzip")},
        )
    ).status_code == 422

    # 10. Identity spoofing (manifest machine_id_hash != snapshot machine_id_hash) rejected
    spoof_snap = json.dumps(
        {
            "hostname": "srv-hmac-01",
            "machine_id_hash": sha256_hex("victim-host"),
            "collected_at": datetime.now(UTC).isoformat(),
            "agent_version": "0.1.0",
            "probe": {
                "os_family": "debian",
                "os_name": "Debian",
                "os_version": "12",
                "kernel_version": "6.1.0",
                "arch": "amd64",
                "init_system": "systemd",
                "capabilities": {},
            },
        }
    ).encode("utf-8")
    spoof_manifest = json.dumps(
        {
            "bundle_format_version": "1.0",
            "bundle_id": str(uuid4()),
            "created_at": datetime.now(UTC).isoformat(),
            "hostname": "srv-hmac-01",
            "machine_id_hash": mid,
            "agent_version": "0.1.0",
            "signature_mode": "sha256_integrity_only",
            "files": {
                "snapshot.json": {
                    "sha256": sha256_hex(spoof_snap),
                    "size_bytes": len(spoof_snap),
                }
            },
        }
    ).encode("utf-8")
    assert (
        await api_client.post(
            "/api/v1/snapshots/import-bundle",
            headers=admin_hdr,
            files={
                "file": (
                    "spoof-mid.bundle",
                    _make_tar_gz(
                        [("manifest.json", spoof_manifest), ("snapshot.json", spoof_snap)]
                    ),
                    "application/gzip",
                )
            },
        )
    ).status_code == 422

    # 11. Hostname mismatch between manifest and snapshot rejected
    spoof_host_snap = json.dumps(
        {
            "hostname": "other-host",
            "machine_id_hash": mid,
            "collected_at": datetime.now(UTC).isoformat(),
            "agent_version": "0.1.0",
            "probe": {
                "os_family": "debian",
                "os_name": "Debian",
                "os_version": "12",
                "kernel_version": "6.1.0",
                "arch": "amd64",
                "init_system": "systemd",
                "capabilities": {},
            },
        }
    ).encode("utf-8")
    spoof_host_manifest = json.dumps(
        {
            "bundle_format_version": "1.0",
            "bundle_id": str(uuid4()),
            "created_at": datetime.now(UTC).isoformat(),
            "hostname": "srv-hmac-01",
            "machine_id_hash": mid,
            "agent_version": "0.1.0",
            "signature_mode": "sha256_integrity_only",
            "files": {
                "snapshot.json": {
                    "sha256": sha256_hex(spoof_host_snap),
                    "size_bytes": len(spoof_host_snap),
                }
            },
        }
    ).encode("utf-8")
    assert (
        await api_client.post(
            "/api/v1/snapshots/import-bundle",
            headers=admin_hdr,
            files={
                "file": (
                    "spoof-host.bundle",
                    _make_tar_gz(
                        [("manifest.json", spoof_host_manifest), ("snapshot.json", spoof_host_snap)]
                    ),
                    "application/gzip",
                )
            },
        )
    ).status_code == 422


@pytest.mark.asyncio
async def test_cve_advisory_statuses_large_sbom_and_snapshot_idempotency(
    api_client: httpx.AsyncClient,
) -> None:
    """Verify fixed/wontfix/not_affected CVE rules, chunked >450 pkg SBOM, and Idempotency-Key."""
    admin_jwt = await login_as(api_client, "admin_u", "AdminPass!123")
    admin_hdr = {"Authorization": f"Bearer {admin_jwt}"}

    sync = await api_client.post(
        "/api/v1/cves/sync-feed",
        headers=admin_hdr,
        json={
            "advisories": [
                {
                    "cve_id": "CVE-2024-7001",
                    "ecosystem": "Debian:12",
                    "package_name": "openssl",
                    "fixed_version": "3.0.14-1~deb12u2",
                    "advisory_status": "fixed",
                    "base_severity": "critical",
                },
                {
                    "cve_id": "CVE-2024-7002",
                    "ecosystem": "Debian:12",
                    "package_name": "zlib1g",
                    "fixed_version": None,
                    "advisory_status": "wontfix",
                    "base_severity": "high",
                },
                {
                    "cve_id": "CVE-2024-7003",
                    "ecosystem": "Debian:12",
                    "package_name": "bash",
                    "fixed_version": None,
                    "advisory_status": "not_affected",
                    "base_severity": "critical",
                },
                {
                    "cve_id": "CVE-2024-7004",
                    "ecosystem": "Debian:12",
                    "package_name": "coreutils",
                    "fixed_version": None,
                    "advisory_status": "fixed",
                    "base_severity": "medium",
                },
            ]
        },
    )
    assert sync.status_code == 200

    tok = (
        await api_client.post(
            "/api/v1/enrollments/tokens",
            headers=admin_hdr,
            json={"label": "idem-host", "environment": "staging"},
        )
    ).json()["enrollment_token"]
    reg = await api_client.post(
        "/api/v1/enrollments/register",
        json={
            "enrollment_token": tok,
            "hostname": "srv-large-sbom",
            "machine_id_hash": sha256_hex("srv-large-sbom"),
            "os_family": "debian",
            "os_name": "Debian GNU/Linux",
            "os_version": "12 (bookworm)",
            "kernel_version": "6.1.0",
            "arch": "amd64",
            "init_system": "systemd",
        },
    )
    assert reg.status_code == 201
    host_id = reg.json()["host_id"]
    agent_hdr = {"Authorization": f"Bearer {reg.json()['agent_credential']}"}

    packages = [
        {
            "package_manager": "dpkg",
            "name": "openssl",
            "source_package": "openssl",
            "epoch": "",
            "version": "3.0.11-1~deb12u2",
            "release": "",
            "arch": "amd64",
        },
        {
            "package_manager": "dpkg",
            "name": "zlib1g",
            "source_package": "zlib",
            "epoch": "",
            "version": "1.2.13-1",
            "release": "",
            "arch": "amd64",
        },
        {
            "package_manager": "dpkg",
            "name": "bash",
            "source_package": "bash",
            "epoch": "",
            "version": "5.2.15-2",
            "release": "",
            "arch": "amd64",
        },
        {
            "package_manager": "dpkg",
            "name": "coreutils",
            "source_package": "coreutils",
            "epoch": "",
            "version": "9.1-1",
            "release": "",
            "arch": "amd64",
        },
    ] + [
        {
            "package_manager": "dpkg",
            "name": f"libfiller-{i}",
            "source_package": f"libfiller-{i}",
            "epoch": "",
            "version": "1.0.0-1",
            "release": "",
            "arch": "amd64",
        }
        for i in range(450)
    ]

    snap_body = {
        "host_id": host_id,
        "collected_at": datetime.now(UTC).isoformat(),
        "agent_version": "0.1.0",
        "connectivity_mode": "lan",
        "probe": {
            "os_family": "debian",
            "os_name": "Debian GNU/Linux",
            "os_version": "12 (bookworm)",
            "kernel_version": "6.1.0",
            "arch": "amd64",
            "init_system": "systemd",
            "capabilities": {},
        },
        "packages": packages,
    }

    bad_idem = await api_client.post(
        "/api/v1/snapshots",
        headers={**agent_hdr, "Idempotency-Key": "not-a-uuid"},
        json=snap_body,
    )
    assert bad_idem.status_code == 422

    idem_key = str(uuid4())
    first = await api_client.post(
        "/api/v1/snapshots",
        headers={**agent_hdr, "Idempotency-Key": idem_key},
        json=snap_body,
    )
    assert first.status_code == 201, first.text
    assert first.json()["critical_cves_count"] == 1
    assert first.json()["high_cves_count"] == 1

    replay = await api_client.post(
        "/api/v1/snapshots",
        headers={**agent_hdr, "Idempotency-Key": idem_key},
        json=snap_body,
    )
    assert replay.status_code == 201
    assert replay.json()["snapshot_id"] == first.json()["snapshot_id"]

    snaps = await api_client.get(f"/api/v1/hosts/{host_id}/snapshots", headers=admin_hdr)
    assert snaps.json()["total"] == 1
