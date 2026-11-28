"""End-to-end API, RBAC, enrollment, snapshot drift, CVE search, and tool bundle tests."""

from __future__ import annotations

import io
import json
import tarfile
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest

from app.core.config import Settings
from app.core.security import sha256_hex, sign_ed25519_b64, verify_ed25519_b64
from tests.conftest import FIXTURES_DIR, login_as


def _sample_snapshot_payload(host_id: str, lynis_dat: str) -> dict[str, object]:
    return {
        "host_id": host_id,
        "collected_at": datetime.now(UTC).isoformat(),
        "agent_version": "0.1.0",
        "connectivity_mode": "lan",
        "probe": {
            "os_family": "debian",
            "os_name": "Debian GNU/Linux",
            "os_version": "8",
            "kernel_version": "3.16.0-11-amd64",
            "arch": "amd64",
            "init_system": "sysvinit",
            "capabilities": {
                "network_inspector": {
                    "status": "supported",
                    "binary": "netstat",
                    "fallback_used": True,
                },
                "systemd_security": {
                    "status": "not_supported_on_os",
                    "reason": "init_system_is_sysvinit",
                    "fallback_used": False,
                },
            },
        },
        "packages": [
            {
                "package_manager": "dpkg",
                "name": "openssh-server",
                "source_package": "openssh",
                "epoch": "1",
                "version": "6.7p1-5+deb8u4",
                "release": "",
                "arch": "amd64",
            },
            {
                "package_manager": "dpkg",
                "name": "openssl",
                "source_package": "openssl",
                "epoch": "",
                "version": "1.0.1t-1+deb8u12",
                "release": "",
                "arch": "amd64",
            },
        ],
        "network": {
            "listening_sockets": [
                {
                    "proto": "tcp",
                    "local_addr": "0.0.0.0",  # noqa: S104
                    "port": 22,
                    "process": "sshd",
                    "pid": 412,
                }
            ]
        },
        "services": [{"name": "ssh", "state": "running", "init_system": "sysvinit"}],
        "sysctl": {"net.ipv4.ip_forward": "0", "kernel.kptr_restrict": "0"},
        "repos": {
            "access_ok": False,
            "configured_sources": ["deb http://archive.debian.org/debian jessie main"],
            "check_detail": "eol_archive_unreachable",
        },
        "lynis": {
            "executed": True,
            "lynis_version": "3.1.4",
            "report_dat": lynis_dat,
        },
    }


def _build_bundle_bytes(
    *,
    snapshot_obj: dict[str, object],
    hostname: str,
    machine_id_hash: str,
    signature_mode: str,
    privkey_b64: str = "",
    lynis_dat: str | None = None,
    corrupt_hash: bool = False,
) -> bytes:
    snap_bytes = json.dumps(snapshot_obj).encode("utf-8")
    files_meta: dict[str, dict[str, object]] = {
        "snapshot.json": {
            "sha256": ("0" * 64) if corrupt_hash else sha256_hex(snap_bytes),
            "size_bytes": len(snap_bytes),
        }
    }
    raw_files: dict[str, bytes] = {"snapshot.json": snap_bytes}
    if lynis_dat is not None:
        lynis_bytes = lynis_dat.encode("utf-8")
        files_meta["lynis-report.dat"] = {
            "sha256": sha256_hex(lynis_bytes),
            "size_bytes": len(lynis_bytes),
        }
        raw_files["lynis-report.dat"] = lynis_bytes

    manifest = {
        "bundle_format_version": "1.0",
        "bundle_id": str(uuid4()),
        "created_at": datetime.now(UTC).isoformat(),
        "hostname": hostname,
        "machine_id_hash": machine_id_hash,
        "agent_version": "0.1.0",
        "signature_mode": signature_mode,
        "files": files_meta,
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
    raw_files["manifest.json"] = manifest_bytes
    if signature_mode == "ed25519":
        sig = sign_ed25519_b64(privkey_b64, manifest_bytes) if privkey_b64 else "invalid_sig"
        raw_files["manifest.sig"] = sig.encode("utf-8")
    elif signature_mode == "sha256_integrity_only":
        raw_files["manifest.sig"] = b"sha256_integrity_only"

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in raw_files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o600
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.mark.asyncio
async def test_health_auth_lockout_and_rbac(api_client: httpx.AsyncClient) -> None:
    """Verify /healthz, JWT login/me, account lockout, and RBAC enforcement."""
    health = await api_client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    viewer_jwt = await login_as(api_client, "viewer_u", "ViewPass!123")
    me = await api_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {viewer_jwt}"})
    assert me.status_code == 200
    assert me.json()["role"] == "viewer"

    denied = await api_client.post(
        "/api/v1/enrollments/tokens",
        headers={"Authorization": f"Bearer {viewer_jwt}"},
        json={"label": "denied", "environment": "prod"},
    )
    assert denied.status_code == 403
    assert denied.headers["content-type"].startswith("application/problem+json")

    for _ in range(5):
        bad = await api_client.post(
            "/api/v1/auth/login",
            json={"username": "viewer_u", "password": "wrong-password"},
        )
        assert bad.status_code == 401

    locked = await api_client.post(
        "/api/v1/auth/login",
        json={"username": "viewer_u", "password": "ViewPass!123"},
    )
    assert locked.status_code == 423


@pytest.mark.asyncio
async def test_full_agent_lifecycle_drift_cve_and_reports(
    api_client: httpx.AsyncClient,
) -> None:
    """Exercise enrollment -> CVE sync -> snapshot 1 & 2 -> drift -> reverse search -> SARIF."""
    admin_jwt = await login_as(api_client, "admin_u", "AdminPass!123")
    admin_hdr = {"Authorization": f"Bearer {admin_jwt}"}

    sync = await api_client.post(
        "/api/v1/cves/sync-feed",
        headers=admin_hdr,
        json={
            "advisories": [
                {
                    "cve_id": "CVE-2024-6387",
                    "ecosystem": "Debian:8",
                    "package_name": "openssh-server",
                    "fixed_version": "1:6.7p1-5+deb8u9",
                    "advisory_status": "affected",
                    "base_severity": "high",
                    "cvss_score": 8.1,
                    "source_feed": "osv",
                    "summary": "RegreSSHion in OpenSSH server",
                    "references": ["DSA-9999-1"],
                }
            ]
        },
    )
    assert sync.status_code == 200
    assert sync.json()["upserted"] == 1

    tok_resp = await api_client.post(
        "/api/v1/enrollments/tokens",
        headers=admin_hdr,
        json={"label": "legacy-batch", "environment": "prod", "ttl_minutes": 30},
    )
    assert tok_resp.status_code == 201
    enroll_tok = tok_resp.json()["enrollment_token"]

    reg_payload = {
        "enrollment_token": enroll_tok,
        "hostname": "srv-legacy-01.internal",
        "machine_id_hash": sha256_hex("machine-legacy-01"),
        "os_family": "debian",
        "os_name": "Debian GNU/Linux",
        "os_version": "8",
        "kernel_version": "3.16.0-11-amd64",
        "arch": "amd64",
        "init_system": "sysvinit",
        "connectivity_mode": "lan",
    }
    reg = await api_client.post("/api/v1/enrollments/register", json=reg_payload)
    assert reg.status_code == 201
    host_id = reg.json()["host_id"]
    agent_cred = reg.json()["agent_credential"]
    agent_hdr = {"Authorization": f"Bearer {agent_cred}"}

    reuse = await api_client.post("/api/v1/enrollments/register", json=reg_payload)
    assert reuse.status_code == 401

    hb = await api_client.post(
        f"/api/v1/agents/{host_id}/heartbeat",
        headers=agent_hdr,
        json={"agent_version": "0.1.0", "lynis_version": "3.1.4", "repo_access_ok": False},
    )
    assert hb.status_code == 200

    lynis_v1 = (FIXTURES_DIR / "lynis_debian8.dat").read_text(encoding="utf-8")
    lynis_v2 = (FIXTURES_DIR / "lynis_debian8_v2.dat").read_text(encoding="utf-8")

    snap1 = await api_client.post(
        "/api/v1/snapshots",
        headers=agent_hdr,
        json=_sample_snapshot_payload(host_id, lynis_v1),
    )
    assert snap1.status_code == 201
    s1_body = snap1.json()
    assert s1_body["hardening_index"] == 64
    assert s1_body["eol_status"] == "eol"
    assert s1_body["critical_cves_count"] == 1

    snap2 = await api_client.post(
        "/api/v1/snapshots",
        headers=agent_hdr,
        json=_sample_snapshot_payload(host_id, lynis_v2),
    )
    assert snap2.status_code == 201
    snap2_id = snap2.json()["snapshot_id"]

    drift = await api_client.get(f"/api/v1/snapshots/{snap2_id}/drift", headers=admin_hdr)
    assert drift.status_code == 200
    drift_body = drift.json()
    assert drift_body["hardening_index_delta"] == 14
    assert drift_body["summary"]["new"] == 1
    assert drift_body["summary"]["resolved"] == 4

    cve_search = await api_client.get("/api/v1/cves/search?q=CVE-2024-6387", headers=admin_hdr)
    assert cve_search.status_code == 200
    assert cve_search.json()["total"] == 1
    assert cve_search.json()["items"][0]["exposed_network"] is True
    assert cve_search.json()["items"][0]["effective_severity"] == "critical"

    pkg_search = await api_client.get("/api/v1/cves/search?q=openssl", headers=admin_hdr)
    assert pkg_search.status_code == 200
    assert pkg_search.json()["total"] == 1

    fleet = await api_client.get("/api/v1/hosts?eol_status=eol", headers=admin_hdr)
    assert fleet.status_code == 200
    assert fleet.json()["total"] == 1

    detail = await api_client.get(f"/api/v1/hosts/{host_id}", headers=admin_hdr)
    assert detail.status_code == 200
    assert detail.json()["total_snapshots"] == 2

    pkgs = await api_client.get(f"/api/v1/hosts/{host_id}/packages", headers=admin_hdr)
    assert pkgs.status_code == 200
    assert pkgs.json()["total"] == 2

    sarif = await api_client.get(
        f"/api/v1/reports/hosts/{host_id}?format=sarif",
        headers=admin_hdr,
    )
    assert sarif.status_code == 200
    assert sarif.json()["version"] == "2.1.0"

    worm = await api_client.get("/api/v1/audit/verify", headers=admin_hdr)
    assert worm.status_code == 200
    assert worm.json()["valid"] is True
    assert worm.json()["checked_records"] >= 5


@pytest.mark.asyncio
async def test_airgapped_bundle_security_and_tool_bundles(
    api_client: httpx.AsyncClient,
    ed25519_keys: tuple[str, str],
    test_settings: Settings,
) -> None:
    """Verify Ed25519 .bundle import, tamper rejection, zip-slip rejection, and tool download."""
    priv_b64, pub_b64 = ed25519_keys
    assert test_settings.hostgrid_bundle_signing_pubkey_b64 == pub_b64

    oper_jwt = await login_as(api_client, "operator_u", "OperPass!123")
    oper_hdr = {"Authorization": f"Bearer {oper_jwt}"}
    machine_hash = sha256_hex("airgap-host-01")
    lynis_dat = (FIXTURES_DIR / "lynis_debian8.dat").read_text(encoding="utf-8")

    snap_obj: dict[str, object] = {
        "hostname": "srv-airgap-01",
        "machine_id_hash": machine_hash,
        "collected_at": datetime.now(UTC).isoformat(),
        "agent_version": "0.1.0",
        "connectivity_mode": "airgapped",
        "probe": {
            "os_family": "ubuntu",
            "os_name": "Ubuntu",
            "os_version": "22.04",
            "kernel_version": "5.15.0-119-generic",
            "arch": "amd64",
            "init_system": "systemd",
            "capabilities": {},
        },
        "packages": [],
        "network": {"listening_sockets": []},
        "services": [],
        "sysctl": {},
        "repos": {"access_ok": False, "configured_sources": [], "check_detail": "airgapped"},
        "lynis": {"executed": True, "lynis_version": "3.1.4", "report_dat": ""},
    }

    signed_bundle = _build_bundle_bytes(
        snapshot_obj=snap_obj,
        hostname="srv-airgap-01",
        machine_id_hash=machine_hash,
        signature_mode="ed25519",
        privkey_b64=priv_b64,
        lynis_dat=lynis_dat,
    )
    ok_import = await api_client.post(
        "/api/v1/snapshots/import-bundle",
        headers=oper_hdr,
        files={"file": ("srv-airgap-01.bundle", signed_bundle, "application/gzip")},
    )
    assert ok_import.status_code == 201, ok_import.text
    assert ok_import.json()["ingestion_source"] == "offline_bundle"
    assert ok_import.json()["hardening_index"] == 64

    bad_sig_bundle = _build_bundle_bytes(
        snapshot_obj=snap_obj,
        hostname="srv-airgap-01",
        machine_id_hash=machine_hash,
        signature_mode="ed25519",
        privkey_b64="",
    )
    bad_sig = await api_client.post(
        "/api/v1/snapshots/import-bundle",
        headers=oper_hdr,
        files={"file": ("tampered.bundle", bad_sig_bundle, "application/gzip")},
    )
    assert bad_sig.status_code == 422

    bad_hash_bundle = _build_bundle_bytes(
        snapshot_obj=snap_obj,
        hostname="srv-airgap-01",
        machine_id_hash=machine_hash,
        signature_mode="sha256_integrity_only",
        corrupt_hash=True,
    )
    bad_hash = await api_client.post(
        "/api/v1/snapshots/import-bundle",
        headers=oper_hdr,
        files={"file": ("corrupt.bundle", bad_hash_bundle, "application/gzip")},
    )
    assert bad_hash.status_code == 422

    zip_slip_buf = io.BytesIO()
    with tarfile.open(fileobj=zip_slip_buf, mode="w:gz") as tf:
        payload = b"evil"
        info = tarfile.TarInfo(name="../../etc/cron.d/pwn")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    zip_slip = await api_client.post(
        "/api/v1/snapshots/import-bundle",
        headers=oper_hdr,
        files={"file": ("slip.bundle", zip_slip_buf.getvalue(), "application/gzip")},
    )
    assert zip_slip.status_code == 422

    agentless_resp = await api_client.post(
        "/api/v1/snapshots/import-agentless",
        headers=oper_hdr,
        json={
            "hostname": "appliance-old-01",
            "machine_id_hash": sha256_hex("appliance-old-01"),
            "collected_at": datetime.now(UTC).isoformat(),
            "probe": {
                "os_family": "centos",
                "os_name": "CentOS Linux",
                "os_version": "6",
                "kernel_version": "2.6.32-754.el6.x86_64",
                "arch": "amd64",
                "init_system": "sysvinit",
                "capabilities": {},
            },
            "packages": [],
            "network": {"listening_sockets": []},
            "services": [],
            "sysctl": {"kernel.kptr_restrict": "0"},
            "repos": {"access_ok": False, "configured_sources": [], "check_detail": "none"},
            "lynis": {"executed": False, "report_dat": ""},
        },
    )
    assert agentless_resp.status_code == 201
    assert agentless_resp.json()["eol_status"] == "eol"

    tar_payload = b"fake-lynis-portable-tarball-content"
    reg_bundle = await api_client.post(
        "/api/v1/bundles/register",
        headers=oper_hdr,
        data={"tool_name": "lynis", "version": "3.1.4", "arch": "noarch"},
        files={"file": ("lynis-3.1.4-portable.tar.gz", tar_payload, "application/gzip")},
    )
    assert reg_bundle.status_code == 201, reg_bundle.text
    manifest = reg_bundle.json()
    assert verify_ed25519_b64(
        pub_b64,
        manifest["manifest_canonical_json"].encode("utf-8"),
        manifest["signature_b64"],
    )

    latest = await api_client.get("/api/v1/bundles/lynis/latest/manifest", headers=oper_hdr)
    assert latest.status_code == 200
    assert latest.json()["version"] == "3.1.4"

    dl = await api_client.get("/api/v1/bundles/lynis/3.1.4/download", headers=oper_hdr)
    assert dl.status_code == 200
    assert dl.content == tar_payload
