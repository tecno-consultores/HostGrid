"""Comprehensive Phase 2 & Phase 3 API, feed parser, reporting, user, and patching tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest

from app.core.errors import DomainError
from app.core.security import sha256_hex
from app.schemas.host import HostDetailResponse
from app.services.cve.feed_parsers import parse_cve_feed
from app.services.reporting import render_html_report, render_markdown_report
from tests.conftest import FIXTURES_DIR, login_as


async def _enroll_and_push_snapshot(
    client: httpx.AsyncClient,
    admin_hdr: dict[str, str],
    *,
    hostname: str,
    os_family: str = "debian",
    os_name: str = "Debian GNU/Linux",
    os_version: str = "12",
    repo_access_ok: bool = True,
    pkg_version: str = "1:9.2p1-2+deb12u1",
) -> tuple[str, str]:
    tok_resp = await client.post(
        "/api/v1/enrollments/tokens",
        headers=admin_hdr,
        json={"label": f"tok-{hostname}", "environment": "prod", "ttl_minutes": 30},
    )
    assert tok_resp.status_code == 201
    reg = await client.post(
        "/api/v1/enrollments/register",
        json={
            "enrollment_token": tok_resp.json()["enrollment_token"],
            "hostname": hostname,
            "machine_id_hash": sha256_hex(f"machine-{hostname}"),
            "os_family": os_family,
            "os_name": os_name,
            "os_version": os_version,
            "kernel_version": "6.1.0-26-amd64",
            "arch": "amd64",
            "init_system": "systemd",
            "connectivity_mode": "lan",
        },
    )
    assert reg.status_code == 201
    host_id: str = reg.json()["host_id"]
    cred: str = reg.json()["agent_credential"]
    lynis_dat = (FIXTURES_DIR / "lynis_debian8.dat").read_text(encoding="utf-8")
    snap = await client.post(
        "/api/v1/snapshots",
        headers={"Authorization": f"Bearer {cred}"},
        json={
            "host_id": host_id,
            "collected_at": datetime.now(UTC).isoformat(),
            "agent_version": "0.1.0",
            "connectivity_mode": "lan",
            "probe": {
                "os_family": os_family,
                "os_name": os_name,
                "os_version": os_version,
                "kernel_version": "6.1.0-26-amd64",
                "arch": "amd64",
                "init_system": "systemd",
                "capabilities": {
                    "network_inspector": {
                        "status": "supported",
                        "binary": "ss",
                        "fallback_used": False,
                    }
                },
            },
            "packages": [
                {
                    "package_manager": "dpkg",
                    "name": "openssh-server",
                    "source_package": "openssh",
                    "epoch": "",
                    "version": pkg_version,
                    "release": "",
                    "arch": "amd64",
                }
            ],
            "network": {
                "listening_sockets": [
                    {
                        "proto": "tcp",
                        "local_addr": "0.0.0.0",  # noqa: S104
                        "port": 22,
                        "process": "sshd",
                        "pid": 120,
                    }
                ]
            },
            "services": [{"name": "ssh.service", "state": "running", "init_system": "systemd"}],
            "sysctl": {"net.ipv4.ip_forward": "0"},
            "repos": {
                "access_ok": repo_access_ok,
                "configured_sources": ["deb https://mirror.internal/debian bookworm main"],
                "check_detail": "ok" if repo_access_ok else "unreachable",
            },
            "lynis": {"executed": True, "lynis_version": "3.1.4", "report_dat": lynis_dat},
        },
    )
    assert snap.status_code == 201, snap.text
    return host_id, cred


def test_offline_cve_feed_parsers_osv_trivy_oval_and_security() -> None:
    """Verify OSV JSON, Trivy JSON, OVAL XML parsing and XXE/error rejection."""
    osv_payload = json.dumps(
        {
            "vulns": [
                {
                    "id": "DSA-5724-1",
                    "aliases": ["CVE-2024-6387"],
                    "summary": "OpenSSH regreSSHion",
                    "database_specific": {"severity": "CRITICAL"},
                    "references": [{"url": "https://security-tracker.debian.org/CVE-2024-6387"}],
                    "affected": [
                        {
                            "package": {"ecosystem": "Debian:12", "name": "openssh-server"},
                            "ranges": [
                                {"events": [{"introduced": "0"}, {"fixed": "1:9.2p1-2+deb12u3"}]}
                            ],
                        }
                    ],
                },
                {"id": "GHSA-no-cve", "aliases": [], "affected": []},
            ]
        }
    )
    osv_items = parse_cve_feed(feed_format="osv", raw_text=osv_payload)
    assert len(osv_items) == 1
    assert osv_items[0].cve_id == "CVE-2024-6387"
    assert osv_items[0].ecosystem == "Debian:12"
    assert osv_items[0].fixed_version == "1:9.2p1-2+deb12u3"
    assert osv_items[0].base_severity == "critical"

    # Single OSV object + list form + default_ecosystem fallback
    single_osv = json.dumps(
        {
            "id": "CVE-2024-1111",
            "severity": [{"score": "important"}],
            "affected": [{"package": {"name": "openssl"}}],
        }
    )
    single_items = parse_cve_feed(
        feed_format="osv", raw_text=single_osv, default_ecosystem="ubuntu:22.04"
    )
    assert single_items[0].ecosystem == "Ubuntu:22.04"
    assert single_items[0].base_severity == "high"

    list_osv = json.dumps([json.loads(single_osv)])
    parsed_list = parse_cve_feed(
        feed_format="osv", raw_text=list_osv, default_ecosystem="Debian:12"
    )
    assert len(parsed_list) == 1

    # Trivy JSON with Metadata.OS derivation + CVSS V3Score
    trivy_payload = json.dumps(
        {
            "Metadata": {"OS": {"Family": "debian", "Name": "12.6"}},
            "Results": [
                {
                    "Target": "debian-host",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-6387",
                            "PkgName": "openssh-server",
                            "FixedVersion": "1:9.2p1-2+deb12u3, 1:9.2p1-2+deb12u4",
                            "Severity": "HIGH",
                            "Title": "OpenSSH race condition",
                            "CVSS": {"nvd": {"V3Score": 8.1}},
                            "References": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
                        },
                        {"VulnerabilityID": "NOT-A-CVE", "PkgName": "ignored"},
                    ],
                },
                {"Target": "empty-result"},
            ],
        }
    )
    trivy_items = parse_cve_feed(feed_format="trivy", raw_text=trivy_payload)
    assert len(trivy_items) == 1
    assert trivy_items[0].ecosystem == "Debian:12"
    assert trivy_items[0].fixed_version == "1:9.2p1-2+deb12u3"
    assert trivy_items[0].cvss_score == 8.1

    # OVAL XML (namespaced)
    oval_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
      <definitions>
        <definition id="oval:org.debian:def:1">
          <metadata>
            <title>DSA-5724 openssh security update</title>
            <reference source="CVE" ref_id="CVE-2024-6387"/>
            <advisory><severity>Moderate</severity></advisory>
          </metadata>
          <criteria>
            <criterion comment="openssh-server package is earlier than 1:9.2p1-2+deb12u3"/>
          </criteria>
        </definition>
      </definitions>
    </oval_definitions>"""
    oval_items = parse_cve_feed(
        feed_format="oval", raw_text=oval_xml, default_ecosystem="Debian:12"
    )
    assert len(oval_items) == 1
    assert oval_items[0].base_severity == "medium"
    assert oval_items[0].fixed_version == "1:9.2p1-2+deb12u3"

    # Reject XXE DOCTYPE/ENTITY
    xxe_xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><oval_definitions/>'
    with pytest.raises(DomainError) as xxe_exc:
        parse_cve_feed(feed_format="oval", raw_text=xxe_xml, default_ecosystem="Debian:12")
    assert xxe_exc.value.status_code == 422

    # Invalid JSON, malformed XML, missing ecosystem, and empty feed checks
    for fmt, bad_raw, eco in (
        ("osv", "{not-json", None),
        ("osv", "42", None),
        ("osv", '{"vulns": []}', None),
        ("trivy", '{"bad": true}', "Debian:12"),
        ("trivy", '{"Results": []}', None),
        ("oval", "<oval_definitions/>", None),
        ("oval", "<broken", "Debian:12"),
    ):
        with pytest.raises(DomainError) as bad_exc:
            parse_cve_feed(feed_format=fmt, raw_text=bad_raw, default_ecosystem=eco)  # type: ignore[arg-type]
        assert bad_exc.value.status_code == 422


def test_reporting_xss_and_empty_branches() -> None:
    """Verify Markdown pipe escaping, HTML escaping against XSS, and empty capability/findings."""
    detail = HostDetailResponse(
        id=uuid4(),
        hostname='srv-<script>alert(1)</script>|pipe',
        machine_id_hash="a" * 64,
        os_family="debian",
        os_name="Debian",
        os_version="12",
        kernel_version="6.1.0",
        arch="amd64",
        init_system="systemd",
        connectivity_mode="lan",
        environment="prod",
        eol_status="supported",
        eol_date=None,
        repo_access_ok=None,
        last_hardening_index=None,
        last_hardening_delta=None,
        last_lynis_version=None,
        critical_cves_count=0,
        high_cves_count=0,
        last_seen_at=None,
        capabilities={},
        latest_snapshot_id=uuid4(),
        latest_snapshot_at=None,
        total_snapshots=1,
    )
    md = render_markdown_report(detail=detail, snapshot_id="s1", findings=[], drift=None)
    assert "\\|pipe" in md
    assert "Sin metadatos de capacidades" in md
    assert "No se registraron hallazgos" in md

    html = render_html_report(detail=detail, snapshot_id="s1", findings=[], drift=None)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Sin hallazgos registrados." in html


@pytest.mark.asyncio
async def test_phase2_reports_and_offline_cve_import_rescan(
    api_client: httpx.AsyncClient,
) -> None:
    """Exercise Markdown/HTML report endpoints, offline feed import, and fleet CVE rescan."""
    admin_jwt = await login_as(api_client, "admin_u", "AdminPass!123")
    oper_jwt = await login_as(api_client, "operator_u", "OperPass!123")
    admin_hdr = {"Authorization": f"Bearer {admin_jwt}"}
    oper_hdr = {"Authorization": f"Bearer {oper_jwt}"}

    host_id, _ = await _enroll_and_push_snapshot(
        api_client, admin_hdr, hostname="srv-p2-01.internal"
    )

    # Import Trivy JSON offline feed and auto-rescan fleet
    trivy_feed = json.dumps(
        {
            "Metadata": {"OS": {"Family": "debian", "Name": "12"}},
            "Results": [
                {
                    "Target": "debian12",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-6387",
                            "PkgName": "openssh-server",
                            "FixedVersion": "1:9.2p1-2+deb12u3",
                            "Severity": "HIGH",
                            "Title": "RegreSSHion in OpenSSH",
                            "CVSS": {"nvd": {"V3Score": 8.1}},
                        }
                    ],
                }
            ],
        }
    )
    denied = await api_client.post(
        "/api/v1/cves/import-feed",
        headers=oper_hdr,
        json={"feed_format": "trivy", "payload": trivy_feed, "rescan_fleet": True},
    )
    assert denied.status_code == 403

    imp = await api_client.post(
        "/api/v1/cves/import-feed",
        headers=admin_hdr,
        json={"feed_format": "trivy", "payload": trivy_feed, "rescan_fleet": True},
    )
    assert imp.status_code == 200, imp.text
    imp_body = imp.json()
    assert imp_body["parsed"] == 1
    assert imp_body["upserted"] == 1
    assert imp_body["hosts_rescanned"] == 1
    assert imp_body["total_cve_matches"] == 1

    # Explicit rescan endpoint
    rescan = await api_client.post("/api/v1/cves/rescan-fleet", headers=admin_hdr)
    assert rescan.status_code == 200
    assert rescan.json()["critical_matches"] == 1

    # Markdown and HTML reports
    md_resp = await api_client.get(
        f"/api/v1/reports/hosts/{host_id}?format=markdown", headers=oper_hdr
    )
    assert md_resp.status_code == 200
    assert md_resp.headers["content-type"].startswith("text/markdown")
    assert "CVE-2024-6387" in md_resp.text
    assert "## Capability Probe" in md_resp.text

    html_resp = await api_client.get(
        f"/api/v1/reports/hosts/{host_id}?format=html", headers=oper_hdr
    )
    assert html_resp.status_code == 200
    assert html_resp.headers["content-type"].startswith("text/html")
    assert "@media print" in html_resp.text
    assert "CVE-2024-6387" in html_resp.text


@pytest.mark.asyncio
async def test_phase3_users_patching_governance_and_agent_pull_jobs(
    api_client: httpx.AsyncClient,
) -> None:
    """Exercise admin user provisioning, full PatchPlan lifecycle, Maker-Checker, and agent pull."""
    admin_jwt = await login_as(api_client, "admin_u", "AdminPass!123")
    oper_jwt = await login_as(api_client, "operator_u", "OperPass!123")
    viewer_jwt = await login_as(api_client, "viewer_u", "ViewPass!123")
    admin_hdr = {"Authorization": f"Bearer {admin_jwt}"}
    oper_hdr = {"Authorization": f"Bearer {oper_jwt}"}
    viewer_hdr = {"Authorization": f"Bearer {viewer_jwt}"}

    # 1. Admin user management (create approver, enforce RBAC, duplicate & self-lockout guards)
    assert (await api_client.get("/api/v1/users", headers=oper_hdr)).status_code == 403
    created_app = await api_client.post(
        "/api/v1/users",
        headers=admin_hdr,
        json={
            "username": "approver_u",
            "email": "approver@example.local",
            "password": "ApproverStrong!123",
            "role": "approver",
        },
    )
    assert created_app.status_code == 201, created_app.text
    approver_id = created_app.json()["id"]

    dup_user = await api_client.post(
        "/api/v1/users",
        headers=admin_hdr,
        json={
            "username": "approver_u",
            "email": "other@example.local",
            "password": "ApproverStrong!123",
            "role": "approver",
        },
    )
    assert dup_user.status_code == 409

    users_list = await api_client.get("/api/v1/users", headers=admin_hdr)
    assert users_list.status_code == 200
    admin_id = next(u["id"] for u in users_list.json()["items"] if u["username"] == "admin_u")
    self_demote = await api_client.patch(
        f"/api/v1/users/{admin_id}",
        headers=admin_hdr,
        json={"role": "viewer"},
    )
    assert self_demote.status_code == 409

    patch_ok = await api_client.patch(
        f"/api/v1/users/{approver_id}",
        headers=admin_hdr,
        json={"role": "approver", "is_active": True, "unlock": True},
    )
    assert patch_ok.status_code == 200
    assert (
        await api_client.patch(f"/api/v1/users/{uuid4()}", headers=admin_hdr, json={"unlock": True})
    ).status_code == 404

    approver_jwt = await login_as(api_client, "approver_u", "ApproverStrong!123")
    approver_hdr = {"Authorization": f"Bearer {approver_jwt}"}

    # 2. Enroll 2 healthy hosts + 1 unreachable-repo host
    h1, h1_cred = await _enroll_and_push_snapshot(
        api_client, admin_hdr, hostname="srv-wave-01.internal", repo_access_ok=True
    )
    h2, h2_cred = await _enroll_and_push_snapshot(
        api_client, admin_hdr, hostname="srv-wave-02.internal", repo_access_ok=True
    )
    h_bad, _ = await _enroll_and_push_snapshot(
        api_client, admin_hdr, hostname="srv-norepo-03.internal", repo_access_ok=False
    )

    # Plan with unreachable repo fails precheck cleanly
    failed_plan = await api_client.post(
        "/api/v1/patching/plans",
        headers=oper_hdr,
        json={
            "title": "Patch blocked host",
            "target_host_ids": [h_bad],
            "packages": ["openssh-server"],
        },
    )
    assert failed_plan.status_code == 201
    assert failed_plan.json()["status"] == "FAILED_PRECHECK"
    assert failed_plan.json()["precheck"]["passed"] is False

    # Cannot submit dry-run on FAILED_PRECHECK plan
    dry_conflict = await api_client.post(
        f"/api/v1/patching/plans/{failed_plan.json()['id']}/dry-run",
        headers=oper_hdr,
        json={"outcomes": [{"host_id": h_bad, "succeeded": True, "repo_verified": True}]},
    )
    assert dry_conflict.status_code == 409

    # Unknown host & bad idempotency key validation
    assert (
        await api_client.post(
            "/api/v1/patching/plans",
            headers=oper_hdr,
            json={"title": "Unknown host", "target_host_ids": [str(uuid4())], "packages": ["curl"]},
        )
    ).status_code == 404
    assert (
        await api_client.post(
            "/api/v1/patching/plans",
            headers={**oper_hdr, "Idempotency-Key": "not-a-uuid"},
            json={"title": "Bad key", "target_host_ids": [h1], "packages": ["curl"]},
        )
    ).status_code == 422

    # 3. Create valid 2-host plan with Idempotency-Key
    idem_key = str(uuid4())
    plan_payload = {
        "title": "OpenSSH Security Rollout",
        "target_host_ids": [h1, h2],
        "packages": ["openssh-server"],
        "canary_percent": 50,
        "max_wave_percent": 50,
    }
    p1 = await api_client.post(
        "/api/v1/patching/plans",
        headers={**oper_hdr, "Idempotency-Key": idem_key},
        json=plan_payload,
    )
    assert p1.status_code == 201, p1.text
    plan_id = p1.json()["id"]
    assert p1.json()["status"] == "DRY_RUN_READY"
    assert len(p1.json()["waves"]) == 2

    # Replay returns identical plan ID
    p1_replay = await api_client.post(
        "/api/v1/patching/plans",
        headers={**oper_hdr, "Idempotency-Key": idem_key},
        json=plan_payload,
    )
    assert p1_replay.status_code == 201
    assert p1_replay.json()["id"] == plan_id

    # Reusing the same Idempotency-Key with a DIFFERENT payload must fail with 409 Conflict
    p1_conflict_title = await api_client.post(
        "/api/v1/patching/plans",
        headers={**oper_hdr, "Idempotency-Key": idem_key},
        json={**plan_payload, "title": "Different Plan Title"},
    )
    assert p1_conflict_title.status_code == 409

    p1_conflict_policy = await api_client.post(
        "/api/v1/patching/plans",
        headers={**oper_hdr, "Idempotency-Key": idem_key},
        json={**plan_payload, "max_failed_hosts": 2},
    )
    assert p1_conflict_policy.status_code == 409

    # Viewer can list & view plans, but cannot create
    assert (
        await api_client.post("/api/v1/patching/plans", headers=viewer_hdr, json=plan_payload)
    ).status_code == 403
    listed = await api_client.get("/api/v1/patching/plans?status=DRY_RUN_READY", headers=viewer_hdr)
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    detail_resp = await api_client.get(f"/api/v1/patching/plans/{plan_id}", headers=viewer_hdr)
    assert detail_resp.status_code == 200
    missing_resp = await api_client.get(f"/api/v1/patching/plans/{uuid4()}", headers=viewer_hdr)
    assert missing_resp.status_code == 404

    # 4. Pull-based Agent Dry-Run flow (both agents pull job and report)
    h1_hdr = {"Authorization": f"Bearer {h1_cred}"}
    h2_hdr = {"Authorization": f"Bearer {h2_cred}"}
    mismatch_jobs = await api_client.get(f"/api/v1/agents/{h2}/patch-jobs", headers=h1_hdr)
    assert mismatch_jobs.status_code == 403

    h1_jobs = await api_client.get(f"/api/v1/agents/{h1}/patch-jobs", headers=h1_hdr)
    assert h1_jobs.status_code == 200
    assert len(h1_jobs.json()) == 1
    assert h1_jobs.json()[0]["mode"] == "dry_run"

    r1 = await api_client.post(
        f"/api/v1/agents/{h1}/patch-jobs/{plan_id}/result",
        headers=h1_hdr,
        json={
            "mode": "dry_run",
            "status": "dry_run_only",
            "succeeded": True,
            "repo_verified": True,
            "planned_changes_count": 1,
        },
    )
    assert r1.status_code == 200
    assert r1.json()["status"] == "DRY_RUN_READY"

    r2 = await api_client.post(
        f"/api/v1/agents/{h2}/patch-jobs/{plan_id}/result",
        headers=h2_hdr,
        json={
            "mode": "dry_run",
            "status": "dry_run_only",
            "succeeded": True,
            "repo_verified": True,
            "planned_changes_count": 1,
        },
    )
    assert r2.status_code == 200
    assert r2.json()["status"] == "PENDING_APPROVAL"

    # 5. Maker-Checker enforcement (operator cannot approve; distinct approver approves)
    assert (
        await api_client.post(
            f"/api/v1/patching/plans/{plan_id}/decision",
            headers=oper_hdr,
            json={"decision": "approved", "rationale": "Operator forbidden"},
        )
    ).status_code == 403

    approved = await api_client.post(
        f"/api/v1/patching/plans/{plan_id}/decision",
        headers=approver_hdr,
        json={"decision": "approved", "rationale": "Verified dry-run across canary targets."},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"
    assert len(approved.json()["approvals"]) == 1

    # 6. Canary start + Agent Wave 1 + Agent Wave 2 -> COMPLETED
    started = await api_client.post(
        f"/api/v1/patching/plans/{plan_id}/execute", headers=oper_hdr
    )
    assert started.status_code == 200
    assert started.json()["status"] == "CANARY_WAVE"
    assert started.json()["active_wave_number"] == 1

    # Wave 1 has h1, NOT h2 yet
    w1_jobs = await api_client.get(f"/api/v1/agents/{h1}/patch-jobs", headers=h1_hdr)
    assert len(w1_jobs.json()) == 1 and w1_jobs.json()[0]["mode"] == "apply"
    w2_early = await api_client.get(f"/api/v1/agents/{h2}/patch-jobs", headers=h2_hdr)
    assert w2_early.json() == []

    w1_res = await api_client.post(
        f"/api/v1/agents/{h1}/patch-jobs/{plan_id}/result",
        headers=h1_hdr,
        json={
            "mode": "apply",
            "status": "completed",
            "succeeded": True,
            "healthy_after_patch": True,
            "detail": "sshd healthy",
        },
    )
    assert w1_res.status_code == 200
    assert w1_res.json()["status"] == "ROLLOUT_IN_PROGRESS"
    assert w1_res.json()["active_wave_number"] == 2

    w2_res = await api_client.post(
        f"/api/v1/agents/{h2}/patch-jobs/{plan_id}/result",
        headers=h2_hdr,
        json={
            "mode": "apply",
            "status": "completed",
            "succeeded": True,
            "healthy_after_patch": True,
        },
    )
    assert w2_res.status_code == 200
    assert w2_res.json()["status"] == "COMPLETED"

    # 7. Second plan: Operator dry-run API + Maker-Checker self-approval 403 + Safe Mode Rollback
    p2 = await api_client.post(
        "/api/v1/patching/plans",
        headers=admin_hdr,
        json={"title": "Rollback Test Plan", "target_host_ids": [h1], "packages": ["openssl"]},
    )
    assert p2.status_code == 201
    p2_id = p2.json()["id"]

    dr_ok = await api_client.post(
        f"/api/v1/patching/plans/{p2_id}/dry-run",
        headers=oper_hdr,
        json={"outcomes": [{"host_id": h1, "succeeded": True, "repo_verified": True}]},
    )
    assert dr_ok.status_code == 200
    assert dr_ok.json()["status"] == "PENDING_APPROVAL"

    # Admin creator cannot self-approve!
    self_app = await api_client.post(
        f"/api/v1/patching/plans/{p2_id}/decision",
        headers=admin_hdr,
        json={"decision": "approved", "rationale": "Trying to bypass Maker-Checker"},
    )
    assert self_app.status_code == 403

    # Distinct approver approves, operator starts canary, wave health fails -> ROLLED_BACK
    assert (
        await api_client.post(
            f"/api/v1/patching/plans/{p2_id}/decision",
            headers=approver_hdr,
            json={"decision": "approved", "rationale": "Approved for canary test."},
        )
    ).status_code == 200
    assert (
        await api_client.post(f"/api/v1/patching/plans/{p2_id}/execute", headers=oper_hdr)
    ).status_code == 200

    # Wave mismatch 409
    assert (
        await api_client.post(
            f"/api/v1/patching/plans/{p2_id}/wave-report",
            headers=oper_hdr,
            json={"wave_number": 2, "healthy_hosts": 1, "failed_hosts": 0},
        )
    ).status_code == 409

    rb = await api_client.post(
        f"/api/v1/patching/plans/{p2_id}/wave-report",
        headers=oper_hdr,
        json={"wave_number": 1, "healthy_hosts": 0, "failed_hosts": 1},
    )
    assert rb.status_code == 200
    assert rb.json()["status"] == "ROLLED_BACK"

    # Non-target host cannot report agent result -> 403
    assert (
        await api_client.post(
            f"/api/v1/agents/{h2}/patch-jobs/{p2_id}/result",
            headers=h2_hdr,
            json={"mode": "apply", "status": "completed", "succeeded": True},
        )
    ).status_code == 403

    # Verify WORM chain integrity across all Phase 3 events
    worm = await api_client.get("/api/v1/audit/verify", headers=viewer_hdr)
    assert worm.status_code == 200
    assert worm.json()["valid"] is True
    assert worm.json()["checked_records"] >= 15


def test_feed_parsers_cvss3_multiline_and_structured_rhel_oval() -> None:
    """Verify OSV CVSS3 base scoring, multiline sanitization, and structured OVAL XML parsing."""
    osv_cvss = json.dumps(
        {
            "vulns": [
                {
                    "id": "CVE-2024-9901",
                    "details": "Critical RCE\nwith multiline\tdetails and\r\nCRLF",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    ],
                    "affected": [
                        {
                            "package": {"ecosystem": "Debian:12", "name": "openssh-server"},
                            "ranges": [{"events": [{"fixed": "1:9.2p1-2+deb12u4"}]}],
                        },
                        {
                            "package": {"ecosystem": "Debian:12", "name": "openssh-server"},
                            "ranges": [{"events": [{"fixed": "1:9.2p1-2+deb12u5"}]}],
                        },
                    ],
                },
                {
                    "id": "CVE-2024-9902",
                    "summary": "Scope changed medium and high CVSS",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:N",
                        }
                    ],
                    "affected": [{"package": {"ecosystem": "Alpine:3.19", "name": "curl"}}],
                },
                {
                    "id": "CVE-2024-9905",
                    "summary": "High CVSS 8.1 regreSSHion",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    ],
                    "affected": [{"package": {"ecosystem": "Debian:12", "name": "openssh"}}],
                },
                {
                    "id": "CVE-2024-9903",
                    "summary": "Numeric low CVSS",
                    "severity": [{"score": "3.1"}],
                    "affected": [{"package": {"ecosystem": "Ubuntu:22.04", "name": "tar"}}],
                },
                {
                    "id": "CVE-2024-9904",
                    "summary": "Zero impact CVSS and malformed vector fallback",
                    "severity": [
                        {"score": "CVSS:3.1/BAD"},
                        {"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
                    ],
                    "affected": [{"package": {"ecosystem": "Ubuntu:22.04", "name": "gzip"}}],
                },
            ]
        }
    )
    osv_items = parse_cve_feed(feed_format="osv", raw_text=osv_cvss)
    by_cve = {item.cve_id: item for item in osv_items}
    assert len(osv_items) == 5  # duplicates collapsed
    assert by_cve["CVE-2024-9901"].base_severity == "critical"
    assert by_cve["CVE-2024-9901"].cvss_score == 9.8
    assert by_cve["CVE-2024-9901"].fixed_version == "1:9.2p1-2+deb12u5"
    assert "\n" not in by_cve["CVE-2024-9901"].summary
    assert by_cve["CVE-2024-9902"].base_severity == "medium"
    assert by_cve["CVE-2024-9902"].cvss_score == 6.5
    assert by_cve["CVE-2024-9905"].base_severity == "high"
    assert by_cve["CVE-2024-9905"].cvss_score == 8.1
    assert by_cve["CVE-2024-9903"].base_severity == "low"
    assert by_cve["CVE-2024-9903"].cvss_score == 3.1
    assert by_cve["CVE-2024-9904"].base_severity == "low"
    assert by_cve["CVE-2024-9904"].cvss_score == 0.0

    rhel_oval = """<?xml version="1.0" encoding="UTF-8"?>
    <oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
                      xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <definitions>
        <definition id="oval:com.redhat.rhsa:def:20241234">
          <metadata>
            <title>RHSA-2024:1234:\nopenssh security update</title>
            <reference source="CVE" ref_id="CVE-2024-6387"/>
            <advisory><severity>Important</severity></advisory>
          </metadata>
          <criteria>
            <criterion test_ref="oval:com.redhat.rhsa:tst:1" comment="openssh-server vulnerable"/>
            <criterion test_ref="oval:com.redhat.rhsa:tst:neg" negate="true" comment="ignored"/>
          </criteria>
        </definition>
      </definitions>
      <tests>
        <linux-def:rpminfo_test id="oval:com.redhat.rhsa:tst:1" check="at least one">
          <linux-def:object object_ref="oval:com.redhat.rhsa:obj:1"/>
          <linux-def:state state_ref="oval:com.redhat.rhsa:ste:1"/>
        </linux-def:rpminfo_test>
        <linux-def:rpminfo_test id="oval:com.redhat.rhsa:tst:neg" check="at least one">
          <linux-def:object object_ref="oval:com.redhat.rhsa:obj:2"/>
          <linux-def:state state_ref="oval:com.redhat.rhsa:ste:2"/>
        </linux-def:rpminfo_test>
      </tests>
      <objects>
        <linux-def:rpminfo_object id="oval:com.redhat.rhsa:obj:1">
          <linux-def:name>openssh-server</linux-def:name>
        </linux-def:rpminfo_object>
        <linux-def:rpminfo_object id="oval:com.redhat.rhsa:obj:2">
          <linux-def:name>negated-pkg</linux-def:name>
        </linux-def:rpminfo_object>
      </objects>
      <states>
        <linux-def:rpminfo_state id="oval:com.redhat.rhsa:ste:1">
          <linux-def:evr datatype="evr_string" operation="less than">
            0:8.7p1-38.el9_4.1
          </linux-def:evr>
        </linux-def:rpminfo_state>
        <linux-def:rpminfo_state id="oval:com.redhat.rhsa:ste:2">
          <linux-def:evr datatype="evr_string" operation="equals">1.0</linux-def:evr>
        </linux-def:rpminfo_state>
      </states>
    </oval_definitions>"""
    rhel_items = parse_cve_feed(
        feed_format="oval", raw_text=rhel_oval, default_ecosystem="RedHat:9"
    )
    assert len(rhel_items) == 1
    assert rhel_items[0].ecosystem == "RedHat:9"
    assert rhel_items[0].package_name == "openssh-server"
    assert rhel_items[0].fixed_version == "0:8.7p1-38.el9_4.1"
    assert rhel_items[0].base_severity == "high"
    assert "\n" not in rhel_items[0].summary


@pytest.mark.asyncio
async def test_duplicate_sync_rescan_drift_csp_and_partial_wave_threshold(
    api_client: httpx.AsyncClient,
) -> None:
    """Verify duplicate sync deduplication, drift update on rescan, HTML CSP, and wave threshold."""
    admin_jwt = await login_as(api_client, "admin_u", "AdminPass!123")
    oper_jwt = await login_as(api_client, "operator_u", "OperPass!123")
    admin_hdr = {"Authorization": f"Bearer {admin_jwt}"}
    oper_hdr = {"Authorization": f"Bearer {oper_jwt}"}

    h1, h1_cred = await _enroll_and_push_snapshot(
        api_client, admin_hdr, hostname="srv-dup-01.internal", repo_access_ok=True
    )
    h2, h2_cred = await _enroll_and_push_snapshot(
        api_client, admin_hdr, hostname="srv-dup-02.internal", repo_access_ok=True
    )
    h1_hdr = {"Authorization": f"Bearer {h1_cred}"}
    h2_hdr = {"Authorization": f"Bearer {h2_cred}"}

    # 1. Duplicate advisories in a single /cves/sync-feed batch must deduplicate without 500
    dup_sync = await api_client.post(
        "/api/v1/cves/sync-feed",
        headers=admin_hdr,
        json={
            "advisories": [
                {
                    "cve_id": "CVE-2024-6387",
                    "ecosystem": "Debian:12",
                    "package_name": "openssh-server",
                    "fixed_version": "1:9.2p1-2+deb12u2",
                    "base_severity": "high",
                    "source_feed": "trivy",
                    "summary": "Initial advisory",
                },
                {
                    "cve_id": "CVE-2024-6387",
                    "ecosystem": "Debian:12",
                    "package_name": "openssh-server",
                    "fixed_version": "1:9.2p1-2+deb12u3",
                    "base_severity": "critical",
                    "source_feed": "trivy",
                    "summary": "Updated advisory",
                },
            ]
        },
    )
    assert dup_sync.status_code == 200, dup_sync.text
    assert dup_sync.json()["upserted"] == 1

    # 2. Fleet rescan updates snapshot drift items and HTML report includes strict CSP header
    rescan = await api_client.post("/api/v1/cves/rescan-fleet", headers=admin_hdr)
    assert rescan.status_code == 200
    assert rescan.json()["total_cve_matches"] == 2
    snaps = await api_client.get(f"/api/v1/hosts/{h1}/snapshots", headers=admin_hdr)
    snap_id = snaps.json()["items"][0]["id"]
    drift = await api_client.get(f"/api/v1/snapshots/{snap_id}/drift", headers=admin_hdr)
    assert any(item["category"] == "cve" for item in drift.json()["items"])

    html_resp = await api_client.get(f"/api/v1/reports/hosts/{h1}?format=html", headers=admin_hdr)
    assert html_resp.status_code == 200
    assert "default-src 'none'" in html_resp.headers["content-security-policy"]

    # 3. 2-host canary wave with max_failed_hosts=1 must NOT prematurely complete after 1st failure
    plan_resp = await api_client.post(
        "/api/v1/patching/plans",
        headers=oper_hdr,
        json={
            "title": "Two-host wave threshold test",
            "target_host_ids": [h1, h2],
            "packages": ["openssh-server"],
            "canary_percent": 100,
            "max_wave_percent": 100,
            "safe_mode_enabled": True,
            "max_failed_hosts": 1,
            "rollback_on_unreachable": True,
        },
    )
    assert plan_resp.status_code == 201
    plan_id = plan_resp.json()["id"]
    assert (
        await api_client.post(
            f"/api/v1/patching/plans/{plan_id}/dry-run",
            headers=oper_hdr,
            json={
                "outcomes": [
                    {"host_id": h1, "succeeded": True, "repo_verified": True},
                    {"host_id": h2, "succeeded": True, "repo_verified": True},
                ]
            },
        )
    ).status_code == 200
    assert (
        await api_client.post(
            f"/api/v1/patching/plans/{plan_id}/decision",
            headers=admin_hdr,
            json={"decision": "approved", "rationale": "Threshold test approved."},
        )
    ).status_code == 200
    assert (
        await api_client.post(f"/api/v1/patching/plans/{plan_id}/execute", headers=oper_hdr)
    ).status_code == 200

    # Host 1 fails (failed=1 <= max_failed_hosts=1): MUST stay CANARY_WAVE waiting for Host 2!
    r1 = await api_client.post(
        f"/api/v1/agents/{h1}/patch-jobs/{plan_id}/result",
        headers=h1_hdr,
        json={
            "mode": "apply",
            "status": "failed_healthcheck",
            "succeeded": False,
            "healthy_after_patch": False,
            "rolled_back": False,
            "detail": "nginx failed post-patch",
        },
    )
    assert r1.status_code == 200, r1.text
    assert r1.json()["status"] == "CANARY_WAVE"

    # Host 2 ALSO fails (failed=2 > max_failed_hosts=1): NOW Safe Mode triggers ROLLED_BACK!
    r2 = await api_client.post(
        f"/api/v1/agents/{h2}/patch-jobs/{plan_id}/result",
        headers=h2_hdr,
        json={
            "mode": "apply",
            "status": "rolled_back",
            "succeeded": False,
            "healthy_after_patch": False,
            "rolled_back": True,
            "detail": "ssh healthcheck failed",
        },
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["status"] == "ROLLED_BACK"


@pytest.mark.asyncio
async def test_tool_bundle_arch_query_disambiguation(api_client: httpx.AsyncClient) -> None:
    """Verify deterministic ?arch= selection on tool bundle /manifest and /download."""
    oper_jwt = await login_as(api_client, "operator_u", "OperPass!123")
    oper_hdr = {"Authorization": f"Bearer {oper_jwt}"}

    amd64_payload = b"amd64-lynis-portable-bytes"
    arm64_payload = b"arm64-lynis-portable-bytes"
    noarch_payload = b"noarch-lynis-portable-bytes"

    for arch, fname, content in (
        ("amd64", "lynis-3.2.0-amd64.tar.gz", amd64_payload),
        ("arm64", "lynis-3.2.0-arm64.tar.gz", arm64_payload),
        ("noarch", "lynis-3.2.0-noarch.tar.gz", noarch_payload),
    ):
        reg = await api_client.post(
            "/api/v1/bundles/register",
            headers=oper_hdr,
            data={"tool_name": "lynis", "version": "3.2.0", "arch": arch},
            files={"file": (fname, content, "application/gzip")},
        )
        assert reg.status_code == 201, reg.text

    # Explicit ?arch=arm64 returns arm64 manifest + download_url with ?arch=arm64
    arm_man = await api_client.get(
        "/api/v1/bundles/lynis/3.2.0/manifest?arch=arm64", headers=oper_hdr
    )
    assert arm_man.status_code == 200
    assert arm_man.json()["arch"] == "arm64"
    assert arm_man.json()["download_url"] == "/api/v1/bundles/lynis/3.2.0/download?arch=arm64"

    arm_dl = await api_client.get(arm_man.json()["download_url"], headers=oper_hdr)
    assert arm_dl.status_code == 200
    assert arm_dl.content == arm64_payload

    # Explicit ?arch=amd64 on latest resolves deterministically to amd64
    amd_latest = await api_client.get(
        "/api/v1/bundles/lynis/latest/manifest?arch=amd64", headers=oper_hdr
    )
    assert amd_latest.status_code == 200
    assert amd_latest.json()["arch"] == "amd64"
    amd_dl = await api_client.get(
        "/api/v1/bundles/lynis/3.2.0/download?arch=amd64", headers=oper_hdr
    )
    assert amd_dl.status_code == 200
    assert amd_dl.content == amd64_payload

    # Omitting ?arch= on version 3.2.0 deterministically prefers noarch
    default_man = await api_client.get(
        "/api/v1/bundles/lynis/3.2.0/manifest", headers=oper_hdr
    )
    assert default_man.status_code == 200
    assert default_man.json()["arch"] == "noarch"
    assert default_man.json()["download_url"] == "/api/v1/bundles/lynis/3.2.0/download"

    # Unknown arch -> 404, unsafe/unsupported/overlong identifiers -> 400
    assert (
        await api_client.get("/api/v1/bundles/lynis/3.2.0/manifest?arch=386", headers=oper_hdr)
    ).status_code == 404
    assert (
        await api_client.get(
            "/api/v1/bundles/lynis/3.2.0/download?arch=../etc", headers=oper_hdr
        )
    ).status_code == 400
    assert (
        await api_client.get("/api/v1/bundles/lynis/3.2.0/manifest?arch=mips", headers=oper_hdr)
    ).status_code == 400
    assert (
        await api_client.post(
            "/api/v1/bundles/register",
            headers=oper_hdr,
            data={"tool_name": "lynis", "version": "1." + "0" * 40, "arch": "noarch"},
            files={"file": ("long-ver.tar.gz", b"bytes", "application/gzip")},
        )
    ).status_code == 400
    assert (
        await api_client.post(
            "/api/v1/bundles/register",
            headers=oper_hdr,
            data={"tool_name": "lynis", "version": "3.2.1", "arch": "mips"},
            files={"file": ("bad-arch.tar.gz", b"bytes", "application/gzip")},
        )
    ).status_code == 400

    # Two architectures sharing the SAME filename MUST NOT overwrite each other on disk
    shared_amd = b"shared-name-amd64-payload"
    shared_arm = b"shared-name-arm64-payload"
    for arch, payload in (("amd64", shared_amd), ("arm64", shared_arm)):
        reg_shared = await api_client.post(
            "/api/v1/bundles/register",
            headers=oper_hdr,
            data={"tool_name": "lynis", "version": "3.3.0", "arch": arch},
            files={"file": ("lynis-3.3.0-portable.tar.gz", payload, "application/gzip")},
        )
        assert reg_shared.status_code == 201, reg_shared.text

    dl_shared_amd = await api_client.get(
        "/api/v1/bundles/lynis/3.3.0/download?arch=amd64", headers=oper_hdr
    )
    assert dl_shared_amd.status_code == 200
    assert dl_shared_amd.content == shared_amd
    assert dl_shared_amd.headers["x-hostgrid-sha256"] == sha256_hex(shared_amd)

    dl_shared_arm = await api_client.get(
        "/api/v1/bundles/lynis/3.3.0/download?arch=arm64", headers=oper_hdr
    )
    assert dl_shared_arm.status_code == 200
    assert dl_shared_arm.content == shared_arm
    assert dl_shared_arm.headers["x-hostgrid-sha256"] == sha256_hex(shared_arm)


@pytest.mark.asyncio
async def test_commit_plan_with_idempotency_integrity_race_replay_and_conflict() -> None:
    """Exercise IntegrityError race path in _commit_plan_with_idempotency (replay + 409)."""
    from unittest.mock import AsyncMock

    from sqlalchemy.exc import IntegrityError

    from app.schemas.patching import PatchPlanCreateRequest, PatchPlanResponse
    from app.services.patching.service import _commit_plan_with_idempotency

    host_id = uuid4()
    plan_id = uuid4()
    creator_id = uuid4()
    key = str(uuid4())
    actor_scope = f"user:{creator_id}"
    payload = PatchPlanCreateRequest(
        title="Race Plan",
        target_host_ids=[host_id],
        packages=["curl"],
        canary_percent=10,
        max_wave_percent=50,
    )
    cached_resp = PatchPlanResponse(
        id=plan_id,
        title="Race Plan",
        target_host_ids=[host_id],
        packages=["curl"],
        canary_percent=10,
        status="DRY_RUN_READY",
        created_by=creator_id,
        created_by_username="operator_u",
        created_at="2026-11-28T00:00:00.000Z",
        updated_at="2026-11-28T00:00:00.000Z",
        precheck={"passed": True, "eligible_host_ids": [str(host_id)], "blocked_host_ids": []},
        policy={
            "canary_percent": 10,
            "max_wave_percent": 50,
            "safe_mode_enabled": True,
            "max_failed_hosts": 0,
            "rollback_on_unreachable": True,
        },
        waves=[],
        active_wave_number=None,
        dry_run_report=None,
        wave_reports=[],
        approvals=[],
    )

    class _FakeRecord:
        def __init__(self, data: dict[str, object]) -> None:
            self.response_json = data

    class _FakeResult:
        def __init__(self, rec: _FakeRecord | None) -> None:
            self._rec = rec

        def scalar_one_or_none(self) -> _FakeRecord | None:
            return self._rec

    fake_session = AsyncMock()
    fake_session.commit.side_effect = IntegrityError("INSERT", {}, Exception("unique violation"))
    fake_session.execute.return_value = _FakeResult(
        _FakeRecord(cached_resp.model_dump(mode="json"))
    )

    # Same payload after IntegrityError -> rolls back and returns cached response
    replayed = await _commit_plan_with_idempotency(
        fake_session,
        clean_key=key,
        actor_scope=actor_scope,
        payload=payload,
        response=cached_resp,
    )
    assert replayed.id == plan_id
    fake_session.rollback.assert_awaited_once()

    # Different payload after IntegrityError -> rolls back and raises 409 Conflict
    fake_session.rollback.reset_mock()
    diff_payload = PatchPlanCreateRequest(
        title="Conflicting Race Plan",
        target_host_ids=[host_id],
        packages=["openssl"],
    )
    with pytest.raises(DomainError) as exc_info:
        await _commit_plan_with_idempotency(
            fake_session,
            clean_key=key,
            actor_scope=actor_scope,
            payload=diff_payload,
            response=cached_resp,
        )
    assert exc_info.value.status_code == 409
    fake_session.rollback.assert_awaited_once()


def test_healthcheck_http_https_and_error_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify TLS/mTLS-aware container healthcheck target resolution and exit codes."""
    from datetime import timedelta
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from pathlib import Path
    from tempfile import TemporaryDirectory
    from threading import Thread

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from app.healthcheck import check_health, resolve_healthcheck_target

    # Default HTTP target
    url, ctx = resolve_healthcheck_target({})
    assert url == "http://127.0.0.1:8000/healthz"
    assert ctx is None

    # Invalid scheme fails closed
    with pytest.raises(ValueError, match="http:// or https://"):
        resolve_healthcheck_target({"HOSTGRID_HEALTH_URL": "file:///etc/passwd"})
    assert check_health({"HOSTGRID_HEALTH_URL": "file:///etc/passwd"}) == 1

    # Partial mTLS client cert/key fails closed
    with pytest.raises(ValueError, match="HOSTGRID_HEALTH_CLIENT_CERT"):
        resolve_healthcheck_target(
            {
                "HOSTGRID_HEALTH_URL": "https://127.0.0.1:8443/healthz",
                "HOSTGRID_HEALTH_CLIENT_CERT": "/etc/hostgrid/certs/only-cert.pem",
            }
        )
    assert (
        check_health(
            {
                "HOSTGRID_HEALTH_URL": "https://127.0.0.1:8443/healthz",
                "HOSTGRID_HEALTH_CLIENT_KEY": "/etc/hostgrid/certs/only-key.pem",
            }
        )
        == 1
    )

    # Local HTTP server 200 and 503 checks
    status_holder = {"code": 200}

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(status_holder["code"])
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert check_health({"HOSTGRID_SERVER_PORT": str(port)}) == 0
        status_holder["code"] = 503
        assert check_health({"HOSTGRID_SERVER_PORT": str(port)}) == 1
    finally:
        server.shutdown()
        server.server_close()

    # HTTPS + mTLS context resolution with temporary self-signed PEM cert/key
    with TemporaryDirectory() as tmp:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(hours=1))
            .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
            .sign(key, hashes.SHA256())
        )
        cert_path = Path(tmp) / "server.crt"
        key_path = Path(tmp) / "server.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        tls_url, tls_ctx = resolve_healthcheck_target(
            {
                "HOSTGRID_TLS_CERTFILE": str(cert_path),
                "HOSTGRID_TLS_KEYFILE": str(key_path),
                "HOSTGRID_HEALTH_CLIENT_CERT": str(cert_path),
                "HOSTGRID_HEALTH_CLIENT_KEY": str(key_path),
            }
        )
        assert tls_url == "https://127.0.0.1:8443/healthz"
        assert tls_ctx is not None

        # Default env fallback (env=None) when server is unreachable returns 1
        monkeypatch.setenv("HOSTGRID_HEALTH_URL", "http://127.0.0.1:1/healthz")
        assert check_health(timeout=0.2) == 1
