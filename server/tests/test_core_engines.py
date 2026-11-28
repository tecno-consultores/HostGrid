"""Unit tests for Lynis parser, EOL detector, CVE versioning, scoring, drift, and WORM."""

from __future__ import annotations

from datetime import date
from uuid import uuid4

import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog
from app.schemas.snapshot import ListeningSocket, NetworkPayload
from app.services.cve.versioning import compare_distro_versions, is_version_vulnerable
from app.services.drift.engine import FindingDigest, compute_drift_items, compute_hardening_delta
from app.services.eol.detector import evaluate_eol_offline, normalize_os_version_key
from app.services.normalizer.lynis_parser import parse_lynis_report
from app.services.normalizer.native_analyzers import analyze_network, analyze_sysctl
from app.services.normalizer.scoring import (
    NormalizedFinding,
    ScoringContext,
    build_sarif_report,
    compute_fingerprint,
    deduplicate_and_score,
    score_finding,
)
from app.services.worm import append_audit_log, verify_audit_chain
from tests.conftest import FIXTURES_DIR


def test_parse_real_lynis_report_fixture() -> None:
    """Verify real lynis-report.dat parses metrics, warnings, suggestions, and fingerprints."""
    raw = (FIXTURES_DIR / "lynis_debian8.dat").read_text(encoding="utf-8")
    parsed = parse_lynis_report(raw)

    assert parsed.lynis_version == "3.1.4"
    assert parsed.hardening_index == 64
    assert parsed.tests_executed == 248
    assert parsed.tests_skipped == 2
    assert parsed.warnings_count == 2
    assert parsed.suggestions_count == 4
    assert len(parsed.findings) == 6

    ssh_finding = next(f for f in parsed.findings if f.rule_id == "SSH-7408")
    assert ssh_finding.base_severity == "high"
    assert ssh_finding.category == "hardening"
    assert ssh_finding.fingerprint == compute_fingerprint(
        "lynis", "hardening", "SSH-7408", "/etc/ssh/sshd_config"
    )
    banner_finding = next(f for f in parsed.findings if f.rule_id == "BANN-7126")
    assert banner_finding.base_severity == "low"
    assert "Revisar y remediar" in banner_finding.remediation


def test_parse_empty_and_malformed_lynis_report() -> None:
    """Empty input yields zero metrics; non-integer fields degrade safely."""
    empty = parse_lynis_report("   \n# comment only\n")
    assert empty.hardening_index is None
    assert empty.findings == []

    bad_num = parse_lynis_report(
        "hardening_index=not_a_number\nlynis_tests_done=abc\n"
    )
    assert bad_num.hardening_index is None
    assert bad_num.tests_executed == 0

    out_of_range = parse_lynis_report("hardening_index=150\n")
    assert out_of_range.hardening_index is None


def test_eol_detector_states_and_version_normalization() -> None:
    """Verify EOL, approaching_eol, supported, and unknown states offline."""
    assert normalize_os_version_key("debian", "8.11") == "8"
    assert normalize_os_version_key("debian", "8 (jessie)") == "8"
    assert normalize_os_version_key("ubuntu", "22.04.5") == "22.04"
    assert normalize_os_version_key("ubuntu", "22.04 LTS") == "22.04"
    assert normalize_os_version_key("alpine", "3") == "3"
    assert normalize_os_version_key("other", "rolling") == "rolling"

    eol_res = evaluate_eol_offline(
        os_family="debian",
        os_version="8.11",
        standard_eol_date=None,
        reference_date=date(2026, 1, 15),
    )
    assert eol_res.status == "eol"
    assert eol_res.finding is not None
    assert eol_res.finding.base_severity == "critical"
    assert eol_res.finding.rule_id == "OS_EOL"

    approaching = evaluate_eol_offline(
        os_family="debian",
        os_version="12",
        standard_eol_date=None,
        reference_date=date(2026, 2, 1),
    )
    assert approaching.status == "approaching_eol"
    assert approaching.finding is not None
    assert approaching.finding.base_severity == "high"

    supported = evaluate_eol_offline(
        os_family="ubuntu",
        os_version="24.04",
        standard_eol_date=None,
        reference_date=date(2026, 1, 1),
    )
    assert supported.status == "supported"
    assert supported.finding is None

    unknown = evaluate_eol_offline(
        os_family="other",
        os_version="99.9",
        standard_eol_date=None,
        reference_date=date(2026, 1, 1),
    )
    assert unknown.status == "unknown"
    assert unknown.eol_date is None


def test_distro_backport_version_comparison() -> None:
    """Verify epoch, Debian backports, tilde pre-releases, and RPM versions."""
    assert compare_distro_versions("1:8.9p1-3ubuntu0.6", "1:8.9p1-3ubuntu0.10") == -1
    assert compare_distro_versions("1:8.9p1-3ubuntu0.10", "1:8.9p1-3ubuntu0.10") == 0
    assert compare_distro_versions("2:1.0-1", "1:9.9-9") == 1
    assert compare_distro_versions("1.0~beta1-1", "1.0-1") == -1
    assert compare_distro_versions("1.0-1", "1.0~rc1-1") == 1
    assert compare_distro_versions("1.01", "1.1") == 0
    assert compare_distro_versions("1.0~01", "1.0~1") == 0
    assert compare_distro_versions("badepoch:1.0", "1.0") != 0
    assert is_version_vulnerable("1:8.9p1-3ubuntu0.6", "1:8.9p1-3ubuntu0.10") is True
    assert is_version_vulnerable("1:8.9p1-3ubuntu0.10", "1:8.9p1-3ubuntu0.10") is False
    assert is_version_vulnerable("1.0.0", None) is True


def test_contextual_scoring_dedup_and_sarif() -> None:
    """Verify contextual risk modifiers, severity elevation, deduplication, and SARIF output."""
    base = NormalizedFinding(
        fingerprint=compute_fingerprint("cve_engine", "cve", "CVE-2024-6387", "openssh-server"),
        rule_id="CVE-2024-6387",
        source_tool="cve_engine",
        category="cve",
        base_severity="high",
        confidence="high",
        title="CVE-2024-6387 en openssh-server",
        description="Vulnerable OpenSSH",
        evidence={"package": "openssh-server"},
        remediation="Upgrade openssh-server",
        reference_ids=["CVE-2024-6387"],
        exposed_wildcard=True,
        exposed_ports=["0.0.0.0:22"],
        cvss_score=8.1,
    )
    loopback_item = NormalizedFinding(
        fingerprint=base.fingerprint,
        rule_id="CVE-2024-6387",
        source_tool="cve_engine",
        category="cve",
        base_severity="medium",
        confidence="high",
        title="Duplicate lower score",
        description="Lower score duplicate",
        evidence={},
        remediation="Upgrade",
        loopback_only=True,
    )
    ctx = ScoringContext(is_eol=True, environment="prod")
    scored_list = deduplicate_and_score([loopback_item, base], ctx)
    assert len(scored_list) == 1
    assert scored_list[0].severity == "critical"
    assert scored_list[0].contextual_score == 100.0

    medium_elevated = score_finding(
        NormalizedFinding(
            fingerprint="b" * 64,
            rule_id="NET-1",
            source_tool="native_net",
            category="network",
            base_severity="medium",
            confidence="high",
            title="Medium exposed",
            description="Test",
            evidence={},
            remediation="Fix",
            exposed_wildcard=True,
        ),
        ScoringContext(is_eol=True, environment="dev"),
    )
    assert medium_elevated.severity == "high"
    assert medium_elevated.contextual_score == 72.0

    sarif = build_sarif_report(
        host_name="srv-01",
        snapshot_id="snap-1",
        findings=[
            {
                "source_tool": "cve_engine",
                "rule_id": "CVE-2024-6387",
                "title": "CVE-2024-6387",
                "description": "OpenSSH issue",
                "remediation": "Upgrade",
                "severity": "critical",
                "fingerprint": base.fingerprint,
                "category": "cve",
                "contextual_score": 100.0,
                "contextual_factors": ["host_eol(+12)"],
                "reference_ids": ["CVE-2024-6387"],
                "evidence": {},
            }
        ],
    )
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["level"] == "error"


def test_native_network_and_sysctl_analyzers() -> None:
    """Verify unencrypted binds, sensitive wildcard binds, and insecure sysctl detection."""
    net = NetworkPayload(
        listening_sockets=[
            ListeningSocket(
                proto="tcp", local_addr="0.0.0.0", port=23, process="telnetd"  # noqa: S104
            ),
            ListeningSocket(proto="tcp", local_addr="::", port=5432, process="postgres"),
            ListeningSocket(proto="tcp", local_addr="127.0.0.1", port=5432, process="postgres"),
            ListeningSocket(
                proto="tcp", local_addr="0.0.0.0", port=22, process="sshd"  # noqa: S104
            ),
        ]
    )
    net_findings = analyze_network(net)
    assert len(net_findings) == 2
    assert {f.rule_id for f in net_findings} == {"UNENCRYPTED_BIND", "SENSITIVE_WILDCARD"}

    sysctl_findings = analyze_sysctl(
        {
            "net.ipv4.ip_forward": "1",
            "kernel.kptr_restrict": "2",
            "kernel.randomize_va_space": "0",
        }
    )
    assert len(sysctl_findings) == 2


def test_drift_computation_new_resolved_persisted() -> None:
    """Verify deterministic drift set calculation and hardening index delta."""
    prev = [
        FindingDigest("fp_a", "high", "hardening", "Finding A"),
        FindingDigest("fp_b", "medium", "network", "Finding B"),
    ]
    curr = [
        FindingDigest("fp_b", "high", "network", "Finding B"),
        FindingDigest("fp_c", "critical", "cve", "Finding C"),
    ]
    res = compute_drift_items(
        snapshot_id=uuid4(),
        previous_snapshot_id=uuid4(),
        current_findings=curr,
        previous_findings=prev,
    )
    assert res.summary == {"new": 1, "resolved": 1, "persisted": 1}
    statuses = {item.fingerprint: item.status for item in res.items}
    assert statuses == {"fp_a": "resolved", "fp_b": "persisted", "fp_c": "new"}
    assert compute_hardening_delta(78, 64) == 14
    assert compute_hardening_delta(78, None) is None


@pytest.mark.asyncio
async def test_worm_audit_chain_and_tamper_detection(db_session: AsyncSession) -> None:
    """Verify SHA-256 WORM hash chain passes intact and fails immediately when tampered."""
    empty_check = await verify_audit_chain(db_session)
    assert empty_check.valid is True
    assert empty_check.checked_records == 0

    await append_audit_log(
        db_session,
        actor_id=None,
        actor_username="system",
        action="test.first",
        resource_type="test",
        resource_id="1",
        details={"k": "v1"},
    )
    await append_audit_log(
        db_session,
        actor_id=None,
        actor_username="system",
        action="test.second",
        resource_type="test",
        resource_id="2",
        details={"k": "v2"},
    )
    await db_session.commit()

    ok_check = await verify_audit_chain(db_session)
    assert ok_check.valid is True
    assert ok_check.checked_records == 2
    assert ok_check.broken_at_seq_num is None

    await db_session.execute(
        update(AuditLog).where(AuditLog.seq_num == 1).values(action="tampered.action")
    )
    await db_session.commit()

    broken = await verify_audit_chain(db_session)
    assert broken.valid is False
    assert broken.broken_at_seq_num == 1
