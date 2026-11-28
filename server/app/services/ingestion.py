"""End-to-end snapshot ingestion pipeline: Lynis, EOL, CVE, contextual scoring, drift, WORM."""

from __future__ import annotations

from decimal import Decimal
from uuid import UUID

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import DomainError
from app.core.rbac import (
    OPERATOR_OR_ADMIN,
    ActorContext,
    require_agent_host,
    require_roles,
)
from app.core.security import utc_now
from app.db.models import Finding, Host, IdempotencyRecord, Snapshot, SnapshotPackage
from app.schemas.snapshot import (
    AgentlessIngestRequest,
    SnapshotCreatedResponse,
    SnapshotIngestRequest,
)
from app.services.artifacts.bundle_importer import validate_airgapped_bundle
from app.services.cve.matcher import match_snapshot_cves
from app.services.drift.engine import (
    FindingDigest,
    compute_drift_items,
    compute_hardening_delta,
    load_previous_finding_digests,
)
from app.services.eol.detector import EolEvaluation, evaluate_host_eol
from app.services.normalizer.lynis_parser import ParsedLynisReport, parse_lynis_report
from app.services.normalizer.native_analyzers import analyze_network, analyze_sysctl
from app.services.normalizer.scoring import (
    NormalizedFinding,
    ScoredFinding,
    ScoringContext,
    deduplicate_and_score,
)
from app.services.worm import append_audit_log


async def _resolve_agent_host(
    session: AsyncSession,
    *,
    payload: SnapshotIngestRequest,
    actor: ActorContext,
) -> Host:
    if payload.host_id is None:
        raise DomainError(
            status_code=422,
            title="Missing host_id",
            detail="Agent snapshot submission requires host_id.",
            error_type="urn:hostgrid:error:missing_host_id",
        )
    require_agent_host(actor, payload.host_id)
    host = (
        await session.execute(select(Host).where(Host.id == payload.host_id))
    ).scalar_one_or_none()
    if host is None:
        raise DomainError(
            status_code=404,
            title="Not Found",
            detail="Enrolled host not found.",
            error_type="urn:hostgrid:error:not_found",
        )
    return host


async def _resolve_or_upsert_host(
    session: AsyncSession,
    *,
    payload: SnapshotIngestRequest,
    actor: ActorContext,
    eol: EolEvaluation,
) -> Host:
    if actor.is_agent:
        return await _resolve_agent_host(session, payload=payload, actor=actor)

    if not payload.machine_id_hash or not payload.hostname:
        raise DomainError(
            status_code=422,
            title="Missing Host Identity",
            detail="Offline or agentless snapshot requires hostname and machine_id_hash.",
            error_type="urn:hostgrid:error:missing_host_identity",
        )
    host = (
        await session.execute(
            select(Host).where(Host.machine_id_hash == payload.machine_id_hash)
        )
    ).scalar_one_or_none()
    if host is not None:
        return host

    host = Host(
        hostname=payload.hostname,
        machine_id_hash=payload.machine_id_hash,
        os_family=payload.probe.os_family,
        os_name=payload.probe.os_name,
        os_version=payload.probe.os_version,
        kernel_version=payload.probe.kernel_version,
        arch=payload.probe.arch,
        init_system=payload.probe.init_system,
        connectivity_mode=payload.connectivity_mode,
        environment=payload.environment,
        eol_status=eol.status,
        eol_date=eol.eol_date,
    )
    session.add(host)
    await session.flush()
    return host


def _update_host_posture(
    *,
    host: Host,
    payload: SnapshotIngestRequest,
    eol: EolEvaluation,
    lynis_parsed: ParsedLynisReport,
    prev_snapshot: Snapshot | None,
    critical_cves: int,
    high_cves: int,
) -> None:
    host.os_family = payload.probe.os_family
    host.os_name = payload.probe.os_name
    host.os_version = payload.probe.os_version
    host.kernel_version = payload.probe.kernel_version
    host.arch = payload.probe.arch
    host.init_system = payload.probe.init_system
    host.connectivity_mode = payload.connectivity_mode
    host.eol_status = eol.status
    host.eol_date = eol.eol_date
    host.repo_access_ok = payload.repos.access_ok
    host.capabilities_json = {
        key: val.model_dump() for key, val in payload.probe.capabilities.items()
    }
    host.critical_cves_count = critical_cves
    host.high_cves_count = high_cves
    host.last_seen_at = utc_now()
    if lynis_parsed.hardening_index is not None:
        prev_idx = prev_snapshot.hardening_index if prev_snapshot is not None else None
        host.last_hardening_index = lynis_parsed.hardening_index
        host.last_hardening_delta = compute_hardening_delta(lynis_parsed.hardening_index, prev_idx)
    if lynis_parsed.lynis_version or payload.lynis.lynis_version:
        host.last_lynis_version = lynis_parsed.lynis_version or payload.lynis.lynis_version


def _build_finding_models(
    *,
    snapshot_id: UUID,
    host_id: UUID,
    scored_items: list[ScoredFinding],
) -> list[Finding]:
    return [
        Finding(
            snapshot_id=snapshot_id,
            host_id=host_id,
            fingerprint=item.finding.fingerprint,
            rule_id=item.finding.rule_id,
            source_tool=item.finding.source_tool,
            category=item.finding.category,
            severity=item.severity,
            base_severity=item.finding.base_severity,
            confidence=item.finding.confidence,
            title=item.finding.title,
            description=item.finding.description,
            evidence_json=item.finding.evidence,
            remediation=item.finding.remediation,
            reference_ids_json=item.finding.reference_ids,
            contextual_score=Decimal(f"{item.contextual_score:.2f}"),
            contextual_factors_json=item.contextual_factors,
        )
        for item in scored_items
    ]


async def _persist_snapshot_pipeline(
    session: AsyncSession,
    *,
    payload: SnapshotIngestRequest,
    actor: ActorContext,
    ingestion_source: str,
    bundle_sha256: str | None = None,
    idempotency_meta: tuple[str, str, str] | None = None,
) -> SnapshotCreatedResponse:
    eol = await evaluate_host_eol(
        session,
        os_family=payload.probe.os_family,
        os_version=payload.probe.os_version,
    )
    host = await _resolve_or_upsert_host(session, payload=payload, actor=actor, eol=eol)
    prev_snapshot = (
        await session.execute(
            select(Snapshot)
            .where(Snapshot.host_id == host.id)
            .order_by(desc(Snapshot.ingested_at), desc(Snapshot.id))
            .limit(1)
        )
    ).scalar_one_or_none()

    lynis_parsed = (
        parse_lynis_report(payload.lynis.report_dat)
        if payload.lynis.executed and payload.lynis.report_dat
        else ParsedLynisReport()
    )

    snapshot = Snapshot(
        host_id=host.id,
        previous_snapshot_id=prev_snapshot.id if prev_snapshot is not None else None,
        ingestion_source=ingestion_source,
        agent_version=payload.agent_version,
        collected_at=payload.collected_at,
        hardening_index=lynis_parsed.hardening_index,
        lynis_version=lynis_parsed.lynis_version or payload.lynis.lynis_version,
        tests_executed=lynis_parsed.tests_executed,
        tests_skipped=lynis_parsed.tests_skipped,
        warnings_count=lynis_parsed.warnings_count,
        suggestions_count=lynis_parsed.suggestions_count,
        raw_probe_json=payload.probe.model_dump(),
        raw_network_json=payload.network.model_dump(),
        raw_services_json=[svc.model_dump() for svc in payload.services],
        raw_sysctl_json=payload.sysctl,
        raw_repos_json=payload.repos.model_dump(),
        bundle_sha256=bundle_sha256,
    )
    session.add(snapshot)
    await session.flush()

    session.add_all(
        [
            SnapshotPackage(
                snapshot_id=snapshot.id,
                package_manager=pkg.package_manager,
                name=pkg.name,
                source_package=pkg.source_package,
                epoch=pkg.epoch or None,
                version=pkg.version,
                release=pkg.release or None,
                arch=pkg.arch,
            )
            for pkg in payload.packages
        ]
    )

    scoring_ctx = ScoringContext(is_eol=(eol.status == "eol"), environment=host.environment)
    cve_result = await match_snapshot_cves(
        session,
        host_id=host.id,
        snapshot_id=snapshot.id,
        os_family=payload.probe.os_family,
        os_version=payload.probe.os_version,
        packages=payload.packages,
        network=payload.network,
        scoring_context=scoring_ctx,
    )
    session.add_all(cve_result.matches)

    raw_findings: list[NormalizedFinding] = [
        *lynis_parsed.findings,
        *analyze_network(payload.network),
        *analyze_sysctl(payload.sysctl),
        *cve_result.findings,
    ]
    if eol.finding is not None:
        raw_findings.append(eol.finding)

    scored = deduplicate_and_score(raw_findings, scoring_ctx)
    finding_models = _build_finding_models(
        snapshot_id=snapshot.id,
        host_id=host.id,
        scored_items=scored,
    )
    session.add_all(finding_models)

    prev_digests = await load_previous_finding_digests(session, snapshot.previous_snapshot_id)
    curr_digests = [
        FindingDigest(
            fingerprint=item.finding.fingerprint,
            severity=item.severity,
            category=item.finding.category,
            title=item.finding.title,
        )
        for item in scored
    ]
    drift = compute_drift_items(
        snapshot_id=snapshot.id,
        previous_snapshot_id=snapshot.previous_snapshot_id,
        current_findings=curr_digests,
        previous_findings=prev_digests,
    )
    session.add_all(drift.items)

    snapshot.critical_cves_count = cve_result.critical_count
    snapshot.high_cves_count = cve_result.high_count
    _update_host_posture(
        host=host,
        payload=payload,
        eol=eol,
        lynis_parsed=lynis_parsed,
        prev_snapshot=prev_snapshot,
        critical_cves=cve_result.critical_count,
        high_cves=cve_result.high_count,
    )

    await append_audit_log(
        session,
        actor_id=actor.actor_id,
        actor_username=actor.username,
        action=f"snapshot.ingested.{ingestion_source}",
        resource_type="snapshot",
        resource_id=str(snapshot.id),
        details={
            "host_id": str(host.id),
            "hostname": host.hostname,
            "hardening_index": snapshot.hardening_index,
            "eol_status": eol.status,
            "findings_total": len(scored),
            "drift_summary": drift.summary,
            "bundle_sha256": bundle_sha256,
        },
    )
    response = SnapshotCreatedResponse(
        snapshot_id=snapshot.id,
        host_id=host.id,
        previous_snapshot_id=snapshot.previous_snapshot_id,
        ingestion_source=ingestion_source,
        hardening_index=snapshot.hardening_index,
        eol_status=eol.status,
        findings_total=len(scored),
        critical_cves_count=cve_result.critical_count,
        high_cves_count=cve_result.high_count,
        drift_summary=drift.summary,
        bundle_sha256=bundle_sha256,
    )
    if idempotency_meta is not None:
        key_val, endpoint_val, scope_val = idempotency_meta
        session.add(
            IdempotencyRecord(
                idempotency_key=key_val,
                endpoint=endpoint_val,
                actor_scope=scope_val,
                status_code=201,
                response_json=response.model_dump(mode="json"),
            )
        )
    await session.commit()
    return response


def _validate_idempotency_key(raw_key: str | None) -> str | None:
    if raw_key is None or not raw_key.strip():
        return None
    cleaned = raw_key.strip()
    try:
        return str(UUID(cleaned))
    except ValueError as exc:
        raise DomainError(
            status_code=422,
            title="Invalid Idempotency-Key",
            detail="Idempotency-Key header must be a valid UUID.",
            error_type="urn:hostgrid:error:invalid_idempotency_key",
        ) from exc


async def _lookup_idempotent_snapshot(
    session: AsyncSession,
    *,
    key: str,
    endpoint: str,
    actor_scope: str,
) -> SnapshotCreatedResponse | None:
    existing = (
        await session.execute(
            select(IdempotencyRecord).where(
                IdempotencyRecord.idempotency_key == key,
                IdempotencyRecord.endpoint == endpoint,
                IdempotencyRecord.actor_scope == actor_scope,
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        return None
    return SnapshotCreatedResponse.model_validate(existing.response_json)


async def ingest_agent_snapshot(
    session: AsyncSession,
    *,
    actor: ActorContext,
    payload: SnapshotIngestRequest,
    idempotency_key: str | None = None,
) -> SnapshotCreatedResponse:
    """Ingest snapshot pushed directly by an enrolled agent (LAN or Relay)."""
    clean_key = _validate_idempotency_key(idempotency_key)
    endpoint = "POST /api/v1/snapshots"
    actor_scope = f"host:{actor.host_id}"
    idempotency_meta: tuple[str, str, str] | None = None
    if clean_key is not None:
        cached = await _lookup_idempotent_snapshot(
            session,
            key=clean_key,
            endpoint=endpoint,
            actor_scope=actor_scope,
        )
        if cached is not None:
            return cached
        idempotency_meta = (clean_key, endpoint, actor_scope)

    source = "relay_push" if payload.connectivity_mode == "relay" else "agent_push"
    return await _persist_snapshot_pipeline(
        session,
        payload=payload,
        actor=actor,
        ingestion_source=source,
        idempotency_meta=idempotency_meta,
    )


async def ingest_agentless_snapshot(
    session: AsyncSession,
    *,
    actor: ActorContext,
    payload: AgentlessIngestRequest,
) -> SnapshotCreatedResponse:
    """Ingest POSIX agentless snapshot JSON uploaded by operator/admin."""
    require_roles(actor, OPERATOR_OR_ADMIN)
    converted = SnapshotIngestRequest(
        hostname=payload.hostname,
        machine_id_hash=payload.machine_id_hash,
        environment=payload.environment,
        collected_at=payload.collected_at,
        agent_version=payload.agent_version,
        connectivity_mode="agentless",
        probe=payload.probe,
        packages=payload.packages,
        network=payload.network,
        services=payload.services,
        sysctl=payload.sysctl,
        repos=payload.repos,
        lynis=payload.lynis,
    )
    return await _persist_snapshot_pipeline(
        session,
        payload=converted,
        actor=actor,
        ingestion_source="agentless_ssh",
    )


async def ingest_airgapped_bundle(
    session: AsyncSession,
    *,
    settings: Settings,
    actor: ActorContext,
    raw_bytes: bytes,
) -> SnapshotCreatedResponse:
    """Validate and ingest a signed air-gapped .bundle archive."""
    require_roles(actor, OPERATOR_OR_ADMIN)
    validated = await validate_airgapped_bundle(
        session,
        settings=settings,
        actor=actor,
        raw_bytes=raw_bytes,
    )
    return await _persist_snapshot_pipeline(
        session,
        payload=validated.snapshot,
        actor=actor,
        ingestion_source="offline_bundle",
        bundle_sha256=validated.bundle_sha256,
    )
