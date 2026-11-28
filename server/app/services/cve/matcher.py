"""Offline distro-aware CVE matching, feed sync, and fleet reverse search."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID

from sqlalchemy import delete, desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import ADMIN_ONLY, ALL_USER_ROLES, ActorContext, require_roles
from app.core.security import format_rfc3339
from app.db.models import (
    CveAdvisory,
    Finding,
    Host,
    HostCveMatch,
    Snapshot,
    SnapshotDriftItem,
    SnapshotPackage,
)
from app.schemas.host import (
    CveAdvisoryIn,
    CveFeedImportRequest,
    CveFeedImportResponse,
    CveSearchItem,
    CveSearchResponse,
    CveSyncRequest,
    CveSyncResponse,
    FleetRescanResponse,
)
from app.schemas.snapshot import NetworkPayload, PackageItem
from app.services.cve.versioning import is_version_vulnerable
from app.services.drift.engine import (
    FindingDigest,
    compute_drift_items,
    load_previous_finding_digests,
)
from app.services.eol.detector import normalize_os_version_key
from app.services.normalizer.native_analyzers import is_loopback_address, is_wildcard_address
from app.services.normalizer.scoring import (
    NormalizedFinding,
    ScoringContext,
    compute_fingerprint,
    deduplicate_and_score,
    score_finding,
)
from app.services.worm import append_audit_log

ECOSYSTEM_FAMILY_ALIASES: dict[str, str] = {
    "redhat": "rhel",
    "red hat": "rhel",
    "sles": "suse",
    "opensuse": "suse",
}

ECOSYSTEM_PREFIX: dict[str, str] = {
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "rhel": "RedHat",
    "centos": "CentOS",
    "alpine": "Alpine",
    "suse": "SUSE",
    "rocky": "Rocky",
    "almalinux": "AlmaLinux",
}

PROCESS_PACKAGE_ALIASES: dict[str, frozenset[str]] = {
    "sshd": frozenset({"openssh-server", "openssh", "openssh-clients"}),
    "nginx": frozenset({"nginx", "nginx-core", "nginx-full"}),
    "apache2": frozenset({"apache2", "httpd"}),
    "httpd": frozenset({"httpd", "apache2"}),
    "postgres": frozenset({"postgresql", "postgresql-15", "postgresql-16", "postgresql-17"}),
    "mysqld": frozenset({"mysql-server", "mariadb-server"}),
    "mariadbd": frozenset({"mariadb-server", "mysql-server"}),
    "redis-server": frozenset({"redis-server", "redis", "keydb"}),
    "haproxy": frozenset({"haproxy"}),
    "dockerd": frozenset({"docker-ce", "docker.io", "moby-engine"}),
}


@dataclass(frozen=True)
class CveMatchResult:
    """Pair of persisted HostCveMatch specifications and normalized findings."""

    matches: list[HostCveMatch]
    findings: list[NormalizedFinding]
    critical_count: int
    high_count: int


def resolve_ecosystem(os_family: str, os_version: str) -> str:
    """Build canonical advisory ecosystem key such as Debian:12, Ubuntu:22.04, or RedHat:9."""
    raw_family = os_family.strip().lower()
    family = ECOSYSTEM_FAMILY_ALIASES.get(raw_family, raw_family)
    prefix = ECOSYSTEM_PREFIX.get(family, family.title())
    version = normalize_os_version_key(family, os_version)
    return f"{prefix}:{version}"


def _format_installed_version(pkg: PackageItem) -> str:
    base = f"{pkg.epoch}:{pkg.version}" if pkg.epoch else pkg.version
    if pkg.release and "-" not in base:
        return f"{base}-{pkg.release}"
    return base


def _socket_matches_names(process: str, names: set[str]) -> bool:
    proc = process.strip().lower()
    aliases = PROCESS_PACKAGE_ALIASES.get(proc, frozenset({proc}))
    return bool(names & aliases)


def _package_exposure(
    pkg: PackageItem,
    network: NetworkPayload,
) -> tuple[bool, bool, list[str]]:
    names = {pkg.name.lower()} | ({pkg.source_package.lower()} if pkg.source_package else set())
    wildcard_ports: list[str] = []
    loopback_found = False
    for sock in network.listening_sockets:
        if not _socket_matches_names(sock.process, names):
            continue
        if is_wildcard_address(sock.local_addr):
            wildcard_ports.append(f"{sock.local_addr}:{sock.port}")
        elif is_loopback_address(sock.local_addr):
            loopback_found = True
    return bool(wildcard_ports), (loopback_found and not wildcard_ports), wildcard_ports


def _build_cve_finding(
    *,
    advisory: CveAdvisory,
    pkg: PackageItem,
    installed_version: str,
    exposed_wildcard: bool,
    loopback_only: bool,
    exposed_ports: list[str],
) -> NormalizedFinding:
    port_suffix = f" expuesto en {exposed_ports[0]}" if exposed_ports else ""
    fix_msg = (
        f"Actualizar {pkg.name} a >= {advisory.fixed_version} mediante plan de parcheo gobernado."
        if advisory.fixed_version
        else f"No hay parche oficial publicado; aplicar mitigación/aislamiento para {pkg.name}."
    )
    refs = list(dict.fromkeys([advisory.cve_id, *advisory.references_json]))
    return NormalizedFinding(
        fingerprint=compute_fingerprint("cve_engine", "cve", advisory.cve_id, pkg.name),
        rule_id=advisory.cve_id,
        source_tool="cve_engine",
        category="cve",
        base_severity=advisory.base_severity,
        confidence="high",
        title=f"{advisory.cve_id} en {pkg.name}{port_suffix}"[:255],
        description=(
            advisory.summary
            or f"La versión instalada {installed_version} es vulnerable ({advisory.ecosystem})."
        ),
        evidence={
            "package": pkg.name,
            "source_package": pkg.source_package,
            "installed_version": installed_version,
            "fixed_version": advisory.fixed_version,
            "ecosystem": advisory.ecosystem,
            "listening_sockets": exposed_ports,
        },
        remediation=fix_msg,
        reference_ids=refs,
        exposed_wildcard=exposed_wildcard,
        loopback_only=loopback_only,
        exposed_ports=exposed_ports,
        cvss_score=float(advisory.cvss_score) if advisory.cvss_score is not None else None,
    )


def _index_packages(packages: list[PackageItem]) -> dict[str, list[PackageItem]]:
    index: dict[str, list[PackageItem]] = {}
    for pkg in packages:
        index.setdefault(pkg.name.lower(), []).append(pkg)
        if pkg.source_package:
            index.setdefault(pkg.source_package.lower(), []).append(pkg)
    return index


def _evaluate_advisory_pkg(
    *,
    host_id: UUID,
    snapshot_id: UUID,
    adv: CveAdvisory,
    pkg: PackageItem,
    network: NetworkPayload,
    scoring_context: ScoringContext,
) -> tuple[HostCveMatch, NormalizedFinding, str] | None:
    if adv.advisory_status == "fixed" and not adv.fixed_version:
        return None
    installed_ver = _format_installed_version(pkg)
    if not is_version_vulnerable(installed_ver, adv.fixed_version):
        return None
    wildcard, loopback, ports = _package_exposure(pkg, network)
    finding = _build_cve_finding(
        advisory=adv,
        pkg=pkg,
        installed_version=installed_ver,
        exposed_wildcard=wildcard,
        loopback_only=loopback,
        exposed_ports=ports,
    )
    scored = score_finding(finding, scoring_context)
    match_row = HostCveMatch(
        host_id=host_id,
        snapshot_id=snapshot_id,
        cve_id=adv.cve_id,
        package_name=pkg.name,
        installed_version=installed_ver,
        fixed_version=adv.fixed_version,
        effective_severity=scored.severity,
        exposed_network=wildcard,
        exposed_ports_json=ports,
        contextual_score=Decimal(f"{scored.contextual_score:.2f}"),
    )
    return match_row, finding, scored.severity


def _iter_unique_advisory_pkgs(
    advisories: list[CveAdvisory],
    pkg_index: dict[str, list[PackageItem]],
) -> list[tuple[CveAdvisory, PackageItem]]:
    pairs: list[tuple[CveAdvisory, PackageItem]] = []
    seen_keys: set[tuple[str, str]] = set()
    for adv in advisories:
        for pkg in pkg_index.get(adv.package_name.lower(), []):
            key = (adv.cve_id, pkg.name)
            if key not in seen_keys:
                seen_keys.add(key)
                pairs.append((adv, pkg))
    return pairs


def _collect_advisory_matches(
    *,
    host_id: UUID,
    snapshot_id: UUID,
    advisories: list[CveAdvisory],
    pkg_index: dict[str, list[PackageItem]],
    network: NetworkPayload,
    scoring_context: ScoringContext,
) -> CveMatchResult:
    matches: list[HostCveMatch] = []
    findings: list[NormalizedFinding] = []
    severity_counts = {"critical": 0, "high": 0}

    for adv, pkg in _iter_unique_advisory_pkgs(advisories, pkg_index):
        evaluated = _evaluate_advisory_pkg(
            host_id=host_id,
            snapshot_id=snapshot_id,
            adv=adv,
            pkg=pkg,
            network=network,
            scoring_context=scoring_context,
        )
        if evaluated is None:
            continue
        match_row, finding, severity = evaluated
        matches.append(match_row)
        findings.append(finding)
        if severity in severity_counts:
            severity_counts[severity] += 1

    return CveMatchResult(
        matches=matches,
        findings=findings,
        critical_count=severity_counts["critical"],
        high_count=severity_counts["high"],
    )


_IN_CHUNK_SIZE = 400


async def _fetch_matching_advisories(
    session: AsyncSession,
    ecosystem: str,
    pkg_names: list[str],
) -> list[CveAdvisory]:
    advisories: list[CveAdvisory] = []
    for start in range(0, len(pkg_names), _IN_CHUNK_SIZE):
        batch = pkg_names[start : start + _IN_CHUNK_SIZE]
        rows = (
            await session.execute(
                select(CveAdvisory).where(
                    CveAdvisory.ecosystem == ecosystem,
                    CveAdvisory.advisory_status != "not_affected",
                    CveAdvisory.package_name.in_(batch),
                )
            )
        ).scalars().all()
        advisories.extend(rows)
    return advisories


async def match_snapshot_cves(
    session: AsyncSession,
    *,
    host_id: UUID,
    snapshot_id: UUID,
    os_family: str,
    os_version: str,
    packages: list[PackageItem],
    network: NetworkPayload,
    scoring_context: ScoringContext,
) -> CveMatchResult:
    """Match snapshot SBOM against offline distro-aware advisories."""
    if not packages:
        return CveMatchResult(matches=[], findings=[], critical_count=0, high_count=0)

    ecosystem = resolve_ecosystem(os_family, os_version)
    pkg_index = _index_packages(packages)
    adv_rows = await _fetch_matching_advisories(session, ecosystem, list(pkg_index.keys()))
    return _collect_advisory_matches(
        host_id=host_id,
        snapshot_id=snapshot_id,
        advisories=adv_rows,
        pkg_index=pkg_index,
        network=network,
        scoring_context=scoring_context,
    )


def _deduplicate_sync_items(advisories: list[CveAdvisoryIn]) -> list[CveAdvisoryIn]:
    by_key: dict[tuple[str, str, str], CveAdvisoryIn] = {}
    for item in advisories:
        by_key[(item.ecosystem, item.package_name.lower(), item.cve_id)] = item
    return list(by_key.values())


def _apply_advisory_update(
    existing: CveAdvisory,
    item: CveAdvisoryIn,
    cvss: Decimal | None,
) -> None:
    existing.fixed_version = item.fixed_version
    existing.advisory_status = item.advisory_status
    existing.base_severity = item.base_severity
    existing.cvss_score = cvss
    existing.source_feed = item.source_feed
    existing.summary = item.summary
    existing.references_json = item.references


async def sync_cve_advisories(
    session: AsyncSession,
    *,
    actor: ActorContext,
    payload: CveSyncRequest,
) -> CveSyncResponse:
    """Upsert offline CVE advisories (admin only) and record WORM audit event."""
    require_roles(actor, ADMIN_ONLY)
    unique_items = _deduplicate_sync_items(payload.advisories)
    upserted = 0
    for item in unique_items:
        pkg_lower = item.package_name.lower()
        existing = (
            await session.execute(
                select(CveAdvisory).where(
                    CveAdvisory.ecosystem == item.ecosystem,
                    CveAdvisory.package_name == pkg_lower,
                    CveAdvisory.cve_id == item.cve_id,
                )
            )
        ).scalar_one_or_none()
        cvss = Decimal(f"{item.cvss_score:.1f}") if item.cvss_score is not None else None
        if existing is None:
            session.add(
                CveAdvisory(
                    cve_id=item.cve_id,
                    ecosystem=item.ecosystem,
                    package_name=pkg_lower,
                    fixed_version=item.fixed_version,
                    advisory_status=item.advisory_status,
                    base_severity=item.base_severity,
                    cvss_score=cvss,
                    source_feed=item.source_feed,
                    summary=item.summary,
                    references_json=item.references,
                )
            )
        else:
            _apply_advisory_update(existing, item, cvss)
        upserted += 1

    await append_audit_log(
        session,
        actor_id=actor.actor_id,
        actor_username=actor.username,
        action="cve_feed.synced",
        resource_type="cve_advisories",
        resource_id="offline_sync",
        details={"upserted": upserted},
    )
    await session.commit()
    return CveSyncResponse(upserted=upserted)


async def _latest_snapshot_map(session: AsyncSession) -> dict[UUID, tuple[UUID, datetime]]:
    rows = (
        await session.execute(
            select(Snapshot.id, Snapshot.host_id, Snapshot.collected_at).order_by(
                desc(Snapshot.ingested_at), desc(Snapshot.id)
            )
        )
    ).all()
    latest: dict[UUID, tuple[UUID, datetime]] = {}
    for snap_id, host_id, collected_at in rows:
        latest.setdefault(host_id, (snap_id, collected_at))
    return latest


async def _search_installed_packages_fallback(
    session: AsyncSession,
    *,
    latest_snap_ids: list[UUID],
    pattern: str,
    exclude_pairs: set[tuple[UUID, str]],
) -> list[CveSearchItem]:
    pkg_rows = (
        await session.execute(
            select(SnapshotPackage, Snapshot, Host)
            .join(Snapshot, Snapshot.id == SnapshotPackage.snapshot_id)
            .join(Host, Host.id == Snapshot.host_id)
            .where(
                SnapshotPackage.snapshot_id.in_(latest_snap_ids),
                or_(
                    SnapshotPackage.name.ilike(pattern),
                    SnapshotPackage.source_package.ilike(pattern),
                ),
            )
            .limit(100)
        )
    ).all()
    extras: list[CveSearchItem] = []
    for pkg, snap, host in pkg_rows:
        if (host.id, pkg.name) in exclude_pairs:
            continue
        extras.append(
            CveSearchItem(
                host_id=host.id,
                hostname=host.hostname,
                os=f"{host.os_name} {host.os_version}".strip(),
                eol_status=host.eol_status,
                cve_id=None,
                package_name=pkg.name,
                installed_version=pkg.version,
                fixed_version=None,
                effective_severity="info",
                exposed_network=False,
                exposed_ports=[],
                last_snapshot_at=format_rfc3339(snap.collected_at),
            )
        )
    return extras


async def search_cves_across_fleet(
    session: AsyncSession,
    *,
    actor: ActorContext,
    query: str,
) -> CveSearchResponse:
    """Reverse search across latest host snapshots by CVE ID or package name."""
    require_roles(actor, ALL_USER_ROLES)
    clean_q = query.strip()
    latest_by_host = await _latest_snapshot_map(session) if clean_q else {}
    latest_snap_ids = [entry[0] for entry in latest_by_host.values()]
    if not clean_q or not latest_snap_ids:
        return CveSearchResponse(query=clean_q, total=0, items=[])

    pattern = f"%{clean_q}%"
    rows = (
        await session.execute(
            select(HostCveMatch, Host)
            .join(Host, Host.id == HostCveMatch.host_id)
            .where(
                HostCveMatch.snapshot_id.in_(latest_snap_ids),
                or_(
                    HostCveMatch.cve_id.ilike(pattern),
                    HostCveMatch.package_name.ilike(pattern),
                ),
            )
            .order_by(desc(HostCveMatch.contextual_score))
            .limit(200)
        )
    ).all()

    items: list[CveSearchItem] = []
    matched_host_pkg: set[tuple[UUID, str]] = set()
    for match, host in rows:
        snap_meta = latest_by_host.get(host.id)
        matched_host_pkg.add((host.id, match.package_name))
        items.append(
            CveSearchItem(
                host_id=host.id,
                hostname=host.hostname,
                os=f"{host.os_name} {host.os_version}".strip(),
                eol_status=host.eol_status,
                cve_id=match.cve_id,
                package_name=match.package_name,
                installed_version=match.installed_version,
                fixed_version=match.fixed_version,
                effective_severity=match.effective_severity,
                exposed_network=match.exposed_network,
                exposed_ports=match.exposed_ports_json,
                last_snapshot_at=format_rfc3339(snap_meta[1]) if snap_meta else None,
            )
        )

    if not clean_q.upper().startswith("CVE-"):
        extras = await _search_installed_packages_fallback(
            session,
            latest_snap_ids=latest_snap_ids,
            pattern=pattern,
            exclude_pairs=matched_host_pkg,
        )
        items.extend(extras)

    return CveSearchResponse(query=clean_q, total=len(items), items=items)


async def _load_snapshot_packages(
    session: AsyncSession,
    snapshot_id: UUID,
) -> list[PackageItem]:
    rows = (
        await session.execute(
            select(SnapshotPackage).where(SnapshotPackage.snapshot_id == snapshot_id)
        )
    ).scalars().all()
    return [
        PackageItem(
            package_manager=row.package_manager,  # type: ignore[arg-type]
            name=row.name,
            source_package=row.source_package,
            epoch=row.epoch or "",
            version=row.version,
            release=row.release or "",
            arch=row.arch,
        )
        for row in rows
    ]


async def _refresh_snapshot_drift(session: AsyncSession, snapshot: Snapshot) -> None:
    await session.flush()
    curr_rows = (
        await session.execute(select(Finding).where(Finding.snapshot_id == snapshot.id))
    ).scalars().all()
    curr_digests = [
        FindingDigest(
            fingerprint=row.fingerprint,
            severity=row.severity,
            category=row.category,
            title=row.title,
        )
        for row in curr_rows
    ]
    prev_digests = await load_previous_finding_digests(session, snapshot.previous_snapshot_id)
    drift = compute_drift_items(
        snapshot_id=snapshot.id,
        previous_snapshot_id=snapshot.previous_snapshot_id,
        current_findings=curr_digests,
        previous_findings=prev_digests,
    )
    await session.execute(
        delete(SnapshotDriftItem).where(SnapshotDriftItem.snapshot_id == snapshot.id)
    )
    session.add_all(drift.items)


async def _rescan_single_host_snapshot(
    session: AsyncSession,
    host: Host,
    snapshot: Snapshot,
) -> tuple[int, int, int]:
    packages = await _load_snapshot_packages(session, snapshot.id)
    network = NetworkPayload.model_validate(snapshot.raw_network_json or {})
    ctx = ScoringContext(is_eol=(host.eol_status == "eol"), environment=host.environment)
    cve_res = await match_snapshot_cves(
        session,
        host_id=host.id,
        snapshot_id=snapshot.id,
        os_family=host.os_family,
        os_version=host.os_version,
        packages=packages,
        network=network,
        scoring_context=ctx,
    )
    await session.execute(delete(HostCveMatch).where(HostCveMatch.snapshot_id == snapshot.id))
    await session.execute(
        delete(Finding).where(
            Finding.snapshot_id == snapshot.id,
            Finding.source_tool == "cve_engine",
        )
    )
    session.add_all(cve_res.matches)
    scored = deduplicate_and_score(cve_res.findings, ctx)
    session.add_all(
        [
            Finding(
                snapshot_id=snapshot.id,
                host_id=host.id,
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
            for item in scored
        ]
    )
    await _refresh_snapshot_drift(session, snapshot)
    snapshot.critical_cves_count = cve_res.critical_count
    snapshot.high_cves_count = cve_res.high_count
    host.critical_cves_count = cve_res.critical_count
    host.high_cves_count = cve_res.high_count
    return len(cve_res.matches), cve_res.critical_count, cve_res.high_count


async def rescan_fleet_cves(
    session: AsyncSession,
    *,
    actor: ActorContext,
) -> FleetRescanResponse:
    """Re-evaluate latest snapshots across all hosts against the current offline CVE DB."""
    require_roles(actor, ADMIN_ONLY)
    latest_map = await _latest_snapshot_map(session)
    hosts_rescanned = 0
    total_matches = 0
    critical_matches = 0
    high_matches = 0
    for host_id, (snap_id, _) in latest_map.items():
        host = (await session.execute(select(Host).where(Host.id == host_id))).scalar_one_or_none()
        snap = (
            await session.execute(select(Snapshot).where(Snapshot.id == snap_id))
        ).scalar_one_or_none()
        if host is None or snap is None:
            continue
        m_cnt, c_cnt, h_cnt = await _rescan_single_host_snapshot(session, host, snap)
        hosts_rescanned += 1
        total_matches += m_cnt
        critical_matches += c_cnt
        high_matches += h_cnt

    await append_audit_log(
        session,
        actor_id=actor.actor_id,
        actor_username=actor.username,
        action="cve_feed.fleet_rescanned",
        resource_type="cve_advisories",
        resource_id="fleet_rescan",
        details={
            "hosts_rescanned": hosts_rescanned,
            "total_cve_matches": total_matches,
            "critical_matches": critical_matches,
            "high_matches": high_matches,
        },
    )
    await session.commit()
    return FleetRescanResponse(
        hosts_rescanned=hosts_rescanned,
        total_cve_matches=total_matches,
        critical_matches=critical_matches,
        high_matches=high_matches,
    )


async def import_offline_cve_feed(
    session: AsyncSession,
    *,
    actor: ActorContext,
    payload: CveFeedImportRequest,
) -> CveFeedImportResponse:
    """Parse an offline OSV/Trivy/OVAL feed, upsert advisories, and optionally rescan fleet."""
    from app.services.cve.feed_parsers import parse_cve_feed

    require_roles(actor, ADMIN_ONLY)
    advisories = parse_cve_feed(
        feed_format=payload.feed_format,
        raw_text=payload.payload,
        default_ecosystem=payload.ecosystem,
    )
    sync_res = await sync_cve_advisories(
        session,
        actor=actor,
        payload=CveSyncRequest(advisories=advisories[:5000]),
    )
    hosts_rescanned = 0
    total_matches = 0
    if payload.rescan_fleet:
        rescan = await rescan_fleet_cves(session, actor=actor)
        hosts_rescanned = rescan.hosts_rescanned
        total_matches = rescan.total_cve_matches
    return CveFeedImportResponse(
        feed_format=payload.feed_format,
        parsed=len(advisories),
        upserted=sync_res.upserted,
        hosts_rescanned=hosts_rescanned,
        total_cve_matches=total_matches,
    )
