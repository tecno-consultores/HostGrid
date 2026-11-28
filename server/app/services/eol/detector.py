"""Offline End-of-Life evaluator and finding generator."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import EolCatalog
from app.services.eol.catalog_data import BUILTIN_EOL_CATALOG, BUILTIN_EOL_INDEX
from app.services.normalizer.scoring import NormalizedFinding, compute_fingerprint

APPROACHING_WINDOW_DAYS = 180
_OS_VERSION_NUM_RE = re.compile(r"(\d+)(?:\.(\d+))?")


@dataclass(frozen=True)
class EolEvaluation:
    """Outcome of offline EOL lookup for a host OS."""

    status: str
    eol_date: date | None
    finding: NormalizedFinding | None


def normalize_os_version_key(os_family: str, os_version: str) -> str:
    """Extract canonical numeric release key stripping codenames and LTS suffixes."""
    cleaned = os_version.strip().lower()
    match = _OS_VERSION_NUM_RE.search(cleaned)
    if match is None:
        return cleaned
    major, minor = match.group(1), match.group(2)
    if os_family in {"debian", "centos", "rhel", "suse"} or minor is None:
        return major
    return f"{major}.{minor}"


async def seed_eol_catalog(session: AsyncSession) -> int:
    """Ensure built-in offline EOL rows exist in eol_catalog table."""
    existing_result = await session.execute(select(EolCatalog.os_family, EolCatalog.os_version))
    existing = {(row[0], row[1]) for row in existing_result.all()}
    added = 0
    for item in BUILTIN_EOL_CATALOG:
        if (item.os_family, item.os_version) in existing:
            continue
        session.add(
            EolCatalog(
                os_family=item.os_family,
                os_version=item.os_version,
                codename=item.codename,
                standard_eol_date=item.standard_eol_date,
                extended_eol_date=item.extended_eol_date,
                notes=item.notes,
            )
        )
        added += 1
    if added > 0:
        await session.flush()
    return added


def _build_eol_finding(
    *,
    os_family: str,
    os_version: str,
    eol_date: date,
    status: str,
) -> NormalizedFinding:
    is_eol = status == "eol"
    rule_id = "OS_EOL" if is_eol else "OS_APPROACHING_EOL"
    target = f"{os_family}:{os_version}"
    severity = "critical" if is_eol else "high"
    title = (
        f"Sistema operativo fuera de soporte (EOL): {os_family} {os_version}"
        if is_eol
        else f"Sistema operativo próximo a fin de soporte: {os_family} {os_version}"
    )
    eol_iso = eol_date.isoformat()
    description = (
        f"{os_family} {os_version} alcanzó su fin de vida estándar el {eol_iso}."
        if is_eol
        else f"{os_family} {os_version} alcanza su fin de vida el {eol_iso}."
    )
    return NormalizedFinding(
        fingerprint=compute_fingerprint("eol_engine", "eol", rule_id, target),
        rule_id=rule_id,
        source_tool="eol_engine",
        category="eol",
        base_severity=severity,
        confidence="high",
        title=title,
        description=description,
        evidence={
            "os_family": os_family,
            "os_version": os_version,
            "standard_eol_date": eol_date.isoformat(),
            "eol_status": status,
        },
        remediation=(
            f"Planificar migración de {os_family} {os_version} a una versión con soporte activo "
            "y aplicar controles compensatorios de segmentación de red."
        ),
        reference_ids=[f"EOL:{os_family}:{os_version}"],
    )


def evaluate_eol_offline(
    *,
    os_family: str,
    os_version: str,
    standard_eol_date: date | None,
    reference_date: date | None = None,
) -> EolEvaluation:
    """Classify OS support status using a resolved EOL date."""
    today = reference_date or date.today()
    family = os_family.strip().lower()
    ver_key = normalize_os_version_key(family, os_version)
    resolved_date = standard_eol_date
    if resolved_date is None:
        entry = BUILTIN_EOL_INDEX.get((family, ver_key))
        resolved_date = entry.standard_eol_date if entry is not None else None
    if resolved_date is None:
        return EolEvaluation(status="unknown", eol_date=None, finding=None)

    if today >= resolved_date:
        status = "eol"
    elif today + timedelta(days=APPROACHING_WINDOW_DAYS) >= resolved_date:
        status = "approaching_eol"
    else:
        return EolEvaluation(status="supported", eol_date=resolved_date, finding=None)

    finding = _build_eol_finding(
        os_family=family,
        os_version=ver_key,
        eol_date=resolved_date,
        status=status,
    )
    return EolEvaluation(status=status, eol_date=resolved_date, finding=finding)


async def evaluate_host_eol(
    session: AsyncSession,
    *,
    os_family: str,
    os_version: str,
    reference_date: date | None = None,
) -> EolEvaluation:
    """Look up EOL date in eol_catalog table (with built-in fallback) and evaluate."""
    family = os_family.strip().lower()
    ver_key = normalize_os_version_key(family, os_version)
    row = (
        await session.execute(
            select(EolCatalog).where(
                EolCatalog.os_family == family,
                EolCatalog.os_version == ver_key,
            )
        )
    ).scalar_one_or_none()
    db_date = row.standard_eol_date if row is not None else None
    return evaluate_eol_offline(
        os_family=family,
        os_version=ver_key,
        standard_eol_date=db_date,
        reference_date=reference_date,
    )
