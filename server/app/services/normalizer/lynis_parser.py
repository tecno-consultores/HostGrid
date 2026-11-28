"""Parser for real Lynis `lynis-report.dat` audit output files."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.services.normalizer.scoring import NormalizedFinding, compute_fingerprint

CATEGORY_BY_PREFIX: dict[str, str] = {
    "SSH": "hardening",
    "NETW": "network",
    "FIRE": "network",
    "HTTP": "service_isolation",
    "CONT": "service_isolation",
    "FINT": "integrity",
    "FILE": "integrity",
    "MALW": "integrity",
    "PKGS": "hardening",
    "AUTH": "hardening",
    "KRNL": "hardening",
}

HIGH_PRIORITY_SUGGESTION_PREFIXES: frozenset[str] = frozenset(
    {"SSH", "AUTH", "FIRE", "KRNL", "MALW", "FINT"}
)


@dataclass(frozen=True)
class ParsedLynisReport:
    """Structured metadata and normalized findings parsed from lynis-report.dat."""

    lynis_version: str | None = None
    hardening_index: int | None = None
    tests_executed: int = 0
    tests_skipped: int = 0
    warnings_count: int = 0
    suggestions_count: int = 0
    findings: list[NormalizedFinding] = field(default_factory=list)


def _parse_int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def _split_lynis_item(raw: str) -> tuple[str, str, str, str]:
    parts = [part.strip() for part in raw.split("|")]
    test_id = parts[0] if len(parts) > 0 and parts[0] else "LYNIS-UNKNOWN"
    description = parts[1] if len(parts) > 1 and parts[1] else raw.strip()
    target = parts[2] if len(parts) > 2 and parts[2] not in {"", "-"} else "host"
    solution = parts[3] if len(parts) > 3 and parts[3] not in {"", "-"} else ""
    return test_id, description, target, solution


def _map_category(test_id: str) -> str:
    prefix = test_id.split("-", 1)[0].upper()
    return CATEGORY_BY_PREFIX.get(prefix, "hardening")


def _build_lynis_finding(raw_entry: str, *, is_warning: bool) -> NormalizedFinding:
    test_id, desc, target, solution = _split_lynis_item(raw_entry)
    category = _map_category(test_id)
    prefix = test_id.split("-", 1)[0].upper()
    if is_warning:
        severity = "high"
    elif prefix in HIGH_PRIORITY_SUGGESTION_PREFIXES:
        severity = "medium"
    else:
        severity = "low"
    remediation = (
        solution
        if solution
        else f"Revisar y remediar el control Lynis {test_id} sobre '{target}'."
    )
    return NormalizedFinding(
        fingerprint=compute_fingerprint("lynis", category, test_id, target),
        rule_id=test_id,
        source_tool="lynis",
        category=category,
        base_severity=severity,
        confidence="high",
        title=f"[{test_id}] {desc}"[:255],
        description=desc,
        evidence={
            "lynis_test_id": test_id,
            "target": target,
            "entry_type": "warning" if is_warning else "suggestion",
            "raw_entry": raw_entry,
        },
        remediation=remediation,
        reference_ids=[f"LYNIS:{test_id}"],
    )


def _extract_kv_maps(report_dat: str) -> tuple[dict[str, str], dict[str, list[str]]]:
    scalars: dict[str, str] = {}
    arrays: dict[str, list[str]] = {}
    for line in report_dat.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        clean_key = key.strip()
        clean_val = value.strip()
        if clean_key.endswith("[]"):
            arrays.setdefault(clean_key[:-2], []).append(clean_val)
        else:
            scalars[clean_key] = clean_val
    return scalars, arrays


def parse_lynis_report(report_dat: str) -> ParsedLynisReport:
    """Parse raw `lynis-report.dat` content into metrics and NormalizedFindings."""
    if not report_dat.strip():
        return ParsedLynisReport()

    scalars, arrays = _extract_kv_maps(report_dat)
    warnings = arrays.get("warning", [])
    suggestions = arrays.get("suggestion", [])
    skipped = arrays.get("test_skipped", [])

    findings = [_build_lynis_finding(item, is_warning=True) for item in warnings]
    findings.extend(_build_lynis_finding(item, is_warning=False) for item in suggestions)

    tests_executed = _parse_int_or_none(scalars.get("lynis_tests_done")) or 0
    raw_idx = _parse_int_or_none(scalars.get("hardening_index"))
    hardening_index = raw_idx if raw_idx is not None and 0 <= raw_idx <= 100 else None
    return ParsedLynisReport(
        lynis_version=scalars.get("lynis_version"),
        hardening_index=hardening_index,
        tests_executed=tests_executed,
        tests_skipped=len(skipped),
        warnings_count=len(warnings),
        suggestions_count=len(suggestions),
        findings=findings,
    )
