"""Offline distro-aware CVE feed parsers for OSV JSON, Trivy JSON, and OVAL XML (Phase 2)."""

from __future__ import annotations

import json
import math
import re
import xml.etree.ElementTree as ET  # noqa: S405
from dataclasses import dataclass
from typing import Any, Literal

from app.core.errors import DomainError
from app.schemas.host import CveAdvisoryIn
from app.services.cve.matcher import resolve_ecosystem

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_DTD_GUARD_RE = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)
_CTRL_WS_RE = re.compile(r"[\x00-\x1f\x7f]+")
_OVAL_COMMENT_RE = re.compile(
    r"([a-zA-Z0-9.+_-]+)\s+(?:is earlier than|package is earlier than)\s+([^\s,]+)"
)
_SEVERITY_ALIASES: dict[str, Literal["critical", "high", "medium", "low"]] = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "negligible": "low",
    "unknown": "medium",
}

_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
_CVSS3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_CVSS3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_OVAL_PKG_TESTS = frozenset({"rpminfo_test", "dpkginfo_test", "apkinfo_test"})
_OVAL_PKG_OBJECTS = frozenset({"rpminfo_object", "dpkginfo_object", "apkinfo_object"})
_OVAL_PKG_STATES = frozenset({"rpminfo_state", "dpkginfo_state", "apkinfo_state"})
_LESS_THAN_OPS = frozenset({"less than", "less than or equal"})


@dataclass(frozen=True)
class _OvalIndex:
    """Indexed OVAL test -> object/state maps for RPM/DPKG/APK package checks."""

    tests: dict[str, tuple[str, tuple[str, ...]]]
    objects: dict[str, str]
    states: dict[str, str | None]


def _clean_feed_text(raw: object, max_len: int) -> str:
    text = _CTRL_WS_RE.sub(" ", str(raw))
    return " ".join(text.split())[:max_len]


def _normalize_severity(raw: str | None) -> Literal["critical", "high", "medium", "low"]:
    if not raw:
        return "medium"
    return _SEVERITY_ALIASES.get(raw.strip().lower(), "medium")


def _severity_from_cvss(score: float) -> Literal["critical", "high", "medium", "low"]:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _parse_cvss3_metrics(vector: str) -> dict[str, str] | None:
    if not (vector.startswith("CVSS:3.0/") or vector.startswith("CVSS:3.1/")):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if ":" not in part:
            return None
        key, val = part.split(":", 1)
        metrics[key] = val
    return metrics


def _compute_cvss3_base_score(vector: str) -> float | None:
    metrics = _parse_cvss3_metrics(vector.strip())
    if metrics is None:
        return None
    try:
        scope = metrics["S"]
        pr_map = _CVSS3_PR_C if scope == "C" else _CVSS3_PR_U
        av = _CVSS3_AV[metrics["AV"]]
        ac = _CVSS3_AC[metrics["AC"]]
        pr = pr_map[metrics["PR"]]
        ui = _CVSS3_UI[metrics["UI"]]
        c_val = _CVSS3_CIA[metrics["C"]]
        i_val = _CVSS3_CIA[metrics["I"]]
        a_val = _CVSS3_CIA[metrics["A"]]
    except KeyError:
        return None
    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))
    impact = (
        7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15) if scope == "C" else 6.42 * iss
    )
    if impact <= 0.0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = min(1.08 * (impact + exploitability) if scope == "C" else impact + exploitability, 10.0)
    return math.ceil(round(raw * 100000) / 10000) / 10.0


def _parse_numeric_cvss(raw: str) -> float | None:
    try:
        val = float(raw)
    except ValueError:
        return None
    return val if 0.0 <= val <= 10.0 else None


def _extract_cve_id(primary_id: str, aliases: list[Any]) -> str | None:
    if _CVE_RE.match(primary_id):
        return primary_id
    for alias in aliases:
        alias_str = str(alias).strip()
        if _CVE_RE.match(alias_str):
            return alias_str
    return None


def _parse_json_payload(raw_text: str) -> Any:
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise DomainError(
            status_code=422,
            title="Invalid Feed JSON",
            detail="Offline CVE feed payload is not valid JSON.",
            error_type="urn:hostgrid:error:invalid_cve_feed",
        ) from exc


def _fixed_from_range(rng: Any) -> str | None:
    if not isinstance(rng, dict):
        return None
    for event in rng.get("events", []):
        if isinstance(event, dict) and event.get("fixed"):
            cleaned = _clean_feed_text(event["fixed"], 128)
            if cleaned:
                return cleaned
    return None


def _extract_osv_fixed_version(affected: dict[str, Any]) -> str | None:
    for rng in affected.get("ranges", []):
        fixed = _fixed_from_range(rng)
        if fixed is not None:
            return fixed
    return None


def _extract_osv_score_entry(
    raw_score: str,
) -> tuple[Literal["critical", "high", "medium", "low"], float | None] | None:
    cvss = _compute_cvss3_base_score(raw_score)
    if cvss is None:
        cvss = _parse_numeric_cvss(raw_score)
    if cvss is not None:
        return _severity_from_cvss(cvss), round(cvss, 1)
    key = raw_score.strip().lower()
    if key in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[key], None
    return None


def _extract_osv_severity_and_cvss(
    vuln: dict[str, Any],
) -> tuple[Literal["critical", "high", "medium", "low"], float | None]:
    db_spec = vuln.get("database_specific")
    db_sev = (
        _normalize_severity(str(db_spec["severity"]))
        if isinstance(db_spec, dict) and db_spec.get("severity")
        else None
    )
    for entry in vuln.get("severity", []):
        if not isinstance(entry, dict) or not entry.get("score"):
            continue
        parsed = _extract_osv_score_entry(str(entry["score"]))
        if parsed is not None:
            sev, cvss = parsed
            return (db_sev or sev), cvss
    return (db_sev or "high"), None


def _extract_osv_refs(vuln: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for ref in vuln.get("references", []):
        if isinstance(ref, dict) and ref.get("url"):
            cleaned = _clean_feed_text(ref["url"], 255)
            if cleaned:
                refs.append(cleaned)
    return refs[:10]


def _normalize_osv_ecosystem(raw: str) -> str:
    cleaned = _clean_feed_text(raw, 64)
    if ":" not in cleaned:
        return cleaned
    fam, ver = cleaned.split(":", 1)
    return resolve_ecosystem(fam, ver)[:64]


def _osv_advisory_for_affected(
    *,
    aff: Any,
    cve_id: str,
    severity: Literal["critical", "high", "medium", "low"],
    cvss_score: float | None,
    summary: str,
    refs: list[str],
    default_ecosystem: str | None,
) -> CveAdvisoryIn | None:
    if not isinstance(aff, dict) or not isinstance(aff.get("package"), dict):
        return None
    pkg = aff["package"]
    pkg_name = _clean_feed_text(pkg.get("name", ""), 255).lower()
    eco_raw = _clean_feed_text(pkg.get("ecosystem") or default_ecosystem or "", 64)
    if not pkg_name or len(eco_raw) < 2:
        return None
    return CveAdvisoryIn(
        cve_id=cve_id,
        ecosystem=_normalize_osv_ecosystem(eco_raw),
        package_name=pkg_name,
        fixed_version=_extract_osv_fixed_version(aff),
        advisory_status="affected",
        base_severity=severity,
        cvss_score=cvss_score,
        source_feed="osv",
        summary=summary,
        references=refs,
    )


def _advisories_from_osv_vuln(
    vuln: dict[str, Any],
    default_ecosystem: str | None,
) -> list[CveAdvisoryIn]:
    cve_id = _extract_cve_id(str(vuln.get("id", "")).strip(), list(vuln.get("aliases", [])))
    if cve_id is None:
        return []
    severity, cvss_score = _extract_osv_severity_and_cvss(vuln)
    summary = _clean_feed_text(vuln.get("summary") or vuln.get("details") or "", 2000)
    refs = _extract_osv_refs(vuln)
    items: list[CveAdvisoryIn] = []
    for aff in vuln.get("affected", []):
        adv = _osv_advisory_for_affected(
            aff=aff,
            cve_id=cve_id,
            severity=severity,
            cvss_score=cvss_score,
            summary=summary,
            refs=refs,
            default_ecosystem=default_ecosystem,
        )
        if adv is not None:
            items.append(adv)
    return items


def _extract_osv_vulns_list(data: Any) -> list[Any]:
    if isinstance(data, dict) and isinstance(data.get("vulns"), list):
        return list(data["vulns"])
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    raise DomainError(
        status_code=422,
        title="Invalid OSV Feed",
        detail="OSV payload must be a JSON object or array of vulnerabilities.",
        error_type="urn:hostgrid:error:invalid_cve_feed",
    )


def parse_osv_feed(raw_text: str, default_ecosystem: str | None = None) -> list[CveAdvisoryIn]:
    """Parse an offline OSV JSON bundle (list, single record, or {'vulns': [...]}) into DTOs."""
    vulns = _extract_osv_vulns_list(_parse_json_payload(raw_text))
    advisories: list[CveAdvisoryIn] = []
    for entry in vulns:
        if isinstance(entry, dict):
            advisories.extend(_advisories_from_osv_vuln(entry, default_ecosystem))
    return advisories


def _extract_trivy_ecosystem(data: dict[str, Any], default_ecosystem: str | None) -> str:
    if default_ecosystem and default_ecosystem.strip():
        return _normalize_osv_ecosystem(default_ecosystem)
    meta = data.get("Metadata")
    os_info = meta.get("OS") if isinstance(meta, dict) else None
    if isinstance(os_info, dict) and os_info.get("Family") and os_info.get("Name"):
        return resolve_ecosystem(str(os_info["Family"]), str(os_info["Name"]))
    return ""


def _extract_trivy_cvss(vuln: dict[str, Any]) -> float | None:
    cvss = vuln.get("CVSS")
    if not isinstance(cvss, dict):
        return None
    for source_data in cvss.values():
        if isinstance(source_data, dict):
            score = source_data.get("V3Score") or source_data.get("V2Score")
            if isinstance(score, (int, float)) and 0.0 <= float(score) <= 10.0:
                return float(score)
    return None


def _advisory_from_trivy_vuln(vuln: dict[str, Any], ecosystem: str) -> CveAdvisoryIn | None:
    cve_id = _clean_feed_text(vuln.get("VulnerabilityID", ""), 32)
    pkg_name = _clean_feed_text(vuln.get("PkgName", ""), 255).lower()
    if not _CVE_RE.match(cve_id) or not pkg_name:
        return None
    fixed_raw = _clean_feed_text(vuln.get("FixedVersion") or "", 255)
    fixed_ver = fixed_raw.split(",")[0].strip()[:128] if fixed_raw else None
    refs = [
        _clean_feed_text(r, 255)
        for r in vuln.get("References", [])
        if isinstance(r, str) and _clean_feed_text(r, 255)
    ][:10]
    summary = _clean_feed_text(vuln.get("Title") or vuln.get("Description") or "", 2000)
    return CveAdvisoryIn(
        cve_id=cve_id,
        ecosystem=ecosystem,
        package_name=pkg_name,
        fixed_version=fixed_ver or None,
        advisory_status="affected",
        base_severity=_normalize_severity(str(vuln.get("Severity", "high"))),
        cvss_score=_extract_trivy_cvss(vuln),
        source_feed="trivy",
        summary=summary,
        references=refs,
    )


def _advisories_from_trivy_result(result: Any, ecosystem: str) -> list[CveAdvisoryIn]:
    vulns = result.get("Vulnerabilities") if isinstance(result, dict) else None
    if not isinstance(vulns, list):
        return []
    out: list[CveAdvisoryIn] = []
    for vuln in vulns:
        adv = _advisory_from_trivy_vuln(vuln, ecosystem) if isinstance(vuln, dict) else None
        if adv is not None:
            out.append(adv)
    return out


def parse_trivy_feed(raw_text: str, default_ecosystem: str | None = None) -> list[CveAdvisoryIn]:
    """Parse an offline Trivy JSON vulnerability report into HostGrid advisories."""
    data = _parse_json_payload(raw_text)
    if not isinstance(data, dict) or not isinstance(data.get("Results"), list):
        raise DomainError(
            status_code=422,
            title="Invalid Trivy Feed",
            detail="Trivy payload must be a JSON object containing a 'Results' array.",
            error_type="urn:hostgrid:error:invalid_cve_feed",
        )
    ecosystem = _extract_trivy_ecosystem(data, default_ecosystem)
    if len(ecosystem) < 2:
        raise DomainError(
            status_code=422,
            title="Missing Ecosystem",
            detail="Trivy feed requires Metadata.OS or an explicit ecosystem parameter.",
            error_type="urn:hostgrid:error:missing_ecosystem",
        )
    advisories: list[CveAdvisoryIn] = []
    for result in data["Results"]:
        advisories.extend(_advisories_from_trivy_result(result, ecosystem))
    return advisories


def _local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _find_child_text(elem: ET.Element, target: str) -> str:
    for node in elem.iter():
        if _local_tag(node.tag) == target and node.text:
            return _clean_feed_text(node.text, 2000)
    return ""


def _index_oval_test(node: ET.Element) -> tuple[str, tuple[str, ...]] | None:
    obj_ref = ""
    state_refs: list[str] = []
    for child in node:
        tag = _local_tag(child.tag)
        if tag == "object" and child.attrib.get("object_ref"):
            obj_ref = child.attrib["object_ref"].strip()
        elif tag == "state" and child.attrib.get("state_ref"):
            state_refs.append(child.attrib["state_ref"].strip())
    return (obj_ref, tuple(state_refs)) if obj_ref else None


def _extract_oval_state_evr(node: ET.Element) -> str | None:
    for child in node:
        if _local_tag(child.tag) not in {"evr", "version"}:
            continue
        op = child.attrib.get("operation", "less than").strip().lower()
        if op in _LESS_THAN_OPS and child.text:
            cleaned = _clean_feed_text(child.text, 128)
            return cleaned or None
    return None


def _index_oval_node(node: ET.Element, idx: _OvalIndex) -> None:
    node_id = node.attrib.get("id", "").strip()
    tag = _local_tag(node.tag)
    if not node_id:
        return
    if tag in _OVAL_PKG_TESTS and (indexed := _index_oval_test(node)):
        idx.tests[node_id] = indexed
    elif tag in _OVAL_PKG_OBJECTS and (pkg_name := _find_child_text(node, "name").lower()[:255]):
        idx.objects[node_id] = pkg_name
    elif tag in _OVAL_PKG_STATES:
        idx.states[node_id] = _extract_oval_state_evr(node)


def _build_oval_index(root: ET.Element) -> _OvalIndex:
    idx = _OvalIndex(tests={}, objects={}, states={})
    for node in root.iter():
        _index_oval_node(node, idx)
    return idx


def _extract_oval_cves(defn: ET.Element) -> list[str]:
    found: list[str] = []
    for node in defn.iter():
        tag = _local_tag(node.tag)
        cand = node.attrib.get("ref_id", "") if tag == "reference" else (node.text or "")
        cand = cand.strip()
        if _CVE_RE.match(cand) and cand not in found:
            found.append(cand)
    return found


def _resolve_oval_test_ref(test_ref: str, oval_index: _OvalIndex) -> tuple[str, str] | None:
    test_entry = oval_index.tests.get(test_ref)
    if test_entry is None:
        return None
    obj_ref, state_refs = test_entry
    pkg_name = oval_index.objects.get(obj_ref)
    fixed_ver = next((oval_index.states.get(sr) for sr in state_refs if sr), None)
    if pkg_name and fixed_ver is not None:
        return (pkg_name, fixed_ver)
    return None


def _resolve_oval_criterion(
    node: ET.Element,
    oval_index: _OvalIndex,
) -> tuple[str, str | None] | None:
    if node.attrib.get("negate", "").strip().lower() == "true":
        return None
    test_ref = node.attrib.get("test_ref", "").strip()
    if test_ref and (structured := _resolve_oval_test_ref(test_ref, oval_index)) is not None:
        return structured
    comment = _clean_feed_text(node.attrib.get("comment", ""), 500)
    match = _OVAL_COMMENT_RE.search(comment)
    return (match.group(1).lower()[:255], match.group(2).strip()[:128]) if match else None


def _extract_oval_packages(
    defn: ET.Element,
    oval_index: _OvalIndex,
) -> list[tuple[str, str | None]]:
    pairs: list[tuple[str, str | None]] = []
    for node in defn.iter():
        if _local_tag(node.tag) != "criterion":
            continue
        pair = _resolve_oval_criterion(node, oval_index)
        if pair is not None and pair not in pairs:
            pairs.append(pair)
    return pairs


def _parse_oval_xml_root(raw_text: str) -> ET.Element:
    if _DTD_GUARD_RE.search(raw_text):
        raise DomainError(
            status_code=422,
            title="Unsafe XML Payload",
            detail="XML DOCTYPE and ENTITY declarations are forbidden for XXE safety.",
            error_type="urn:hostgrid:error:unsafe_xml",
        )
    try:
        return ET.fromstring(raw_text)  # noqa: S314
    except ET.ParseError as exc:
        raise DomainError(
            status_code=422,
            title="Invalid OVAL XML",
            detail="Offline OVAL feed payload is not well-formed XML.",
            error_type="urn:hostgrid:error:invalid_cve_feed",
        ) from exc


def _advisories_from_oval_definition(
    defn: ET.Element,
    ecosystem: str,
    oval_index: _OvalIndex,
) -> list[CveAdvisoryIn]:
    cves = _extract_oval_cves(defn)
    pkgs = _extract_oval_packages(defn, oval_index)
    if not cves or not pkgs:
        return []
    severity = _normalize_severity(_find_child_text(defn, "severity"))
    summary = (_find_child_text(defn, "title") or _find_child_text(defn, "description"))[:2000]
    items: list[CveAdvisoryIn] = []
    for cve_id in cves:
        for pkg_name, fixed_ver in pkgs:
            items.append(
                CveAdvisoryIn(
                    cve_id=cve_id,
                    ecosystem=ecosystem,
                    package_name=pkg_name,
                    fixed_version=fixed_ver,
                    advisory_status="affected",
                    base_severity=severity,
                    source_feed="oval",
                    summary=summary,
                    references=[],
                )
            )
    return items


def parse_oval_feed(raw_text: str, default_ecosystem: str | None = None) -> list[CveAdvisoryIn]:
    """Parse an offline Linux OVAL XML definition bundle safely (anti-XXE)."""
    if not default_ecosystem or len(default_ecosystem.strip()) < 2:
        raise DomainError(
            status_code=422,
            title="Missing Ecosystem",
            detail=(
                "OVAL XML import requires an explicit ecosystem (e.g. Debian:12 or RedHat:9)."
            ),
            error_type="urn:hostgrid:error:missing_ecosystem",
        )
    root = _parse_oval_xml_root(raw_text)
    ecosystem = _normalize_osv_ecosystem(default_ecosystem)
    oval_index = _build_oval_index(root)
    advisories: list[CveAdvisoryIn] = []
    for node in root.iter():
        if _local_tag(node.tag) == "definition":
            advisories.extend(_advisories_from_oval_definition(node, ecosystem, oval_index))
    return advisories


def deduplicate_advisories(advisories: list[CveAdvisoryIn]) -> list[CveAdvisoryIn]:
    """Deduplicate parsed advisories by (ecosystem, package_name, cve_id) preserving latest."""
    by_key: dict[tuple[str, str, str], CveAdvisoryIn] = {}
    for adv in advisories:
        by_key[(adv.ecosystem, adv.package_name.lower(), adv.cve_id)] = adv
    return list(by_key.values())


def parse_cve_feed(
    *,
    feed_format: Literal["osv", "trivy", "oval"],
    raw_text: str,
    default_ecosystem: str | None = None,
) -> list[CveAdvisoryIn]:
    """Dispatch offline CVE feed parsing to OSV, Trivy, or OVAL parsers."""
    parsers = {
        "osv": parse_osv_feed,
        "trivy": parse_trivy_feed,
        "oval": parse_oval_feed,
    }
    advisories = deduplicate_advisories(parsers[feed_format](raw_text, default_ecosystem))
    if not advisories:
        raise DomainError(
            status_code=422,
            title="Empty CVE Feed",
            detail=f"No valid CVE advisories could be extracted from {feed_format} feed.",
            error_type="urn:hostgrid:error:empty_cve_feed",
        )
    return advisories
