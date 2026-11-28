"""Unified finding model, deterministic fingerprinting, contextual scoring, and SARIF 2.1.0."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.security import sha256_hex

BASE_SEVERITY_SCORES: dict[str, float] = {
    "critical": 85.0,
    "high": 68.0,
    "medium": 45.0,
    "low": 22.0,
    "info": 5.0,
}

SARIF_LEVEL_MAP: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


@dataclass(frozen=True)
class ScoringContext:
    """Host-level environmental risk modifiers."""

    is_eol: bool
    environment: str


@dataclass(frozen=True)
class NormalizedFinding:
    """Pre-scoring normalized finding emitted by any HostGrid analyzer."""

    fingerprint: str
    rule_id: str
    source_tool: str
    category: str
    base_severity: str
    confidence: str
    title: str
    description: str
    evidence: dict[str, Any]
    remediation: str
    reference_ids: list[str] = field(default_factory=list)
    exposed_wildcard: bool = False
    loopback_only: bool = False
    exposed_ports: list[str] = field(default_factory=list)
    cvss_score: float | None = None


@dataclass(frozen=True)
class ScoredFinding:
    """Deduplicated finding with final contextual score and effective severity."""

    finding: NormalizedFinding
    severity: str
    contextual_score: float
    contextual_factors: list[str]


def compute_fingerprint(
    source_tool: str,
    category: str,
    canonical_rule_id: str,
    canonical_target_key: str,
) -> str:
    """Compute deterministic SHA-256 fingerprint matching SPEC.md section 3.2."""
    raw = (
        f"{source_tool.strip().lower()}|{category.strip().lower()}|"
        f"{canonical_rule_id.strip()}|{canonical_target_key.strip()}"
    )
    return sha256_hex(raw)


def _derive_effective_severity(base_severity: str, score: float) -> str:
    if score >= 85.0:
        return "critical"
    if score >= 70.0 and base_severity not in {"critical", "high"}:
        return "high"
    return base_severity


def _network_modifier(finding: NormalizedFinding) -> tuple[float, list[str]]:
    if finding.exposed_wildcard:
        ports = ",".join(finding.exposed_ports[:3]) or "wildcard"
        return 15.0, [f"exposed_wildcard_socket:{ports}(+15)"]
    if finding.loopback_only:
        return -10.0, ["loopback_only_socket(-10)"]
    return 0.0, []


def _collect_modifiers(
    finding: NormalizedFinding,
    context: ScoringContext,
) -> tuple[float, list[str]]:
    delta, net_factors = _network_modifier(finding)
    factors: list[str] = [f"base_severity:{finding.base_severity}"]
    if finding.cvss_score is not None:
        factors.append(f"base_cvss:{finding.cvss_score:.1f}")
    factors.extend(net_factors)
    if context.is_eol:
        delta += 12.0
        factors.append("host_eol(+12)")
    if context.environment in {"prod", "dmz"}:
        delta += 10.0
        factors.append(f"environment:{context.environment}(+10)")
    return delta, factors


def score_finding(finding: NormalizedFinding, context: ScoringContext) -> ScoredFinding:
    """Apply SPEC.md section 3.3 contextual risk modifiers and clamp to [0, 100]."""
    base = BASE_SEVERITY_SCORES.get(finding.base_severity, 22.0)
    delta, factors = _collect_modifiers(finding, context)
    score = round(min(100.0, max(0.0, base + delta)), 2)
    severity = _derive_effective_severity(finding.base_severity, score)
    return ScoredFinding(
        finding=finding,
        severity=severity,
        contextual_score=score,
        contextual_factors=factors,
    )


def deduplicate_and_score(
    findings: list[NormalizedFinding],
    context: ScoringContext,
) -> list[ScoredFinding]:
    """Deduplicate findings by deterministic fingerprint keeping highest contextual score."""
    by_fp: dict[str, ScoredFinding] = {}
    for item in findings:
        scored = score_finding(item, context)
        existing = by_fp.get(item.fingerprint)
        if existing is None or scored.contextual_score > existing.contextual_score:
            by_fp[item.fingerprint] = scored
    return sorted(
        by_fp.values(),
        key=lambda s: (-s.contextual_score, s.finding.fingerprint),
    )


def build_sarif_report(
    *,
    host_name: str,
    snapshot_id: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Serialize host findings into a SARIF 2.1.0 compliant document (SPEC.md 3.4)."""
    rules_map: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for item in findings:
        full_rule_id = f"{item['source_tool']}:{item['rule_id']}"
        rules_map.setdefault(
            full_rule_id,
            {
                "id": full_rule_id,
                "shortDescription": {"text": item["title"]},
                "help": {"text": item["remediation"]},
            },
        )
        results.append(
            {
                "ruleId": full_rule_id,
                "level": SARIF_LEVEL_MAP.get(item["severity"], "note"),
                "message": {"text": f"{item['title']} — {item['description']}"},
                "partialFingerprints": {"primaryLocationLineHash": item["fingerprint"]},
                "properties": {
                    "category": item["category"],
                    "severity": item["severity"],
                    "contextual_score": item["contextual_score"],
                    "contextual_factors": item["contextual_factors"],
                    "reference_ids": item["reference_ids"],
                    "evidence": item["evidence"],
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "HostGrid",
                        "version": "0.1.0",
                        "rules": list(rules_map.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {"hostname": host_name, "snapshot_id": snapshot_id},
                    }
                ],
                "results": results,
            }
        ],
    }
