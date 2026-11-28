"""Executive Markdown and print-ready HTML report renderers (Phase 2)."""

from __future__ import annotations

from collections import Counter
from html import escape
from typing import Any

from app.schemas.host import DriftResponse, HostDetailResponse

_SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
_SEVERITY_COLORS: dict[str, tuple[str, str]] = {
    "critical": ("#7f1d1d", "#fecaca"),
    "high": ("#7c2d12", "#fed7aa"),
    "medium": ("#78350f", "#fde68a"),
    "low": ("#1e3a8a", "#bfdbfe"),
    "info": ("#334155", "#e2e8f0"),
}


def _md_cell(value: object) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|").strip()
    return text or "—"


def _count_severities(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item.get("severity", "info")).lower() for item in findings)
    return {sev: counts.get(sev, 0) for sev in _SEVERITY_ORDER}


def _format_delta(delta: int | None) -> str:
    if delta is None:
        return "N/D"
    return f"+{delta}" if delta > 0 else str(delta)


def _md_capabilities_section(detail: HostDetailResponse) -> list[str]:
    lines = ["## Capability Probe", ""]
    if not detail.capabilities:
        lines.append("Sin metadatos de capacidades registrados.")
        lines.append("")
        return lines
    lines.append("| Módulo | Estado | Binario / Motivo | Fallback |")
    lines.append("| :--- | :--- | :--- | :---: |")
    for name, cap in sorted(detail.capabilities.items()):
        cap_dict = cap if isinstance(cap, dict) else {}
        status = _md_cell(cap_dict.get("status", "unknown"))
        info = _md_cell(cap_dict.get("binary") or cap_dict.get("reason") or "—")
        fallback = "Sí" if cap_dict.get("fallback_used") else "No"
        lines.append(f"| `{_md_cell(name)}` | {status} | {info} | {fallback} |")
    lines.append("")
    return lines


def _md_drift_section(drift: DriftResponse | None) -> list[str]:
    if drift is None:
        return []
    return [
        "## Drift respecto al Snapshot Anterior",
        "",
        f"- **Nuevos hallazgos**: {drift.summary.get('new', 0)}",
        f"- **Hallazgos resueltos**: {drift.summary.get('resolved', 0)}",
        f"- **Hallazgos persistentes**: {drift.summary.get('persisted', 0)}",
        f"- **Delta índice Lynis**: {_format_delta(drift.hardening_index_delta)}",
        "",
    ]


def _md_findings_section(findings: list[dict[str, Any]]) -> list[str]:
    lines = ["## Hallazgos Priorizados", ""]
    if not findings:
        lines.append("No se registraron hallazgos en el último snapshot.")
        lines.append("")
        return lines
    lines.append("| Severidad | Puntaje | Fuente | Título | Remediación |")
    lines.append("| :--- | ---: | :--- | :--- | :--- |")
    for item in findings:
        sev = _md_cell(str(item.get("severity", "info")).upper())
        score = f"{float(item.get('contextual_score', 0.0)):.1f}"
        src = _md_cell(item.get("source_tool", ""))
        title = _md_cell(item.get("title", ""))
        remediation = _md_cell(item.get("remediation", ""))
        lines.append(f"| {sev} | {score} | `{src}` | {title} | {remediation} |")
    lines.append("")
    return lines


def render_markdown_report(
    *,
    detail: HostDetailResponse,
    snapshot_id: str,
    findings: list[dict[str, Any]],
    drift: DriftResponse | None = None,
) -> str:
    """Render an executive posture report in sanitized Markdown format."""
    counts = _count_severities(findings)
    repo_label = (
        "OK"
        if detail.repo_access_ok is True
        else ("Sin acceso" if detail.repo_access_ok is False else "Desconocido")
    )
    score_label = (
        f"{detail.last_hardening_index}/100" if detail.last_hardening_index is not None else "N/D"
    )
    os_line = f"{_md_cell(detail.os_name)} {_md_cell(detail.os_version)}"
    kernel_line = (
        f"`{_md_cell(detail.kernel_version)}` / `{_md_cell(detail.arch)}` / "
        f"`{_md_cell(detail.init_system)}`"
    )
    conn_line = f"`{_md_cell(detail.connectivity_mode)}` / `{_md_cell(detail.environment)}`"
    delta_label = _format_delta(detail.last_hardening_delta)
    cves_line = f"{detail.critical_cves_count} / {detail.high_cves_count}"
    lines = [
        f"# Reporte Ejecutivo de Postura — {_md_cell(detail.hostname)}",
        "",
        "## Resumen del Servidor",
        "",
        f"- **Host ID**: `{detail.id}`",
        f"- **Snapshot ID**: `{snapshot_id}`",
        f"- **Fecha de recolección**: {detail.latest_snapshot_at or 'N/D'}",
        f"- **Sistema Operativo**: {os_line} ({_md_cell(detail.eol_status)})",
        f"- **Kernel / Arch / Init**: {kernel_line}",
        f"- **Conectividad / Entorno**: {conn_line}",
        f"- **Acceso a Repositorios**: {repo_label}",
        f"- **Índice de Endurecimiento Lynis**: {score_label} (delta: {delta_label})",
        f"- **CVEs Activos (Críticos / Altos)**: {cves_line}",
        "",
        "## Distribución de Hallazgos",
        "",
        "| Crítico | Alto | Medio | Bajo | Info | Total |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {counts['critical']} | {counts['high']} | {counts['medium']} | "
            f"{counts['low']} | {counts['info']} | {len(findings)} |"
        ),
        "",
    ]
    lines.extend(_md_drift_section(drift))
    lines.extend(_md_capabilities_section(detail))
    lines.extend(_md_findings_section(findings))
    return "\n".join(lines)


def _html_badge(label: str, bg: str, fg: str) -> str:
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:4px;'
        f'font-size:11px;font-weight:700;background:{bg};color:{fg};">'
        f"{escape(label, quote=True)}</span>"
    )


def _html_finding_row(item: dict[str, Any]) -> str:
    sev = str(item.get("severity", "info")).lower()
    bg, fg = _SEVERITY_COLORS.get(sev, ("#334155", "#e2e8f0"))
    score = f"{float(item.get('contextual_score', 0.0)):.1f}"
    factors = ", ".join(str(f) for f in item.get("contextual_factors", []))
    return (
        "<tr>"
        f"<td>{_html_badge(sev.upper(), bg, fg)}</td>"
        f'<td class="num">{escape(score, quote=True)}</td>'
        f"<td><code>{escape(str(item.get('source_tool', '')), quote=True)}</code></td>"
        f"<td><strong>{escape(str(item.get('title', '')), quote=True)}</strong>"
        f'<div class="muted">{escape(str(item.get("description", "")), quote=True)}</div>'
        f'<div class="meta">{escape(factors, quote=True)}</div></td>'
        f"<td>{escape(str(item.get('remediation', '')), quote=True)}</td>"
        "</tr>"
    )


def _html_capabilities_rows(detail: HostDetailResponse) -> str:
    if not detail.capabilities:
        return '<tr><td colspan="4" class="muted">Sin metadatos de capacidades.</td></tr>'
    rows: list[str] = []
    for name, cap in sorted(detail.capabilities.items()):
        cap_dict = cap if isinstance(cap, dict) else {}
        info = str(cap_dict.get("binary") or cap_dict.get("reason") or "—")
        fallback = "Sí" if cap_dict.get("fallback_used") else "No"
        rows.append(
            "<tr>"
            f"<td><code>{escape(name, quote=True)}</code></td>"
            f"<td>{escape(str(cap_dict.get('status', 'unknown')), quote=True)}</td>"
            f"<td>{escape(info, quote=True)}</td>"
            f"<td>{fallback}</td>"
            "</tr>"
        )
    return "".join(rows)


def _html_drift_block(drift: DriftResponse | None) -> str:
    if drift is None:
        return ""
    return (
        "<section><h2>Drift respecto al Snapshot Anterior</h2>"
        '<div class="kpis">'
        f'<div class="kpi"><span class="label">Nuevos</span>'
        f'<strong class="num">+{drift.summary.get("new", 0)}</strong></div>'
        f'<div class="kpi"><span class="label">Resueltos</span>'
        f'<strong class="num">-{drift.summary.get("resolved", 0)}</strong></div>'
        f'<div class="kpi"><span class="label">Persistentes</span>'
        f'<strong class="num">{drift.summary.get("persisted", 0)}</strong></div>'
        f'<div class="kpi"><span class="label">Delta Lynis</span>'
        f'<strong class="num">{escape(_format_delta(drift.hardening_index_delta), quote=True)}'
        "</strong></div></div></section>"
    )


def render_html_report(
    *,
    detail: HostDetailResponse,
    snapshot_id: str,
    findings: list[dict[str, Any]],
    drift: DriftResponse | None = None,
) -> str:
    """Render a self-contained print/PDF-ready HTML executive report with strict HTML escaping."""
    counts = _count_severities(findings)
    finding_rows = (
        "".join(_html_finding_row(item) for item in findings)
        if findings
        else '<tr><td colspan="5" class="muted">Sin hallazgos registrados.</td></tr>'
    )
    score_val = (
        f"{detail.last_hardening_index}/100" if detail.last_hardening_index is not None else "N/D"
    )
    hostname_safe = escape(detail.hostname, quote=True)
    os_safe = escape(f"{detail.os_name} {detail.os_version}", quote=True)
    meta_safe = escape(
        f"Kernel {detail.kernel_version} · {detail.arch} · Init: {detail.init_system} · "
        f"Modo: {detail.connectivity_mode} · Entorno: {detail.environment}",
        quote=True,
    )
    return (
        "<!DOCTYPE html><html lang=\"es\"><head><meta charset=\"utf-8\">"
        f"<title>HostGrid — Reporte Ejecutivo {hostname_safe}</title>"
        "<style>"
        "body{font-family:system-ui,-apple-system,sans-serif;margin:0;padding:24px;"
        "background:#090e1a;color:#e2e8f0;line-height:1.45;font-size:13px;}"
        "h1{margin:0 0 4px;font-size:22px;color:#f8fafc;}"
        "h2{margin:24px 0 10px;font-size:15px;color:#38bdf8;border-bottom:1px solid #1e293b;"
        "padding-bottom:4px;}"
        ".meta{color:#94a3b8;font-size:11px;margin-top:4px;}"
        ".muted{color:#cbd5e1;font-size:12px;margin-top:4px;}"
        ".kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:14px 0;}"
        ".kpi{background:#0f172a;border:1px solid #1e293b;border-radius:6px;padding:10px;}"
        ".label{display:block;font-size:11px;color:#94a3b8;}"
        ".num{font-variant-numeric:tabular-nums;font-family:ui-monospace,monospace;}"
        ".kpi strong{font-size:18px;color:#f8fafc;}"
        "table{width:100%;border-collapse:collapse;margin-top:8px;background:#0f172a;}"
        "th,td{border:1px solid #1e293b;padding:8px;text-align:left;vertical-align:top;}"
        "th{background:#111c33;color:#cbd5e1;font-size:11px;text-transform:uppercase;}"
        "code{font-family:ui-monospace,monospace;font-size:11px;color:#7dd3fc;}"
        "@media print{body{background:#fff;color:#0f172a;padding:12px;}"
        "h1,strong{color:#0f172a;}h2{color:#0369a1;border-color:#cbd5e1;}"
        ".kpi,table{background:#fff;border-color:#cbd5e1;}th{background:#f1f5f9;color:#0f172a;}"
        ".muted,.meta,.label{color:#334155;}code{color:#0369a1;}}"
        "</style></head><body>"
        f"<header><h1>HostGrid — Reporte Ejecutivo: {hostname_safe}</h1>"
        f"<div class=\"meta\">{os_safe} · EOL: {escape(detail.eol_status, quote=True)} · "
        f"Snapshot: <code>{escape(snapshot_id, quote=True)}</code> · "
        f"Fecha: {escape(detail.latest_snapshot_at or 'N/D', quote=True)}</div>"
        f"<div class=\"meta\">{meta_safe}</div></header>"
        "<section><h2>Indicadores Clave</h2><div class=\"kpis\">"
        f"<div class=\"kpi\"><span class=\"label\">Índice Lynis</span>"
        f"<strong class=\"num\">{escape(score_val, quote=True)}</strong></div>"
        f"<div class=\"kpi\"><span class=\"label\">CVEs Críticos / Altos</span>"
        f"<strong class=\"num\">{detail.critical_cves_count} / {detail.high_cves_count}"
        "</strong></div>"
        f"<div class=\"kpi\"><span class=\"label\">Hallazgos Críticos / Altos</span>"
        f"<strong class=\"num\">{counts['critical']} / {counts['high']}</strong></div>"
        f"<div class=\"kpi\"><span class=\"label\">Total Hallazgos</span>"
        f"<strong class=\"num\">{len(findings)}</strong></div>"
        "</div></section>"
        f"{_html_drift_block(drift)}"
        "<section><h2>Capability Probe</h2><table><thead><tr>"
        "<th>Módulo</th><th>Estado</th><th>Binario / Motivo</th><th>Fallback</th>"
        f"</tr></thead><tbody>{_html_capabilities_rows(detail)}</tbody></table></section>"
        "<section><h2>Hallazgos Priorizados</h2><table><thead><tr>"
        "<th>Severidad</th><th>Riesgo</th><th>Fuente</th><th>Hallazgo</th><th>Remediación</th>"
        f"</tr></thead><tbody>{finding_rows}</tbody></table></section>"
        "</body></html>"
    )
