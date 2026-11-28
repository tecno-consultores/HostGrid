import type { CapabilityItem, ConnectivityMode, EolStatus, Severity } from "../types/api";

const SEVERITY_STYLE: Record<Severity, { symbol: string; label: string; cls: string }> = {
  critical: {
    symbol: "▲",
    label: "CRÍTICO",
    cls: "bg-red-950 text-red-200 border-red-700",
  },
  high: {
    symbol: "◆",
    label: "ALTO",
    cls: "bg-orange-950 text-orange-200 border-orange-700",
  },
  medium: {
    symbol: "●",
    label: "MEDIO",
    cls: "bg-amber-950 text-amber-200 border-amber-700",
  },
  low: {
    symbol: "■",
    label: "BAJO",
    cls: "bg-sky-950 text-sky-200 border-sky-700",
  },
  info: {
    symbol: "○",
    label: "INFO",
    cls: "bg-slate-800 text-slate-200 border-slate-600",
  },
};

const EOL_STYLE: Record<EolStatus, { symbol: string; label: string; cls: string }> = {
  eol: {
    symbol: "✕",
    label: "EOL",
    cls: "bg-red-950 text-red-200 border-red-700",
  },
  approaching_eol: {
    symbol: "▲",
    label: "PRÓX. EOL",
    cls: "bg-amber-950 text-amber-200 border-amber-700",
  },
  supported: {
    symbol: "✓",
    label: "SOPORTADO",
    cls: "bg-emerald-950 text-emerald-200 border-emerald-700",
  },
  unknown: {
    symbol: "?",
    label: "DESCONOCIDO",
    cls: "bg-slate-800 text-slate-200 border-slate-600",
  },
};

const MODE_LABELS: Record<ConnectivityMode, string> = {
  lan: "LAN Pull",
  relay: "Relay DMZ",
  airgapped: "Air-Gapped",
  agentless: "Agentless SSH",
};

export function SeverityBadge({ severity }: { readonly severity: Severity }) {
  const cfg = SEVERITY_STYLE[severity] ?? SEVERITY_STYLE.info;
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-semibold tracking-wide ${cfg.cls}`}
    >
      <span aria-hidden="true">{cfg.symbol}</span>
      <span>{cfg.label}</span>
    </span>
  );
}

export function EolBadge({ status }: { readonly status: EolStatus }) {
  const cfg = EOL_STYLE[status] ?? EOL_STYLE.unknown;
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-semibold ${cfg.cls}`}
    >
      <span aria-hidden="true">{cfg.symbol}</span>
      <span>{cfg.label}</span>
    </span>
  );
}

export function ModeBadge({ mode }: { readonly mode: ConnectivityMode }) {
  return (
    <span className="inline-flex items-center rounded border border-slate-700 bg-slate-900 px-2 py-0.5 font-mono text-xs text-slate-200">
      {MODE_LABELS[mode] ?? mode}
    </span>
  );
}

export function RepoBadge({ ok }: { readonly ok: boolean | null }) {
  if (ok === true) {
    return (
      <span className="inline-flex items-center gap-1 rounded border border-emerald-700 bg-emerald-950 px-1.5 py-0.5 text-xs font-medium text-emerald-200">
        <span aria-hidden="true">✓</span>
        <span>OK</span>
      </span>
    );
  }
  if (ok === false) {
    return (
      <span className="inline-flex items-center gap-1 rounded border border-red-700 bg-red-950 px-1.5 py-0.5 text-xs font-medium text-red-200">
        <span aria-hidden="true">✕</span>
        <span>Sin acceso</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded border border-slate-600 bg-slate-800 px-1.5 py-0.5 text-xs font-medium text-slate-300">
      <span aria-hidden="true">○</span>
      <span>Offline / N/D</span>
    </span>
  );
}

export function CapabilityBadge({ cap }: { readonly cap: CapabilityItem }) {
  if (cap.status === "supported" && cap.fallback_used) {
    return (
      <span className="inline-flex items-center gap-1 rounded border border-amber-700 bg-amber-950 px-2 py-0.5 text-xs font-medium text-amber-200">
        <span aria-hidden="true">◆</span>
        <span>Fallback ({cap.binary ?? "clásico"})</span>
      </span>
    );
  }
  if (cap.status === "supported") {
    return (
      <span className="inline-flex items-center gap-1 rounded border border-emerald-700 bg-emerald-950 px-2 py-0.5 text-xs font-medium text-emerald-200">
        <span aria-hidden="true">✓</span>
        <span>Soportado ({cap.binary ?? "nativo"})</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded border border-slate-600 bg-slate-800 px-2 py-0.5 text-xs font-medium text-slate-200">
      <span aria-hidden="true">■</span>
      <span>not_supported_on_os</span>
    </span>
  );
}
