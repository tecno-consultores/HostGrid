import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Download } from "lucide-react";
import { ApiError, hostGridApi } from "../api/client";
import {
  CapabilityBadge,
  EolBadge,
  ModeBadge,
  RepoBadge,
  SeverityBadge,
} from "../components/Badges";
import { ScoreTrendChart } from "../components/ScoreTrendChart";
import type {
  DriftResponse,
  FindingItem,
  HostDetailResponse,
  PackageRecord,
  SnapshotSummary,
} from "../types/api";

type DetailTab = "overview" | "findings" | "drift" | "packages";
const TAB_ORDER: readonly { id: DetailTab; label: string }[] = [
  { id: "overview", label: "Capacidades & Evolución" },
  { id: "findings", label: "Hallazgos Deduplicados" },
  { id: "drift", label: "Drift entre Snapshots" },
  { id: "packages", label: "Paquetes SBOM" },
];

export function HostDetailPage() {
  const { hostId = "" } = useParams();
  const [host, setHost] = useState<HostDetailResponse | null>(null);
  const [snapshots, setSnapshots] = useState<readonly SnapshotSummary[]>([]);
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string>("");
  const [findings, setFindings] = useState<readonly FindingItem[]>([]);
  const [drift, setDrift] = useState<DriftResponse | null>(null);
  const [packages, setPackages] = useState<readonly PackageRecord[]>([]);
  const [activeTab, setActiveTab] = useState<DetailTab>("overview");
  const [viewMode, setViewMode] = useState<"executive" | "technical">("executive");
  const [severityFilter, setSeverityFilter] = useState("");
  const [pkgSearch, setPkgSearch] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const tabRefs = useRef<Partial<Record<DetailTab, HTMLButtonElement | null>>>({});

  useEffect(() => {
    if (!hostId) return;
    setLoading(true);
    setError(null);
    Promise.all([
      hostGridApi.getHost(hostId),
      hostGridApi.listHostSnapshots(hostId),
      hostGridApi.listHostPackages(hostId),
    ])
      .then(([hostRes, snapRes, pkgRes]) => {
        setHost(hostRes);
        setSnapshots(snapRes.items);
        setPackages(pkgRes.items);
        const initialSnap = hostRes.latest_snapshot_id ?? snapRes.items[0]?.id ?? "";
        setSelectedSnapshotId(initialSnap);
      })
      .catch((err) => {
        setError(err instanceof ApiError ? err.detail : "Error cargando detalle del servidor.");
      })
      .finally(() => setLoading(false));
  }, [hostId]);

  useEffect(() => {
    if (!selectedSnapshotId) return;
    hostGridApi
      .listSnapshotFindings(selectedSnapshotId, severityFilter || undefined)
      .then((findRes) => setFindings(findRes.items))
      .catch(() => setFindings([]));
  }, [selectedSnapshotId, severityFilter]);

  useEffect(() => {
    if (!selectedSnapshotId) return;
    hostGridApi
      .getSnapshotDrift(selectedSnapshotId)
      .then((driftRes) => setDrift(driftRes))
      .catch(() => setDrift(null));
  }, [selectedSnapshotId]);

  useEffect(() => {
    if (!hostId) return;
    hostGridApi
      .listHostPackages(hostId, pkgSearch || undefined)
      .then((res) => setPackages(res.items))
      .catch(() => setPackages([]));
  }, [hostId, pkgSearch]);

  const activateTab = (nextId: DetailTab, focusTab: boolean) => {
    setActiveTab(nextId);
    const btn = tabRefs.current[nextId];
    if (btn) {
      if (focusTab) {
        btn.focus();
      }
      if (typeof btn.scrollIntoView === "function") {
        btn.scrollIntoView({ block: "nearest", inline: "nearest" });
      }
    }
  };

  const handleTabKeyDown = (evt: KeyboardEvent<HTMLDivElement>) => {
    const idx = TAB_ORDER.findIndex((t) => t.id === activeTab);
    if (evt.key === "ArrowRight") {
      evt.preventDefault();
      const next = TAB_ORDER[(idx + 1) % TAB_ORDER.length];
      if (next) activateTab(next.id, true);
    } else if (evt.key === "ArrowLeft") {
      evt.preventDefault();
      const prev = TAB_ORDER[(idx - 1 + TAB_ORDER.length) % TAB_ORDER.length];
      if (prev) activateTab(prev.id, true);
    } else if (evt.key === "Home") {
      evt.preventDefault();
      const first = TAB_ORDER[0];
      if (first) activateTab(first.id, true);
    } else if (evt.key === "End") {
      evt.preventDefault();
      const last = TAB_ORDER[TAB_ORDER.length - 1];
      if (last) activateTab(last.id, true);
    }
  };

  const triggerDownload = (content: string, mimeType: string, filename: string) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadSarif = async () => {
    if (!host) return;
    setExportError(null);
    try {
      const data = await hostGridApi.exportHostReport(host.id, "sarif");
      triggerDownload(
        JSON.stringify(data, null, 2),
        "application/sarif+json",
        `hostgrid-${host.hostname}.sarif.json`
      );
    } catch (err) {
      setExportError(err instanceof ApiError ? err.detail : "Error exportando reporte SARIF.");
    }
  };

  const handleDownloadTextReport = async (format: "markdown" | "html") => {
    if (!host) return;
    setExportError(null);
    try {
      const content = await hostGridApi.exportHostTextReport(host.id, format);
      const mime = format === "markdown" ? "text/markdown;charset=utf-8" : "text/html;charset=utf-8";
      const ext = format === "markdown" ? "md" : "html";
      triggerDownload(content, mime, `hostgrid-${host.hostname}.${ext}`);
    } catch (err) {
      setExportError(
        err instanceof ApiError ? err.detail : `Error exportando reporte ${format.toUpperCase()}.`
      );
    }
  };

  if (loading) {
    return <p className="py-8 text-sm text-slate-400">Cargando detalle del servidor...</p>;
  }
  if (error || !host) {
    return (
      <div className="space-y-3">
        <Link to="/" className="inline-flex items-center gap-1 text-xs text-sky-300 hover:underline">
          <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
          Volver a la flota
        </Link>
        <div role="alert" className="rounded-md border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          {error ?? "Servidor no encontrado."}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <Link to="/" className="inline-flex items-center gap-1 text-xs text-sky-300 hover:underline">
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
            Volver a Flota
          </Link>
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="font-mono text-xl font-semibold text-slate-50">{host.hostname}</h1>
            <EolBadge status={host.eol_status} />
            <ModeBadge mode={host.connectivity_mode} />
            <RepoBadge ok={host.repo_access_ok} />
          </div>
          <p className="font-mono text-xs text-slate-400">
            {host.os_name} {host.os_version} · Kernel {host.kernel_version} · {host.arch} · Init:{" "}
            {host.init_system}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {snapshots.length > 0 && (
            <label className="flex items-center gap-2 text-xs text-slate-300">
              <span>Snapshot:</span>
              <select
                value={selectedSnapshotId}
                onChange={(e) => setSelectedSnapshotId(e.target.value)}
                className="rounded border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-xs text-slate-100"
              >
                {snapshots.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.collected_at.slice(0, 19).replace("T", " ")}Z (Lynis {s.hardening_index ?? "N/D"})
                  </option>
                ))}
              </select>
            </label>
          )}
          <button
            type="button"
            onClick={() => void handleDownloadSarif()}
            disabled={!host.latest_snapshot_id}
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 disabled:opacity-50"
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Exportar SARIF</span>
          </button>
          <button
            type="button"
            onClick={() => void handleDownloadTextReport("markdown")}
            disabled={!host.latest_snapshot_id}
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 disabled:opacity-50"
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Exportar Markdown</span>
          </button>
          <button
            type="button"
            onClick={() => void handleDownloadTextReport("html")}
            disabled={!host.latest_snapshot_id}
            className="inline-flex items-center gap-1.5 rounded-md border border-sky-700 bg-sky-950 px-3 py-1.5 text-xs font-medium text-sky-200 hover:bg-sky-900 disabled:opacity-50"
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Reporte Ejecutivo HTML/PDF</span>
          </button>
        </div>
      </div>

      {exportError && (
        <div role="alert" className="rounded-md border border-red-800 bg-red-950 p-3 text-xs text-red-200">
          {exportError}
        </div>
      )}

      <div>
        <div
          role="tablist"
          aria-label="Secciones de detalle del servidor"
          className="hg-tablist"
          onKeyDown={handleTabKeyDown}
          {...({ focusgroup: "tablist nomemory" } as Record<string, string>)}
        >
          {TAB_ORDER.map((tab) => {
            const isSelected = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                ref={(el) => {
                  tabRefs.current[tab.id] = el;
                }}
                type="button"
                role="tab"
                id={`tab-${tab.id}`}
                tabIndex={isSelected ? 0 : -1}
                aria-selected={isSelected}
                onClick={() => activateTab(tab.id, false)}
                className="hg-tab focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400"
                {...(isSelected ? ({ focusgroupstart: "" } as Record<string, string>) : {})}
              >
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Panel 1: Capability Probe & Score Evolution */}
        <div
          role="tabpanel"
          aria-labelledby="tab-overview"
          hidden={activeTab !== "overview"}
          tabIndex={activeTab === "overview" ? 0 : undefined}
        >
          <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
            <section className="rounded-md border border-slate-800 bg-[#0f172a] p-4">
              <h2 className="mb-3 text-sm font-semibold text-slate-100">
                Capability Probe (Degradación Controlada)
              </h2>
              {Object.keys(host.capabilities).length === 0 ? (
                <p className="text-xs text-slate-400">Sin metadatos de capacidades detectadas.</p>
              ) : (
                <ul role="list" className="space-y-2">
                  {Object.entries(host.capabilities).map(([name, cap]) => (
                    <li
                      key={name}
                      className="flex flex-wrap items-center justify-between gap-2 rounded border border-slate-800 bg-slate-950 px-3 py-2 text-xs"
                    >
                      <div>
                        <span className="font-mono font-medium text-slate-100">{name}</span>
                        {cap.reason && (
                          <p className="text-[11px] text-slate-400">Motivo: {cap.reason}</p>
                        )}
                      </div>
                      <CapabilityBadge cap={cap} />
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section className="rounded-md border border-slate-800 bg-[#0f172a] p-4">
              <h2 className="mb-3 text-sm font-semibold text-slate-100">
                Evolución Histórica del Puntaje Lynis
              </h2>
              <ScoreTrendChart snapshots={snapshots} />
            </section>
          </div>
        </div>

        {/* Panel 2: Deduplicated Findings (Executive vs Technical View) */}
        <div
          role="tabpanel"
          aria-labelledby="tab-findings"
          hidden={activeTab !== "findings"}
          tabIndex={activeTab === "findings" ? 0 : undefined}
        >
          <div className="mt-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="inline-flex rounded-md border border-slate-700 bg-slate-950 p-0.5 text-xs">
                <button
                  type="button"
                  onClick={() => setViewMode("executive")}
                  aria-pressed={viewMode === "executive"}
                  className={`rounded px-3 py-1 font-medium ${
                    viewMode === "executive"
                      ? "bg-sky-500 text-slate-950"
                      : "text-slate-300 hover:text-slate-100"
                  }`}
                >
                  Vista Ejecutiva
                </button>
                <button
                  type="button"
                  onClick={() => setViewMode("technical")}
                  aria-pressed={viewMode === "technical"}
                  className={`rounded px-3 py-1 font-medium ${
                    viewMode === "technical"
                      ? "bg-sky-500 text-slate-950"
                      : "text-slate-300 hover:text-slate-100"
                  }`}
                >
                  Vista Técnica
                </button>
              </div>

              <select
                aria-label="Filtrar por severidad"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="rounded border border-slate-700 bg-slate-950 px-2.5 py-1 text-xs text-slate-100"
              >
                <option value="">Todas las severidades</option>
                <option value="critical">Crítico</option>
                <option value="high">Alto</option>
                <option value="medium">Medio</option>
                <option value="low">Bajo</option>
              </select>
            </div>

            {findings.length === 0 ? (
              <p className="rounded-md border border-slate-800 bg-[#0f172a] p-4 text-xs text-slate-400">
                No hay hallazgos para el snapshot y filtro seleccionados.
              </p>
            ) : (
              <ul role="list" className="space-y-2.5">
                {findings.map((f) => (
                  <li
                    key={f.id}
                    className="rounded-md border border-slate-800 bg-[#0f172a] p-3.5 text-xs"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={f.severity} />
                        <span className="rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5 font-mono text-[11px] text-slate-300">
                          {f.source_tool}
                        </span>
                        <span className="font-semibold text-slate-100">{f.title}</span>
                      </div>
                      <span className="font-mono text-xs font-semibold text-sky-300 tabular-nums">
                        Riesgo {f.contextual_score.toFixed(1)}
                      </span>
                    </div>

                    <p className="mt-2 text-slate-300">{f.description}</p>
                    <p className="mt-1.5 text-emerald-300">
                      <strong className="font-semibold">Remediación:</strong> {f.remediation}
                    </p>

                    {viewMode === "technical" && (
                      <div className="mt-3 space-y-2 border-t border-slate-800 pt-2.5">
                        <div className="flex flex-wrap gap-2 font-mono text-[11px] text-slate-400">
                          <span>Fingerprint: {f.fingerprint.slice(0, 16)}…</span>
                          <span>Regla: {f.rule_id}</span>
                          <span>Base: {f.base_severity}</span>
                        </div>
                        {f.contextual_factors.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {f.contextual_factors.map((fac) => (
                              <span
                                key={fac}
                                className="rounded border border-slate-700 bg-slate-950 px-1.5 py-0.5 font-mono text-[11px] text-amber-200"
                              >
                                {fac}
                              </span>
                            ))}
                          </div>
                        )}
                        <pre className="overflow-x-auto rounded border border-slate-800 bg-slate-950 p-2 font-mono text-[11px] text-slate-200">
                          {JSON.stringify(f.evidence, null, 2)}
                        </pre>
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {/* Panel 3: Drift */}
        <div
          role="tabpanel"
          aria-labelledby="tab-drift"
          hidden={activeTab !== "drift"}
          tabIndex={activeTab === "drift" ? 0 : undefined}
        >
          <div className="mt-4 space-y-3">
            {!drift ? (
              <p className="text-xs text-slate-400">Sin datos de drift disponibles.</p>
            ) : (
              <>
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div className="rounded border border-slate-800 bg-[#0f172a] p-3">
                    <p className="text-[11px] text-slate-400">Nuevos</p>
                    <p className="font-mono text-xl font-semibold text-red-300 tabular-nums">
                      +{drift.summary.new}
                    </p>
                  </div>
                  <div className="rounded border border-slate-800 bg-[#0f172a] p-3">
                    <p className="text-[11px] text-slate-400">Resueltos</p>
                    <p className="font-mono text-xl font-semibold text-emerald-300 tabular-nums">
                      -{drift.summary.resolved}
                    </p>
                  </div>
                  <div className="rounded border border-slate-800 bg-[#0f172a] p-3">
                    <p className="text-[11px] text-slate-400">Persistentes</p>
                    <p className="font-mono text-xl font-semibold text-slate-200 tabular-nums">
                      {drift.summary.persisted}
                    </p>
                  </div>
                  <div className="rounded border border-slate-800 bg-[#0f172a] p-3">
                    <p className="text-[11px] text-slate-400">Delta Puntaje Lynis</p>
                    <p className="font-mono text-xl font-semibold text-sky-300 tabular-nums">
                      {drift.hardening_index_delta === null
                        ? "N/D"
                        : drift.hardening_index_delta > 0
                          ? `+${drift.hardening_index_delta}`
                          : String(drift.hardening_index_delta)}
                    </p>
                  </div>
                </div>

                <ul role="list" className="space-y-2">
                  {drift.items.map((item) => (
                    <li
                      key={`${item.status}-${item.fingerprint}`}
                      className="flex flex-wrap items-center justify-between gap-2 rounded border border-slate-800 bg-[#0f172a] px-3 py-2 text-xs"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`rounded border px-1.5 py-0.5 font-mono text-[11px] uppercase ${
                            item.status === "new"
                              ? "border-red-700 bg-red-950 text-red-200"
                              : item.status === "resolved"
                                ? "border-emerald-700 bg-emerald-950 text-emerald-200"
                                : "border-slate-700 bg-slate-900 text-slate-300"
                          }`}
                        >
                          {item.status}
                        </span>
                        <SeverityBadge severity={item.severity} />
                        <span className="text-slate-100">{item.title}</span>
                      </div>
                      <span className="font-mono text-[11px] text-slate-400">
                        {item.category}
                      </span>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        </div>

        {/* Panel 4: SBOM Packages */}
        <div
          role="tabpanel"
          aria-labelledby="tab-packages"
          hidden={activeTab !== "packages"}
          tabIndex={activeTab === "packages" ? 0 : undefined}
        >
          <div className="mt-4 space-y-3">
            <input
              type="search"
              aria-label="Filtrar paquetes instalados"
              value={pkgSearch}
              onChange={(e) => setPkgSearch(e.target.value)}
              placeholder="Filtrar paquete (ej. openssh-server, openssl)..."
              className="w-full max-w-sm rounded border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-100 placeholder-slate-500"
            />
            <div
              tabIndex={0}
              role="region"
              aria-labelledby="pkg-table-caption"
              className="hg-table-wrapper hg-scroller rounded-md border border-slate-800 bg-[#0f172a]"
            >
              <table className="hg-data-table text-left text-xs">
                <caption id="pkg-table-caption" className="sr-only">
                  Paquetes SBOM instalados en {host.hostname}
                </caption>
                <thead>
                  <tr className="border-b border-slate-700 text-[11px] uppercase text-slate-300">
                    <th scope="col" className="px-3 py-2">Paquete</th>
                    <th scope="col" className="px-3 py-2">Fuente</th>
                    <th scope="col" className="px-3 py-2">Versión</th>
                    <th scope="col" className="px-3 py-2">Gestor</th>
                    <th scope="col" className="px-3 py-2">Arch</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 font-mono">
                  {packages.map((pkg, idx) => (
                    <tr key={`${pkg.name}-${pkg.version}-${idx}`} className="hover:bg-slate-900/70">
                      <th scope="row" className="px-3 py-2 text-slate-100">{pkg.name}</th>
                      <td data-label="Fuente" className="px-3 py-2 text-slate-300">
                        {pkg.source_package ?? "—"}
                      </td>
                      <td data-label="Versión" className="px-3 py-2 text-sky-300">
                        {pkg.epoch ? `${pkg.epoch}:` : ""}
                        {pkg.version}
                        {pkg.release ? `-${pkg.release}` : ""}
                      </td>
                      <td data-label="Gestor" className="px-3 py-2 text-slate-300">
                        {pkg.package_manager}
                      </td>
                      <td data-label="Arch" className="px-3 py-2 text-slate-400">{pkg.arch}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
