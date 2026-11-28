import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Database, RefreshCw, Search } from "lucide-react";
import { ApiError, hostGridApi } from "../api/client";
import { EolBadge, SeverityBadge } from "../components/Badges";
import { useAuth } from "../context/AuthContext";
import type {
  CveFeedFormat,
  CveFeedImportResponse,
  CveSearchResponse,
  FleetRescanResponse,
} from "../types/api";

export function CveSearchPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<CveSearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [feedFormat, setFeedFormat] = useState<CveFeedFormat>("osv");
  const [feedEcosystem, setFeedEcosystem] = useState("");
  const [feedPayload, setFeedPayload] = useState("");
  const [rescanOnImport, setRescanOnImport] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);
  const [syncResult, setSyncResult] = useState<CveFeedImportResponse | null>(null);
  const [rescanResult, setRescanResult] = useState<FleetRescanResponse | null>(null);

  const handleSearch = async (evt: FormEvent<HTMLFormElement>) => {
    evt.preventDefault();
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await hostGridApi.searchCves(query.trim());
      setResult(res);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Error realizando búsqueda inversa.");
    } finally {
      setLoading(false);
    }
  };

  const handleImportFeed = async (evt: FormEvent<HTMLFormElement>) => {
    evt.preventDefault();
    if (!feedPayload.trim()) return;
    setSyncing(true);
    setSyncError(null);
    setSyncResult(null);
    try {
      const res = await hostGridApi.importCveFeed({
        feed_format: feedFormat,
        ecosystem: feedEcosystem.trim() || null,
        payload: feedPayload,
        rescan_fleet: rescanOnImport,
      });
      setSyncResult(res);
      setFeedPayload("");
    } catch (err) {
      setSyncError(
        err instanceof ApiError ? err.detail : "Error importando feed CVE offline."
      );
    } finally {
      setSyncing(false);
    }
  };

  const handleRescanFleet = async () => {
    setSyncing(true);
    setSyncError(null);
    setRescanResult(null);
    try {
      const res = await hostGridApi.rescanFleetCves();
      setRescanResult(res);
    } catch (err) {
      setSyncError(
        err instanceof ApiError ? err.detail : "Error re-evaluando flota contra catálogo CVE."
      );
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">Búsqueda Inversa de CVEs y Paquetes</h1>
        <p className="text-xs text-slate-400">
          Localiza en segundos qué servidores de la flota están afectados por un CVE ID o ejecutan un paquete vulnerable
        </p>
      </div>

      <form onSubmit={(e) => void handleSearch(e)} className="flex flex-wrap gap-2">
        <label htmlFor="cve-query" className="sr-only">
          CVE ID o nombre de paquete
        </label>
        <input
          id="cve-query"
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Ej: CVE-2024-6387, openssh-server, openssl..."
          className="min-w-[260px] flex-1 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-100 placeholder-slate-500"
        />
        <button
          type="submit"
          disabled={loading}
          className="inline-flex items-center gap-1.5 rounded-md bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-60"
        >
          <Search className="h-4 w-4" aria-hidden="true" />
          <span>{loading ? "Buscando..." : "Buscar en flota"}</span>
        </button>
      </form>

      {isAdmin && (
        <details className="hg-disclosure rounded-md border border-slate-800 bg-[#0f172a] p-4">
          <summary className="text-sm font-semibold text-slate-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400">
            <Database className="h-4 w-4 text-sky-400" aria-hidden="true" />
            <span>Sincronización Offline de Feeds CVE (OSV / Trivy / OVAL) — Admin</span>
          </summary>

          <div className="mt-4 space-y-4 border-t border-slate-800 pt-4">
            {syncError && (
              <div
                role="alert"
                className="rounded-md border border-red-800 bg-red-950 p-3 text-xs text-red-200"
              >
                {syncError}
              </div>
            )}

            {syncResult && (
              <div
                role="status"
                className="rounded-md border border-emerald-700 bg-emerald-950 p-3 text-xs text-emerald-100 tabular-nums"
              >
                Feed <strong className="font-mono uppercase">{syncResult.feed_format}</strong>{" "}
                importado: {syncResult.parsed} avisos analizados, {syncResult.upserted} guardados,{" "}
                {syncResult.hosts_rescanned} servidores re-evaluados ({syncResult.total_cve_matches}{" "}
                coincidencias activas).
              </div>
            )}

            {rescanResult && (
              <div
                role="status"
                className="rounded-md border border-sky-700 bg-sky-950 p-3 text-xs text-sky-100 tabular-nums"
              >
                Re-escaneo offline completado: {rescanResult.hosts_rescanned} servidores,{" "}
                {rescanResult.total_cve_matches} CVEs ({rescanResult.critical_matches} críticos /{" "}
                {rescanResult.high_matches} altos).
              </div>
            )}

            <form onSubmit={(e) => void handleImportFeed(e)} className="space-y-3">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label
                    htmlFor="cve-feed-format"
                    className="mb-1 block text-xs font-medium text-slate-300"
                  >
                    Formato del feed offline
                  </label>
                  <select
                    id="cve-feed-format"
                    value={feedFormat}
                    onChange={(e) => setFeedFormat(e.target.value as CveFeedFormat)}
                    className="w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-100"
                  >
                    <option value="osv">OSV JSON (vulns / array / objeto)</option>
                    <option value="trivy">Trivy JSON (Results / Vulnerabilities)</option>
                    <option value="oval">OVAL XML (definiciones distro)</option>
                  </select>
                </div>

                <div>
                  <label
                    htmlFor="cve-feed-eco"
                    className="mb-1 block text-xs font-medium text-slate-300"
                  >
                    Ecosistema por defecto (obligatorio para OVAL)
                  </label>
                  <input
                    id="cve-feed-eco"
                    type="text"
                    value={feedEcosystem}
                    onChange={(e) => setFeedEcosystem(e.target.value)}
                    placeholder="Ej: Debian:12, Ubuntu:22.04, RedHat:9"
                    className="w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 font-mono text-xs text-slate-100 placeholder-slate-500"
                  />
                </div>
              </div>

              <div>
                <label
                  htmlFor="cve-feed-payload"
                  className="mb-1 block text-xs font-medium text-slate-300"
                >
                  Contenido exportado (JSON o XML)
                </label>
                <textarea
                  id="cve-feed-payload"
                  rows={5}
                  value={feedPayload}
                  onChange={(e) => setFeedPayload(e.target.value)}
                  placeholder='{"vulns":[...]} o reporte Trivy JSON / OVAL XML...'
                  className="w-full rounded border border-slate-700 bg-slate-950 p-2.5 font-mono text-xs text-slate-100 placeholder-slate-500"
                />
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3">
                <label className="inline-flex items-center gap-2 text-xs text-slate-300">
                  <input
                    type="checkbox"
                    checked={rescanOnImport}
                    onChange={(e) => setRescanOnImport(e.target.checked)}
                    className="rounded border-slate-600 bg-slate-950"
                  />
                  <span>Re-evaluar automáticamente los últimos snapshots de toda la flota</span>
                </label>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    disabled={syncing}
                    onClick={() => void handleRescanFleet()}
                    className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 disabled:opacity-50"
                  >
                    <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Re-escanear Flota</span>
                  </button>
                  <button
                    type="submit"
                    disabled={!feedPayload.trim() || syncing}
                    className="inline-flex items-center gap-1.5 rounded-md bg-sky-500 px-3.5 py-1.5 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
                  >
                    <span>{syncing ? "Procesando..." : "Importar Feed Offline"}</span>
                  </button>
                </div>
              </div>
            </form>
          </div>
        </details>
      )}

      {error && (
        <div role="alert" className="rounded-md border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-2">
          <p className="text-xs text-slate-300 tabular-nums">
            Resultados para <strong className="font-mono text-sky-300">{result.query}</strong>:{" "}
            <strong>{result.total}</strong> coincidencias
          </p>

          <div
            tabIndex={0}
            role="region"
            aria-labelledby="cve-search-caption"
            className="hg-table-wrapper hg-scroller rounded-md border border-slate-800 bg-[#0f172a]"
          >
            <table className="hg-data-table text-left text-xs">
              <caption id="cve-search-caption" className="sr-only">
                Resultados de búsqueda inversa de CVEs y paquetes
              </caption>
              <thead>
                <tr className="border-b border-slate-700 text-[11px] uppercase text-slate-300">
                  <th scope="col" className="px-3 py-2.5">Servidor</th>
                  <th scope="col" className="px-3 py-2.5">SO / EOL</th>
                  <th scope="col" className="px-3 py-2.5">CVE / Severidad</th>
                  <th scope="col" className="px-3 py-2.5">Paquete &amp; Versión</th>
                  <th scope="col" className="px-3 py-2.5">Versión corregida</th>
                  <th scope="col" className="px-3 py-2.5">Exposición de red</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {result.items.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-3 py-6 text-center text-slate-400">
                      Ningún servidor afectado para la consulta indicada.
                    </td>
                  </tr>
                ) : (
                  result.items.map((item, idx) => (
                    <tr key={`${item.host_id}-${item.package_name}-${item.cve_id ?? idx}`} className="hover:bg-slate-900/70">
                      <th scope="row" className="px-3 py-2.5 font-mono text-sky-300">
                        <Link to={`/hosts/${item.host_id}`} className="hover:underline">
                          {item.hostname}
                        </Link>
                      </th>
                      <td data-label="SO / EOL" className="px-3 py-2.5">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span>{item.os}</span>
                          <EolBadge status={item.eol_status} />
                        </div>
                      </td>
                      <td data-label="CVE / Severidad" className="px-3 py-2.5">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="font-mono font-semibold text-slate-100">
                            {item.cve_id ?? "Inventario"}
                          </span>
                          <SeverityBadge severity={item.effective_severity} />
                        </div>
                      </td>
                      <td data-label="Paquete & Versión" className="px-3 py-2.5 font-mono">
                        <span className="text-slate-100">{item.package_name}</span>{" "}
                        <span className="text-slate-400">{item.installed_version}</span>
                      </td>
                      <td data-label="Versión corregida" className="px-3 py-2.5 font-mono text-emerald-300">
                        {item.fixed_version ?? "Sin parche / EOL"}
                      </td>
                      <td data-label="Exposición de red" className="px-3 py-2.5 font-mono">
                        {item.exposed_network ? (
                          <span className="rounded border border-red-700 bg-red-950 px-1.5 py-0.5 text-red-200">
                            ▲ {item.exposed_ports.join(", ") || "Expuesto"}
                          </span>
                        ) : (
                          <span className="text-slate-400">Interno / No expuesto</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
