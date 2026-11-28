import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { RefreshCw } from "lucide-react";
import { ApiError, hostGridApi, type HostFilters } from "../api/client";
import { EolBadge, ModeBadge, RepoBadge } from "../components/Badges";
import type { HostListItem } from "../types/api";

function formatDelta(delta: number | null): { text: string; cls: string } {
  if (delta === null || delta === 0) {
    return { text: "0", cls: "text-slate-400" };
  }
  if (delta > 0) {
    return { text: `+${delta} ▲`, cls: "text-emerald-300" };
  }
  return { text: `${delta} ▼`, cls: "text-red-300" };
}

export function FleetPage() {
  const [hosts, setHosts] = useState<readonly HostListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<HostFilters>({
    search: "",
    os_family: "",
    eol_status: "",
    connectivity_mode: "",
    repo_access_ok: "",
  });

  const loadHosts = async (activeFilters: HostFilters) => {
    setLoading(true);
    setError(null);
    try {
      const page = await hostGridApi.listHosts(activeFilters);
      setHosts(page.items);
      setTotal(page.total);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Error cargando flota de servidores.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadHosts(filters);
  }, [filters]);

  const eolCount = hosts.filter((h) => h.eol_status === "eol").length;
  const totalCriticalCves = hosts.reduce((acc, h) => acc + h.critical_cves_count, 0);
  const scoredHosts = hosts.filter((h) => h.last_hardening_index !== null);
  const avgScore =
    scoredHosts.length > 0
      ? Math.round(
          scoredHosts.reduce((acc, h) => acc + (h.last_hardening_index ?? 0), 0) /
            scoredHosts.length
        )
      : null;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-slate-50">Vista de Flota</h1>
          <p className="text-xs text-slate-400">
            Postura consolidada de servidores Linux sin Internet, Relay DMZ, Air-Gapped y Agentless
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadHosts(filters)}
          className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
        >
          <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
          <span>Actualizar</span>
        </button>
      </div>

      <section aria-label="Resumen de flota" className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div className="rounded-md border border-slate-800 bg-[#0f172a] p-3.5">
          <p className="text-xs text-slate-400">Servidores monitoreados</p>
          <p className="mt-1 font-mono text-2xl font-semibold text-slate-50 tabular-nums">
            {total}
          </p>
        </div>
        <div className="rounded-md border border-slate-800 bg-[#0f172a] p-3.5">
          <p className="text-xs text-slate-400">Sistemas fuera de soporte (EOL)</p>
          <p className="mt-1 font-mono text-2xl font-semibold text-red-300 tabular-nums">
            {eolCount}
          </p>
        </div>
        <div className="rounded-md border border-slate-800 bg-[#0f172a] p-3.5">
          <p className="text-xs text-slate-400">CVEs críticos activos</p>
          <p className="mt-1 font-mono text-2xl font-semibold text-orange-300 tabular-nums">
            {totalCriticalCves}
          </p>
        </div>
        <div className="rounded-md border border-slate-800 bg-[#0f172a] p-3.5">
          <p className="text-xs text-slate-400">Índice Lynis promedio</p>
          <p className="mt-1 font-mono text-2xl font-semibold text-sky-300 tabular-nums">
            {avgScore !== null ? `${avgScore}/100` : "—"}
          </p>
        </div>
      </section>

      <section
        aria-label="Filtros de flota"
        className="grid grid-cols-1 gap-2.5 rounded-md border border-slate-800 bg-[#0f172a] p-3 md:grid-cols-5"
      >
        <div>
          <label htmlFor="flt-search" className="mb-1 block text-[11px] font-medium text-slate-400">
            Buscar hostname
          </label>
          <input
            id="flt-search"
            type="search"
            value={filters.search ?? ""}
            onChange={(e) => setFilters((prev) => ({ ...prev, search: e.target.value }))}
            placeholder="srv-prod-..."
            className="w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500"
          />
        </div>
        <div>
          <label htmlFor="flt-os" className="mb-1 block text-[11px] font-medium text-slate-400">
            Distribución
          </label>
          <select
            id="flt-os"
            value={filters.os_family ?? ""}
            onChange={(e) => setFilters((prev) => ({ ...prev, os_family: e.target.value }))}
            className="w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-100"
          >
            <option value="">Todas</option>
            <option value="debian">Debian</option>
            <option value="ubuntu">Ubuntu</option>
            <option value="centos">CentOS</option>
            <option value="rhel">RHEL</option>
            <option value="alpine">Alpine</option>
            <option value="suse">SUSE</option>
          </select>
        </div>
        <div>
          <label htmlFor="flt-eol" className="mb-1 block text-[11px] font-medium text-slate-400">
            Estado EOL
          </label>
          <select
            id="flt-eol"
            value={filters.eol_status ?? ""}
            onChange={(e) => setFilters((prev) => ({ ...prev, eol_status: e.target.value }))}
            className="w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-100"
          >
            <option value="">Todos</option>
            <option value="eol">EOL (Fuera de soporte)</option>
            <option value="approaching_eol">Próximo a EOL</option>
            <option value="supported">Soportado</option>
            <option value="unknown">Desconocido</option>
          </select>
        </div>
        <div>
          <label htmlFor="flt-mode" className="mb-1 block text-[11px] font-medium text-slate-400">
            Conectividad
          </label>
          <select
            id="flt-mode"
            value={filters.connectivity_mode ?? ""}
            onChange={(e) => setFilters((prev) => ({ ...prev, connectivity_mode: e.target.value }))}
            className="w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-100"
          >
            <option value="">Todos</option>
            <option value="lan">LAN Pull</option>
            <option value="relay">Relay DMZ</option>
            <option value="airgapped">Air-Gapped</option>
            <option value="agentless">Agentless SSH</option>
          </select>
        </div>
        <div>
          <label htmlFor="flt-repo" className="mb-1 block text-[11px] font-medium text-slate-400">
            Acceso a repositorios
          </label>
          <select
            id="flt-repo"
            value={filters.repo_access_ok ?? ""}
            onChange={(e) => setFilters((prev) => ({ ...prev, repo_access_ok: e.target.value }))}
            className="w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-100"
          >
            <option value="">Todos</option>
            <option value="true">Con acceso (OK)</option>
            <option value="false">Sin acceso</option>
          </select>
        </div>
      </section>

      {error && (
        <div role="alert" className="rounded-md border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          {error}
        </div>
      )}

      <div
        tabIndex={0}
        role="region"
        aria-labelledby="fleet-table-caption"
        className="hg-table-wrapper hg-scroller rounded-md border border-slate-800 bg-[#0f172a]"
      >
        <table className="hg-data-table text-left text-xs">
          <caption id="fleet-table-caption" className="sr-only">
            Tabla de flota de servidores monitoreados en HostGrid
          </caption>
          <thead>
            <tr className="border-b border-slate-700 text-[11px] uppercase tracking-wider text-slate-300">
              <th scope="col" className="px-3 py-2.5">Hostname</th>
              <th scope="col" className="px-3 py-2.5">SO &amp; EOL</th>
              <th scope="col" className="px-3 py-2.5">Modo</th>
              <th scope="col" className="px-3 py-2.5 text-right">Lynis / Tendencia</th>
              <th scope="col" className="px-3 py-2.5 text-right">CVEs Crít. / Altos</th>
              <th scope="col" className="px-3 py-2.5">Repositorios</th>
              <th scope="col" className="px-3 py-2.5">Última sincronización</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {loading ? (
              <tr>
                <td colSpan={7} className="px-3 py-6 text-center text-slate-400">
                  Cargando inventario de flota...
                </td>
              </tr>
            ) : hosts.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-3 py-6 text-center text-slate-400">
                  No se encontraron servidores con los filtros actuales. Enrola un agente o importa un{" "}
                  <Link to="/import" className="text-sky-300 underline">
                    archivo .bundle air-gapped
                  </Link>
                  .
                </td>
              </tr>
            ) : (
              hosts.map((host) => {
                const delta = formatDelta(host.last_hardening_delta);
                return (
                  <tr key={host.id} className="hover:bg-slate-900/80">
                    <th scope="row" className="px-3 py-2.5 font-mono font-medium text-sky-300">
                      <Link to={`/hosts/${host.id}`} className="hover:underline">
                        {host.hostname}
                      </Link>
                      <div className="font-sans text-[11px] font-normal text-slate-400">
                        {host.environment.toUpperCase()} · {host.arch} · {host.init_system}
                      </div>
                    </th>
                    <td data-label="SO & EOL" className="px-3 py-2.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="text-slate-100">
                          {host.os_name} {host.os_version}
                        </span>
                        <EolBadge status={host.eol_status} />
                      </div>
                    </td>
                    <td data-label="Modo" className="px-3 py-2.5">
                      <ModeBadge mode={host.connectivity_mode} />
                    </td>
                    <td data-label="Lynis / Tendencia" className="px-3 py-2.5 text-right font-mono tabular-nums">
                      <span className="text-sm font-semibold text-slate-100">
                        {host.last_hardening_index ?? "—"}
                      </span>
                      <span className={`ml-2 text-[11px] ${delta.cls}`}>{delta.text}</span>
                    </td>
                    <td data-label="CVEs Crít. / Altos" className="px-3 py-2.5 text-right font-mono tabular-nums">
                      <span className="font-semibold text-red-300">{host.critical_cves_count}</span>
                      <span className="mx-1 text-slate-500">/</span>
                      <span className="font-semibold text-orange-300">{host.high_cves_count}</span>
                    </td>
                    <td data-label="Repositorios" className="px-3 py-2.5">
                      <RepoBadge ok={host.repo_access_ok} />
                    </td>
                    <td data-label="Última sincronización" className="px-3 py-2.5 font-mono text-[11px] text-slate-300 tabular-nums">
                      {host.last_seen_at ? host.last_seen_at.replace("T", " ").slice(0, 19) + "Z" : "—"}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
