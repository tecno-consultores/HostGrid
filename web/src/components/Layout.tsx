import { useState, type ReactNode } from "react";
import { NavLink } from "react-router-dom";
import {
  ClipboardCheck,
  LogOut,
  Search,
  Server,
  Settings,
  ShieldCheck,
  UploadCloud,
} from "lucide-react";
import { hostGridApi } from "../api/client";
import { useAuth } from "../context/AuthContext";
import type { AuditVerifyResponse } from "../types/api";

export function Layout({ children }: { readonly children: ReactNode }) {
  const { user, logout } = useAuth();
  const [wormState, setWormState] = useState<AuditVerifyResponse | null>(null);
  const [wormError, setWormError] = useState<boolean>(false);
  const [verifying, setVerifying] = useState<boolean>(false);

  const handleVerifyWorm = async () => {
    setVerifying(true);
    setWormError(false);
    try {
      const res = await hostGridApi.verifyWormAudit();
      setWormState(res);
    } catch {
      setWormError(true);
    } finally {
      setVerifying(false);
    }
  };

  const navClass = ({ isActive }: { isActive: boolean }) =>
    `inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400 ${
      isActive
        ? "bg-slate-800 text-sky-300 border border-slate-700"
        : "text-slate-300 hover:bg-slate-900 hover:text-slate-100 border border-transparent"
    }`;

  return (
    <div className="flex min-h-screen flex-col bg-[#090e1a] text-slate-100">
      <header className="sticky top-0 z-30 border-b border-slate-800 bg-[#0f172a]">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-2.5">
          <div className="flex items-center gap-6">
            <NavLink to="/" className="flex items-center gap-2 font-semibold tracking-tight text-slate-50">
              <ShieldCheck className="h-5 w-5 text-sky-400" aria-hidden="true" />
              <span>HostGrid</span>
              <span className="rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5 font-mono text-[11px] text-slate-300">
                v0.1
              </span>
            </NavLink>

            <nav aria-label="Navegación principal" className="flex flex-wrap items-center gap-1">
              <NavLink to="/" end className={navClass}>
                <Server className="h-4 w-4" aria-hidden="true" />
                <span>Flota</span>
              </NavLink>
              <NavLink to="/cves" className={navClass}>
                <Search className="h-4 w-4" aria-hidden="true" />
                <span>Búsqueda CVE</span>
              </NavLink>
              <NavLink to="/import" className={navClass}>
                <UploadCloud className="h-4 w-4" aria-hidden="true" />
                <span>Importar Air-Gapped</span>
              </NavLink>
              <NavLink to="/governance" className={navClass}>
                <ClipboardCheck className="h-4 w-4" aria-hidden="true" />
                <span>Gobernanza</span>
              </NavLink>
              {(user?.role === "operator" || user?.role === "admin") && (
                <NavLink to="/operations" className={navClass}>
                  <Settings className="h-4 w-4" aria-hidden="true" />
                  <span>Operaciones</span>
                </NavLink>
              )}
            </nav>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => void handleVerifyWorm()}
              disabled={verifying}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-200 hover:bg-slate-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400"
            >
              <span aria-hidden="true">
                {wormError ? "!" : wormState === null ? "○" : wormState.valid ? "✓" : "✕"}
              </span>
              <span>
                {verifying
                  ? "Verificando WORM..."
                  : wormError
                    ? "Error WORM"
                    : wormState === null
                      ? "Verificar WORM"
                      : wormState.valid
                        ? `WORM OK (${wormState.checked_records})`
                        : `WORM ROTO (#${wormState.broken_at_seq_num})`}
              </span>
            </button>

            {user && (
              <div className="flex items-center gap-2 border-l border-slate-700 pl-3 text-xs">
                <span className="font-medium text-slate-200">{user.username}</span>
                <span className="rounded border border-sky-800 bg-sky-950 px-1.5 py-0.5 font-mono uppercase text-sky-200">
                  {user.role}
                </span>
                <button
                  type="button"
                  onClick={logout}
                  aria-label="Cerrar sesión"
                  className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200 hover:bg-slate-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400"
                >
                  <LogOut className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Salir</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-7xl flex-1 flex-col px-4 py-5">
        {children}
      </main>

      <footer className="mt-auto border-t border-slate-800 bg-[#0f172a] py-3 text-center text-xs text-slate-400">
        HostGrid Control Plane — Offline-First Linux Security Posture, CVE Distro-Aware &amp; WORM Audit
      </footer>
    </div>
  );
}
