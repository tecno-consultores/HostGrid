import { useState, type FormEvent } from "react";
import { ShieldCheck } from "lucide-react";
import { ApiError } from "../api/client";
import { useAuth } from "../context/AuthContext";

export function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (evt: FormEvent<HTMLFormElement>) => {
    evt.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(username.trim(), password);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "No fue posible autenticar la sesión.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#090e1a] px-4">
      <div className="w-full max-w-md rounded-md border border-slate-800 bg-[#0f172a] p-6 shadow-xl">
        <div className="mb-6 flex items-center gap-2.5">
          <ShieldCheck className="h-7 w-7 text-sky-400" aria-hidden="true" />
          <div>
            <h1 className="text-lg font-semibold text-slate-50">HostGrid Control Plane</h1>
            <p className="text-xs text-slate-400">
              Auditoría Linux Offline-First, CVEs Distro-Aware y Deriva
            </p>
          </div>
        </div>

        <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4">
          <div>
            <label htmlFor="hg-username" className="mb-1 block text-xs font-medium text-slate-300">
              Usuario
            </label>
            <input
              id="hg-username"
              name="username"
              type="text"
              autoComplete="username"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-400 focus:outline-none"
              placeholder="operador"
            />
          </div>

          <div>
            <label htmlFor="hg-password" className="mb-1 block text-xs font-medium text-slate-300">
              Contraseña
            </label>
            <input
              id="hg-password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-400 focus:outline-none"
              placeholder="••••••••••••"
            />
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-md border border-red-800 bg-red-950 px-3 py-2 text-xs text-red-200"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-md bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-60 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-300"
          >
            {submitting ? "Autenticando..." : "Iniciar sesión"}
          </button>
        </form>
      </div>
    </div>
  );
}
