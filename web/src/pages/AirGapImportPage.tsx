import { useState, type ChangeEvent, type DragEvent, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { FileArchive, UploadCloud } from "lucide-react";
import { ApiError, hostGridApi } from "../api/client";
import { useAuth } from "../context/AuthContext";
import type { SnapshotCreatedResponse } from "../types/api";

const MAX_CLIENT_BYTES = 25 * 1024 * 1024;

export function AirGapImportPage() {
  const { user } = useAuth();
  const canImport = user?.role === "admin" || user?.role === "operator";
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [agentlessJson, setAgentlessJson] = useState("");
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SnapshotCreatedResponse | null>(null);

  const pickFile = (file: File | null) => {
    setError(null);
    setResult(null);
    if (!file) {
      setSelectedFile(null);
      return;
    }
    if (!file.name.endsWith(".bundle") && !file.name.endsWith(".tar.gz")) {
      setError("Solo se permiten archivos .bundle (o .tar.gz) exportados por hostgrid-agent.");
      setSelectedFile(null);
      return;
    }
    if (file.size > MAX_CLIENT_BYTES) {
      setError("El archivo supera el límite máximo permitido de 25 MB.");
      setSelectedFile(null);
      return;
    }
    setSelectedFile(file);
  };

  const handleFileChange = (evt: ChangeEvent<HTMLInputElement>) => {
    pickFile(evt.target.files?.[0] ?? null);
    evt.target.value = "";
  };

  const handleDrop = (evt: DragEvent<HTMLDivElement>) => {
    evt.preventDefault();
    setDragging(false);
    pickFile(evt.dataTransfer.files?.[0] ?? null);
  };

  const handleBundleUpload = async (evt: FormEvent<HTMLFormElement>) => {
    evt.preventDefault();
    if (!selectedFile) return;
    setUploading(true);
    setError(null);
    setResult(null);
    try {
      const res = await hostGridApi.importBundle(selectedFile);
      setResult(res);
      setSelectedFile(null);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.detail
          : "Falló la verificación criptográfica o integridad del .bundle."
      );
    } finally {
      setUploading(false);
    }
  };

  const handleAgentlessSubmit = async (evt: FormEvent<HTMLFormElement>) => {
    evt.preventDefault();
    if (!agentlessJson.trim()) return;
    setUploading(true);
    setError(null);
    setResult(null);
    try {
      JSON.parse(agentlessJson);
      const res = await hostGridApi.importAgentless(agentlessJson);
      setResult(res);
      setAgentlessJson("");
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.detail
          : "JSON agentless inválido o rechazado por validación estricta."
      );
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">
          Importador Air-Gapped (.bundle) y Agentless POSIX
        </h1>
        <p className="text-xs text-slate-400">
          Valida integridad SHA-256, anti-zip-slip, límite descomprimido y firma Ed25519/HMAC antes de ingerir el snapshot
        </p>
      </div>

      {!canImport && (
        <div
          role="status"
          className="rounded-md border border-amber-700 bg-amber-950 p-3 text-xs text-amber-200"
        >
          Tu rol actual (<strong className="font-mono uppercase">{user?.role}</strong>) es de solo
          lectura para importaciones. Se requiere rol <code className="font-mono">operator</code> o{" "}
          <code className="font-mono">admin</code> para ingerir archivos .bundle o JSON agentless.
        </div>
      )}

      {error && (
        <div role="alert" className="rounded-md border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          {error}
        </div>
      )}

      {result && (
        <div
          role="status"
          className="rounded-md border border-emerald-700 bg-emerald-950 p-4 text-xs text-emerald-100"
        >
          <p className="font-semibold">Snapshot verificado e ingerido correctamente</p>
          <div className="mt-2 grid grid-cols-2 gap-2 font-mono sm:grid-cols-4">
            <span>Fuente: {result.ingestion_source}</span>
            <span>Lynis: {result.hardening_index ?? "N/D"}</span>
            <span>Hallazgos: {result.findings_total}</span>
            <span>EOL: {result.eol_status}</span>
          </div>
          {result.bundle_sha256 && (
            <p className="mt-1.5 font-mono text-[11px] text-emerald-200">
              SHA-256: {result.bundle_sha256}
            </p>
          )}
          <Link
            to={`/hosts/${result.host_id}`}
            className="mt-2 inline-block font-semibold text-sky-300 underline"
          >
            Ver detalle completo del servidor →
          </Link>
        </div>
      )}

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <form
          onSubmit={(e) => void handleBundleUpload(e)}
          className="space-y-4 rounded-md border border-slate-800 bg-[#0f172a] p-4"
        >
          <div className="flex items-center gap-2">
            <FileArchive className="h-5 w-5 text-sky-400" aria-hidden="true" />
            <h2 className="text-sm font-semibold text-slate-100">
              Cargar archivo firmado (.bundle)
            </h2>
          </div>

          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            className={`flex flex-col items-center justify-center rounded-md border-2 border-dashed p-6 text-center transition-colors ${
              dragging ? "border-sky-400 bg-slate-900" : "border-slate-700 bg-slate-950"
            }`}
          >
            <UploadCloud className="mb-2 h-8 w-8 text-slate-400" aria-hidden="true" />
            <p className="text-xs text-slate-300">
              Arrastra un archivo <code className="font-mono text-sky-300">.bundle</code> aquí o
              selecciónalo desde disco
            </p>
            <label className="mt-3 cursor-pointer rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800">
              <span>Seleccionar archivo .bundle</span>
              <input
                type="file"
                accept=".bundle,.tar.gz"
                onChange={handleFileChange}
                className="sr-only"
              />
            </label>
            {selectedFile && (
              <p className="mt-2 font-mono text-xs text-emerald-300">
                Listo: {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)
              </p>
            )}
          </div>

          <button
            type="submit"
            disabled={!selectedFile || uploading}
            className="w-full rounded-md bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
          >
            {uploading ? "Verificando firma e ingiriendo..." : "Validar e Ingerir .bundle"}
          </button>
        </form>

        <form
          onSubmit={(e) => void handleAgentlessSubmit(e)}
          className="space-y-4 rounded-md border border-slate-800 bg-[#0f172a] p-4"
        >
          <h2 className="text-sm font-semibold text-slate-100">
            Ingesta Plan B Agentless (collect_posix.sh)
          </h2>
          <p className="text-xs text-slate-400">
            Pega la salida JSON de{" "}
            <code className="font-mono text-sky-300">
              ssh -T host &lt; agentless/collect_posix.sh
            </code>
          </p>
          <label htmlFor="agentless-json" className="sr-only">
            JSON de collect_posix.sh
          </label>
          <textarea
            id="agentless-json"
            rows={8}
            value={agentlessJson}
            onChange={(e) => setAgentlessJson(e.target.value)}
            placeholder='{"hostname":"legacy-01","machine_id_hash":"...","connectivity_mode":"agentless",...}'
            className="w-full rounded border border-slate-700 bg-slate-950 p-2.5 font-mono text-xs text-slate-100 placeholder-slate-500"
          />
          <button
            type="submit"
            disabled={!agentlessJson.trim() || uploading}
            className="w-full rounded-md border border-sky-500 bg-slate-900 px-4 py-2 text-sm font-semibold text-sky-300 hover:bg-slate-800 disabled:opacity-50"
          >
            {uploading ? "Ingiriendo JSON..." : "Ingerir reporte Agentless"}
          </button>
        </form>
      </div>
    </div>
  );
}
