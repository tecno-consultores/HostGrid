import { useEffect, useRef, useState, type FormEvent } from "react";
import { CheckCircle2, Play, RefreshCw, RotateCcw, ShieldAlert, XCircle } from "lucide-react";
import { ApiError, hostGridApi } from "../api/client";
import { useAuth } from "../context/AuthContext";
import type {
  AuditLogItem,
  HostListItem,
  PatchPlanItem,
  PatchPlanStatus,
} from "../types/api";

const STATUS_STYLE: Readonly<Record<PatchPlanStatus, { cls: string; marker: string }>> = {
  DRAFT: { cls: "border-slate-700 bg-slate-900 text-slate-200", marker: "○" },
  REPO_PRECHECK: { cls: "border-sky-800 bg-sky-950 text-sky-200", marker: "●" },
  FAILED_PRECHECK: { cls: "border-red-700 bg-red-950 text-red-200", marker: "✕" },
  DRY_RUN_READY: { cls: "border-amber-700 bg-amber-950 text-amber-200", marker: "▲" },
  PENDING_APPROVAL: { cls: "border-indigo-700 bg-indigo-950 text-indigo-200", marker: "◆" },
  APPROVED: { cls: "border-emerald-700 bg-emerald-950 text-emerald-200", marker: "✓" },
  REJECTED: { cls: "border-red-700 bg-red-950 text-red-200", marker: "✕" },
  CANARY_WAVE: { cls: "border-sky-700 bg-sky-950 text-sky-200", marker: "▶" },
  ROLLOUT_IN_PROGRESS: { cls: "border-sky-700 bg-sky-950 text-sky-200", marker: "▶" },
  COMPLETED: { cls: "border-emerald-700 bg-emerald-950 text-emerald-200", marker: "✓" },
  ROLLED_BACK: { cls: "border-orange-700 bg-orange-950 text-orange-200", marker: "↺" },
};

function PlanStatusBadge({ status }: { readonly status: PatchPlanStatus }) {
  const style = STATUS_STYLE[status] ?? STATUS_STYLE.DRAFT;
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 font-mono text-[11px] font-semibold ${style.cls}`}
    >
      <span aria-hidden="true">{style.marker}</span>
      <span>{status}</span>
    </span>
  );
}

export function GovernancePage() {
  const { user } = useAuth();
  const canOperate = user?.role === "operator" || user?.role === "admin";
  const canApprove = user?.role === "approver" || user?.role === "admin";

  const [plans, setPlans] = useState<readonly PatchPlanItem[]>([]);
  const [hosts, setHosts] = useState<readonly HostListItem[]>([]);
  const [auditLogs, setAuditLogs] = useState<readonly AuditLogItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyPlanId, setBusyPlanId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [title, setTitle] = useState("");
  const [titleTouched, setTitleTouched] = useState(false);
  const [packagesInput, setPackagesInput] = useState("");
  const [packagesTouched, setPackagesTouched] = useState(false);
  const [selectedHostIds, setSelectedHostIds] = useState<readonly string[]>([]);
  const [canaryPercentInput, setCanaryPercentInput] = useState("10");
  const [canaryTouched, setCanaryTouched] = useState(false);
  const [maxWavePercentInput, setMaxWavePercentInput] = useState("50");
  const [waveTouched, setWaveTouched] = useState(false);
  const [maxFailedHostsInput, setMaxFailedHostsInput] = useState("0");
  const [maxFailedTouched, setMaxFailedTouched] = useState(false);
  const [safeModeEnabled, setSafeModeEnabled] = useState(true);
  const [rollbackOnUnreachable, setRollbackOnUnreachable] = useState(true);
  const [fieldAnnouncement, setFieldAnnouncement] = useState("");
  const [rationales, setRationales] = useState<Record<string, string>>({});

  const titleInputRef = useRef<HTMLInputElement | null>(null);
  const pkgInputRef = useRef<HTMLInputElement | null>(null);
  const canaryInputRef = useRef<HTMLInputElement | null>(null);
  const waveInputRef = useRef<HTMLInputElement | null>(null);
  const maxFailedInputRef = useRef<HTMLInputElement | null>(null);

  const titleInvalid = titleTouched && title.trim().length < 3;
  const parsedPackages = packagesInput
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  const packagesInvalid = packagesTouched && parsedPackages.length === 0;
  const parsedMaxWave =
    maxWavePercentInput.trim() === "" ? Number.NaN : Number(maxWavePercentInput);
  const parsedCanary =
    canaryPercentInput.trim() === "" ? Number.NaN : Number(canaryPercentInput);
  const waveOutOfRange = !Number.isInteger(parsedMaxWave) || parsedMaxWave < 1 || parsedMaxWave > 100;
  const canaryOutOfRange =
    !Number.isInteger(parsedCanary) ||
    parsedCanary < 1 ||
    parsedCanary > 100 ||
    (!waveOutOfRange && parsedCanary > parsedMaxWave);
  const parsedMaxFailed =
    maxFailedHostsInput.trim() === "" ? Number.NaN : Number(maxFailedHostsInput);
  const maxFailedOutOfRange =
    !Number.isInteger(parsedMaxFailed) || parsedMaxFailed < 0 || parsedMaxFailed > 100;
  const canaryInvalid = canaryTouched && canaryOutOfRange;
  const waveInvalid = waveTouched && waveOutOfRange;
  const maxFailedInvalid = maxFailedTouched && maxFailedOutOfRange;

  const hostNameById = new Map(hosts.map((h) => [h.id, h.hostname]));

  const loadAll = async () => {
    setLoading(true);
    setError(null);
    try {
      const [plansRes, hostsRes, auditRes] = await Promise.all([
        hostGridApi.listPatchPlans(),
        hostGridApi.listHosts(),
        hostGridApi.listAuditLogs(25),
      ]);
      setPlans(plansRes.items);
      setHosts(hostsRes.items);
      setAuditLogs(auditRes.items);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Error cargando cola de gobernanza.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadAll();
  }, []);

  const toggleHost = (hostId: string) => {
    setSelectedHostIds((prev) =>
      prev.includes(hostId) ? prev.filter((id) => id !== hostId) : [...prev, hostId]
    );
  };

  const handleCreatePlan = async (evt: FormEvent<HTMLFormElement>) => {
    evt.preventDefault();
    setTitleTouched(true);
    setPackagesTouched(true);
    setCanaryTouched(true);
    setWaveTouched(true);
    setMaxFailedTouched(true);
    setError(null);
    setNotice(null);

    if (title.trim().length < 3) {
      titleInputRef.current?.focus();
      return;
    }
    if (parsedPackages.length === 0) {
      pkgInputRef.current?.focus();
      return;
    }
    if (canaryOutOfRange) {
      canaryInputRef.current?.focus();
      return;
    }
    if (waveOutOfRange) {
      waveInputRef.current?.focus();
      return;
    }
    if (maxFailedOutOfRange) {
      maxFailedInputRef.current?.focus();
      return;
    }
    if (selectedHostIds.length === 0) {
      setError("Selecciona al menos un servidor objetivo para el plan de parcheo.");
      return;
    }

    setBusyPlanId("create");
    try {
      const created = await hostGridApi.createPatchPlan({
        title: title.trim(),
        target_host_ids: selectedHostIds,
        packages: parsedPackages,
        canary_percent: parsedCanary,
        max_wave_percent: parsedMaxWave,
        safe_mode_enabled: safeModeEnabled,
        max_failed_hosts: parsedMaxFailed,
        rollback_on_unreachable: rollbackOnUnreachable,
      });
      setTitle("");
      setTitleTouched(false);
      setPackagesInput("");
      setPackagesTouched(false);
      setCanaryPercentInput("10");
      setCanaryTouched(false);
      setMaxWavePercentInput("50");
      setWaveTouched(false);
      setMaxFailedHostsInput("0");
      setMaxFailedTouched(false);
      setSafeModeEnabled(true);
      setRollbackOnUnreachable(true);
      setFieldAnnouncement("");
      setSelectedHostIds([]);
      setNotice(`Plan "${created.title}" creado en estado ${created.status}.`);
      await loadAll();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Error creando plan de parcheo.");
    } finally {
      setBusyPlanId(null);
    }
  };

  const handleSubmitDryRun = async (plan: PatchPlanItem) => {
    setBusyPlanId(plan.id);
    setError(null);
    setNotice(null);
    try {
      const updated = await hostGridApi.submitPatchDryRun(
        plan.id,
        plan.target_host_ids.map((hid) => ({
          host_id: hid,
          succeeded: true,
          repo_verified: true,
          planned_changes_count: plan.packages.length,
        }))
      );
      setNotice(`Dry-Run registrado. Estado actual: ${updated.status}.`);
      await loadAll();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Error registrando simulación Dry-Run.");
    } finally {
      setBusyPlanId(null);
    }
  };

  const handleDecision = async (plan: PatchPlanItem, decision: "approved" | "rejected") => {
    const rationale = (rationales[plan.id] ?? "").trim();
    if (rationale.length < 3) {
      setError("Ingresa una justificación auditable (mínimo 3 caracteres) para decidir el plan.");
      return;
    }
    setBusyPlanId(plan.id);
    setError(null);
    setNotice(null);
    try {
      const updated = await hostGridApi.decidePatchPlan(plan.id, decision, rationale);
      setNotice(`Decisión Maker-Checker registrada: ${updated.status}.`);
      await loadAll();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Error registrando decisión Maker-Checker.");
    } finally {
      setBusyPlanId(null);
    }
  };

  const handleStartCanary = async (planId: string) => {
    setBusyPlanId(planId);
    setError(null);
    setNotice(null);
    try {
      const updated = await hostGridApi.startCanaryExecution(planId);
      setNotice(`Oleada canario iniciada (${updated.status}).`);
      await loadAll();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Error iniciando oleada canario.");
    } finally {
      setBusyPlanId(null);
    }
  };

  const handleWaveReport = async (plan: PatchPlanItem, simulateFailure: boolean) => {
    const waveNum = plan.active_wave_number ?? 1;
    const wave = plan.waves.find((w) => w.wave_number === waveNum);
    const waveCount = wave?.host_ids.length ?? 1;
    const threshold = plan.policy.max_failed_hosts ?? 0;
    const neededFailures = Math.max(1, threshold + 1);
    const failedHosts = simulateFailure ? Math.min(waveCount, neededFailures) : 0;
    const unreachableHosts = simulateFailure && failedHosts <= threshold ? 1 : 0;
    setBusyPlanId(plan.id);
    setError(null);
    setNotice(null);
    try {
      const updated = await hostGridApi.reportWaveHealth(plan.id, {
        wave_number: waveNum,
        healthy_hosts: simulateFailure ? Math.max(0, waveCount - failedHosts) : waveCount,
        failed_hosts: failedHosts,
        unreachable_hosts: unreachableHosts,
      });
      setNotice(`Ola #${waveNum} evaluada. Estado del plan: ${updated.status}.`);
      await loadAll();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Error reportando salud de la oleada.");
    } finally {
      setBusyPlanId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-slate-50">
            Gobernanza de Parcheo (Maker-Checker &amp; Canario)
          </h1>
          <p className="text-xs text-slate-400">
            Pre-verificación de repositorios firmados, Dry-Run obligatorio, separación de funciones Maker-Checker, oleadas canario y Safe Mode
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadAll()}
          className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
        >
          <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
          <span>Actualizar</span>
        </button>
      </div>

      {error && (
        <div role="alert" className="rounded-md border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          {error}
        </div>
      )}
      {notice && (
        <div
          role="status"
          aria-live="polite"
          className="rounded-md border border-emerald-700 bg-emerald-950 p-3 text-sm text-emerald-100"
        >
          {notice}
        </div>
      )}

      {canOperate && (
        <section
          aria-labelledby="create-plan-heading"
          className="rounded-md border border-slate-800 bg-[#0f172a] p-4"
        >
          <h2 id="create-plan-heading" className="text-sm font-semibold text-slate-100">
            Crear Plan de Parcheo Gobernado (Maker)
          </h2>
          <form
            aria-labelledby="create-plan-heading"
            onSubmit={(e) => void handleCreatePlan(e)}
            noValidate
            className="mt-3 space-y-4"
          >
            <div aria-live="polite" className="sr-only">
              {fieldAnnouncement}
            </div>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div>
                <label htmlFor="plan-title" className="mb-1 block text-xs font-medium text-slate-300">
                  Título del plan
                </label>
                <input
                  ref={titleInputRef}
                  id="plan-title"
                  type="text"
                  required
                  minLength={3}
                  aria-invalid={titleInvalid ? "true" : "false"}
                  aria-describedby={titleInvalid ? "plan-title-err" : undefined}
                  value={title}
                  onBlur={() => {
                    setTitleTouched(true);
                    if (title.trim().length < 3) {
                      setFieldAnnouncement("Error en Título del plan: ingresa al menos 3 caracteres.");
                    }
                  }}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="Ej: Parcheo OpenSSH CVE-2024-6387"
                  className="hg-field-control w-full rounded border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-100 placeholder-slate-500"
                />
                {titleInvalid && (
                  <p id="plan-title-err" className="mt-1 text-[11px] text-red-300">
                    Error: ingresa un título de al menos 3 caracteres.
                  </p>
                )}
              </div>

              <div>
                <label
                  htmlFor="plan-packages"
                  className="mb-1 block text-xs font-medium text-slate-300"
                >
                  Paquetes a actualizar (separados por coma o espacio)
                </label>
                <input
                  ref={pkgInputRef}
                  id="plan-packages"
                  type="text"
                  required
                  aria-invalid={packagesInvalid ? "true" : "false"}
                  aria-describedby={packagesInvalid ? "plan-packages-err" : undefined}
                  value={packagesInput}
                  onBlur={() => {
                    setPackagesTouched(true);
                    if (parsedPackages.length === 0) {
                      setFieldAnnouncement("Error en Paquetes: indica al menos un paquete válido.");
                    }
                  }}
                  onChange={(e) => setPackagesInput(e.target.value)}
                  placeholder="openssh-server, openssl"
                  className="hg-field-control w-full rounded border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-100 placeholder-slate-500"
                />
                {packagesInvalid && (
                  <p id="plan-packages-err" className="mt-1 text-[11px] text-red-300">
                    Error: indica al menos un paquete válido.
                  </p>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label
                  htmlFor="plan-canary-pct"
                  className="mb-1 block text-xs font-medium text-slate-300"
                >
                  Porcentaje Oleada Canario (1–100%)
                </label>
                <input
                  ref={canaryInputRef}
                  id="plan-canary-pct"
                  type="number"
                  required
                  min={1}
                  max={100}
                  aria-invalid={canaryInvalid ? "true" : "false"}
                  aria-describedby={canaryInvalid ? "plan-canary-err" : undefined}
                  value={canaryPercentInput}
                  onBlur={() => {
                    setCanaryTouched(true);
                    if (canaryOutOfRange) {
                      setFieldAnnouncement(
                        "Error en Porcentaje Canario: debe estar entre 1 y 100 y no superar el máximo por oleada."
                      );
                    }
                  }}
                  onChange={(e) => setCanaryPercentInput(e.target.value)}
                  className="hg-field-control w-full rounded border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-100 tabular-nums"
                />
                {canaryInvalid && (
                  <p id="plan-canary-err" className="mt-1 text-[11px] text-red-300">
                    Error: el porcentaje canario debe estar entre 1 y 100 y no superar el máximo por oleada.
                  </p>
                )}
              </div>
              <div>
                <label
                  htmlFor="plan-wave-pct"
                  className="mb-1 block text-xs font-medium text-slate-300"
                >
                  Máximo por Oleada (1–100%)
                </label>
                <input
                  ref={waveInputRef}
                  id="plan-wave-pct"
                  type="number"
                  required
                  min={1}
                  max={100}
                  aria-invalid={waveInvalid ? "true" : "false"}
                  aria-describedby={waveInvalid ? "plan-wave-err" : undefined}
                  value={maxWavePercentInput}
                  onBlur={() => {
                    setWaveTouched(true);
                    if (waveOutOfRange) {
                      setFieldAnnouncement(
                        "Error en Máximo por Oleada: ingresa un entero entre 1 y 100."
                      );
                    }
                  }}
                  onChange={(e) => setMaxWavePercentInput(e.target.value)}
                  className="hg-field-control w-full rounded border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-100 tabular-nums"
                />
                {waveInvalid && (
                  <p id="plan-wave-err" className="mt-1 text-[11px] text-red-300">
                    Error: el máximo por oleada debe ser un entero entre 1 y 100.
                  </p>
                )}
              </div>
            </div>

            <fieldset className="space-y-3 rounded border border-slate-800 bg-slate-950/60 p-3">
              <legend className="px-1 text-xs font-medium text-slate-300">
                Política Safe Mode y Rollback
              </legend>
              <div className="grid grid-cols-1 gap-3 md:grid-cols-3 md:items-start">
                <div>
                  <label
                    htmlFor="plan-max-failed"
                    className="mb-1 block text-xs font-medium text-slate-300"
                  >
                    Máx. hosts fallidos tolerados (0–100)
                  </label>
                  <input
                    ref={maxFailedInputRef}
                    id="plan-max-failed"
                    type="number"
                    required
                    min={0}
                    max={100}
                    aria-invalid={maxFailedInvalid ? "true" : "false"}
                    aria-describedby={maxFailedInvalid ? "plan-max-failed-err" : undefined}
                    value={maxFailedHostsInput}
                    onBlur={() => {
                      setMaxFailedTouched(true);
                      if (maxFailedOutOfRange) {
                        setFieldAnnouncement(
                          "Error en Máx. hosts fallidos: ingresa un entero entre 0 y 100."
                        );
                      }
                    }}
                    onChange={(e) => setMaxFailedHostsInput(e.target.value)}
                    className="hg-field-control w-full rounded border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-100 tabular-nums"
                  />
                  {maxFailedInvalid && (
                    <p id="plan-max-failed-err" className="mt-1 text-[11px] text-red-300">
                      Error: el máximo de hosts fallidos debe ser un entero entre 0 y 100.
                    </p>
                  )}
                </div>

                <label className="mt-1 flex cursor-pointer items-start gap-2 rounded border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-200 md:mt-5">
                  <input
                    id="plan-safe-mode"
                    type="checkbox"
                    checked={safeModeEnabled}
                    onChange={(e) => setSafeModeEnabled(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span>Habilitar Safe Mode (rollback automático al superar umbral de fallos)</span>
                </label>

                <label className="mt-1 flex cursor-pointer items-start gap-2 rounded border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-200 md:mt-5">
                  <input
                    id="plan-rollback-unreachable"
                    type="checkbox"
                    checked={rollbackOnUnreachable}
                    onChange={(e) => setRollbackOnUnreachable(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span>Activar rollback si un servidor queda inalcanzable tras el parcheo</span>
                </label>
              </div>
            </fieldset>

            <fieldset className="space-y-2">
              <legend className="text-xs font-medium text-slate-300">
                Servidores objetivo ({selectedHostIds.length} seleccionados)
              </legend>
              {hosts.length === 0 ? (
                <p className="text-xs text-slate-400">No hay servidores registrados en la flota.</p>
              ) : (
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {hosts.map((h) => (
                    <label
                      key={h.id}
                      className="flex cursor-pointer items-center justify-between gap-2 rounded border border-slate-800 bg-slate-950 px-2.5 py-2 text-xs"
                    >
                      <span className="inline-flex items-center gap-2 font-mono text-slate-100">
                        <input
                          type="checkbox"
                          checked={selectedHostIds.includes(h.id)}
                          onChange={() => toggleHost(h.id)}
                        />
                        <span>{h.hostname}</span>
                      </span>
                      <span
                        className={`font-mono text-[10px] ${
                          h.repo_access_ok ? "text-emerald-300" : "text-red-300"
                        }`}
                      >
                        {h.repo_access_ok ? "Repo OK" : "Sin Repo"}
                      </span>
                    </label>
                  ))}
                </div>
              )}
            </fieldset>

            <button
              type="submit"
              disabled={busyPlanId === "create"}
              className="rounded-md bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
            >
              {busyPlanId === "create"
                ? "Verificando repositorios..."
                : "Crear Plan y Ejecutar Precheck"}
            </button>
          </form>
        </section>
      )}

      <section aria-labelledby="plans-queue-heading" className="space-y-3">
        <h2 id="plans-queue-heading" className="text-sm font-semibold text-slate-100">
          Cola de Planes de Parcheo ({plans.length})
        </h2>

        {loading ? (
          <p className="text-xs text-slate-400">Cargando planes de gobernanza...</p>
        ) : plans.length === 0 ? (
          <p className="rounded-md border border-slate-800 bg-[#0f172a] p-4 text-xs text-slate-400">
            No existen planes de parcheo todavía.
          </p>
        ) : (
          <ul role="list" className="space-y-3">
            {plans.map((plan) => {
              const isCreator = user?.id === plan.created_by;
              return (
                <li
                  key={plan.id}
                  className="space-y-3 rounded-md border border-slate-800 bg-[#0f172a] p-4 text-xs"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <PlanStatusBadge status={plan.status} />
                        <span className="text-sm font-semibold text-slate-100">{plan.title}</span>
                      </div>
                      <p className="font-mono text-[11px] text-slate-400">
                        Maker: {plan.created_by_username} · Paquetes:{" "}
                        <span className="text-sky-300">{plan.packages.join(", ")}</span> · Hosts:{" "}
                        {plan.target_host_ids.length} · Canario: {plan.canary_percent}% · Safe Mode:{" "}
                        {plan.policy.safe_mode_enabled === false
                          ? "OFF"
                          : `ON (máx. fallos: ${plan.policy.max_failed_hosts ?? 0}, inalcanzable: ${plan.policy.rollback_on_unreachable === false ? "no" : "rollback"})`}
                      </p>
                    </div>
                    <span className="font-mono text-[11px] text-slate-400 tabular-nums">
                      {plan.created_at.slice(0, 19).replace("T", " ")}Z
                    </span>
                  </div>

                  {plan.waves.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {plan.waves.map((w) => (
                        <span
                          key={w.wave_number}
                          className={`rounded border px-2 py-0.5 font-mono text-[11px] tabular-nums ${
                            plan.active_wave_number === w.wave_number
                              ? "border-sky-500 bg-sky-950 text-sky-200"
                              : "border-slate-700 bg-slate-950 text-slate-300"
                          }`}
                        >
                          {w.is_canary ? `Ola ${w.wave_number} (Canario)` : `Ola ${w.wave_number}`}:{" "}
                          {w.host_ids.length} host(s)
                        </span>
                      ))}
                    </div>
                  )}

                  {plan.status === "FAILED_PRECHECK" &&
                    (plan.precheck.blocked_host_ids?.length ?? 0) > 0 && (
                      <div
                        role="status"
                        className="rounded border border-red-800 bg-red-950/60 px-2.5 py-1.5 text-[11px] text-red-200"
                      >
                        Bloqueado en Precheck (sin repositorio firmado/accesible):{" "}
                        <span className="font-mono">
                          {plan.precheck.blocked_host_ids
                            ?.map((id) => hostNameById.get(id) ?? id)
                            .join(", ")}
                        </span>
                      </div>
                    )}

                  {plan.status === "DRY_RUN_READY" && canOperate && (
                    <div className="flex flex-wrap items-center gap-2 border-t border-slate-800 pt-3">
                      <button
                        type="button"
                        disabled={busyPlanId === plan.id}
                        onClick={() => void handleSubmitDryRun(plan)}
                        className="rounded-md border border-amber-600 bg-amber-950 px-3 py-1.5 font-semibold text-amber-200 hover:bg-amber-900 disabled:opacity-50"
                      >
                        Registrar Dry-Run Verificado
                      </button>
                      <span className="text-[11px] text-slate-400">
                        O esperar ejecución pull del agente (<code>hostgrid-agent patch</code>).
                      </span>
                    </div>
                  )}

                  {plan.status === "PENDING_APPROVAL" && canApprove && (
                    <div className="space-y-2 border-t border-slate-800 pt-3">
                      {isCreator ? (
                        <div
                          role="status"
                          className="inline-flex items-center gap-1.5 rounded border border-amber-700 bg-amber-950 px-2.5 py-1.5 text-amber-200"
                        >
                          <ShieldAlert className="h-4 w-4" aria-hidden="true" />
                          <span>
                            Bloqueo Maker-Checker: el creador del plan no puede auto-aprobarlo.
                          </span>
                        </div>
                      ) : (
                        <div className="flex flex-wrap items-center gap-2">
                          <label htmlFor={`rationale-${plan.id}`} className="sr-only">
                            Justificación de aprobación o rechazo
                          </label>
                          <input
                            id={`rationale-${plan.id}`}
                            type="text"
                            value={rationales[plan.id] ?? ""}
                            onChange={(e) =>
                              setRationales((prev) => ({ ...prev, [plan.id]: e.target.value }))
                            }
                            placeholder="Justificación auditable para WORM..."
                            className="min-w-[220px] flex-1 rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500"
                          />
                          <button
                            type="button"
                            disabled={busyPlanId === plan.id}
                            onClick={() => void handleDecision(plan, "approved")}
                            className="inline-flex items-center gap-1 rounded-md bg-emerald-500 px-3 py-1.5 font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50"
                          >
                            <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                            <span>Aprobar Plan</span>
                          </button>
                          <button
                            type="button"
                            disabled={busyPlanId === plan.id}
                            onClick={() => void handleDecision(plan, "rejected")}
                            className="inline-flex items-center gap-1 rounded-md border border-red-700 bg-red-950 px-3 py-1.5 font-semibold text-red-200 hover:bg-red-900 disabled:opacity-50"
                          >
                            <XCircle className="h-3.5 w-3.5" aria-hidden="true" />
                            <span>Rechazar</span>
                          </button>
                        </div>
                      )}
                    </div>
                  )}

                  {plan.status === "APPROVED" && canOperate && (
                    <div className="border-t border-slate-800 pt-3">
                      <button
                        type="button"
                        disabled={busyPlanId === plan.id}
                        onClick={() => void handleStartCanary(plan.id)}
                        className="inline-flex items-center gap-1.5 rounded-md bg-sky-500 px-3 py-1.5 font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
                      >
                        <Play className="h-3.5 w-3.5" aria-hidden="true" />
                        <span>Iniciar Oleada Canario</span>
                      </button>
                    </div>
                  )}

                  {(plan.status === "CANARY_WAVE" || plan.status === "ROLLOUT_IN_PROGRESS") &&
                    canOperate && (
                      <div className="flex flex-wrap items-center gap-2 border-t border-slate-800 pt-3">
                        <button
                          type="button"
                          disabled={busyPlanId === plan.id}
                          onClick={() => void handleWaveReport(plan, false)}
                          className="inline-flex items-center gap-1 rounded-md bg-emerald-500 px-3 py-1.5 font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50"
                        >
                          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                          <span>Confirmar Ola #{plan.active_wave_number ?? 1} Saludable</span>
                        </button>
                        <button
                          type="button"
                          disabled={busyPlanId === plan.id}
                          onClick={() => void handleWaveReport(plan, true)}
                          className="inline-flex items-center gap-1 rounded-md border border-orange-700 bg-orange-950 px-3 py-1.5 font-semibold text-orange-200 hover:bg-orange-900 disabled:opacity-50"
                        >
                          <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                          <span>Activar Rollback Safe Mode</span>
                        </button>
                      </div>
                    )}

                  {plan.approvals.length > 0 && (
                    <div className="border-t border-slate-800 pt-2 text-[11px] text-slate-300">
                      {plan.approvals.map((a) => (
                        <p key={a.id}>
                          <strong className="font-mono uppercase">{a.decision}</strong> por{" "}
                          <span className="font-mono text-sky-300">{a.approver_username}</span>:{" "}
                          {a.rationale}
                        </p>
                      ))}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <details className="hg-disclosure rounded-md border border-slate-800 bg-[#0f172a] p-4">
        <summary className="text-sm font-semibold text-slate-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400">
          <span>Bitácora Inmutable WORM (Últimos {auditLogs.length} eventos SHA-256)</span>
        </summary>
        <div
          tabIndex={0}
          role="region"
          aria-labelledby="worm-audit-caption"
          className="hg-table-wrapper hg-scroller mt-3 rounded border border-slate-800"
        >
          <table className="hg-data-table text-left text-xs">
            <caption id="worm-audit-caption" className="sr-only">
              Registros recientes de la bitácora WORM encadenada por SHA-256
            </caption>
            <thead>
              <tr className="border-b border-slate-700 text-[11px] uppercase text-slate-300">
                <th scope="col" className="px-3 py-2 text-right">Seq</th>
                <th scope="col" className="px-3 py-2">Fecha UTC</th>
                <th scope="col" className="px-3 py-2">Actor</th>
                <th scope="col" className="px-3 py-2">Acción</th>
                <th scope="col" className="px-3 py-2">Hash SHA-256</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono">
              {auditLogs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-900/70">
                  <th scope="row" className="px-3 py-2 text-right text-slate-200 tabular-nums">
                    #{log.seq_num}
                  </th>
                  <td data-label="Fecha UTC" className="px-3 py-2 text-slate-300 tabular-nums">
                    {log.occurred_at.slice(0, 19).replace("T", " ")}Z
                  </td>
                  <td data-label="Actor" className="px-3 py-2 text-sky-300">
                    {log.actor_username}
                  </td>
                  <td data-label="Acción" className="px-3 py-2 text-slate-100">
                    {log.action}
                  </td>
                  <td data-label="Hash SHA-256" className="px-3 py-2 text-slate-400">
                    {log.record_hash.slice(0, 16)}…
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
