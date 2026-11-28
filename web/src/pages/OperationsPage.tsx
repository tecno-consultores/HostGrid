import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type FormEvent,
} from "react";
import {
  Check,
  Copy,
  KeyRound,
  PackageCheck,
  RefreshCw,
  ShieldAlert,
  Unlock,
  UserPlus,
  Users,
} from "lucide-react";
import { ApiError, hostGridApi } from "../api/client";
import { useAuth } from "../context/AuthContext";
import type {
  EnrollmentTokenResponse,
  EnvironmentType,
  ToolBundleArch,
  ToolBundleManifestResponse,
  UserProfile,
  UserRole,
} from "../types/api";

const MAX_TOOL_BUNDLE_BYTES = 50 * 1024 * 1024;
const USERNAME_RE = /^[a-zA-Z0-9._-]{3,64}$/;
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const SAFE_SEGMENT_RE = /^[a-zA-Z0-9._-]{1,128}$/;
const UNSAFE_SHELL_OR_WS_RE = /[\s;&|$()`'"<>\\]/;

function hasAsciiControlChar(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function isValidAgentServerUrl(raw: string): boolean {
  const trimmed = raw.trim();
  if (!trimmed || UNSAFE_SHELL_OR_WS_RE.test(trimmed) || hasAsciiControlChar(trimmed)) {
    return false;
  }
  try {
    const parsed = new URL(trimmed);
    if (!parsed.host || parsed.username || parsed.password) {
      return false;
    }
    if (parsed.protocol === "https:") {
      return true;
    }
    if (parsed.protocol === "http:") {
      return (
        parsed.hostname === "127.0.0.1" ||
        parsed.hostname === "localhost" ||
        parsed.hostname === "[::1]" ||
        parsed.hostname === "::1"
      );
    }
    return false;
  } catch {
    return false;
  }
}

let lastCopyAnnouncement = "";

function CopyActionButton({
  value,
  label,
}: {
  readonly value: string;
  readonly label: string;
}) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const [tipText, setTipText] = useState("");
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
      }
    };
  }, []);

  const handleCopy = async () => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    let ok = false;
    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        await navigator.clipboard.writeText(value);
        ok = true;
      }
    } catch {
      ok = false;
    }

    let message = ok ? "Copiado" : "Error al copiar";
    if (message === lastCopyAnnouncement) {
      message += "\u00A0";
    }
    lastCopyAnnouncement = message;

    setState(ok ? "copied" : "failed");
    setTipText(message);
    timerRef.current = window.setTimeout(() => {
      setState("idle");
      setTipText("");
      timerRef.current = null;
    }, 2000);
  };

  return (
    <span className="inline-flex items-center gap-1.5">
      <button
        type="button"
        onClick={() => void handleCopy()}
        aria-label={label}
        data-copied={state === "copied" ? "" : undefined}
        data-failed={state === "failed" ? "" : undefined}
        className="hg-copy-btn inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] font-medium text-slate-200 hover:bg-slate-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400"
      >
        {state === "copied" ? (
          <Check className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
        ) : (
          <Copy className="h-3.5 w-3.5" aria-hidden="true" />
        )}
        <span>Copiar</span>
      </button>
      <span
        role="status"
        className={`hg-copy-tip text-[11px] font-medium ${
          state === "failed" ? "text-red-300" : "text-emerald-300"
        }`}
      >
        {tipText}
      </span>
    </span>
  );
}

export function OperationsPage() {
  const { user } = useAuth();
  const canOperate = user?.role === "operator" || user?.role === "admin";
  const isAdmin = user?.role === "admin";

  const [fieldAnnouncement, setFieldAnnouncement] = useState("");

  // --- Enrollment tokens state (operator / admin) ---
  const [enrollLabel, setEnrollLabel] = useState("");
  const [enrollLabelTouched, setEnrollLabelTouched] = useState(false);
  const [enrollEnv, setEnrollEnv] = useState<EnvironmentType>("prod");
  const [enrollTtlInput, setEnrollTtlInput] = useState("60");
  const [enrollTtlTouched, setEnrollTtlTouched] = useState(false);
  const [enrollServerUrl, setEnrollServerUrl] = useState("https://controlplane.internal:8443");
  const [enrollServerUrlTouched, setEnrollServerUrlTouched] = useState(false);
  const [issuingToken, setIssuingToken] = useState(false);
  const [enrollError, setEnrollError] = useState<string | null>(null);
  const [issuedToken, setIssuedToken] = useState<EnrollmentTokenResponse | null>(null);

  const enrollLabelRef = useRef<HTMLInputElement | null>(null);
  const enrollTtlRef = useRef<HTMLInputElement | null>(null);
  const enrollServerUrlRef = useRef<HTMLInputElement | null>(null);

  const enrollLabelBad = enrollLabel.trim().length < 1 || enrollLabel.trim().length > 128;
  const parsedEnrollTtl = enrollTtlInput.trim() === "" ? Number.NaN : Number(enrollTtlInput);
  const enrollTtlBad =
    !Number.isInteger(parsedEnrollTtl) || parsedEnrollTtl < 5 || parsedEnrollTtl > 10080;
  const enrollServerUrlBad = !isValidAgentServerUrl(enrollServerUrl);
  const enrollLabelInvalid = enrollLabelTouched && enrollLabelBad;
  const enrollTtlInvalid = enrollTtlTouched && enrollTtlBad;
  const enrollServerUrlInvalid = enrollServerUrlTouched && enrollServerUrlBad;

  // --- Tool bundle registry state (operator / admin) ---
  const [bundleTool, setBundleTool] = useState("lynis");
  const [bundleToolTouched, setBundleToolTouched] = useState(false);
  const [bundleVersion, setBundleVersion] = useState("");
  const [bundleVersionTouched, setBundleVersionTouched] = useState(false);
  const [bundleArch, setBundleArch] = useState<ToolBundleArch>("noarch");
  const [bundleFile, setBundleFile] = useState<File | null>(null);
  const [bundleFileError, setBundleFileError] = useState<string | null>(null);
  const [bundleSig, setBundleSig] = useState("");
  const [registeringBundle, setRegisteringBundle] = useState(false);
  const [bundleError, setBundleError] = useState<string | null>(null);
  const [registeredBundle, setRegisteredBundle] = useState<ToolBundleManifestResponse | null>(null);

  const bundleToolRef = useRef<HTMLInputElement | null>(null);
  const bundleVersionRef = useRef<HTMLInputElement | null>(null);
  const bundleFileRef = useRef<HTMLInputElement | null>(null);

  const bundleToolBad = !SAFE_SEGMENT_RE.test(bundleTool.trim()) || bundleTool.includes("..");
  const bundleVersionBad =
    !SAFE_SEGMENT_RE.test(bundleVersion.trim()) || bundleVersion.includes("..");
  const bundleToolInvalid = bundleToolTouched && bundleToolBad;
  const bundleVersionInvalid = bundleVersionTouched && bundleVersionBad;

  // --- RBAC user management state (admin only) ---
  const [users, setUsers] = useState<readonly UserProfile[]>([]);
  const [usersTotal, setUsersTotal] = useState<number>(0);
  const [usersLoading, setUsersLoading] = useState(false);
  const [usersError, setUsersError] = useState<string | null>(null);
  const [usersNotice, setUsersNotice] = useState<string | null>(null);
  const [busyUserId, setBusyUserId] = useState<string | null>(null);

  const [newUsername, setNewUsername] = useState("");
  const [newUsernameTouched, setNewUsernameTouched] = useState(false);
  const [newEmail, setNewEmail] = useState("");
  const [newEmailTouched, setNewEmailTouched] = useState(false);
  const [newPassword, setNewPassword] = useState("");
  const [newPasswordTouched, setNewPasswordTouched] = useState(false);
  const [newRole, setNewRole] = useState<UserRole>("viewer");

  const newUsernameRef = useRef<HTMLInputElement | null>(null);
  const newEmailRef = useRef<HTMLInputElement | null>(null);
  const newPasswordRef = useRef<HTMLInputElement | null>(null);

  const usernameBad = !USERNAME_RE.test(newUsername.trim());
  const emailBad = !EMAIL_RE.test(newEmail.trim());
  const passwordBad = newPassword.length < 12;
  const usernameInvalid = newUsernameTouched && usernameBad;
  const emailInvalid = newEmailTouched && emailBad;
  const passwordInvalid = newPasswordTouched && passwordBad;

  const loadUsers = useCallback(async () => {
    if (!isAdmin) return;
    setUsersLoading(true);
    setUsersError(null);
    try {
      const res = await hostGridApi.listUsers(100, 0);
      setUsers(res.items);
      setUsersTotal(res.total);
    } catch (err) {
      setUsersError(err instanceof ApiError ? err.detail : "Error cargando usuarios RBAC.");
    } finally {
      setUsersLoading(false);
    }
  }, [isAdmin]);

  useEffect(() => {
    void loadUsers();
  }, [loadUsers]);

  const handleIssueToken = async (evt: FormEvent<HTMLFormElement>) => {
    evt.preventDefault();
    setEnrollLabelTouched(true);
    setEnrollTtlTouched(true);
    setEnrollServerUrlTouched(true);
    setEnrollError(null);

    if (enrollLabelBad) {
      enrollLabelRef.current?.focus();
      return;
    }
    if (enrollTtlBad) {
      enrollTtlRef.current?.focus();
      return;
    }
    if (enrollServerUrlBad) {
      enrollServerUrlRef.current?.focus();
      return;
    }

    setIssuingToken(true);
    try {
      const res = await hostGridApi.createEnrollmentToken({
        label: enrollLabel.trim(),
        environment: enrollEnv,
        ttl_minutes: parsedEnrollTtl,
      });
      setIssuedToken(res);
      setEnrollLabel("");
      setEnrollLabelTouched(false);
      setEnrollTtlTouched(false);
      setEnrollServerUrlTouched(false);
      setFieldAnnouncement("");
    } catch (err) {
      setEnrollError(
        err instanceof ApiError ? err.detail : "Error emitiendo token de enrolamiento."
      );
    } finally {
      setIssuingToken(false);
    }
  };

  const handleBundleFileChange = (evt: ChangeEvent<HTMLInputElement>) => {
    setBundleFileError(null);
    setBundleError(null);
    const picked = evt.target.files?.[0] ?? null;
    if (!picked) {
      setBundleFile(null);
      return;
    }
    if (!picked.name.endsWith(".tar.gz") && !picked.name.endsWith(".tgz")) {
      setBundleFile(null);
      setBundleFileError("Solo se permiten archivos portables .tar.gz (o .tgz).");
      setFieldAnnouncement("Error en Archivo portable: formato no admitido, selecciona un .tar.gz o .tgz.");
      evt.target.value = "";
      return;
    }
    if (picked.size > MAX_TOOL_BUNDLE_BYTES) {
      setBundleFile(null);
      setBundleFileError("El bundle supera el límite máximo permitido de 50 MB.");
      setFieldAnnouncement("Error en Archivo portable: el archivo excede el límite de 50 MB.");
      evt.target.value = "";
      return;
    }
    setBundleFile(picked);
  };

  const handleRegisterBundle = async (evt: FormEvent<HTMLFormElement>) => {
    evt.preventDefault();
    setBundleToolTouched(true);
    setBundleVersionTouched(true);
    setBundleError(null);
    setBundleFileError(null);
    setRegisteredBundle(null);

    if (bundleToolBad) {
      bundleToolRef.current?.focus();
      return;
    }
    if (bundleVersionBad) {
      bundleVersionRef.current?.focus();
      return;
    }
    if (!bundleFile) {
      setBundleFileError("Selecciona el archivo .tar.gz del bundle portable.");
      bundleFileRef.current?.focus();
      return;
    }

    setRegisteringBundle(true);
    try {
      const manifest = await hostGridApi.registerToolBundle({
        tool_name: bundleTool.trim(),
        version: bundleVersion.trim(),
        arch: bundleArch,
        file: bundleFile,
        signature_b64: bundleSig.trim() || undefined,
      });
      setRegisteredBundle(manifest);
      setBundleVersion("");
      setBundleVersionTouched(false);
      setBundleFile(null);
      setBundleSig("");
      if (bundleFileRef.current) {
        bundleFileRef.current.value = "";
      }
      setFieldAnnouncement("");
    } catch (err) {
      setBundleError(
        err instanceof ApiError ? err.detail : "Error registrando bundle portable firmado."
      );
    } finally {
      setRegisteringBundle(false);
    }
  };

  const handleCreateUser = async (evt: FormEvent<HTMLFormElement>) => {
    evt.preventDefault();
    setNewUsernameTouched(true);
    setNewEmailTouched(true);
    setNewPasswordTouched(true);
    setUsersError(null);
    setUsersNotice(null);

    if (usernameBad) {
      newUsernameRef.current?.focus();
      return;
    }
    if (emailBad) {
      newEmailRef.current?.focus();
      return;
    }
    if (passwordBad) {
      newPasswordRef.current?.focus();
      return;
    }

    setBusyUserId("create");
    try {
      const created = await hostGridApi.createUser({
        username: newUsername.trim(),
        email: newEmail.trim(),
        password: newPassword,
        role: newRole,
      });
      setNewUsername("");
      setNewUsernameTouched(false);
      setNewEmail("");
      setNewEmailTouched(false);
      setNewPassword("");
      setNewPasswordTouched(false);
      setNewRole("viewer");
      setFieldAnnouncement("");
      setUsersNotice(`Usuario "${created.username}" creado con rol ${created.role}.`);
      await loadUsers();
    } catch (err) {
      setUsersError(err instanceof ApiError ? err.detail : "Error creando cuenta de usuario.");
    } finally {
      setBusyUserId(null);
    }
  };

  const handleRoleChange = async (target: UserProfile, role: UserRole) => {
    setBusyUserId(target.id);
    setUsersError(null);
    setUsersNotice(null);
    try {
      const updated = await hostGridApi.updateUser(target.id, { role });
      setUsersNotice(`Rol de "${updated.username}" actualizado a ${updated.role}.`);
      await loadUsers();
    } catch (err) {
      setUsersError(err instanceof ApiError ? err.detail : "Error actualizando rol del usuario.");
    } finally {
      setBusyUserId(null);
    }
  };

  const handleToggleActive = async (target: UserProfile) => {
    setBusyUserId(target.id);
    setUsersError(null);
    setUsersNotice(null);
    try {
      const updated = await hostGridApi.updateUser(target.id, { is_active: !target.is_active });
      setUsersNotice(
        `Cuenta "${updated.username}" ${updated.is_active ? "activada" : "desactivada"}.`
      );
      await loadUsers();
    } catch (err) {
      setUsersError(
        err instanceof ApiError ? err.detail : "Error actualizando estado de la cuenta."
      );
    } finally {
      setBusyUserId(null);
    }
  };

  const handleUnlockUser = async (target: UserProfile) => {
    setBusyUserId(target.id);
    setUsersError(null);
    setUsersNotice(null);
    try {
      const updated = await hostGridApi.updateUser(target.id, { unlock: true });
      setUsersNotice(`Bloqueo de inicio de sesión restablecido para "${updated.username}".`);
      await loadUsers();
    } catch (err) {
      setUsersError(err instanceof ApiError ? err.detail : "Error desbloqueando cuenta.");
    } finally {
      setBusyUserId(null);
    }
  };

  const safeServerUrl = isValidAgentServerUrl(enrollServerUrl)
    ? enrollServerUrl.trim()
    : "https://controlplane.internal:8443";
  const enrollCommand = issuedToken
    ? `hostgrid-agent enroll --server ${safeServerUrl} --token ${issuedToken.enrollment_token} --mode ${issuedToken.environment === "dmz" ? "relay" : "lan"} --env ${issuedToken.environment} --ca-cert /etc/hostgrid/ca.pem`
    : "";

  if (!canOperate) {
    return (
      <div className="space-y-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-50">
            Operaciones y Administración RBAC
          </h1>
          <p className="text-xs text-slate-400">
            Tokens de enrolamiento de agentes, catálogo de bundles firmados y gestión de usuarios
          </p>
        </div>
        <div
          role="status"
          className="flex items-start gap-2 rounded-md border border-amber-700 bg-amber-950 p-4 text-xs text-amber-200"
        >
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          <span>
            Tu rol actual (<strong className="font-mono uppercase">{user?.role}</strong>) no tiene
            permisos en esta sección. Según la matriz RBAC (SPEC.md §1.2), se requiere rol{" "}
            <code className="font-mono">operator</code> o <code className="font-mono">admin</code>{" "}
            para emitir tokens y registrar bundles, y <code className="font-mono">admin</code> para
            gestionar usuarios.
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div aria-live="polite" className="sr-only">
        {fieldAnnouncement}
      </div>

      <div>
        <h1 className="text-xl font-semibold text-slate-50">
          Operaciones y Administración RBAC
        </h1>
        <p className="text-xs text-slate-400">
          Emisión de tokens de enrolamiento de un solo uso, registro de bundles portables firmados (Lynis) y administración de cuentas RBAC
        </p>
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* 1. Enrollment Tokens (operator / admin) */}
        <section
          aria-labelledby="enrollment-tokens-heading"
          className="space-y-4 rounded-md border border-slate-800 bg-[#0f172a] p-4"
        >
          <div className="flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-sky-400" aria-hidden="true" />
            <h2 id="enrollment-tokens-heading" className="text-sm font-semibold text-slate-100">
              Tokens de Enrolamiento de Agentes
            </h2>
          </div>

          {enrollError && (
            <div role="alert" className="rounded border border-red-800 bg-red-950 p-3 text-xs text-red-200">
              {enrollError}
            </div>
          )}

          <form
            aria-labelledby="enrollment-tokens-heading"
            onSubmit={(e) => void handleIssueToken(e)}
            noValidate
            className="space-y-3"
          >
            <div>
              <label htmlFor="enroll-label" className="mb-1 block text-xs font-medium text-slate-300">
                Etiqueta del token
              </label>
              <input
                ref={enrollLabelRef}
                id="enroll-label"
                type="text"
                required
                minLength={1}
                maxLength={128}
                aria-invalid={enrollLabelInvalid ? "true" : "false"}
                aria-describedby={enrollLabelInvalid ? "enroll-label-err" : undefined}
                value={enrollLabel}
                onBlur={() => {
                  setEnrollLabelTouched(true);
                  if (enrollLabelBad) {
                    setFieldAnnouncement("Error en Etiqueta del token: ingresa entre 1 y 128 caracteres.");
                  }
                }}
                onChange={(e) => setEnrollLabel(e.target.value)}
                placeholder="Ej: dmz-web-cluster-01"
                className="hg-field-control w-full rounded border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-100 placeholder-slate-500"
              />
              {enrollLabelInvalid && (
                <p id="enroll-label-err" className="mt-1 text-[11px] text-red-300">
                  Error: ingresa una etiqueta descriptiva (1–128 caracteres).
                </p>
              )}
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label htmlFor="enroll-env" className="mb-1 block text-xs font-medium text-slate-300">
                  Entorno objetivo
                </label>
                <select
                  id="enroll-env"
                  value={enrollEnv}
                  onChange={(e) => setEnrollEnv(e.target.value as EnvironmentType)}
                  className="w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-100"
                >
                  <option value="prod">prod (Producción)</option>
                  <option value="dmz">dmz (Zona DMZ / Relay)</option>
                  <option value="staging">staging</option>
                  <option value="dev">dev</option>
                </select>
              </div>

              <div>
                <label htmlFor="enroll-ttl" className="mb-1 block text-xs font-medium text-slate-300">
                  Vigencia TTL (5–10080 min)
                </label>
                <input
                  ref={enrollTtlRef}
                  id="enroll-ttl"
                  type="number"
                  required
                  min={5}
                  max={10080}
                  aria-invalid={enrollTtlInvalid ? "true" : "false"}
                  aria-describedby={enrollTtlInvalid ? "enroll-ttl-err" : undefined}
                  value={enrollTtlInput}
                  onBlur={() => {
                    setEnrollTtlTouched(true);
                    if (enrollTtlBad) {
                      setFieldAnnouncement("Error en Vigencia TTL: ingresa un entero entre 5 y 10080 minutos.");
                    }
                  }}
                  onChange={(e) => setEnrollTtlInput(e.target.value)}
                  className="hg-field-control w-full rounded border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-100 tabular-nums"
                />
                {enrollTtlInvalid && (
                  <p id="enroll-ttl-err" className="mt-1 text-[11px] text-red-300">
                    Error: la vigencia TTL debe estar entre 5 y 10080 minutos.
                  </p>
                )}
              </div>
            </div>

            <div>
              <label
                htmlFor="enroll-server-url"
                className="mb-1 block text-xs font-medium text-slate-300"
              >
                URL HTTPS del Control Plane / Relay (para comando generado)
              </label>
              <input
                ref={enrollServerUrlRef}
                id="enroll-server-url"
                type="url"
                required
                autoCorrect="off"
                autoCapitalize="none"
                spellCheck={false}
                aria-invalid={enrollServerUrlInvalid ? "true" : "false"}
                aria-describedby={enrollServerUrlInvalid ? "enroll-server-url-err" : undefined}
                value={enrollServerUrl}
                onBlur={() => {
                  setEnrollServerUrlTouched(true);
                  if (enrollServerUrlBad) {
                    setFieldAnnouncement(
                      "Error en URL HTTPS del Control Plane: usa https:// válido sin espacios ni metacaracteres."
                    );
                  }
                }}
                onChange={(e) => setEnrollServerUrl(e.target.value)}
                className="hg-field-control w-full rounded border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-100"
              />
              {enrollServerUrlInvalid && (
                <p id="enroll-server-url-err" className="mt-1 text-[11px] text-red-300">
                  Error: ingresa una URL https:// válida (o loopback http://127.0.0.1) sin espacios ni metacaracteres de shell.
                </p>
              )}
            </div>

            <button
              type="submit"
              disabled={issuingToken}
              className="rounded-md bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
            >
              {issuingToken ? "Generando token..." : "Emitir Token de Enrolamiento"}
            </button>
          </form>

          {issuedToken && (
            <div
              role="status"
              className="space-y-3 rounded-md border border-emerald-700 bg-emerald-950/60 p-3 text-xs text-emerald-100"
            >
              <p className="font-semibold">
                Token de un solo uso emitido — cópialo ahora, no volverá a mostrarse en claro
              </p>
              <p className="font-mono text-[11px] text-emerald-200 tabular-nums">
                Etiqueta: {issuedToken.label} · Entorno: {issuedToken.environment} · Expira:{" "}
                {issuedToken.expires_at}
              </p>

              <div className="space-y-1">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[11px] font-medium text-slate-200">Token secreto</span>
                  <CopyActionButton
                    value={issuedToken.enrollment_token}
                    label="Copiar token de enrolamiento"
                  />
                </div>
                <code
                  id="issued-enroll-token"
                  className="block overflow-x-auto rounded border border-slate-800 bg-slate-950 p-2 font-mono text-[11px] text-sky-300"
                >
                  {issuedToken.enrollment_token}
                </code>
              </div>

              <div className="space-y-1">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[11px] font-medium text-slate-200">
                    Comando listo para el servidor Linux
                  </span>
                  <CopyActionButton
                    value={enrollCommand}
                    label="Copiar comando hostgrid-agent enroll"
                  />
                </div>
                <pre className="overflow-x-auto rounded border border-slate-800 bg-slate-950 p-2 font-mono text-[11px] text-slate-100">
                  <code id="issued-enroll-command">{enrollCommand}</code>
                </pre>
              </div>
            </div>
          )}
        </section>

        {/* 2. Portable Signed Tool Bundles (operator / admin) */}
        <section
          aria-labelledby="tool-bundles-heading"
          className="space-y-4 rounded-md border border-slate-800 bg-[#0f172a] p-4"
        >
          <div className="flex items-center gap-2">
            <PackageCheck className="h-5 w-5 text-sky-400" aria-hidden="true" />
            <h2 id="tool-bundles-heading" className="text-sm font-semibold text-slate-100">
              Registro de Bundles Portables Firmados (Lynis)
            </h2>
          </div>

          {bundleError && (
            <div role="alert" className="rounded border border-red-800 bg-red-950 p-3 text-xs text-red-200">
              {bundleError}
            </div>
          )}

          <form
            aria-labelledby="tool-bundles-heading"
            onSubmit={(e) => void handleRegisterBundle(e)}
            noValidate
            className="space-y-3"
          >
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div>
                <label htmlFor="bundle-tool" className="mb-1 block text-xs font-medium text-slate-300">
                  Herramienta
                </label>
                <input
                  ref={bundleToolRef}
                  id="bundle-tool"
                  type="text"
                  required
                  autoCorrect="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  aria-invalid={bundleToolInvalid ? "true" : "false"}
                  aria-describedby={bundleToolInvalid ? "bundle-tool-err" : undefined}
                  value={bundleTool}
                  onBlur={() => {
                    setBundleToolTouched(true);
                    if (bundleToolBad) {
                      setFieldAnnouncement("Error en Herramienta: usa solo caracteres alfanuméricos, puntos, guiones o guion bajo.");
                    }
                  }}
                  onChange={(e) => setBundleTool(e.target.value)}
                  className="hg-field-control w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 font-mono text-xs text-slate-100"
                />
                {bundleToolInvalid && (
                  <p id="bundle-tool-err" className="mt-1 text-[11px] text-red-300">
                    Error: nombre de herramienta inválido.
                  </p>
                )}
              </div>

              <div>
                <label
                  htmlFor="bundle-version"
                  className="mb-1 block text-xs font-medium text-slate-300"
                >
                  Versión
                </label>
                <input
                  ref={bundleVersionRef}
                  id="bundle-version"
                  type="text"
                  required
                  autoCorrect="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  aria-invalid={bundleVersionInvalid ? "true" : "false"}
                  aria-describedby={bundleVersionInvalid ? "bundle-version-err" : undefined}
                  value={bundleVersion}
                  onBlur={() => {
                    setBundleVersionTouched(true);
                    if (bundleVersionBad) {
                      setFieldAnnouncement("Error en Versión: ingresa una versión válida (ej. 3.1.4).");
                    }
                  }}
                  onChange={(e) => setBundleVersion(e.target.value)}
                  placeholder="3.1.4"
                  className="hg-field-control w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 font-mono text-xs text-slate-100 placeholder-slate-500"
                />
                {bundleVersionInvalid && (
                  <p id="bundle-version-err" className="mt-1 text-[11px] text-red-300">
                    Error: versión obligatoria (ej. 3.1.4).
                  </p>
                )}
              </div>

              <div>
                <label htmlFor="bundle-arch" className="mb-1 block text-xs font-medium text-slate-300">
                  Arquitectura
                </label>
                <select
                  id="bundle-arch"
                  value={bundleArch}
                  onChange={(e) => setBundleArch(e.target.value as ToolBundleArch)}
                  className="w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 font-mono text-xs text-slate-100"
                >
                  <option value="noarch">noarch (portable)</option>
                  <option value="amd64">amd64</option>
                  <option value="arm64">arm64</option>
                  <option value="386">386</option>
                </select>
              </div>
            </div>

            <div>
              <label htmlFor="bundle-file" className="mb-1 block text-xs font-medium text-slate-300">
                Archivo portable (.tar.gz)
              </label>
              <input
                ref={bundleFileRef}
                id="bundle-file"
                type="file"
                accept=".tar.gz,.tgz"
                aria-invalid={bundleFileError ? "true" : "false"}
                aria-describedby={bundleFileError ? "bundle-file-err" : undefined}
                onChange={handleBundleFileChange}
                className="hg-field-control block w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-200 file:mr-3 file:rounded file:border-0 file:bg-slate-800 file:px-2.5 file:py-1 file:text-xs file:font-medium file:text-sky-300"
              />
              {bundleFile && (
                <p className="mt-1 font-mono text-[11px] text-emerald-300">
                  Seleccionado: {bundleFile.name} ({(bundleFile.size / 1024).toFixed(1)} KB)
                </p>
              )}
              {bundleFileError && (
                <p id="bundle-file-err" className="mt-1 text-[11px] text-red-300">
                  {bundleFileError}
                </p>
              )}
            </div>

            <div>
              <label
                htmlFor="bundle-signature"
                className="mb-1 block text-xs font-medium text-slate-300"
              >
                Firma Ed25519 en Base64 (opcional si el servidor tiene clave de firma configurada)
              </label>
              <input
                id="bundle-signature"
                type="text"
                autoCorrect="off"
                autoCapitalize="none"
                spellCheck={false}
                value={bundleSig}
                onChange={(e) => setBundleSig(e.target.value)}
                placeholder="Dejar vacío para firma automática del servidor o pegar .manifest.sig"
                className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-100 placeholder-slate-500"
              />
            </div>

            <button
              type="submit"
              disabled={registeringBundle}
              className="rounded-md bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
            >
              {registeringBundle ? "Registrando y firmando..." : "Registrar Bundle Portable"}
            </button>
          </form>

          {registeredBundle && (
            <div
              role="status"
              className="space-y-1.5 rounded-md border border-emerald-700 bg-emerald-950/60 p-3 text-xs text-emerald-100"
            >
              <p className="font-semibold">
                Bundle portable registrado y publicado para descarga verificada
              </p>
              <p className="font-mono text-[11px]">
                {registeredBundle.tool_name} v{registeredBundle.version} ({registeredBundle.arch}) ·{" "}
                {registeredBundle.filename} ({registeredBundle.size_bytes} bytes)
              </p>
              <p className="break-all font-mono text-[11px] text-emerald-200">
                SHA-256: {registeredBundle.sha256}
              </p>
              <p className="font-mono text-[11px] text-sky-300">
                Descarga: {registeredBundle.download_url}
              </p>
            </div>
          )}
        </section>
      </div>

      {/* 3. RBAC User Management (admin only) */}
      <section
        aria-labelledby="rbac-users-heading"
        className="space-y-4 rounded-md border border-slate-800 bg-[#0f172a] p-4"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Users className="h-5 w-5 text-sky-400" aria-hidden="true" />
            <h2 id="rbac-users-heading" className="text-sm font-semibold text-slate-100">
              Gestión de Usuarios y Roles RBAC{isAdmin ? ` (${usersTotal})` : ""}
            </h2>
          </div>
          {isAdmin && (
            <button
              type="button"
              onClick={() => void loadUsers()}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-3 py-1 text-xs font-medium text-slate-200 hover:bg-slate-800"
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Actualizar usuarios</span>
            </button>
          )}
        </div>

        {!isAdmin ? (
          <div
            role="status"
            className="rounded border border-slate-700 bg-slate-950 p-3 text-xs text-slate-300"
          >
            La administración de usuarios, roles RBAC y desbloqueo de cuentas está restringida al
            rol <code className="font-mono text-sky-300">admin</code> (SPEC.md §1.2).
          </div>
        ) : (
          <div className="space-y-5">
            {usersError && (
              <div role="alert" className="rounded border border-red-800 bg-red-950 p-3 text-xs text-red-200">
                {usersError}
              </div>
            )}
            {usersNotice && (
              <div
                role="status"
                aria-live="polite"
                className="rounded border border-emerald-700 bg-emerald-950 p-3 text-xs text-emerald-100"
              >
                {usersNotice}
              </div>
            )}

            <form
              aria-labelledby="create-user-heading"
              onSubmit={(e) => void handleCreateUser(e)}
              noValidate
              className="space-y-3 rounded border border-slate-800 bg-slate-950/60 p-3"
            >
              <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-200">
                <UserPlus className="h-4 w-4 text-sky-400" aria-hidden="true" />
                <span id="create-user-heading">Crear cuenta de usuario</span>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <div>
                  <label
                    htmlFor="new-user-username"
                    className="mb-1 block text-xs font-medium text-slate-300"
                  >
                    Usuario
                  </label>
                  <input
                    ref={newUsernameRef}
                    id="new-user-username"
                    type="text"
                    required
                    minLength={3}
                    maxLength={64}
                    autoComplete="off"
                    autoCorrect="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    aria-invalid={usernameInvalid ? "true" : "false"}
                    aria-describedby={usernameInvalid ? "new-user-username-err" : undefined}
                    value={newUsername}
                    onBlur={() => {
                      setNewUsernameTouched(true);
                      if (usernameBad) {
                        setFieldAnnouncement("Error en Usuario: usa 3–64 caracteres alfanuméricos, punto, guion o guion bajo.");
                      }
                    }}
                    onChange={(e) => setNewUsername(e.target.value)}
                    placeholder="sec_approver"
                    className="hg-field-control w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 font-mono text-xs text-slate-100 placeholder-slate-500"
                  />
                  {usernameInvalid && (
                    <p id="new-user-username-err" className="mt-1 text-[11px] text-red-300">
                      Error: 3–64 caracteres (a-z, 0-9, ., _, -).
                    </p>
                  )}
                </div>

                <div>
                  <label
                    htmlFor="new-user-email"
                    className="mb-1 block text-xs font-medium text-slate-300"
                  >
                    Correo electrónico
                  </label>
                  <input
                    ref={newEmailRef}
                    id="new-user-email"
                    type="email"
                    required
                    autoComplete="off"
                    autoCorrect="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    aria-invalid={emailInvalid ? "true" : "false"}
                    aria-describedby={emailInvalid ? "new-user-email-err" : undefined}
                    value={newEmail}
                    onBlur={() => {
                      setNewEmailTouched(true);
                      if (emailBad) {
                        setFieldAnnouncement("Error en Correo electrónico: ingresa un formato válido.");
                      }
                    }}
                    onChange={(e) => setNewEmail(e.target.value)}
                    placeholder="approver@corp.internal"
                    className="hg-field-control w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500"
                  />
                  {emailInvalid && (
                    <p id="new-user-email-err" className="mt-1 text-[11px] text-red-300">
                      Error: ingresa un correo electrónico válido.
                    </p>
                  )}
                </div>

                <div>
                  <label
                    htmlFor="new-user-password"
                    className="mb-1 block text-xs font-medium text-slate-300"
                  >
                    Contraseña inicial (mín. 12)
                  </label>
                  <input
                    ref={newPasswordRef}
                    id="new-user-password"
                    type="password"
                    required
                    minLength={12}
                    autoComplete="new-password"
                    aria-invalid={passwordInvalid ? "true" : "false"}
                    aria-describedby={passwordInvalid ? "new-user-password-err" : undefined}
                    value={newPassword}
                    onBlur={() => {
                      setNewPasswordTouched(true);
                      if (passwordBad) {
                        setFieldAnnouncement("Error en Contraseña: se requieren al menos 12 caracteres.");
                      }
                    }}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="hg-field-control w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-100"
                  />
                  {passwordInvalid && (
                    <p id="new-user-password-err" className="mt-1 text-[11px] text-red-300">
                      Error: mínimo 12 caracteres obligatorios.
                    </p>
                  )}
                </div>

                <div>
                  <label
                    htmlFor="new-user-role"
                    className="mb-1 block text-xs font-medium text-slate-300"
                  >
                    Rol RBAC
                  </label>
                  <select
                    id="new-user-role"
                    value={newRole}
                    onChange={(e) => setNewRole(e.target.value as UserRole)}
                    className="w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-100"
                  >
                    <option value="viewer">viewer (solo lectura)</option>
                    <option value="operator">operator (Maker / ingesta)</option>
                    <option value="approver">approver (Checker)</option>
                    <option value="admin">admin (administración total)</option>
                  </select>
                </div>
              </div>

              <button
                type="submit"
                disabled={busyUserId === "create"}
                className="rounded-md bg-sky-500 px-4 py-1.5 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
              >
                {busyUserId === "create" ? "Creando cuenta..." : "Crear Usuario"}
              </button>
            </form>

            {usersLoading && users.length === 0 ? (
              <p className="text-xs text-slate-400">Cargando directorio de usuarios...</p>
            ) : (
              <div
                tabIndex={0}
                role="region"
                aria-labelledby="rbac-users-caption"
                className="hg-table-wrapper hg-scroller rounded border border-slate-800"
              >
                <table className="hg-data-table text-left text-xs">
                  <caption id="rbac-users-caption" className="sr-only">
                    Usuarios registrados en HostGrid y controles de rol, activación y desbloqueo
                  </caption>
                  <thead>
                    <tr className="border-b border-slate-700 text-[11px] uppercase text-slate-300">
                      <th scope="col" className="px-3 py-2">Usuario</th>
                      <th scope="col" className="px-3 py-2">Correo</th>
                      <th scope="col" className="px-3 py-2">Rol RBAC</th>
                      <th scope="col" className="px-3 py-2">Estado</th>
                      <th scope="col" className="px-3 py-2">Acciones</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {users.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="px-3 py-4 text-center text-slate-400">
                          No hay cuentas registradas.
                        </td>
                      </tr>
                    ) : (
                      users.map((u) => {
                        const isSelf = u.id === user?.id;
                        const isBusy = busyUserId === u.id;
                        return (
                          <tr key={u.id} className="hover:bg-slate-900/70">
                            <th scope="row" className="px-3 py-2 font-mono text-slate-100">
                              {u.username}
                              {isSelf && (
                                <span className="ml-1.5 rounded border border-sky-800 bg-sky-950 px-1 py-0.5 text-[10px] font-normal text-sky-200">
                                  Tu cuenta
                                </span>
                              )}
                            </th>
                            <td data-label="Correo" className="px-3 py-2 text-slate-300">
                              {u.email}
                            </td>
                            <td data-label="Rol RBAC" className="px-3 py-2">
                              <select
                                aria-label={`Rol de ${u.username}`}
                                value={u.role}
                                disabled={isSelf || isBusy}
                                onChange={(e) =>
                                  void handleRoleChange(u, e.target.value as UserRole)
                                }
                                className="rounded border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-xs text-slate-100 disabled:opacity-50"
                              >
                                <option value="viewer">viewer</option>
                                <option value="operator">operator</option>
                                <option value="approver">approver</option>
                                <option value="admin">admin</option>
                              </select>
                            </td>
                            <td data-label="Estado" className="px-3 py-2">
                              <span
                                className={`inline-flex rounded border px-2 py-0.5 font-mono text-[11px] font-semibold ${
                                  u.is_active
                                    ? "border-emerald-700 bg-emerald-950 text-emerald-200"
                                    : "border-red-700 bg-red-950 text-red-200"
                                }`}
                              >
                                {u.is_active ? "ACTIVO" : "INACTIVO"}
                              </span>
                            </td>
                            <td data-label="Acciones" className="px-3 py-2">
                              <div className="flex flex-wrap items-center gap-2">
                                <button
                                  type="button"
                                  aria-label={`${u.is_active ? "Desactivar" : "Activar"} cuenta de ${u.username}`}
                                  disabled={isSelf || isBusy}
                                  onClick={() => void handleToggleActive(u)}
                                  className="rounded border border-slate-700 bg-slate-900 px-2.5 py-1 text-[11px] font-medium text-slate-200 hover:bg-slate-800 disabled:opacity-40"
                                >
                                  {u.is_active ? "Desactivar" : "Activar"}
                                </button>
                                <button
                                  type="button"
                                  aria-label={`Desbloquear cuenta de ${u.username}`}
                                  disabled={isBusy}
                                  onClick={() => void handleUnlockUser(u)}
                                  className="inline-flex items-center gap-1 rounded border border-amber-700 bg-amber-950 px-2.5 py-1 text-[11px] font-medium text-amber-200 hover:bg-amber-900 disabled:opacity-40"
                                >
                                  <Unlock className="h-3 w-3" aria-hidden="true" />
                                  <span>Desbloquear</span>
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
