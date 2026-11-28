import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../App";
import { setStoredToken } from "../api/client";
import { AuthProvider } from "../context/AuthContext";

function mockJsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("HostGrid Web MVP", () => {
  afterEach(() => {
    setStoredToken(null);
    vi.restoreAllMocks();
  });

  it("renders fleet table, filters, host detail Executive vs Technical view, and Drift tab", async () => {
    setStoredToken("test-jwt-token");
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
      const url = String(input);
      if (url.endsWith("/api/v1/auth/me")) {
        return Promise.resolve(
          mockJsonResponse({
            id: "u1",
            username: "operator_u",
            email: "op@example.local",
            role: "operator",
            is_active: true,
          })
        );
      }
      if (url.startsWith("/api/v1/hosts?")) {
        return Promise.resolve(
          mockJsonResponse({
            items: [
              {
                id: "h1",
                hostname: "srv-legacy-01.internal",
                os_family: "debian",
                os_name: "Debian GNU/Linux",
                os_version: "8",
                kernel_version: "3.16.0-11-amd64",
                arch: "amd64",
                init_system: "sysvinit",
                connectivity_mode: "lan",
                environment: "prod",
                eol_status: "eol",
                eol_date: "2018-06-17",
                repo_access_ok: false,
                last_hardening_index: 78,
                last_hardening_delta: 14,
                last_lynis_version: "3.1.4",
                critical_cves_count: 1,
                high_cves_count: 2,
                last_seen_at: "2026-11-19T23:10:00.000Z",
              },
            ],
            total: 1,
            limit: 100,
            offset: 0,
          })
        );
      }
      if (url.endsWith("/api/v1/hosts/h1")) {
        return Promise.resolve(
          mockJsonResponse({
            id: "h1",
            hostname: "srv-legacy-01.internal",
            machine_id_hash: "a".repeat(64),
            os_family: "debian",
            os_name: "Debian GNU/Linux",
            os_version: "8",
            kernel_version: "3.16.0-11-amd64",
            arch: "amd64",
            init_system: "sysvinit",
            connectivity_mode: "lan",
            environment: "prod",
            eol_status: "eol",
            eol_date: "2018-06-17",
            repo_access_ok: false,
            last_hardening_index: 78,
            last_hardening_delta: 14,
            last_lynis_version: "3.1.4",
            critical_cves_count: 1,
            high_cves_count: 2,
            last_seen_at: "2026-11-19T23:10:00.000Z",
            capabilities: {
              systemd_security: {
                status: "not_supported_on_os",
                reason: "init_system_is_sysvinit",
                fallback_used: false,
              },
            },
            latest_snapshot_id: "s2",
            latest_snapshot_at: "2026-11-19T23:10:00.000Z",
            total_snapshots: 2,
          })
        );
      }
      if (url.includes("/api/v1/hosts/h1/snapshots")) {
        return Promise.resolve(
          mockJsonResponse({
            items: [
              {
                id: "s2",
                host_id: "h1",
                previous_snapshot_id: "s1",
                ingestion_source: "agent_push",
                agent_version: "0.1.0",
                collected_at: "2026-11-19T23:10:00.000Z",
                ingested_at: "2026-11-19T23:10:01.000Z",
                hardening_index: 78,
                lynis_version: "3.1.4",
                tests_executed: 251,
                tests_skipped: 1,
                warnings_count: 1,
                suggestions_count: 2,
                critical_cves_count: 1,
                high_cves_count: 0,
                bundle_sha256: null,
              },
            ],
            total: 1,
            limit: 50,
            offset: 0,
          })
        );
      }
      if (url.includes("/api/v1/hosts/h1/packages")) {
        return Promise.resolve(
          mockJsonResponse({
            items: [
              {
                package_manager: "dpkg",
                name: "openssh-server",
                source_package: "openssh",
                epoch: "1",
                version: "6.7p1-5+deb8u4",
                release: null,
                arch: "amd64",
              },
            ],
            total: 1,
            limit: 100,
            offset: 0,
          })
        );
      }
      if (url.includes("/api/v1/snapshots/s2/findings")) {
        return Promise.resolve(
          mockJsonResponse({
            items: [
              {
                id: "f1",
                snapshot_id: "s2",
                host_id: "h1",
                fingerprint: "b".repeat(64),
                rule_id: "CVE-2024-6387",
                source_tool: "cve_engine",
                category: "cve",
                severity: "critical",
                base_severity: "high",
                confidence: "high",
                title: "CVE-2024-6387 en openssh-server",
                description: "Versión vulnerable de OpenSSH",
                evidence: { package: "openssh-server", listening_sockets: ["0.0.0.0:22"] },
                remediation: "Actualizar openssh-server",
                reference_ids: ["CVE-2024-6387"],
                contextual_score: 100,
                contextual_factors: ["exposed_wildcard_socket:0.0.0.0:22(+15)", "host_eol(+12)"],
              },
            ],
            total: 1,
            limit: 100,
            offset: 0,
          })
        );
      }
      if (url.includes("/api/v1/snapshots/s2/drift")) {
        return Promise.resolve(
          mockJsonResponse({
            snapshot_id: "s2",
            previous_snapshot_id: "s1",
            hardening_index_current: 78,
            hardening_index_previous: 64,
            hardening_index_delta: 14,
            summary: { new: 1, resolved: 3, persisted: 2 },
            items: [
              {
                fingerprint: "b".repeat(64),
                status: "new",
                severity: "critical",
                previous_severity: null,
                category: "cve",
                title: "CVE-2024-6387 en openssh-server",
              },
            ],
          })
        );
      }
      return Promise.resolve(mockJsonResponse({}));
    });

    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/"]}>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>
    );

    expect(await screen.findByText("srv-legacy-01.internal")).toBeInTheDocument();
    expect(screen.getByText("+14 ▲")).toBeInTheDocument();

    await user.click(screen.getByText("srv-legacy-01.internal"));
    expect(await screen.findByText("not_supported_on_os")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Hallazgos Deduplicados" }));
    const findingsPanel = screen.getByRole("tabpanel", { name: "Hallazgos Deduplicados" });
    expect(await within(findingsPanel).findByText("CVE-2024-6387 en openssh-server")).toBeInTheDocument();

    await user.click(within(findingsPanel).getByRole("button", { name: "Vista Técnica" }));
    expect(within(findingsPanel).getByText(/exposed_wildcard_socket:0\.0\.0\.0:22/)).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Drift entre Snapshots" }));
    const driftPanel = screen.getByRole("tabpanel", { name: "Drift entre Snapshots" });
    expect(within(driftPanel).getByText("+14")).toBeInTheDocument();

    // Verify ArrowRight roving focus moves focus to Paquetes SBOM tab
    const driftTab = screen.getByRole("tab", { name: "Drift entre Snapshots" });
    driftTab.focus();
    await user.keyboard("{ArrowRight}");
    const pkgTab = screen.getByRole("tab", { name: "Paquetes SBOM" });
    expect(pkgTab).toHaveFocus();
    expect(pkgTab).toHaveAttribute("aria-selected", "true");
    expect(fetchSpy).toHaveBeenCalled();
  });

  it("performs reverse CVE search and validates air-gapped .bundle extension client-side", async () => {
    setStoredToken("test-jwt-token");
    vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
      const url = String(input);
      if (url.endsWith("/api/v1/auth/me")) {
        return Promise.resolve(
          mockJsonResponse({
            id: "u1",
            username: "operator_u",
            email: "op@example.local",
            role: "operator",
            is_active: true,
          })
        );
      }
      if (url.startsWith("/api/v1/cves/search")) {
        return Promise.resolve(
          mockJsonResponse({
            query: "CVE-2024-6387",
            total: 1,
            items: [
              {
                host_id: "h1",
                hostname: "srv-app-01.internal",
                os: "Ubuntu 22.04",
                eol_status: "supported",
                cve_id: "CVE-2024-6387",
                package_name: "openssh-server",
                installed_version: "1:8.9p1-3ubuntu0.6",
                fixed_version: "1:8.9p1-3ubuntu0.10",
                effective_severity: "critical",
                exposed_network: true,
                exposed_ports: ["0.0.0.0:22"],
                last_snapshot_at: "2026-11-19T23:10:00.000Z",
              },
            ],
          })
        );
      }
      if (url.endsWith("/api/v1/snapshots/import-bundle")) {
        return Promise.resolve(
          mockJsonResponse(
            {
              snapshot_id: "s-bundle-1",
              host_id: "h-airgap",
              previous_snapshot_id: null,
              ingestion_source: "offline_bundle",
              hardening_index: 77,
              eol_status: "supported",
              findings_total: 4,
              critical_cves_count: 0,
              high_cves_count: 1,
              drift_summary: { new: 4, resolved: 0, persisted: 0 },
              bundle_sha256: "c".repeat(64),
            },
            201
          )
        );
      }
      return Promise.resolve(mockJsonResponse({ items: [], total: 0, limit: 100, offset: 0 }));
    });

    const user = userEvent.setup({ applyAccept: false });
    render(
      <MemoryRouter initialEntries={["/cves"]}>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>
    );

    const searchInput = await screen.findByPlaceholderText(/CVE-2024-6387/i);
    await user.type(searchInput, "CVE-2024-6387");
    await user.click(screen.getByRole("button", { name: /Buscar en flota/i }));

    expect(await screen.findByText("srv-app-01.internal")).toBeInTheDocument();
    expect(screen.getByText(/0\.0\.0\.0:22/)).toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: /Importar Air-Gapped/i }));
    const fileInput = await screen.findByLabelText(/Seleccionar archivo .bundle/i);
    const invalidFile = new File(["hello"], "notes.txt", { type: "text/plain" });
    await user.upload(fileInput, invalidFile);

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/Solo se permiten archivos \.bundle/i);
    });

    const validFile = new File(["tar-gz-bytes"], "srv-airgap.bundle", { type: "application/gzip" });
    await user.upload(fileInput, validFile);
    await user.click(screen.getByRole("button", { name: /Validar e Ingerir \.bundle/i }));

    expect(
      await screen.findByText(/Snapshot verificado e ingerido correctamente/i)
    ).toBeInTheDocument();
  });

  it("supports admin offline CVE feed import, governance plan lifecycle, Maker-Checker guard, and WORM audit view", async () => {
    setStoredToken("test-admin-token");
    let createdPlans: Record<string, unknown>[] = [
      {
        id: "plan-creator-self",
        title: "Plan creado por el mismo admin",
        target_host_ids: ["h1"],
        packages: ["openssl"],
        canary_percent: 10,
        status: "PENDING_APPROVAL",
        created_by: "u-admin",
        created_by_username: "admin_u",
        created_at: "2026-11-27T20:00:00.000Z",
        updated_at: "2026-11-27T20:01:00.000Z",
        precheck: { passed: true, eligible_host_ids: ["h1"], blocked_host_ids: [] },
        policy: { canary_percent: 10, max_wave_percent: 50, safe_mode_enabled: true },
        waves: [{ wave_number: 1, is_canary: true, host_ids: ["h1"] }],
        active_wave_number: null,
        dry_run_report: { ready_for_approval: true },
        wave_reports: [],
        approvals: [],
      },
      {
        id: "plan-other-maker",
        title: "Parcheo OpenSSH desde operador",
        target_host_ids: ["h1"],
        packages: ["openssh-server"],
        canary_percent: 10,
        status: "PENDING_APPROVAL",
        created_by: "u-operator",
        created_by_username: "operator_u",
        created_at: "2026-11-27T20:02:00.000Z",
        updated_at: "2026-11-27T20:03:00.000Z",
        precheck: { passed: true, eligible_host_ids: ["h1"], blocked_host_ids: [] },
        policy: { canary_percent: 10, max_wave_percent: 50, safe_mode_enabled: true },
        waves: [{ wave_number: 1, is_canary: true, host_ids: ["h1"] }],
        active_wave_number: null,
        dry_run_report: { ready_for_approval: true },
        wave_reports: [],
        approvals: [],
      },
    ];

    vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (url.endsWith("/api/v1/auth/me")) {
        return Promise.resolve(
          mockJsonResponse({
            id: "u-admin",
            username: "admin_u",
            email: "admin@example.local",
            role: "admin",
            is_active: true,
          })
        );
      }
      if (url.endsWith("/api/v1/cves/import-feed") && method === "POST") {
        return Promise.resolve(
          mockJsonResponse({
            feed_format: "osv",
            parsed: 2,
            upserted: 2,
            hosts_rescanned: 1,
            total_cve_matches: 1,
          })
        );
      }
      if (url.startsWith("/api/v1/hosts?")) {
        return Promise.resolve(
          mockJsonResponse({
            items: [
              {
                id: "h1",
                hostname: "srv-prod-01.internal",
                os_family: "debian",
                os_name: "Debian GNU/Linux",
                os_version: "12",
                kernel_version: "6.1.0-26-amd64",
                arch: "amd64",
                init_system: "systemd",
                connectivity_mode: "lan",
                environment: "prod",
                eol_status: "supported",
                eol_date: "2028-06-10",
                repo_access_ok: true,
                last_hardening_index: 82,
                last_hardening_delta: 4,
                last_lynis_version: "3.1.4",
                critical_cves_count: 1,
                high_cves_count: 0,
                last_seen_at: "2026-11-27T20:00:00.000Z",
              },
            ],
            total: 1,
            limit: 100,
            offset: 0,
          })
        );
      }
      if (url.startsWith("/api/v1/audit/logs")) {
        return Promise.resolve(
          mockJsonResponse({
            items: [
              {
                seq_num: 7,
                id: "aud-7",
                occurred_at: "2026-11-27T20:05:00.000Z",
                actor_id: "u-admin",
                actor_username: "admin_u",
                action: "patch_plan.approved",
                resource_type: "patch_plan",
                resource_id: "plan-other-maker",
                details: {},
                prev_record_hash: "0".repeat(64),
                record_hash: "a".repeat(64),
              },
            ],
            total: 1,
            limit: 25,
            offset: 0,
          })
        );
      }
      if (url.startsWith("/api/v1/patching/plans?") && method === "GET") {
        return Promise.resolve(
          mockJsonResponse({
            items: createdPlans,
            total: createdPlans.length,
            limit: 50,
            offset: 0,
          })
        );
      }
      if (url.endsWith("/api/v1/patching/plans/plan-other-maker/decision") && method === "POST") {
        createdPlans = createdPlans.map((p) =>
          p.id === "plan-other-maker"
            ? {
                ...p,
                status: "APPROVED",
                approvals: [
                  {
                    id: "app-1",
                    patch_plan_id: "plan-other-maker",
                    approver_id: "u-admin",
                    approver_username: "admin_u",
                    decision: "approved",
                    rationale: "Dry-run validado",
                    decided_at: "2026-11-27T20:06:00.000Z",
                  },
                ],
              }
            : p
        );
        return Promise.resolve(mockJsonResponse(createdPlans[1]));
      }
      return Promise.resolve(mockJsonResponse({ items: [], total: 0, limit: 50, offset: 0 }));
    });

    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/cves"]}>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>
    );

    // Admin offline CVE feed import inside native <details>
    const syncSummary = await screen.findByText(/Sincronización Offline de Feeds CVE/i);
    await user.click(syncSummary);
    const payloadInput = screen.getByLabelText(/Contenido exportado/i);
    await user.click(payloadInput);
    await user.paste('{"vulns":[]}');
    await user.click(screen.getByRole("button", { name: /Importar Feed Offline/i }));
    expect(await screen.findByText(/2 avisos analizados, 2 guardados/i)).toBeInTheDocument();

    // Navigate to Governance Queue
    await user.click(screen.getByRole("link", { name: /Gobernanza/i }));
    expect(await screen.findByText(/Bloqueo Maker-Checker: el creador del plan no puede auto-aprobarlo/i)).toBeInTheDocument();

    // Accessible validation starts with aria-invalid="false" before interaction
    const titleField = screen.getByLabelText(/Título del plan/i);
    expect(titleField).toHaveAttribute("aria-invalid", "false");

    // Approve plan created by another user (distinct Maker-Checker)
    const rationaleInput = screen.getByLabelText(/Justificación de aprobación o rechazo/i);
    await user.type(rationaleInput, "Dry-run validado");
    await user.click(screen.getByRole("button", { name: /Aprobar Plan/i }));

    expect(await screen.findByText(/Decisión Maker-Checker registrada: APPROVED/i)).toBeInTheDocument();
    expect(screen.getByText(/Bitácora Inmutable WORM/i)).toBeInTheDocument();
  });

  it("downloads Markdown/HTML reports on HostDetailPage and validates full GovernancePage create/dry-run/canary/rollback flow", async () => {
    setStoredToken("test-admin-token");
    const createObjectURLSpy = vi.fn().mockReturnValue("blob:hostgrid-report");
    const revokeObjectURLSpy = vi.fn();
    const origCreate = URL.createObjectURL;
    const origRevoke = URL.revokeObjectURL;
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURLSpy });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revokeObjectURLSpy });
    const anchorClickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    let capturedIdempotencyKey: string | null = null;
    let capturedCreateBody: Record<string, unknown> | null = null;
    let plansState: Record<string, unknown>[] = [
      {
        id: "plan-blocked",
        title: "Plan bloqueado por precheck",
        target_host_ids: ["h-norepo"],
        packages: ["curl"],
        canary_percent: 10,
        status: "FAILED_PRECHECK",
        created_by: "u-admin",
        created_by_username: "admin_u",
        created_at: "2026-11-27T20:00:00.000Z",
        updated_at: "2026-11-27T20:00:00.000Z",
        precheck: { passed: false, eligible_host_ids: [], blocked_host_ids: ["h-norepo"] },
        policy: { canary_percent: 10, max_wave_percent: 50, safe_mode_enabled: true, max_failed_hosts: 0 },
        waves: [{ wave_number: 1, is_canary: true, host_ids: ["h-norepo"] }],
        active_wave_number: null,
        dry_run_report: null,
        wave_reports: [],
        approvals: [],
      },
    ];

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (url.endsWith("/api/v1/auth/me")) {
        return Promise.resolve(
          mockJsonResponse({
            id: "u-admin",
            username: "admin_u",
            email: "admin@example.local",
            role: "admin",
            is_active: true,
          })
        );
      }
      if (url.endsWith("/api/v1/hosts/h1")) {
        return Promise.resolve(
          mockJsonResponse({
            id: "h1",
            hostname: "srv-prod-01.internal",
            machine_id_hash: "a".repeat(64),
            os_family: "debian",
            os_name: "Debian GNU/Linux",
            os_version: "12",
            kernel_version: "6.1.0-26-amd64",
            arch: "amd64",
            init_system: "systemd",
            connectivity_mode: "lan",
            environment: "prod",
            eol_status: "supported",
            eol_date: "2028-06-10",
            repo_access_ok: true,
            last_hardening_index: 82,
            last_hardening_delta: 4,
            last_lynis_version: "3.1.4",
            critical_cves_count: 1,
            high_cves_count: 0,
            last_seen_at: "2026-11-27T20:00:00.000Z",
            capabilities: {},
            latest_snapshot_id: "s1",
            latest_snapshot_at: "2026-11-27T20:00:00.000Z",
            total_snapshots: 1,
          })
        );
      }
      if (url.includes("/api/v1/snapshots/s1/drift")) {
        return Promise.resolve(
          mockJsonResponse({
            snapshot_id: "s1",
            previous_snapshot_id: null,
            hardening_index_current: 82,
            hardening_index_previous: null,
            hardening_index_delta: null,
            summary: { new: 0, resolved: 0, persisted: 0 },
            items: [],
          })
        );
      }
      if (url.endsWith("/api/v1/reports/hosts/h1?format=markdown")) {
        return Promise.resolve(
          new Response("# Reporte Ejecutivo", {
            status: 200,
            headers: { "Content-Type": "text/markdown; charset=utf-8" },
          })
        );
      }
      if (url.endsWith("/api/v1/reports/hosts/h1?format=html")) {
        return Promise.resolve(
          new Response("<!DOCTYPE html><html><body>Reporte</body></html>", {
            status: 200,
            headers: { "Content-Type": "text/html; charset=utf-8" },
          })
        );
      }
      if (url.startsWith("/api/v1/hosts?")) {
        return Promise.resolve(
          mockJsonResponse({
            items: [
              {
                id: "h1",
                hostname: "srv-prod-01.internal",
                os_family: "debian",
                os_name: "Debian GNU/Linux",
                os_version: "12",
                kernel_version: "6.1.0-26-amd64",
                arch: "amd64",
                init_system: "systemd",
                connectivity_mode: "lan",
                environment: "prod",
                eol_status: "supported",
                eol_date: "2028-06-10",
                repo_access_ok: true,
                last_hardening_index: 82,
                last_hardening_delta: 4,
                last_lynis_version: "3.1.4",
                critical_cves_count: 1,
                high_cves_count: 0,
                last_seen_at: "2026-11-27T20:00:00.000Z",
              },
              {
                id: "h-norepo",
                hostname: "srv-airgap-norepo.internal",
                os_family: "debian",
                os_name: "Debian GNU/Linux",
                os_version: "12",
                kernel_version: "6.1.0-26-amd64",
                arch: "amd64",
                init_system: "systemd",
                connectivity_mode: "airgapped",
                environment: "prod",
                eol_status: "supported",
                eol_date: "2028-06-10",
                repo_access_ok: false,
                last_hardening_index: 70,
                last_hardening_delta: 0,
                last_lynis_version: "3.1.4",
                critical_cves_count: 0,
                high_cves_count: 0,
                last_seen_at: "2026-11-27T20:00:00.000Z",
              },
            ],
            total: 2,
            limit: 100,
            offset: 0,
          })
        );
      }
      if (url.startsWith("/api/v1/patching/plans?") && method === "GET") {
        return Promise.resolve(
          mockJsonResponse({ items: plansState, total: plansState.length, limit: 50, offset: 0 })
        );
      }
      if (url.endsWith("/api/v1/patching/plans") && method === "POST") {
        const hdrs = new Headers(init?.headers);
        capturedIdempotencyKey = hdrs.get("Idempotency-Key");
        capturedCreateBody = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
        const created = {
          id: "plan-new-1",
          title: "Parcheo Canario OpenSSH",
          target_host_ids: ["h1"],
          packages: ["openssh-server"],
          canary_percent: 20,
          status: "DRY_RUN_READY",
          created_by: "u-operator",
          created_by_username: "operator_u",
          created_at: "2026-11-27T20:10:00.000Z",
          updated_at: "2026-11-27T20:10:00.000Z",
          precheck: { passed: true, eligible_host_ids: ["h1"], blocked_host_ids: [] },
          policy: {
            canary_percent: 20,
            max_wave_percent: 50,
            safe_mode_enabled: Boolean(capturedCreateBody.safe_mode_enabled),
            max_failed_hosts: Number(capturedCreateBody.max_failed_hosts ?? 0),
            rollback_on_unreachable: Boolean(capturedCreateBody.rollback_on_unreachable),
          },
          waves: [{ wave_number: 1, is_canary: true, host_ids: ["h1"] }],
          active_wave_number: null,
          dry_run_report: null,
          wave_reports: [],
          approvals: [],
        };
        plansState = [created, ...plansState];
        return Promise.resolve(mockJsonResponse(created, 201));
      }
      if (url.endsWith("/api/v1/patching/plans/plan-new-1/dry-run") && method === "POST") {
        plansState = plansState.map((p) =>
          p.id === "plan-new-1" ? { ...p, status: "APPROVED" } : p
        );
        return Promise.resolve(mockJsonResponse(plansState[0]));
      }
      if (url.endsWith("/api/v1/patching/plans/plan-new-1/execute") && method === "POST") {
        plansState = plansState.map((p) =>
          p.id === "plan-new-1" ? { ...p, status: "CANARY_WAVE", active_wave_number: 1 } : p
        );
        return Promise.resolve(mockJsonResponse(plansState[0]));
      }
      if (url.endsWith("/api/v1/patching/plans/plan-new-1/wave-report") && method === "POST") {
        plansState = plansState.map((p) =>
          p.id === "plan-new-1" ? { ...p, status: "ROLLED_BACK", active_wave_number: null } : p
        );
        return Promise.resolve(mockJsonResponse(plansState[0]));
      }
      return Promise.resolve(mockJsonResponse({ items: [], total: 0, limit: 50, offset: 0 }));
    });

    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/hosts/h1"]}>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>
    );

    // 1. Trigger Markdown and HTML/PDF report downloads on HostDetailPage
    const mdBtn = await screen.findByRole("button", { name: /Exportar Markdown/i });
    const htmlBtn = screen.getByRole("button", { name: /Reporte Ejecutivo HTML\/PDF/i });
    await user.click(mdBtn);
    await user.click(htmlBtn);
    await waitFor(() => {
      expect(createObjectURLSpy).toHaveBeenCalledTimes(2);
      expect(revokeObjectURLSpy).toHaveBeenCalledTimes(2);
      expect(anchorClickSpy).toHaveBeenCalledTimes(2);
    });
    expect(fetchSpy).toHaveBeenCalledWith("/api/v1/reports/hosts/h1?format=markdown", expect.anything());
    expect(fetchSpy).toHaveBeenCalledWith("/api/v1/reports/hosts/h1?format=html", expect.anything());

    // 2. Navigate to GovernancePage and check FAILED_PRECHECK blocked hostname visibility
    await user.click(screen.getByRole("link", { name: /Gobernanza/i }));
    expect(await screen.findByText(/Bloqueado en Precheck/i)).toBeInTheDocument();
    expect(screen.getAllByText(/srv-airgap-norepo\.internal/i).length).toBeGreaterThanOrEqual(1);

    // 3. Submit empty form -> focuses #plan-title and sets aria-invalid="true"
    const submitBtn = screen.getByRole("button", { name: /Crear Plan y Ejecutar Precheck/i });
    await user.click(submitBtn);
    const titleField = screen.getByLabelText(/Título del plan/i);
    expect(titleField).toHaveFocus();
    expect(titleField).toHaveAttribute("aria-invalid", "true");

    // Fill title + packages, clearing canary stays empty (no "0" snap), then test > maxWavePercent
    await user.type(titleField, "Parcheo Canario OpenSSH");
    const pkgField = screen.getByLabelText(/Paquetes a actualizar/i);
    await user.type(pkgField, "openssh-server");
    const canaryField = screen.getByLabelText(/Porcentaje Oleada Canario/i);
    await user.clear(canaryField);
    expect(canaryField).toHaveValue(null);
    await user.type(canaryField, "80");
    await user.click(submitBtn);
    expect(canaryField).toHaveFocus();
    expect(canaryField).toHaveAttribute("aria-invalid", "true");

    // Fix canaryPercent to 20, test invalid max_failed_hosts (>100) -> focuses #plan-max-failed
    await user.clear(canaryField);
    await user.type(canaryField, "20");
    const maxFailedField = screen.getByLabelText(/Máx\. hosts fallidos tolerados/i);
    await user.clear(maxFailedField);
    await user.type(maxFailedField, "105");
    await user.click(submitBtn);
    expect(maxFailedField).toHaveFocus();
    expect(maxFailedField).toHaveAttribute("aria-invalid", "true");

    // Set valid Safe Mode policy controls (max_failed_hosts=2, rollback_on_unreachable=false)
    await user.clear(maxFailedField);
    await user.type(maxFailedField, "2");
    await user.click(screen.getByLabelText(/Activar rollback si un servidor queda inalcanzable/i));
    await user.click(screen.getByRole("checkbox", { name: /srv-prod-01\.internal/i }));
    await user.click(submitBtn);
    expect(await screen.findByText(/creado en estado DRY_RUN_READY/i)).toBeInTheDocument();
    expect(capturedIdempotencyKey).toMatch(/^[0-9a-f-]{36}$/i);
    expect(capturedCreateBody).toMatchObject({
      safe_mode_enabled: true,
      max_failed_hosts: 2,
      rollback_on_unreachable: false,
    });

    // Run Dry-Run -> Start Canary -> Trigger Safe Mode Rollback
    await user.click(screen.getByRole("button", { name: /Registrar Dry-Run Verificado/i }));
    await user.click(await screen.findByRole("button", { name: /Iniciar Oleada Canario/i }));
    await user.click(await screen.findByRole("button", { name: /Activar Rollback Safe Mode/i }));
    expect(await screen.findByText(/Estado del plan: ROLLED_BACK/i)).toBeInTheDocument();

    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: origCreate });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: origRevoke });
  });

  it("supports admin OperationsPage flows: enrollment token, signed bundle registration, and RBAC user lifecycle", async () => {
    setStoredToken("test-admin-ops-token");

    let usersState = [
      {
        id: "u-admin",
        username: "admin_u",
        email: "admin@example.local",
        role: "admin",
        is_active: true,
      },
      {
        id: "u-op",
        username: "operator_u",
        email: "op@example.local",
        role: "operator",
        is_active: true,
      },
    ];
    let capturedBundleFields: Record<string, string> = {};
    const patchPayloads: Record<string, unknown>[] = [];

    vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (url.endsWith("/api/v1/auth/me")) {
        return Promise.resolve(mockJsonResponse(usersState[0]));
      }
      if (url.startsWith("/api/v1/users?") && method === "GET") {
        return Promise.resolve(
          mockJsonResponse({ items: usersState, total: usersState.length, limit: 100, offset: 0 })
        );
      }
      if (url.endsWith("/api/v1/users") && method === "POST") {
        const body = JSON.parse(String(init?.body ?? "{}")) as {
          username: string;
          email: string;
          role: string;
        };
        const created = {
          id: "u-new-1",
          username: body.username,
          email: body.email,
          role: body.role,
          is_active: true,
        };
        usersState = [...usersState, created];
        return Promise.resolve(mockJsonResponse(created, 201));
      }
      if (url.endsWith("/api/v1/users/u-op") && method === "PATCH") {
        const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
        patchPayloads.push(body);
        usersState = usersState.map((u) =>
          u.id === "u-op"
            ? {
                ...u,
                role: typeof body.role === "string" ? body.role : u.role,
                is_active: typeof body.is_active === "boolean" ? body.is_active : u.is_active,
              }
            : u
        );
        return Promise.resolve(mockJsonResponse(usersState.find((u) => u.id === "u-op")));
      }
      if (url.endsWith("/api/v1/enrollments/tokens") && method === "POST") {
        const body = JSON.parse(String(init?.body ?? "{}")) as {
          label: string;
          environment: string;
        };
        return Promise.resolve(
          mockJsonResponse(
            {
              id: "tok-1",
              enrollment_token: "hg_enroll_secret_token_once",
              label: body.label,
              environment: body.environment,
              expires_at: "2026-11-28T03:00:00.000Z",
            },
            201
          )
        );
      }
      if (url.endsWith("/api/v1/bundles/register") && method === "POST") {
        const fd = init?.body as FormData;
        capturedBundleFields = {
          tool_name: String(fd.get("tool_name") ?? ""),
          version: String(fd.get("version") ?? ""),
          arch: String(fd.get("arch") ?? ""),
          signature_b64: String(fd.get("signature_b64") ?? ""),
        };
        return Promise.resolve(
          mockJsonResponse(
            {
              tool_name: capturedBundleFields.tool_name,
              version: capturedBundleFields.version,
              arch: capturedBundleFields.arch,
              filename: "lynis-3.1.4-arm64.tar.gz",
              sha256: "f".repeat(64),
              size_bytes: 2048,
              manifest_canonical_json: "{}",
              signature_b64: "c2ln",
              download_url: "/api/v1/bundles/lynis/3.1.4/download?arch=arm64",
            },
            201
          )
        );
      }
      return Promise.resolve(mockJsonResponse({ items: [], total: 0, limit: 100, offset: 0 }));
    });

    const user = userEvent.setup({ applyAccept: false });
    const writeTextMock = vi.spyOn(navigator.clipboard, "writeText");
    render(
      <MemoryRouter initialEntries={["/operations"]}>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>
    );

    // 1. Enrollment token accessible validation + issuance + copy button
    const labelInput = await screen.findByLabelText(/Etiqueta del token/i);
    expect(labelInput).toHaveAttribute("aria-invalid", "false");
    await user.click(screen.getByRole("button", { name: /Emitir Token de Enrolamiento/i }));
    expect(labelInput).toHaveFocus();
    expect(labelInput).toHaveAttribute("aria-invalid", "true");

    await user.type(labelInput, "dmz-nodes");
    await user.selectOptions(screen.getByLabelText(/Entorno objetivo/i), "dmz");
    // Clearing TTL stays empty (no snap-to-0), and unsafe server URL is rejected before submit
    const ttlInput = screen.getByLabelText(/Vigencia TTL/i);
    await user.clear(ttlInput);
    expect(ttlInput).toHaveValue(null);
    await user.type(ttlInput, "90");

    const serverUrlInput = screen.getByLabelText(/URL HTTPS del Control Plane/i);
    await user.clear(serverUrlInput);
    await user.type(serverUrlInput, "http://insecure.corp:8000;id");
    await user.click(screen.getByRole("button", { name: /Emitir Token de Enrolamiento/i }));
    expect(serverUrlInput).toHaveFocus();
    expect(serverUrlInput).toHaveAttribute("aria-invalid", "true");

    await user.clear(serverUrlInput);
    await user.type(serverUrlInput, "https://relay.dmz.internal:8443");
    await user.click(screen.getByRole("button", { name: /Emitir Token de Enrolamiento/i }));

    expect(await screen.findByText("hg_enroll_secret_token_once")).toBeInTheDocument();
    expect(screen.getByText(/hostgrid-agent enroll --server https:\/\/relay\.dmz\.internal:8443/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Copiar comando hostgrid-agent enroll/i }));
    await waitFor(() => {
      expect(writeTextMock).toHaveBeenCalledWith(expect.stringContaining("hg_enroll_secret_token_once"));
      expect(screen.getByText(/Copiado/)).toBeInTheDocument();
    });

    // 2. Signed tool bundle registration + extension guard
    const bundleFileInput = screen.getByLabelText(/Archivo portable/i);
    await user.upload(bundleFileInput, new File(["bad"], "bad.zip", { type: "application/zip" }));
    expect(await screen.findByText(/Solo se permiten archivos portables \.tar\.gz/i)).toBeInTheDocument();

    await user.type(screen.getByLabelText(/^Versión$/i), "3.1.4");
    await user.selectOptions(screen.getByLabelText(/Arquitectura/i), "arm64");
    await user.upload(
      bundleFileInput,
      new File(["tarball-bytes"], "lynis-3.1.4-arm64.tar.gz", { type: "application/gzip" })
    );
    await user.click(screen.getByRole("button", { name: /Registrar Bundle Portable/i }));
    expect(
      await screen.findByText(/Bundle portable registrado y publicado/i)
    ).toBeInTheDocument();
    expect(capturedBundleFields).toMatchObject({
      tool_name: "lynis",
      version: "3.1.4",
      arch: "arm64",
    });

    // 3. RBAC user management: self-lockout guard + accessible password validation + create + patch
    expect(screen.getByLabelText("Rol de admin_u")).toBeDisabled();
    const newUserField = screen.getByLabelText(/^Usuario$/i);
    const newEmailField = screen.getByLabelText(/Correo electrónico/i);
    const newPassField = screen.getByLabelText(/Contraseña inicial/i);
    await user.type(newUserField, "checker_u");
    await user.type(newEmailField, "checker@example.local");
    await user.type(newPassField, "short");
    await user.click(screen.getByRole("button", { name: /Crear Usuario/i }));
    expect(newPassField).toHaveFocus();
    expect(newPassField).toHaveAttribute("aria-invalid", "true");

    await user.clear(newPassField);
    await user.type(newPassField, "StrongCheckerPass!123");
    await user.selectOptions(screen.getByLabelText(/Rol RBAC/i), "approver");
    await user.click(screen.getByRole("button", { name: /Crear Usuario/i }));
    expect(await screen.findByText(/Usuario "checker_u" creado con rol approver/i)).toBeInTheDocument();

    // Update role, deactivate, and unlock operator_u
    await user.selectOptions(screen.getByLabelText("Rol de operator_u"), "approver");
    expect(await screen.findByText(/Rol de "operator_u" actualizado a approver/i)).toBeInTheDocument();

    const opRow = screen.getByRole("row", { name: /operator_u/i });
    await user.click(within(opRow).getByRole("button", { name: /Desactivar/i }));
    expect(await screen.findByText(/Cuenta "operator_u" desactivada/i)).toBeInTheDocument();

    await user.click(within(opRow).getByRole("button", { name: /Desbloquear/i }));
    expect(
      await screen.findByText(/Bloqueo de inicio de sesión restablecido para "operator_u"/i)
    ).toBeInTheDocument();
    expect(patchPayloads).toEqual([
      { role: "approver" },
      { is_active: false },
      { unlock: true },
    ]);
  });

  it("enforces OperationsPage RBAC boundaries for operator, approver, and viewer roles", async () => {
    setStoredToken("test-role-token");
    let currentRole: "operator" | "approver" | "viewer" = "operator";
    const usersEndpointHits = vi.fn();

    vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
      const url = String(input);
      if (url.endsWith("/api/v1/auth/me")) {
        return Promise.resolve(
          mockJsonResponse({
            id: `u-${currentRole}`,
            username: `${currentRole}_u`,
            email: `${currentRole}@example.local`,
            role: currentRole,
            is_active: true,
          })
        );
      }
      if (url.includes("/api/v1/users")) {
        usersEndpointHits();
      }
      return Promise.resolve(mockJsonResponse({ items: [], total: 0, limit: 100, offset: 0 }));
    });

    // Operator sees enrollment + bundle forms, does NOT call /api/v1/users
    const { unmount } = render(
      <MemoryRouter initialEntries={["/operations"]}>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>
    );
    expect(await screen.findByText(/Tokens de Enrolamiento de Agentes/i)).toBeInTheDocument();
    expect(screen.getByText(/restringida al rol/i)).toBeInTheDocument();
    expect(usersEndpointHits).not.toHaveBeenCalled();
    unmount();

    // Approver and Viewer cannot see Operaciones nav link and get RBAC restriction on direct route
    for (const deniedRole of ["approver", "viewer"] as const) {
      currentRole = deniedRole;
      const view = render(
        <MemoryRouter initialEntries={["/operations"]}>
          <AuthProvider>
            <AppRoutes />
          </AuthProvider>
        </MemoryRouter>
      );
      expect(await screen.findByText(/no tiene permisos en esta sección/i)).toBeInTheDocument();
      expect(screen.queryByRole("link", { name: /Operaciones/i })).not.toBeInTheDocument();
      expect(screen.queryByText(/Emitir Token de Enrolamiento/i)).not.toBeInTheDocument();
      expect(usersEndpointHits).not.toHaveBeenCalled();
      view.unmount();
    }
  });
});
