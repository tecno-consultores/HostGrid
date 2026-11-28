package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tecno-consultores/HostGrid/agent/internal/collectors"
	"github.com/tecno-consultores/HostGrid/agent/internal/config"
	"github.com/tecno-consultores/HostGrid/agent/internal/probe"
	"github.com/tecno-consultores/HostGrid/agent/internal/tools"
	"github.com/tecno-consultores/HostGrid/agent/internal/transport"
	"github.com/tecno-consultores/HostGrid/agent/internal/updater"
)

var version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Printf("hostgrid-agent %s\n", version)
		return
	case "enroll":
		err = runEnroll(os.Args[2:])
	case "scan":
		err = runScan(os.Args[2:])
	case "run":
		err = runDaemon(os.Args[2:])
	case "patch":
		err = runPatch(os.Args[2:])
	default:
		printUsage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostgrid-agent error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: hostgrid-agent <version|enroll|scan|run|patch> [flags]")
}

func runEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	serverURL := fs.String("server", "", "Control Plane or Relay HTTPS URL")
	token := fs.String("token", "", "Single-use enrollment token")
	cfgPath := fs.String("config", config.DefaultConfigPath, "Path to persist agent.json (0600)")
	mode := fs.String("mode", "lan", "Connectivity mode (lan|relay)")
	envName := fs.String("env", "prod", "Host environment (prod|staging|dev|dmz)")
	caCert := fs.String("ca-cert", "", "Optional custom CA certificate PEM path")
	clientCert := fs.String("client-cert", "", "Optional mTLS client certificate PEM path")
	clientKey := fs.String("client-key", "", "Optional mTLS client private key PEM path")
	proxyURL := fs.String("proxy", "", "Optional HTTP/HTTPS proxy or Relay URL (defaults to HTTPS_PROXY/HTTP_PROXY env)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serverURL == "" || *token == "" {
		return fmt.Errorf("--server and --token are required")
	}

	trimmedProxy := strings.Trim(*proxyURL, " ")
	probeRes := probe.Run(probe.DefaultEnv())
	client, err := transport.NewClient(transport.ClientOptions{
		ServerURL:      *serverURL,
		AgentVersion:   version,
		CACertPath:     *caCert,
		ClientCertPath: *clientCert,
		ClientKeyPath:  *clientKey,
		ProxyURL:       trimmedProxy,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Enroll(ctx, transport.EnrollRequest{
		EnrollmentToken:  *token,
		Hostname:         probeRes.Hostname,
		MachineIDHash:    probeRes.MachineIDHash,
		OSFamily:         probeRes.OSFamily,
		OSName:           probeRes.OSName,
		OSVersion:        probeRes.OSVersion,
		KernelVersion:    probeRes.KernelVersion,
		Arch:             probeRes.Arch,
		InitSystem:       probeRes.InitSystem,
		ConnectivityMode: *mode,
		Environment:      *envName,
	})
	if err != nil {
		return err
	}

	cfg := &config.AgentConfig{
		ServerURL:            *serverURL,
		HostID:               resp.HostID,
		AgentCredential:      resp.AgentCredential,
		BundleSigningPubKey:  resp.BundleSigningPubKey,
		ConnectivityMode:     *mode,
		Environment:          *envName,
		CACertPath:           *caCert,
		ClientCertPath:       *clientCert,
		ClientKeyPath:        *clientKey,
		ProxyURL:             trimmedProxy,
		ToolsDir:             config.DefaultToolsDir,
		HeartbeatIntervalSec: resp.HeartbeatIntervalSec,
		ScanIntervalSec:      resp.ScanIntervalSec,
	}
	if err := config.Save(*cfgPath, cfg); err != nil {
		return err
	}
	fmt.Printf("Enrolled host %s (%s). Config saved to %s (0600)\n", probeRes.Hostname, resp.HostID, *cfgPath)
	return nil
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath, "Path to agent.json")
	offlineExport := fs.String("offline-export", "", "Export signed air-gapped .bundle file path")
	lynisDir := fs.String("lynis-dir", "", "Optional local verified Lynis portable directory")
	skipLynis := fs.Bool("skip-lynis", false, "Skip portable Lynis execution")
	envName := fs.String("env", "prod", "Environment tag for unenrolled offline exports")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cfg, cfgErr := config.Load(*cfgPath)
	if *offlineExport != "" {
		snap := collectSnapshot(ctx, cfg, *envName, *lynisDir, *skipLynis)
		var cred string
		if cfgErr == nil && cfg != nil {
			cred = cfg.AgentCredential
		}
		digest, err := transport.ExportOfflineBundle(*offlineExport, snap, transport.ExportOptions{
			AgentCredential: cred,
		})
		if err != nil {
			return err
		}
		fmt.Printf("Exported air-gapped bundle to %s (sha256=%s)\n", *offlineExport, digest)
		return nil
	}

	if cfgErr != nil {
		return fmt.Errorf("agent config required for online scan (or use --offline-export): %w", cfgErr)
	}
	_, err := executeOnlineScan(ctx, cfg, *lynisDir, *skipLynis)
	return err
}

type daemonOptions struct {
	cfg           *config.AgentConfig
	client        *transport.Client
	exec          *updater.Executor
	skipLynis     bool
	patchInterval time.Duration
	hbInterval    time.Duration
	scanInterval  time.Duration
	scanFn        func(ctx context.Context) (transport.SnapshotPayload, error)
}

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath, "Path to agent.json")
	skipLynis := fs.Bool("skip-lynis", false, "Skip portable Lynis execution")
	allowMutation := fs.Bool("allow-mutation", false, "Explicitly permit live package upgrades for approved wave jobs (default false = dry-run only)")
	patchInterval := fs.Duration("patch-interval", 60*time.Second, "Interval to poll Control Plane for governed patch-jobs (0 disables polling)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *patchInterval < 0 {
		return fmt.Errorf("--patch-interval must be >= 0")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	client, err := newClientFromConfig(cfg)
	if err != nil {
		return err
	}

	return runDaemonLoop(ctx, daemonOptions{
		cfg:           cfg,
		client:        client,
		exec:          newPatchExecutor(client, cfg.HostID, *allowMutation),
		skipLynis:     *skipLynis,
		patchInterval: *patchInterval,
	})
}

func runDaemonLoop(ctx context.Context, opts daemonOptions) error {
	scanFn := opts.scanFn
	if scanFn == nil {
		scanFn = func(sctx context.Context) (transport.SnapshotPayload, error) {
			return executeOnlineScan(sctx, opts.cfg, "", opts.skipLynis)
		}
	}

	hbInterval := opts.hbInterval
	if hbInterval <= 0 {
		hbInterval = time.Duration(opts.cfg.HeartbeatIntervalSec) * time.Second
	}
	if hbInterval <= 0 {
		hbInterval = 300 * time.Second
	}

	scanInterval := opts.scanInterval
	if scanInterval <= 0 {
		scanInterval = time.Duration(opts.cfg.ScanIntervalSec) * time.Second
	}
	if scanInterval <= 0 {
		scanInterval = 3600 * time.Second
	}

	var lastScanAt, lastLynisVer string
	var lastRepoOK *bool

	runBoundedScan := func(label string) {
		if ctx.Err() != nil {
			return
		}
		scanCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		if snap, scanErr := scanFn(scanCtx); scanErr != nil {
			fmt.Fprintf(os.Stderr, "%s scan error: %v\n", label, scanErr)
		} else {
			lastScanAt = snap.CollectedAt
			lastLynisVer = snap.Lynis.LynisVersion
			lastRepoOK = snap.Repos.AccessOK
		}
	}

	runBoundedScan("initial")

	pollPatchJobs := func() {
		if opts.exec == nil || opts.client == nil || ctx.Err() != nil {
			return
		}
		pollCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		if patchErr := processPendingPatchJobs(pollCtx, opts.client, opts.cfg.HostID, opts.exec); patchErr != nil {
			fmt.Fprintf(os.Stderr, "patch-jobs poll error: %v\n", patchErr)
		}
	}

	hbTicker := time.NewTicker(hbInterval)
	scanTicker := time.NewTicker(scanInterval)
	defer hbTicker.Stop()
	defer scanTicker.Stop()

	var patchCh <-chan time.Time
	if opts.patchInterval > 0 {
		pollPatchJobs()
		patchTicker := time.NewTicker(opts.patchInterval)
		defer patchTicker.Stop()
		patchCh = patchTicker.C
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-hbTicker.C:
			if hbErr := opts.client.Heartbeat(ctx, opts.cfg.HostID, transport.HeartbeatRequest{
				AgentVersion: version,
				LynisVersion: lastLynisVer,
				UptimeSec:    readHostUptimeSec(),
				LastScanAt:   lastScanAt,
				RepoAccessOK: lastRepoOK,
			}); hbErr != nil {
				fmt.Fprintf(os.Stderr, "heartbeat error: %v\n", hbErr)
			}
		case <-scanTicker.C:
			runBoundedScan("scheduled")
		case <-patchCh:
			pollPatchJobs()
		}
	}
}

func readHostUptimeSec() int64 {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || secs < 0 {
		return 0
	}
	return int64(secs)
}

func newClientFromConfig(cfg *config.AgentConfig) (*transport.Client, error) {
	return transport.NewClient(transport.ClientOptions{
		ServerURL:      cfg.ServerURL,
		Credential:     cfg.AgentCredential,
		AgentVersion:   version,
		CACertPath:     cfg.CACertPath,
		ClientCertPath: cfg.ClientCertPath,
		ClientKeyPath:  cfg.ClientKeyPath,
		ProxyURL:       cfg.ProxyURL,
	})
}

func resolveManagedLynisDir(ctx context.Context, client *transport.Client, cfg *config.AgentConfig) string {
	manifest, mErr := client.FetchToolManifest(ctx, "lynis", "latest")
	if mErr != nil {
		fmt.Fprintf(os.Stderr, "lynis manifest fetch skipped: %v\n", mErr)
		return ""
	}
	cachedDir, hit, vErr := tools.ResolveCachedBundle(*manifest, cfg.BundleSigningPubKey, cfg.ToolsDir)
	if vErr != nil {
		fmt.Fprintf(os.Stderr, "lynis manifest verification rejected: %v\n", vErr)
		return ""
	}
	if hit {
		return cachedDir
	}
	stream, dlErr := client.DownloadToolStream(ctx, manifest.DownloadURL)
	if dlErr != nil {
		fmt.Fprintf(os.Stderr, "lynis bundle download error: %v\n", dlErr)
		return ""
	}
	defer stream.Close()
	dir, instErr := tools.InstallVerifiedBundle(*manifest, cfg.BundleSigningPubKey, stream, cfg.ToolsDir)
	if instErr != nil {
		fmt.Fprintf(os.Stderr, "lynis bundle install rejected: %v\n", instErr)
		return ""
	}
	return dir
}

func executeOnlineScan(
	ctx context.Context,
	cfg *config.AgentConfig,
	explicitLynisDir string,
	skipLynis bool,
) (transport.SnapshotPayload, error) {
	client, err := newClientFromConfig(cfg)
	if err != nil {
		return transport.SnapshotPayload{}, err
	}

	resolvedLynisDir := explicitLynisDir
	if !skipLynis && resolvedLynisDir == "" && cfg.BundleSigningPubKey != "" {
		resolvedLynisDir = resolveManagedLynisDir(ctx, client, cfg)
	}

	snap := collectSnapshot(ctx, cfg, cfg.Environment, resolvedLynisDir, skipLynis)
	if err := client.SendSnapshot(ctx, snap); err != nil {
		return transport.SnapshotPayload{}, err
	}
	fmt.Printf("Snapshot uploaded for host %s (%d packages)\n", cfg.HostID, len(snap.Packages))
	return snap, nil
}

func collectSnapshot(
	ctx context.Context,
	cfg *config.AgentConfig,
	envName string,
	lynisDir string,
	skipLynis bool,
) transport.SnapshotPayload {
	env := probe.DefaultEnv()
	probeRes := probe.Run(env)
	pkgs, err := collectors.CollectSBOM(ctx, env)
	if err != nil || pkgs == nil {
		pkgs = []collectors.PackageItem{}
	}
	netPayload := collectors.CollectNetwork(ctx, env)
	services := collectors.CollectServices(ctx, env, probeRes.InitSystem)
	sysctl := collectors.CollectSysctl(env)
	repos := collectors.CollectRepos(env)

	var lynisRes tools.LynisPayload
	if !skipLynis {
		dirToRun := lynisDir
		if dirToRun == "" && cfg != nil {
			dirToRun = tools.FindLatestInstalledTool(cfg.ToolsDir, "lynis")
		}
		if dirToRun != "" {
			if out, lErr := tools.RunIsolatedLynis(ctx, dirToRun); lErr == nil {
				lynisRes = out
			} else {
				fmt.Fprintf(os.Stderr, "isolated lynis execution warning: %v\n", lErr)
			}
		}
	}

	mode := "airgapped"
	hostID := ""
	environment := envName
	if cfg != nil {
		hostID = cfg.HostID
		mode = cfg.ConnectivityMode
		environment = cfg.Environment
	}

	return transport.SnapshotPayload{
		HostID:           hostID,
		Hostname:         probeRes.Hostname,
		MachineIDHash:    probeRes.MachineIDHash,
		Environment:      environment,
		CollectedAt:      time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		AgentVersion:     version,
		ConnectivityMode: mode,
		Probe:            probeRes,
		Packages:         pkgs,
		Network:          netPayload,
		Services:         services,
		Sysctl:           sysctl,
		Repos:            repos,
		Lynis:            lynisRes,
	}
}

func newPatchExecutor(client *transport.Client, hostID string, allowMutation bool) *updater.Executor {
	reachCheck := func(rctx context.Context) bool {
		return client.Heartbeat(rctx, hostID, transport.HeartbeatRequest{
			AgentVersion: version,
			UptimeSec:    readHostUptimeSec(),
		}) == nil
	}
	return updater.NewNativeExecutor(probe.DefaultEnv(), allowMutation, reachCheck)
}

func runPatch(args []string) error {
	fs := flag.NewFlagSet("patch", flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath, "Path to agent.json")
	allowMutation := fs.Bool("allow-mutation", false, "Explicitly permit live package upgrades for approved wave jobs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	client, err := newClientFromConfig(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	exec := newPatchExecutor(client, cfg.HostID, *allowMutation)
	return processPendingPatchJobs(ctx, client, cfg.HostID, exec)
}

func processPendingPatchJobs(
	ctx context.Context,
	client *transport.Client,
	hostID string,
	exec *updater.Executor,
) error {
	jobs, err := client.FetchPatchJobs(ctx, hostID)
	if err != nil {
		return err
	}
	var jobErrs []error
	for _, job := range jobs {
		policy := updater.DefaultSafeModePolicy()
		policy.Enabled = job.SafeModeEnabled
		policy.RollbackOnFailure = job.RollbackOnFailure
		req := updater.PatchRequest{
			PlanID:     job.PlanID,
			Packages:   job.Packages,
			SafeMode:   policy,
			DryRunOnly: job.Mode == "dry_run",
		}
		execStatus, report, execErr := exec.Apply(ctx, req)
		// Do not report blocked_read_only as a server failure when agent is running in dry-run-only mode.
		if execStatus == updater.StatusBlockedReadOnly {
			if errors.Is(execErr, updater.ErrMutationDisabled) {
				fmt.Printf("Patch job %s skipped (agent running in read-only mode)\n", job.PlanID)
				continue
			}
			jobErrs = append(jobErrs, fmt.Errorf("plan %s blocked before execution: %w", job.PlanID, execErr))
			continue
		}
		healthy := execStatus == updater.StatusCompleted
		detail := "ok"
		if execErr != nil {
			detail = sanitizeSingleLine(execErr.Error(), 500)
		}
		warnings := sanitizeWarnings(report.Warnings, 32, 255)
		res := transport.PatchJobResult{
			Mode:                job.Mode,
			Status:              string(execStatus),
			Succeeded:           execErr == nil,
			RepoVerified:        report.RepoVerified,
			PlannedChangesCount: len(report.PlannedChanges),
			RolledBack:          execStatus == updater.StatusRolledBack,
			Detail:              detail,
			Warnings:            warnings,
		}
		if job.Mode == "apply" {
			res.HealthyAfterPatch = &healthy
		}
		if repErr := client.ReportPatchJobResult(ctx, hostID, job.PlanID, res); repErr != nil {
			jobErrs = append(jobErrs, fmt.Errorf("plan %s report failed: %w", job.PlanID, repErr))
			continue
		}
		fmt.Printf("Reported patch job %s (mode=%s status=%s)\n", job.PlanID, job.Mode, execStatus)
	}
	return errors.Join(jobErrs...)
}

func sanitizeSingleLine(raw string, maxRunes int) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			b.WriteByte(' ')
		} else {
			b.WriteRune(r)
		}
	}
	cleaned := strings.Join(strings.Fields(b.String()), " ")
	if maxRunes > 0 {
		runes := []rune(cleaned)
		if len(runes) > maxRunes {
			cleaned = string(runes[:maxRunes])
		}
	}
	return cleaned
}

func sanitizeWarnings(raw []string, maxCount, maxRunes int) []string {
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if len(out) >= maxCount {
			break
		}
		if cleaned := sanitizeSingleLine(item, maxRunes); cleaned != "" {
			out = append(out, cleaned)
		}
	}
	return out
}
