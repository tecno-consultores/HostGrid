package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tecno-consultores/HostGrid/agent/internal/config"
	"github.com/tecno-consultores/HostGrid/agent/internal/transport"
	"github.com/tecno-consultores/HostGrid/agent/internal/updater"
)

type stubPatchVerifier struct{}

func (stubPatchVerifier) VerifyRepos(_ context.Context) (updater.RepoCheckResult, error) {
	return updater.RepoCheckResult{Accessible: true, SignedMetadataOK: true, Detail: "ok"}, nil
}

type stubPatchDryRunner struct{}

func (stubPatchDryRunner) DryRun(_ context.Context, req updater.PatchRequest) (updater.DryRunReport, error) {
	return updater.DryRunReport{
		PlanID:         req.PlanID,
		PackageManager: updater.PackageManagerAPT,
		Succeeded:      true,
		PlannedChanges: []updater.PackageChange{{Name: req.Packages[0], TargetVersion: "2.0", Action: "upgrade"}},
	}, nil
}

func TestProcessPendingPatchJobsDryRunAndReadOnlySkip(t *testing.T) {
	var reported atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/agents/h-1/patch-jobs":
			_ = json.NewEncoder(w).Encode([]transport.PatchJob{
				{PlanID: "plan-dry", Title: "Dry", Mode: "dry_run", Packages: []string{"curl"}, SafeModeEnabled: true, RollbackOnFailure: true},
				{PlanID: "plan-apply", Title: "Apply", Mode: "apply", Packages: []string{"curl"}, SafeModeEnabled: true, RollbackOnFailure: true},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/agents/h-1/patch-jobs/plan-dry/result":
			var body transport.PatchJobResult
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if body.Mode != "dry_run" || !body.Succeeded || body.PlannedChangesCount != 1 {
				http.Error(w, "unexpected body", http.StatusBadRequest)
				return
			}
			reported.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := transport.NewClient(transport.ClientOptions{
		ServerURL:    srv.URL,
		Credential:   "hg_agent_test_token",
		AgentVersion: "0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	exec := &updater.Executor{
		Verifier:      stubPatchVerifier{},
		Runner:        stubPatchDryRunner{},
		AllowMutation: false,
	}
	if err := processPendingPatchJobs(context.Background(), client, "h-1", exec); err != nil {
		t.Fatalf("processPendingPatchJobs failed: %v", err)
	}
	if reported.Load() != 1 {
		t.Fatalf("expected exactly 1 dry-run report (apply skipped in read-only mode), got %d", reported.Load())
	}
}

type failingMultiLineDryRunner struct{}

func (failingMultiLineDryRunner) DryRun(_ context.Context, req updater.PatchRequest) (updater.DryRunReport, error) {
	return updater.DryRunReport{
		PlanID:   req.PlanID,
		Warnings: []string{"warn line 1\nwarn line 2\t" + strings.Repeat("w", 300)},
	}, errors.New("E: line one\r\nE: line two " + strings.Repeat("x", 600))
}

func TestProcessPendingPatchJobsSanitizesMultilineAndLongErrorDetails(t *testing.T) {
	var captured transport.PatchJobResult
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/agents/h-2/patch-jobs":
			_ = json.NewEncoder(w).Encode([]transport.PatchJob{
				{PlanID: "plan-err", Title: "Fail", Mode: "dry_run", Packages: []string{"curl"}, SafeModeEnabled: true, RollbackOnFailure: true},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/agents/h-2/patch-jobs/plan-err/result":
			if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, err := transport.NewClient(transport.ClientOptions{
		ServerURL:    srv.URL,
		Credential:   "hg_agent_test_token",
		AgentVersion: "0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	exec := &updater.Executor{
		Verifier: stubPatchVerifier{},
		Runner:   failingMultiLineDryRunner{},
	}
	if err := processPendingPatchJobs(context.Background(), client, "h-2", exec); err != nil {
		t.Fatalf("processPendingPatchJobs failed: %v", err)
	}
	if strings.ContainsAny(captured.Detail, "\r\n\t") || len([]rune(captured.Detail)) > 500 {
		t.Fatalf("detail must be single-line and <=500 runes for Control Plane schema, got len=%d detail=%q", len([]rune(captured.Detail)), captured.Detail)
	}
	if len(captured.Warnings) != 1 || strings.ContainsAny(captured.Warnings[0], "\r\n\t") || len([]rune(captured.Warnings[0])) > 255 {
		t.Fatalf("warnings must be single-line and <=255 runes, got %+v", captured.Warnings)
	}
}

type stubPatchApplier struct {
	applied atomic.Int32
}

func (s *stubPatchApplier) ApplyPackages(_ context.Context, _ updater.PatchRequest) error {
	s.applied.Add(1)
	return nil
}

type stubSafeModeGuard struct{}

func (stubSafeModeGuard) CapturePrePatch(_ context.Context, planID string) (updater.PrePatchSnapshot, error) {
	return updater.PrePatchSnapshot{
		PlanID:          planID,
		ActiveServices:  []string{"sshd"},
		PackageVersions: map[string]string{"curl": "1.0"},
	}, nil
}

func (stubSafeModeGuard) VerifyPostPatch(_ context.Context, _ updater.PrePatchSnapshot, _ updater.SafeModePolicy) (updater.HealthCheckResult, error) {
	return updater.HealthCheckResult{Healthy: true, ControlPlaneReachable: true, Detail: "ok"}, nil
}

func (stubSafeModeGuard) Rollback(_ context.Context, _ updater.PrePatchSnapshot) error {
	return nil
}

func TestRunDaemonLoopPollsPatchJobsReadOnlyAndResilient(t *testing.T) {
	var polls atomic.Int32
	var dryRunReports atomic.Int32
	var applyReports atomic.Int32

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/agents/h-daemon/patch-jobs":
			attempt := polls.Add(1)
			// Simulate transient Control Plane 500 on first poll to confirm daemon keeps polling.
			if attempt == 1 {
				http.Error(w, "temporary outage", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode([]transport.PatchJob{
				{PlanID: "plan-dry", Title: "Dry", Mode: "dry_run", Packages: []string{"curl"}, SafeModeEnabled: true, RollbackOnFailure: true},
				{PlanID: "plan-apply", Title: "Apply", Mode: "apply", Packages: []string{"curl"}, SafeModeEnabled: true, RollbackOnFailure: true},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/agents/h-daemon/patch-jobs/plan-dry/result":
			dryRunReports.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			go func() {
				time.Sleep(10 * time.Millisecond)
				cancel()
			}()
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/agents/h-daemon/patch-jobs/plan-apply/result":
			applyReports.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	client, err := transport.NewClient(transport.ClientOptions{
		ServerURL:    srv.URL,
		Credential:   "hg_agent_daemon_ro",
		AgentVersion: "0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}

	applier := &stubPatchApplier{}
	exec := &updater.Executor{
		Verifier:      stubPatchVerifier{},
		Runner:        stubPatchDryRunner{},
		Applier:       applier,
		Guard:         stubSafeModeGuard{},
		AllowMutation: false,
	}

	done := make(chan error, 1)
	go func() {
		done <- runDaemonLoop(ctx, daemonOptions{
			cfg:           &config.AgentConfig{HostID: "h-daemon", HeartbeatIntervalSec: 3600, ScanIntervalSec: 3600},
			client:        client,
			exec:          exec,
			patchInterval: 15 * time.Millisecond,
			hbInterval:    time.Hour,
			scanInterval:  time.Hour,
			scanFn: func(context.Context) (transport.SnapshotPayload, error) {
				return transport.SnapshotPayload{CollectedAt: "2026-11-28T00:00:00.000Z"}, nil
			},
		})
	}()

	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("runDaemonLoop returned unexpected error: %v", runErr)
		}
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("timed out waiting for daemon patch-jobs poll")
	}

	if polls.Load() < 2 {
		t.Fatalf("expected daemon to recover after transient 500 and poll >= 2 times, got %d", polls.Load())
	}
	if dryRunReports.Load() != 1 {
		t.Fatalf("expected 1 dry-run report, got %d", dryRunReports.Load())
	}
	if applyReports.Load() != 0 || applier.applied.Load() != 0 {
		t.Fatalf("read-only daemon must NOT apply or report apply jobs: applyReports=%d applied=%d", applyReports.Load(), applier.applied.Load())
	}
}

func TestRunDaemonLoopAllowMutationAndDisabledPolling(t *testing.T) {
	var reportedApply atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/agents/h-mut/patch-jobs":
			_ = json.NewEncoder(w).Encode([]transport.PatchJob{
				{PlanID: "plan-wave-1", Title: "Canary", Mode: "apply", Packages: []string{"curl"}, SafeModeEnabled: true, RollbackOnFailure: true},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/agents/h-mut/patch-jobs/plan-wave-1/result":
			var body transport.PatchJobResult
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if body.Mode == "apply" && body.Succeeded && body.HealthyAfterPatch != nil && *body.HealthyAfterPatch {
				reportedApply.Store(true)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			go func() {
				time.Sleep(10 * time.Millisecond)
				cancel()
			}()
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	client, err := transport.NewClient(transport.ClientOptions{
		ServerURL:    srv.URL,
		Credential:   "hg_agent_daemon_rw",
		AgentVersion: "0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}

	applier := &stubPatchApplier{}
	exec := &updater.Executor{
		Verifier:      stubPatchVerifier{},
		Runner:        stubPatchDryRunner{},
		Applier:       applier,
		Guard:         stubSafeModeGuard{},
		AllowMutation: true,
	}

	if err := runDaemonLoop(ctx, daemonOptions{
		cfg:           &config.AgentConfig{HostID: "h-mut"},
		client:        client,
		exec:          exec,
		patchInterval: 20 * time.Millisecond,
		hbInterval:    time.Hour,
		scanInterval:  time.Hour,
		scanFn: func(context.Context) (transport.SnapshotPayload, error) {
			return transport.SnapshotPayload{}, nil
		},
	}); err != nil {
		t.Fatalf("runDaemonLoop allow-mutation failed: %v", err)
	}
	if !reportedApply.Load() || applier.applied.Load() != 1 {
		t.Fatalf("expected apply job to run and report healthy, reported=%v applied=%d", reportedApply.Load(), applier.applied.Load())
	}

	// Disabled patch polling (--patch-interval=0) must never call /patch-jobs
	var disabledPolls atomic.Int32
	srvDisabled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/patch-jobs") {
			disabledPolls.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srvDisabled.Close()

	disabledClient, err := transport.NewClient(transport.ClientOptions{
		ServerURL:    srvDisabled.URL,
		Credential:   "hg_agent_disabled",
		AgentVersion: "0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel2()
	if err := runDaemonLoop(ctx2, daemonOptions{
		cfg:           &config.AgentConfig{HostID: "h-disabled"},
		client:        disabledClient,
		exec:          exec,
		patchInterval: 0,
		hbInterval:    time.Hour,
		scanInterval:  time.Hour,
		scanFn: func(context.Context) (transport.SnapshotPayload, error) {
			return transport.SnapshotPayload{}, nil
		},
	}); err != nil {
		t.Fatalf("runDaemonLoop disabled polling failed: %v", err)
	}
	if disabledPolls.Load() != 0 {
		t.Fatalf("expected 0 patch-jobs polls when patchInterval=0, got %d", disabledPolls.Load())
	}

	// Negative --patch-interval CLI flag rejected before loading config
	if err := runDaemon([]string{"--patch-interval", "-5s"}); err == nil {
		t.Fatal("expected error for negative --patch-interval")
	}
}

func TestProcessPendingPatchJobsContinuesAfterSingleJobReportError(t *testing.T) {
	var secondJobReported atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/agents/h-multi/patch-jobs":
			_ = json.NewEncoder(w).Encode([]transport.PatchJob{
				{PlanID: "plan-conflict", Title: "Stale", Mode: "dry_run", Packages: []string{"curl"}, SafeModeEnabled: true, RollbackOnFailure: true},
				{PlanID: "plan-valid", Title: "Valid", Mode: "dry_run", Packages: []string{"openssl"}, SafeModeEnabled: true, RollbackOnFailure: true},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/agents/h-multi/patch-jobs/plan-conflict/result":
			http.Error(w, "already closed", http.StatusConflict)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/agents/h-multi/patch-jobs/plan-valid/result":
			secondJobReported.Store(true)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, err := transport.NewClient(transport.ClientOptions{
		ServerURL:    srv.URL,
		Credential:   "hg_agent_multi",
		AgentVersion: "0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	exec := &updater.Executor{
		Verifier: stubPatchVerifier{},
		Runner:   stubPatchDryRunner{},
	}
	err = processPendingPatchJobs(context.Background(), client, "h-multi", exec)
	if err == nil {
		t.Fatal("expected aggregated error when first job report fails with 409")
	}
	if !secondJobReported.Load() {
		t.Fatal("expected second valid job to execute and report even after first job report failed")
	}
}
