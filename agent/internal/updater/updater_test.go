package updater_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tecno-consultores/HostGrid/agent/internal/updater"
)

type stubRepoVerifier struct {
	res    updater.RepoCheckResult
	err    error
	called bool
}

func (s *stubRepoVerifier) VerifyRepos(_ context.Context) (updater.RepoCheckResult, error) {
	s.called = true
	return s.res, s.err
}

type stubDryRunner struct {
	report updater.DryRunReport
	err    error
	called bool
}

func (s *stubDryRunner) DryRun(_ context.Context, _ updater.PatchRequest) (updater.DryRunReport, error) {
	s.called = true
	return s.report, s.err
}

func TestValidatePatchRequest(t *testing.T) {
	validReq := updater.PatchRequest{
		PlanID:     "550e8400-e29b-41d4-a716-446655440000",
		Packages:   []string{"openssh-server", "libssl3", "python3.12"},
		SafeMode:   updater.DefaultSafeModePolicy(),
		DryRunOnly: true,
	}
	if err := updater.ValidatePatchRequest(validReq); err != nil {
		t.Fatalf("expected valid request, got %v", err)
	}

	invalidCases := []struct {
		name string
		req  updater.PatchRequest
	}{
		{
			name: "missing plan_id",
			req:  updater.PatchRequest{Packages: []string{"openssh-server"}},
		},
		{
			name: "plan_id with control chars",
			req:  updater.PatchRequest{PlanID: "plan-1\r\nFAKE", Packages: []string{"openssh-server"}},
		},
		{
			name: "invalid critical service name",
			req: updater.PatchRequest{
				PlanID:   "plan-1",
				Packages: []string{"openssl"},
				SafeMode: updater.SafeModePolicy{CriticalServices: []string{"sshd;rm -rf /"}},
			},
		},
		{
			name: "empty packages",
			req:  updater.PatchRequest{PlanID: "plan-1"},
		},
		{
			name: "flag injection package name",
			req:  updater.PatchRequest{PlanID: "plan-1", Packages: []string{"--assume-yes"}},
		},
		{
			name: "shell metacharacters in package name",
			req:  updater.PatchRequest{PlanID: "plan-1", Packages: []string{"openssl;rm -rf /"}},
		},
		{
			name: "duplicate package",
			req:  updater.PatchRequest{PlanID: "plan-1", Packages: []string{"openssl", "openssl"}},
		},
		{
			name: "negative safe mode timeout",
			req: updater.PatchRequest{
				PlanID:   "plan-1",
				Packages: []string{"openssl"},
				SafeMode: updater.SafeModePolicy{HealthCheckTimeout: -1 * time.Second},
			},
		},
	}

	for _, tc := range invalidCases {
		if err := updater.ValidatePatchRequest(tc.req); err == nil {
			t.Errorf("case %q: expected validation error, got nil", tc.name)
		}
	}
}

func TestExecutorPlanAndVerifyEnforcesRepoPrecheckBeforeDryRun(t *testing.T) {
	req := updater.PatchRequest{
		PlanID:     "plan-001",
		Packages:   []string{"openssh-server"},
		SafeMode:   updater.DefaultSafeModePolicy(),
		DryRunOnly: true,
	}

	// Unsigned or unreachable repos must block dry-run from executing.
	blockedVerifier := &stubRepoVerifier{
		res: updater.RepoCheckResult{
			Accessible:       true,
			SignedMetadataOK: false,
			Detail:           "missing_gpg_signature",
		},
	}
	dryRunner := &stubDryRunner{
		report: updater.DryRunReport{Succeeded: true},
	}
	exec := &updater.Executor{Verifier: blockedVerifier, Runner: dryRunner}

	status, _, err := exec.Apply(context.Background(), req)
	if !errors.Is(err, updater.ErrRepoPrecheckFailed) {
		t.Fatalf("expected ErrRepoPrecheckFailed, got %v", err)
	}
	if status != updater.StatusBlockedRepoCheck {
		t.Fatalf("expected status %q, got %q", updater.StatusBlockedRepoCheck, status)
	}
	if dryRunner.called {
		t.Fatal("dry-run must not be invoked when repository pre-verification fails")
	}

	// Healthy repo + successful dry-run returns verified report.
	okVerifier := &stubRepoVerifier{
		res: updater.RepoCheckResult{
			Accessible:       true,
			SignedMetadataOK: true,
			Detail:           "internal_mirror_verified",
		},
	}
	okRunner := &stubDryRunner{
		report: updater.DryRunReport{
			PlanID:         req.PlanID,
			PackageManager: updater.PackageManagerAPT,
			Succeeded:      true,
			PlannedChanges: []updater.PackageChange{
				{
					Name:           "openssh-server",
					CurrentVersion: "1:8.9p1-3ubuntu0.6",
					TargetVersion:  "1:8.9p1-3ubuntu0.10",
					Action:         "upgrade",
				},
			},
		},
	}
	okExec := &updater.Executor{Verifier: okVerifier, Runner: okRunner}
	status, report, err := okExec.Apply(context.Background(), req)
	if err != nil {
		t.Fatalf("expected successful dry-run, got %v", err)
	}
	if status != updater.StatusDryRunOnly || !report.RepoVerified || len(report.PlannedChanges) != 1 {
		t.Fatalf("unexpected dry-run result: status=%q report=%+v", status, report)
	}
}

func TestExecutorBlocksLiveMutationByDefault(t *testing.T) {
	req := updater.PatchRequest{
		PlanID:     "plan-002",
		Packages:   []string{"openssl"},
		SafeMode:   updater.DefaultSafeModePolicy(),
		DryRunOnly: false,
	}
	exec := &updater.Executor{}
	status, _, err := exec.Apply(context.Background(), req)
	if !errors.Is(err, updater.ErrMutationDisabled) {
		t.Fatalf("expected ErrMutationDisabled, got %v", err)
	}
	if status != updater.StatusBlockedReadOnly {
		t.Fatalf("expected StatusBlockedReadOnly, got %q", status)
	}
}

func TestEvaluatePostPatchHealthSafeMode(t *testing.T) {
	pre := updater.PrePatchSnapshot{
		PlanID:         "plan-003",
		KernelVersion:  "6.1.0-26-amd64",
		ActiveServices: []string{"sshd", "nginx"},
	}
	policy := updater.DefaultSafeModePolicy()

	healthy := updater.EvaluatePostPatchHealth(pre, []string{"sshd", "nginx"}, true, policy)
	if !healthy.Healthy || healthy.RollbackRequired {
		t.Fatalf("expected healthy result, got %+v", healthy)
	}

	missingSSH := updater.EvaluatePostPatchHealth(pre, []string{"nginx"}, true, policy)
	if missingSSH.Healthy || !missingSSH.RollbackRequired || len(missingSSH.FailedServices) != 1 {
		t.Fatalf("expected rollback required when sshd fails, got %+v", missingSSH)
	}

	unreachableCP := updater.EvaluatePostPatchHealth(pre, []string{"sshd", "nginx"}, false, policy)
	if unreachableCP.Healthy || !unreachableCP.RollbackRequired {
		t.Fatalf("expected rollback required when control plane is unreachable, got %+v", unreachableCP)
	}

	disabledSafeMode := policy
	disabledSafeMode.Enabled = false
	noRollback := updater.EvaluatePostPatchHealth(pre, []string{"nginx"}, false, disabledSafeMode)
	if noRollback.Healthy || noRollback.RollbackRequired {
		t.Fatalf("expected unhealthy without rollback when SafeMode disabled, got %+v", noRollback)
	}

	dupPolicy := policy
	dupPolicy.CriticalServices = []string{"sshd", "sshd", "  ", ""}
	dedup := updater.EvaluatePostPatchHealth(pre, []string{"nginx"}, true, dupPolicy)
	if dedup.Healthy || len(dedup.FailedServices) != 1 || dedup.FailedServices[0] != "sshd" {
		t.Fatalf("expected deduplicated failed services [sshd], got %+v", dedup)
	}

	// Debian/Ubuntu exposes OpenSSH as "ssh"; DefaultSafeModePolicy ("sshd") must recognize it when active pre+post.
	debianPre := updater.PrePatchSnapshot{
		PlanID:         "plan-deb",
		ActiveServices: []string{"ssh", "nginx"},
	}
	debHealthy := updater.EvaluatePostPatchHealth(debianPre, []string{"ssh", "nginx"}, true, policy)
	if !debHealthy.Healthy || debHealthy.RollbackRequired {
		t.Fatalf("expected Debian 'ssh' service to satisfy 'sshd' policy, got %+v", debHealthy)
	}
	debCrashed := updater.EvaluatePostPatchHealth(debianPre, []string{"nginx"}, true, policy)
	if debCrashed.Healthy || !debCrashed.RollbackRequired {
		t.Fatalf("expected rollback when Debian 'ssh' stops after patch, got %+v", debCrashed)
	}
}

func TestExecutorDryRunFailuresPreserveCausesAndRejectMismatchedPlanID(t *testing.T) {
	req := updater.PatchRequest{
		PlanID:     "plan-004",
		Packages:   []string{"openssh-server"},
		SafeMode:   updater.DefaultSafeModePolicy(),
		DryRunOnly: true,
	}

	okVerifier := &stubRepoVerifier{
		res: updater.RepoCheckResult{Accessible: true, SignedMetadataOK: true},
	}

	// Runner timeout must return StatusFailedDryRun and preserve context.DeadlineExceeded.
	timeoutExec := &updater.Executor{
		Verifier: okVerifier,
		Runner:   &stubDryRunner{err: context.DeadlineExceeded},
	}
	status, _, err := timeoutExec.Apply(context.Background(), req)
	if status != updater.StatusFailedDryRun {
		t.Fatalf("expected StatusFailedDryRun, got %q", status)
	}
	if !errors.Is(err, updater.ErrDryRunFailed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected wrapped ErrDryRunFailed + DeadlineExceeded, got %v", err)
	}

	// Report with mismatched PlanID must be rejected.
	mismatchExec := &updater.Executor{
		Verifier: okVerifier,
		Runner: &stubDryRunner{
			report: updater.DryRunReport{PlanID: "different-plan", Succeeded: true},
		},
	}
	status, _, err = mismatchExec.Apply(context.Background(), req)
	if status != updater.StatusFailedDryRun || !errors.Is(err, updater.ErrDryRunFailed) {
		t.Fatalf("expected mismatched plan_id rejection, got status=%q err=%v", status, err)
	}

	// Nil receiver must not panic.
	var nilExec *updater.Executor
	if _, _, err := nilExec.Apply(context.Background(), req); err == nil {
		t.Fatal("expected error on nil Executor")
	}
}
