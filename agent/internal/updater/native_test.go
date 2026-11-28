package updater_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tecno-consultores/HostGrid/agent/internal/probe"
	"github.com/tecno-consultores/HostGrid/agent/internal/updater"
)

type stubApplier struct {
	err    error
	called bool
}

func (s *stubApplier) ApplyPackages(_ context.Context, _ updater.PatchRequest) error {
	s.called = true
	return s.err
}

type stubGuard struct {
	pre         updater.PrePatchSnapshot
	preErr      error
	health      updater.HealthCheckResult
	verifyErr   error
	rollbackErr error
	rolledBack  bool
}

func (s *stubGuard) CapturePrePatch(_ context.Context, planID string) (updater.PrePatchSnapshot, error) {
	if s.preErr != nil {
		return updater.PrePatchSnapshot{}, s.preErr
	}
	s.pre.PlanID = planID
	return s.pre, nil
}

func (s *stubGuard) VerifyPostPatch(
	_ context.Context,
	_ updater.PrePatchSnapshot,
	_ updater.SafeModePolicy,
) (updater.HealthCheckResult, error) {
	return s.health, s.verifyErr
}

func (s *stubGuard) Rollback(_ context.Context, _ updater.PrePatchSnapshot) error {
	s.rolledBack = true
	return s.rollbackErr
}

func TestExecutorLiveApplySafeModeSuccessAndRollbackPaths(t *testing.T) {
	okVerifier := &stubRepoVerifier{
		res: updater.RepoCheckResult{Accessible: true, SignedMetadataOK: true, Detail: "ok"},
	}
	okRunner := &stubDryRunner{
		report: updater.DryRunReport{PlanID: "plan-live", PackageManager: updater.PackageManagerAPT, Succeeded: true},
	}
	req := updater.PatchRequest{
		PlanID:     "plan-live",
		Packages:   []string{"openssh-server"},
		SafeMode:   updater.DefaultSafeModePolicy(),
		DryRunOnly: false,
	}

	// Fail closed when Applier or Guard is missing even if AllowMutation=true.
	noApplier := &updater.Executor{Verifier: okVerifier, Runner: okRunner, AllowMutation: true}
	if status, _, err := noApplier.Apply(context.Background(), req); !errors.Is(err, updater.ErrApplierRequired) || status != updater.StatusBlockedReadOnly {
		t.Fatalf("expected ErrApplierRequired, got status=%q err=%v", status, err)
	}
	noGuard := &updater.Executor{Verifier: okVerifier, Runner: okRunner, Applier: &stubApplier{}, AllowMutation: true}
	if status, _, err := noGuard.Apply(context.Background(), req); !errors.Is(err, updater.ErrGuardRequired) || status != updater.StatusBlockedReadOnly {
		t.Fatalf("expected ErrGuardRequired, got status=%q err=%v", status, err)
	}

	// Happy path -> StatusCompleted
	applier := &stubApplier{}
	guard := &stubGuard{health: updater.HealthCheckResult{Healthy: true, ControlPlaneReachable: true}}
	exec := &updater.Executor{
		Verifier:      okVerifier,
		Runner:        okRunner,
		Applier:       applier,
		Guard:         guard,
		AllowMutation: true,
	}
	status, report, err := exec.Apply(context.Background(), req)
	if err != nil || status != updater.StatusCompleted || !report.RepoVerified || !applier.called || guard.rolledBack {
		t.Fatalf("unexpected happy path result: status=%q err=%v rolledBack=%v", status, err, guard.rolledBack)
	}

	// Unhealthy post-patch triggers automatic Safe Mode rollback
	unhealthyGuard := &stubGuard{
		health: updater.HealthCheckResult{
			Healthy:          false,
			FailedServices:   []string{"sshd"},
			RollbackRequired: true,
			Detail:           "missing_critical_services:sshd",
		},
	}
	exec.Guard = unhealthyGuard
	status, _, err = exec.Apply(context.Background(), req)
	if !errors.Is(err, updater.ErrHealthCheckFailed) || status != updater.StatusRolledBack || !unhealthyGuard.rolledBack {
		t.Fatalf("expected automatic rollback on health failure, got status=%q err=%v rolledBack=%v", status, err, unhealthyGuard.rolledBack)
	}

	// ApplyPackages failure triggers rollback; rollback error surfaces ErrRollbackFailed
	failingApplier := &stubApplier{err: errors.New("dpkg interrupted")}
	failingRollbackGuard := &stubGuard{rollbackErr: errors.New("downgrade unavailable")}
	exec.Applier = failingApplier
	exec.Guard = failingRollbackGuard
	status, _, err = exec.Apply(context.Background(), req)
	if !errors.Is(err, updater.ErrRollbackFailed) || status != updater.StatusFailedHealthCheck {
		t.Fatalf("expected ErrRollbackFailed, got status=%q err=%v", status, err)
	}
}

func TestNativeRepoVerifierAndDryRunnerAndApplierAndRollback(t *testing.T) {
	root := t.TempDir()
	// Create APT sources + keyring + dpkg status + init.d service + kernel osrelease
	mustWrite := func(rel, content string) {
		t.Helper()
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("etc/apt/sources.list", "deb https://mirror.internal/debian bookworm main\n")
	mustWrite("etc/apt/trusted.gpg.d/debian.gpg", "fake-keyring-bytes")
	mustWrite("proc/sys/kernel/osrelease", "6.1.0-26-amd64\n")
	mustWrite("etc/init.d/sshd", "#!/bin/sh\n")
	mustWrite(
		"var/lib/dpkg/status",
		"Package: openssh-server\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:9.2p1-2+deb12u1\n\n"+
			"Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.36-9+deb12u7\n\n",
	)

	aptEnv := probe.Env{
		RootDir: root,
		LookPath: func(bin string) (string, error) {
			if bin == "apt-get" {
				return "/usr/bin/apt-get", nil
			}
			return "", errors.New("not found")
		},
	}

	verifier := &updater.NativeRepoVerifier{
		Env: aptEnv,
		Run: func(_ context.Context, _ []string, _ string, _ ...string) ([]byte, error) {
			return []byte("Package files:\n 500 https://mirror.internal/debian bookworm/main amd64 Packages\n"), nil
		},
	}
	repoRes, err := verifier.VerifyRepos(context.Background())
	if err != nil || !repoRes.Accessible || !repoRes.SignedMetadataOK {
		t.Fatalf("expected accessible signed repo, got %+v err=%v", repoRes, err)
	}

	// Failing repo check command reports Accessible=false cleanly
	failingVerifier := &updater.NativeRepoVerifier{
		Env: aptEnv,
		Run: func(_ context.Context, _ []string, _ string, _ ...string) ([]byte, error) {
			return []byte("mirror unreachable"), errors.New("exit status 100")
		},
	}
	failRes, err := failingVerifier.VerifyRepos(context.Background())
	if err != nil || failRes.Accessible {
		t.Fatalf("expected inaccessible repo on command error, got %+v err=%v", failRes, err)
	}

	// APT dry-run simulation parses Inst lines and passes -- separator
	var capturedBin string
	var capturedArgs []string
	var capturedEnv []string
	dryRunner := &updater.NativeDryRunner{
		Env: aptEnv,
		Run: func(_ context.Context, extraEnv []string, binary string, args ...string) ([]byte, error) {
			capturedBin = binary
			capturedArgs = args
			capturedEnv = extraEnv
			return []byte("Reading package lists...\nInst openssh-server [1:9.2p1-2+deb12u1] (1:9.2p1-2+deb12u3 Debian:12 [amd64])\n"), nil
		},
	}
	req := updater.PatchRequest{
		PlanID:     "plan-apt-1",
		Packages:   []string{"openssh-server"},
		SafeMode:   updater.DefaultSafeModePolicy(),
		DryRunOnly: true,
	}
	dr, err := dryRunner.DryRun(context.Background(), req)
	if err != nil || !dr.Succeeded || dr.PackageManager != updater.PackageManagerAPT || len(dr.PlannedChanges) != 1 {
		t.Fatalf("unexpected APT dry-run report: %+v err=%v", dr, err)
	}
	if capturedBin != "/usr/bin/apt-get" || !reflect.DeepEqual(capturedEnv, []string{"DEBIAN_FRONTEND=noninteractive"}) {
		t.Fatalf("unexpected APT invocation: bin=%q env=%v", capturedBin, capturedEnv)
	}
	if dr.PlannedChanges[0].TargetVersion != "1:9.2p1-2+deb12u3" || capturedArgs[len(capturedArgs)-2] != "--" {
		t.Fatalf("unexpected APT parsed change or args: %+v args=%v", dr.PlannedChanges[0], capturedArgs)
	}

	// DNF --assumeno treats exit error with "Operation aborted." as successful simulation
	dnfEnv := probe.Env{
		RootDir: root,
		LookPath: func(bin string) (string, error) {
			if bin == "dnf" {
				return "/usr/bin/dnf", nil
			}
			return "", errors.New("not found")
		},
	}
	dnfDry := &updater.NativeDryRunner{
		Env: dnfEnv,
		Run: func(_ context.Context, _ []string, _ string, _ ...string) ([]byte, error) {
			return []byte(
				"Last metadata expiration check: 0:12:34 ago.\n" +
					"Upgrading:\n" +
					" openssh-server x86_64 8.7p1-38.el9 baseos 500 k\n" +
					"Total size: 1.2 M\n" +
					"Installed size: 4.5 M\n" +
					"Operation aborted.\n",
			), errors.New("exit status 1")
		},
	}
	dnfRep, err := dnfDry.DryRun(context.Background(), req)
	if err != nil || !dnfRep.Succeeded || dnfRep.PackageManager != updater.PackageManagerDNF || len(dnfRep.PlannedChanges) != 1 || dnfRep.PlannedChanges[0].Name != "openssh-server" {
		t.Fatalf("unexpected DNF dry-run report: %+v err=%v", dnfRep, err)
	}

	// APK --simulate parses Upgrading lines
	apkEnv := probe.Env{
		RootDir: root,
		LookPath: func(bin string) (string, error) {
			if bin == "apk" {
				return "/sbin/apk", nil
			}
			return "", errors.New("not found")
		},
	}
	apkDry := &updater.NativeDryRunner{
		Env: apkEnv,
		Run: func(_ context.Context, _ []string, _ string, _ ...string) ([]byte, error) {
			return []byte("(1/1) Upgrading openssh-server (9.6_p1-r0 -> 9.7_p1-r4)\n"), nil
		},
	}
	apkRep, err := apkDry.DryRun(context.Background(), req)
	if err != nil || !apkRep.Succeeded || len(apkRep.PlannedChanges) != 1 || apkRep.PlannedChanges[0].TargetVersion != "9.7_p1-r4" {
		t.Fatalf("unexpected APK dry-run report: %+v err=%v", apkRep, err)
	}

	// NativePackageApplier invokes apt-get with --only-upgrade and --
	var applyArgs []string
	applier := &updater.NativePackageApplier{
		Env: aptEnv,
		Run: func(_ context.Context, _ []string, _ string, args ...string) ([]byte, error) {
			applyArgs = args
			return []byte("ok"), nil
		},
	}
	if err := applier.ApplyPackages(context.Background(), req); err != nil {
		t.Fatalf("expected apply success, got %v", err)
	}
	if !strings.Contains(strings.Join(applyArgs, " "), "--only-upgrade -- openssh-server") {
		t.Fatalf("unexpected apply args: %v", applyArgs)
	}

	// NativeSafeModeGuard captures baseline, checks health, and runs version-pinned rollback
	var rbArgs []string
	guard := &updater.NativeSafeModeGuard{
		Env: aptEnv,
		Run: func(_ context.Context, _ []string, _ string, args ...string) ([]byte, error) {
			rbArgs = args
			return []byte("downgraded"), nil
		},
		ReachabilityCheck: func(_ context.Context) bool { return true },
	}
	pre, err := guard.CapturePrePatch(context.Background(), "plan-apt-1")
	if err != nil || pre.PackageVersions["openssh-server"] != "1:9.2p1-2+deb12u1" {
		t.Fatalf("unexpected pre-patch snapshot: %+v err=%v", pre, err)
	}
	hc, err := guard.VerifyPostPatch(context.Background(), pre, updater.DefaultSafeModePolicy())
	if err != nil || !hc.Healthy {
		t.Fatalf("expected healthy post-patch verification, got %+v err=%v", hc, err)
	}

	// Simulate post-patch SBOM where ONLY openssh-server changed while libc6 stayed untouched.
	mustWrite(
		"var/lib/dpkg/status",
		"Package: openssh-server\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:9.2p1-2+deb12u3\n\n"+
			"Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.36-9+deb12u7\n\n",
	)
	if err := guard.Rollback(context.Background(), pre); err != nil {
		t.Fatalf("expected rollback success, got %v", err)
	}
	joinedRB := strings.Join(rbArgs, " ")
	if !strings.Contains(joinedRB, "--allow-downgrades install -- openssh-server=1:9.2p1-2+deb12u1") {
		t.Fatalf("unexpected rollback args: %v", rbArgs)
	}
	if strings.Contains(joinedRB, "libc6") {
		t.Fatalf("rollback must NOT downgrade unchanged packages like libc6, got args: %v", rbArgs)
	}

	// Rollback rejects malicious version string with shell metacharacters
	badPre := updater.PrePatchSnapshot{
		PlanID:          "bad",
		PackageVersions: map[string]string{"openssh-server": "1.0;rm -rf /"},
	}
	if err := guard.Rollback(context.Background(), badPre); err == nil {
		t.Fatal("expected rollback to reject invalid package version string")
	}

	// NativeRepoVerifier rejects explicit signature bypass ([trusted=yes] / gpgcheck=0)
	unsignedRoot := t.TempDir()
	mustWriteAt := func(base, rel, content string) {
		full := filepath.Join(base, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteAt(unsignedRoot, "etc/apt/sources.list", "deb [trusted=yes] http://mirror.internal/debian bookworm main\n")
	mustWriteAt(unsignedRoot, "etc/apt/trusted.gpg.d/debian.gpg", "fake-keyring-bytes")
	unsignedVerifier := &updater.NativeRepoVerifier{
		Env: probe.Env{
			RootDir: unsignedRoot,
			LookPath: func(bin string) (string, error) {
				if bin == "apt-get" {
					return "/usr/bin/apt-get", nil
				}
				return "", errors.New("not found")
			},
		},
		Run: func(_ context.Context, _ []string, _ string, _ ...string) ([]byte, error) {
			return []byte("ok"), nil
		},
	}
	unsRes, err := unsignedVerifier.VerifyRepos(context.Background())
	if err != nil || unsRes.SignedMetadataOK {
		t.Fatalf("expected [trusted=yes] repo to fail signed metadata verification, got %+v err=%v", unsRes, err)
	}
}
