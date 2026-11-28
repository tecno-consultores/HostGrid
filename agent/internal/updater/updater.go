// Package updater defines the Phase 3 governed patching interfaces and base
// invariants for the HostGrid agent: repository pre-verification, mandatory
// dry-run simulation, safe-mode health checks, and rollback snapshots.
package updater

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// PackageManager identifies the native Linux package manager on the host.
type PackageManager string

const (
	PackageManagerAPT     PackageManager = "apt"
	PackageManagerDNF     PackageManager = "dnf"
	PackageManagerYUM     PackageManager = "yum"
	PackageManagerAPK     PackageManager = "apk"
	PackageManagerUnknown PackageManager = "unknown"
)

// ExecutionStatus describes the terminal or intermediate state of an updater run.
type ExecutionStatus string

const (
	StatusDryRunOnly        ExecutionStatus = "dry_run_only"
	StatusBlockedRepoCheck  ExecutionStatus = "blocked_repo_precheck"
	StatusFailedDryRun      ExecutionStatus = "failed_dry_run"
	StatusBlockedReadOnly   ExecutionStatus = "blocked_read_only"
	StatusFailedHealthCheck ExecutionStatus = "failed_healthcheck"
	StatusRolledBack        ExecutionStatus = "rolled_back"
	StatusCompleted         ExecutionStatus = "completed"
)

var (
	// ErrMutationDisabled is returned whenever live package mutation is attempted in read-only mode.
	ErrMutationDisabled = errors.New("live package mutation is disabled in read-only mode")
	// ErrRepoPrecheckFailed indicates configured repositories are unreachable or lack valid signatures.
	ErrRepoPrecheckFailed = errors.New("repository pre-verification failed")
	// ErrDryRunFailed indicates the package manager dry-run simulation reported an error.
	ErrDryRunFailed = errors.New("dry-run simulation failed")
	// ErrVerifierRequired indicates no RepoVerifier was wired into the Executor.
	ErrVerifierRequired = errors.New("repository verifier is required")
	// ErrDryRunnerRequired indicates no DryRunner was wired into the Executor.
	ErrDryRunnerRequired = errors.New("dry-run simulator is required")
	// ErrApplierRequired indicates no PackageApplier was wired for live patching.
	ErrApplierRequired = errors.New("package applier is required for live mutation")
	// ErrGuardRequired indicates no SafeModeGuard was wired for live patching.
	ErrGuardRequired = errors.New("safe mode guard is required for live mutation")
	// ErrHealthCheckFailed indicates post-patch Safe Mode verification failed.
	ErrHealthCheckFailed = errors.New("post-patch safe mode health check failed")
	// ErrRollbackFailed indicates automatic Safe Mode rollback did not succeed.
	ErrRollbackFailed = errors.New("safe mode rollback failed")

	validPackageNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.+_-]{0,127}$`)
	validPlanIDRe      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	validServiceNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:@-]{0,127}$`)
	validVersionRe     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.+:~_-]{0,127}$`)
)

// RepoCheckResult captures the read-only pre-verification state of configured package repositories.
type RepoCheckResult struct {
	Accessible        bool      `json:"accessible"`
	SignedMetadataOK  bool      `json:"signed_metadata_ok"`
	ConfiguredSources []string  `json:"configured_sources"`
	Detail            string    `json:"detail"`
	CheckedAt         time.Time `json:"checked_at"`
}

// RepoVerifier validates repository reachability and signature metadata prior to any dry-run.
type RepoVerifier interface {
	VerifyRepos(ctx context.Context) (RepoCheckResult, error)
}

// SafeModePolicy governs post-patch health validation and automatic rollback triggers.
type SafeModePolicy struct {
	Enabled                        bool          `json:"enabled"`
	CriticalServices               []string      `json:"critical_services"`
	VerifyControlPlaneReachability bool          `json:"verify_control_plane_reachability"`
	RollbackOnFailure              bool          `json:"rollback_on_failure"`
	HealthCheckTimeout             time.Duration `json:"health_check_timeout"`
}

// DefaultSafeModePolicy returns the recommended conservative Safe Mode defaults.
func DefaultSafeModePolicy() SafeModePolicy {
	return SafeModePolicy{
		Enabled:                        true,
		CriticalServices:               []string{"sshd"},
		VerifyControlPlaneReachability: true,
		RollbackOnFailure:              true,
		HealthCheckTimeout:             30 * time.Second,
	}
}

// PatchRequest describes a governed patch operation requested by the Control Plane.
type PatchRequest struct {
	PlanID     string         `json:"plan_id"`
	Packages   []string       `json:"packages"`
	SafeMode   SafeModePolicy `json:"safe_mode"`
	DryRunOnly bool           `json:"dry_run_only"`
}

// PackageChange summarizes a single package mutation predicted during dry-run.
type PackageChange struct {
	Name           string `json:"name"`
	CurrentVersion string `json:"current_version,omitempty"`
	TargetVersion  string `json:"target_version"`
	Action         string `json:"action"`
}

// DryRunReport captures the deterministic outcome of a non-mutating simulation.
type DryRunReport struct {
	PlanID         string          `json:"plan_id"`
	PackageManager PackageManager  `json:"package_manager"`
	Succeeded      bool            `json:"succeeded"`
	RepoVerified   bool            `json:"repo_verified"`
	PlannedChanges []PackageChange `json:"planned_changes"`
	Warnings       []string        `json:"warnings,omitempty"`
	SimulatedAt    time.Time       `json:"simulated_at"`
}

// DryRunner simulates package upgrades without mutating host state (e.g. apt-get -s / dnf --assumeno).
type DryRunner interface {
	DryRun(ctx context.Context, req PatchRequest) (DryRunReport, error)
}

// PrePatchSnapshot records baseline host state before applying any governed patch wave.
type PrePatchSnapshot struct {
	PlanID          string            `json:"plan_id"`
	CapturedAt      time.Time         `json:"captured_at"`
	KernelVersion   string            `json:"kernel_version"`
	ActiveServices  []string          `json:"active_services"`
	PackageVersions map[string]string `json:"package_versions"`
}

// HealthCheckResult records the outcome of Safe Mode verification after patching.
type HealthCheckResult struct {
	Healthy               bool     `json:"healthy"`
	FailedServices        []string `json:"failed_services,omitempty"`
	ControlPlaneReachable bool     `json:"control_plane_reachable"`
	RollbackRequired      bool     `json:"rollback_required"`
	Detail                string   `json:"detail"`
}

// SafeModeGuard captures pre-patch baselines, verifies post-patch health, and performs rollbacks.
type SafeModeGuard interface {
	CapturePrePatch(ctx context.Context, planID string) (PrePatchSnapshot, error)
	VerifyPostPatch(ctx context.Context, pre PrePatchSnapshot, policy SafeModePolicy) (HealthCheckResult, error)
	Rollback(ctx context.Context, pre PrePatchSnapshot) error
}

// ValidatePatchRequest enforces strict allow-list validation on plan metadata and package names.
func ValidatePatchRequest(req PatchRequest) error {
	if strings.TrimSpace(req.PlanID) == "" {
		return errors.New("plan_id is required")
	}
	if !validPlanIDRe.MatchString(req.PlanID) {
		return errors.New("plan_id contains disallowed characters")
	}
	if len(req.Packages) == 0 {
		return errors.New("at least one package must be specified")
	}
	seen := make(map[string]struct{}, len(req.Packages))
	for _, pkg := range req.Packages {
		if !validPackageNameRe.MatchString(pkg) {
			return fmt.Errorf("invalid package name %q", pkg)
		}
		if _, dup := seen[pkg]; dup {
			return fmt.Errorf("duplicate package name %q", pkg)
		}
		seen[pkg] = struct{}{}
	}
	if req.SafeMode.HealthCheckTimeout < 0 {
		return errors.New("safe_mode.health_check_timeout cannot be negative")
	}
	for _, svc := range req.SafeMode.CriticalServices {
		if !validServiceNameRe.MatchString(svc) {
			return fmt.Errorf("invalid critical service name %q", svc)
		}
	}
	return nil
}

// EvaluatePostPatchHealth determines whether a patched host remains healthy under SafeModePolicy.
func EvaluatePostPatchHealth(
	pre PrePatchSnapshot,
	activeAfter []string,
	controlPlaneReachable bool,
	policy SafeModePolicy,
) HealthCheckResult {
	activeSet := make(map[string]struct{}, len(activeAfter))
	for _, svc := range activeAfter {
		trimmed := strings.TrimSpace(svc)
		if trimmed != "" {
			activeSet[trimmed] = struct{}{}
		}
	}
	preSet := make(map[string]struct{}, len(pre.ActiveServices))
	for _, svc := range pre.ActiveServices {
		trimmed := strings.TrimSpace(svc)
		if trimmed != "" {
			preSet[trimmed] = struct{}{}
		}
	}

	required := policy.CriticalServices
	if len(required) == 0 {
		required = pre.ActiveServices
	}

	var failed []string
	seenFailed := make(map[string]struct{}, len(required))
	for _, svc := range required {
		trimmed := strings.TrimSpace(svc)
		if trimmed == "" {
			continue
		}
		if !isCriticalServiceHealthy(trimmed, preSet, activeSet) {
			if _, already := seenFailed[trimmed]; !already {
				seenFailed[trimmed] = struct{}{}
				failed = append(failed, trimmed)
			}
		}
	}

	cpFailed := policy.VerifyControlPlaneReachability && !controlPlaneReachable
	if len(failed) == 0 && !cpFailed {
		return HealthCheckResult{
			Healthy:               true,
			ControlPlaneReachable: controlPlaneReachable,
			RollbackRequired:      false,
			Detail:                "post_patch_health_verified",
		}
	}

	reasons := make([]string, 0, 2)
	if len(failed) > 0 {
		reasons = append(reasons, "missing_critical_services:"+strings.Join(failed, ","))
	}
	if cpFailed {
		reasons = append(reasons, "control_plane_unreachable")
	}

	return HealthCheckResult{
		Healthy:               false,
		FailedServices:        failed,
		ControlPlaneReachable: controlPlaneReachable,
		RollbackRequired:      policy.Enabled && policy.RollbackOnFailure,
		Detail:                strings.Join(reasons, ";"),
	}
}

func isCriticalServiceHealthy(svc string, preSet, activeSet map[string]struct{}) bool {
	if _, ok := activeSet[svc]; ok {
		return true
	}
	// Debian/Ubuntu systemd/SysVinit exposes OpenSSH as "ssh" while RHEL/Alpine uses "sshd".
	var alias string
	switch svc {
	case "sshd":
		alias = "ssh"
	case "ssh":
		alias = "sshd"
	default:
		return false
	}
	_, wasRunning := preSet[alias]
	_, stillRunning := activeSet[alias]
	return wasRunning && stillRunning
}

// PackageApplier executes validated package upgrades when AllowMutation is explicitly enabled.
type PackageApplier interface {
	ApplyPackages(ctx context.Context, req PatchRequest) error
}

// Executor orchestrates repository pre-checks, dry-run simulation, live apply, and Safe Mode guards.
// AllowMutation defaults to false so Phase 1/2 deployments remain strictly read-only.
type Executor struct {
	Verifier      RepoVerifier
	Runner        DryRunner
	Applier       PackageApplier
	Guard         SafeModeGuard
	AllowMutation bool
}

// PlanAndVerify executes mandatory repository pre-verification followed by dry-run simulation.
func (e *Executor) PlanAndVerify(ctx context.Context, req PatchRequest) (DryRunReport, error) {
	if e == nil {
		return DryRunReport{}, errors.New("executor cannot be nil")
	}
	if err := ValidatePatchRequest(req); err != nil {
		return DryRunReport{}, err
	}
	if e.Verifier == nil {
		return DryRunReport{}, ErrVerifierRequired
	}
	if e.Runner == nil {
		return DryRunReport{}, ErrDryRunnerRequired
	}

	repoRes, err := e.Verifier.VerifyRepos(ctx)
	if err != nil {
		return DryRunReport{}, fmt.Errorf("%w: %w", ErrRepoPrecheckFailed, err)
	}
	if !repoRes.Accessible || !repoRes.SignedMetadataOK {
		return DryRunReport{}, fmt.Errorf("%w: %s", ErrRepoPrecheckFailed, repoRes.Detail)
	}

	report, err := e.Runner.DryRun(ctx, req)
	if err != nil {
		return report, fmt.Errorf("%w: %w", ErrDryRunFailed, err)
	}
	if report.PlanID == "" {
		report.PlanID = req.PlanID
	} else if report.PlanID != req.PlanID {
		return report, fmt.Errorf("%w: report plan_id mismatch", ErrDryRunFailed)
	}
	report.RepoVerified = true
	if !report.Succeeded {
		return report, ErrDryRunFailed
	}
	return report, nil
}

// Apply executes governed dry-run or live mutation with mandatory Safe Mode guardrails.
// Live mutation is refused unless AllowMutation is explicitly enabled and DryRunOnly is false.
func (e *Executor) Apply(ctx context.Context, req PatchRequest) (ExecutionStatus, DryRunReport, error) {
	if e == nil {
		return StatusBlockedReadOnly, DryRunReport{}, errors.New("executor cannot be nil")
	}
	if req.DryRunOnly {
		return e.runDryRunOnly(ctx, req)
	}
	if err := ValidatePatchRequest(req); err != nil {
		return StatusBlockedReadOnly, DryRunReport{}, err
	}
	if !e.AllowMutation {
		return StatusBlockedReadOnly, DryRunReport{}, ErrMutationDisabled
	}
	if e.Applier == nil {
		return StatusBlockedReadOnly, DryRunReport{}, ErrApplierRequired
	}
	if e.Guard == nil {
		return StatusBlockedReadOnly, DryRunReport{}, ErrGuardRequired
	}

	status, report, err := e.runDryRunOnly(ctx, req)
	if err != nil {
		return status, report, err
	}

	pre, err := e.Guard.CapturePrePatch(ctx, req.PlanID)
	if err != nil {
		return StatusFailedHealthCheck, report, fmt.Errorf("capture pre-patch baseline: %w", err)
	}

	if applyErr := e.Applier.ApplyPackages(ctx, req); applyErr != nil {
		return e.handleMutationFailure(ctx, pre, req.SafeMode, report, applyErr)
	}

	health, verifyErr := e.Guard.VerifyPostPatch(ctx, pre, req.SafeMode)
	if verifyErr != nil {
		wrapped := fmt.Errorf("%w: %w", ErrHealthCheckFailed, verifyErr)
		return e.handleMutationFailure(ctx, pre, req.SafeMode, report, wrapped)
	}
	if !health.Healthy {
		hcErr := fmt.Errorf("%w: %s", ErrHealthCheckFailed, health.Detail)
		if health.RollbackRequired {
			return e.triggerRollback(ctx, pre, report, hcErr)
		}
		return StatusFailedHealthCheck, report, hcErr
	}
	return StatusCompleted, report, nil
}

func (e *Executor) runDryRunOnly(ctx context.Context, req PatchRequest) (ExecutionStatus, DryRunReport, error) {
	report, err := e.PlanAndVerify(ctx, req)
	if err != nil {
		if errors.Is(err, ErrRepoPrecheckFailed) {
			return StatusBlockedRepoCheck, report, err
		}
		return StatusFailedDryRun, report, err
	}
	return StatusDryRunOnly, report, nil
}

func (e *Executor) handleMutationFailure(
	ctx context.Context,
	pre PrePatchSnapshot,
	policy SafeModePolicy,
	report DryRunReport,
	cause error,
) (ExecutionStatus, DryRunReport, error) {
	if policy.Enabled && policy.RollbackOnFailure {
		return e.triggerRollback(ctx, pre, report, cause)
	}
	return StatusFailedHealthCheck, report, cause
}

func (e *Executor) triggerRollback(
	ctx context.Context,
	pre PrePatchSnapshot,
	report DryRunReport,
	cause error,
) (ExecutionStatus, DryRunReport, error) {
	if rbErr := e.Guard.Rollback(ctx, pre); rbErr != nil {
		return StatusFailedHealthCheck, report, fmt.Errorf("%w: %w (cause: %v)", ErrRollbackFailed, rbErr, cause)
	}
	return StatusRolledBack, report, cause
}
