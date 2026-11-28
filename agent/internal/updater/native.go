package updater

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/tecno-consultores/HostGrid/agent/internal/collectors"
	"github.com/tecno-consultores/HostGrid/agent/internal/probe"
)

// CommandRunner executes a validated binary with explicit args and optional extra env vars (never sh -c).
type CommandRunner func(ctx context.Context, extraEnv []string, binary string, args ...string) ([]byte, error)

// DefaultCommandRunner invokes exec.CommandContext directly with zero shell interpolation.
func DefaultCommandRunner(ctx context.Context, extraEnv []string, binary string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	return cmd.CombinedOutput()
}

// DetectPackageManager identifies the host's native Linux package manager binary.
func DetectPackageManager(env probe.Env) (PackageManager, string) {
	look := env.LookPath
	if look == nil {
		look = exec.LookPath
	}
	candidates := []struct {
		pm  PackageManager
		bin string
	}{
		{PackageManagerAPT, "apt-get"},
		{PackageManagerDNF, "dnf"},
		{PackageManagerYUM, "yum"},
		{PackageManagerAPK, "apk"},
	}
	for _, c := range candidates {
		if binPath, err := look(c.bin); err == nil && binPath != "" {
			return c.pm, binPath
		}
	}
	return PackageManagerUnknown, ""
}

// NativeRepoVerifier verifies configured Linux package repositories and local GPG keyrings read-only.
type NativeRepoVerifier struct {
	Env probe.Env
	Run CommandRunner
}

// VerifyRepos inspects configured sources, GPG keyrings, and read-only package manager repo metadata.
func (v *NativeRepoVerifier) VerifyRepos(ctx context.Context) (RepoCheckResult, error) {
	env := v.Env
	if env.RootDir == "" {
		env.RootDir = "/"
	}
	repos := collectors.CollectRepos(env)
	if len(repos.ConfiguredSources) == 0 {
		return RepoCheckResult{
			Accessible:        false,
			SignedMetadataOK:  false,
			ConfiguredSources: repos.ConfiguredSources,
			Detail:            "no_repositories_configured",
			CheckedAt:         time.Now().UTC(),
		}, nil
	}
	gpgOK := hasTrustedKeyring(env.RootDir)
	if !gpgOK {
		return RepoCheckResult{
			Accessible:        false,
			SignedMetadataOK:  false,
			ConfiguredSources: repos.ConfiguredSources,
			Detail:            "missing_trusted_gpg_keyrings",
			CheckedAt:         time.Now().UTC(),
		}, nil
	}
	if hasUnsignedRepoDirective(env.RootDir) {
		return RepoCheckResult{
			Accessible:        true,
			SignedMetadataOK:  false,
			ConfiguredSources: repos.ConfiguredSources,
			Detail:            "unsigned_repository_directive_detected",
			CheckedAt:         time.Now().UTC(),
		}, nil
	}
	pm, binPath := DetectPackageManager(env)
	if pm == PackageManagerUnknown {
		return RepoCheckResult{
			Accessible:        false,
			SignedMetadataOK:  gpgOK,
			ConfiguredSources: repos.ConfiguredSources,
			Detail:            "no_supported_package_manager",
			CheckedAt:         time.Now().UTC(),
		}, nil
	}
	runner := v.Run
	if runner == nil {
		runner = DefaultCommandRunner
	}
	checkBin, checkArgs := buildRepoCheckCommand(env, pm, binPath)
	out, err := runner(ctx, nil, checkBin, checkArgs...)
	if err != nil {
		return RepoCheckResult{
			Accessible:        false,
			SignedMetadataOK:  gpgOK,
			ConfiguredSources: repos.ConfiguredSources,
			Detail:            "repo_metadata_check_failed: " + strings.TrimSpace(string(out)),
			CheckedAt:         time.Now().UTC(),
		}, nil
	}
	return RepoCheckResult{
		Accessible:        true,
		SignedMetadataOK:  true,
		ConfiguredSources: repos.ConfiguredSources,
		Detail:            "repo_metadata_and_gpg_verified",
		CheckedAt:         time.Now().UTC(),
	}, nil
}

func buildRepoCheckCommand(env probe.Env, pm PackageManager, pmBin string) (string, []string) {
	switch pm {
	case PackageManagerAPT:
		if env.LookPath != nil {
			if cacheBin, err := env.LookPath("apt-cache"); err == nil && cacheBin != "" {
				return cacheBin, []string{"policy"}
			}
		}
		return pmBin, []string{"check", "-o", "Debug::NoLocking=1"}
	case PackageManagerDNF:
		return pmBin, []string{"repolist", "--enabled"}
	case PackageManagerYUM:
		return pmBin, []string{"repolist", "enabled"}
	case PackageManagerAPK:
		return pmBin, []string{"policy"}
	default:
		return pmBin, nil
	}
}

func hasTrustedKeyring(rootDir string) bool {
	dirs := []string{
		"etc/apt/trusted.gpg.d",
		"usr/share/keyrings",
		"etc/pki/rpm-gpg",
		"etc/apk/keys",
	}
	for _, rel := range dirs {
		entries, err := os.ReadDir(filepath.Join(rootDir, rel))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
				return true
			}
		}
	}
	return false
}

var (
	aptTrustedYesRe  = regexp.MustCompile(`(?i)\btrusted\s*[:=]\s*(yes|true|1)\b`)
	rpmGPGCheckOffRe = regexp.MustCompile(`(?i)^\s*(repo_)?gpgcheck\s*=\s*(0|false|no)\s*$`)
)

func hasUnsignedRepoDirective(rootDir string) bool {
	aptFiles := []string{filepath.Join(rootDir, "etc/apt/sources.list")}
	if entries, err := os.ReadDir(filepath.Join(rootDir, "etc/apt/sources.list.d")); err == nil {
		for _, e := range entries {
			if !e.IsDir() && (strings.HasSuffix(e.Name(), ".list") || strings.HasSuffix(e.Name(), ".sources")) {
				aptFiles = append(aptFiles, filepath.Join(rootDir, "etc/apt/sources.list.d", e.Name()))
			}
		}
	}
	for _, f := range aptFiles {
		if fileMatchesLinePattern(f, aptTrustedYesRe) {
			return true
		}
	}
	if entries, err := os.ReadDir(filepath.Join(rootDir, "etc/yum.repos.d")); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".repo") {
				if fileMatchesLinePattern(filepath.Join(rootDir, "etc/yum.repos.d", e.Name()), rpmGPGCheckOffRe) {
					return true
				}
			}
		}
	}
	return false
}

func fileMatchesLinePattern(path string, re *regexp.Regexp) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// NativeDryRunner runs non-mutating package manager simulations (apt-get -s, dnf/yum --assumeno, apk --simulate).
type NativeDryRunner struct {
	Env probe.Env
	Run CommandRunner
}

var (
	aptInstRe = regexp.MustCompile(`^Inst\s+(\S+)\s+(?:\[([^\]]+)\]\s+)?\(([^\s)]+)`)
	apkUpgRe  = regexp.MustCompile(`Upgrading\s+(\S+)\s+\(([^\s]+)\s+->\s+([^\s)]+)\)`)
)

// DryRun simulates package upgrades without touching host packages.
func (r *NativeDryRunner) DryRun(ctx context.Context, req PatchRequest) (DryRunReport, error) {
	if err := ValidatePatchRequest(req); err != nil {
		return DryRunReport{}, err
	}
	pm, binPath := DetectPackageManager(r.Env)
	if pm == PackageManagerUnknown {
		return DryRunReport{PlanID: req.PlanID, PackageManager: pm, Succeeded: false}, errors.New("no supported package manager detected")
	}
	runner := r.Run
	if runner == nil {
		runner = DefaultCommandRunner
	}

	args, extraEnv := buildDryRunArgs(pm, req.Packages)
	out, err := runner(ctx, extraEnv, binPath, args...)
	changes := parseDryRunOutput(pm, out)
	succeeded := err == nil
	// dnf/yum --assumeno exits non-zero intentionally when refusing to commit a simulated transaction.
	if err != nil && (pm == PackageManagerDNF || pm == PackageManagerYUM) && strings.Contains(string(out), "Operation aborted.") {
		succeeded = true
		err = nil
	}
	return DryRunReport{
		PlanID:         req.PlanID,
		PackageManager: pm,
		Succeeded:      succeeded,
		PlannedChanges: changes,
		SimulatedAt:    time.Now().UTC(),
	}, err
}

func buildDryRunArgs(pm PackageManager, packages []string) ([]string, []string) {
	switch pm {
	case PackageManagerAPT:
		args := append([]string{"-s", "-o", "Debug::NoLocking=1", "install", "--only-upgrade", "--"}, packages...)
		return args, []string{"DEBIAN_FRONTEND=noninteractive"}
	case PackageManagerDNF, PackageManagerYUM:
		args := append([]string{"--assumeno", "upgrade", "--"}, packages...)
		return args, nil
	case PackageManagerAPK:
		args := append([]string{"upgrade", "--simulate", "--"}, packages...)
		return args, nil
	default:
		return nil, nil
	}
}

var validRPMArches = map[string]struct{}{
	"x86_64":  {},
	"aarch64": {},
	"noarch":  {},
	"i686":    {},
	"i386":    {},
	"armv7hl": {},
	"ppc64le": {},
	"s390x":   {},
	"riscv64": {},
}

func parseDryRunOutput(pm PackageManager, out []byte) []PackageChange {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	var changes []PackageChange
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch pm {
		case PackageManagerAPT:
			if m := aptInstRe.FindStringSubmatch(line); len(m) == 4 {
				changes = append(changes, PackageChange{
					Name:           m[1],
					CurrentVersion: m[2],
					TargetVersion:  m[3],
					Action:         "upgrade",
				})
			}
		case PackageManagerAPK:
			if m := apkUpgRe.FindStringSubmatch(line); len(m) == 4 {
				changes = append(changes, PackageChange{
					Name:           m[1],
					CurrentVersion: m[2],
					TargetVersion:  m[3],
					Action:         "upgrade",
				})
			}
		case PackageManagerDNF, PackageManagerYUM:
			fields := strings.Fields(line)
			if len(fields) >= 4 && validPackageNameRe.MatchString(fields[0]) && validVersionRe.MatchString(fields[2]) {
				if _, isArch := validRPMArches[fields[1]]; isArch {
					changes = append(changes, PackageChange{
						Name:          fields[0],
						TargetVersion: fields[2],
						Action:        "upgrade",
					})
				}
			}
		}
	}
	return changes
}

// NativePackageApplier performs validated, non-interactive native package upgrades (no shell).
type NativePackageApplier struct {
	Env probe.Env
	Run CommandRunner
}

// ApplyPackages invokes the native package manager with strictly validated package arguments.
func (a *NativePackageApplier) ApplyPackages(ctx context.Context, req PatchRequest) error {
	if err := ValidatePatchRequest(req); err != nil {
		return err
	}
	pm, binPath := DetectPackageManager(a.Env)
	if pm == PackageManagerUnknown {
		return errors.New("no supported package manager detected")
	}
	runner := a.Run
	if runner == nil {
		runner = DefaultCommandRunner
	}
	args, extraEnv := buildApplyArgs(pm, req.Packages)
	out, err := runner(ctx, extraEnv, binPath, args...)
	if err != nil {
		return fmt.Errorf("%s upgrade failed: %w (%s)", pm, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func buildApplyArgs(pm PackageManager, packages []string) ([]string, []string) {
	switch pm {
	case PackageManagerAPT:
		args := append([]string{"-y", "install", "--only-upgrade", "--"}, packages...)
		return args, []string{"DEBIAN_FRONTEND=noninteractive"}
	case PackageManagerDNF, PackageManagerYUM:
		args := append([]string{"-y", "upgrade", "--"}, packages...)
		return args, nil
	case PackageManagerAPK:
		args := append([]string{"upgrade", "--"}, packages...)
		return args, nil
	default:
		return nil, nil
	}
}

// NativeSafeModeGuard captures baselines, verifies post-patch health, and rolls back on failure.
type NativeSafeModeGuard struct {
	Env               probe.Env
	Run               CommandRunner
	ReachabilityCheck func(ctx context.Context) bool
}

func collectPackageVersionMap(ctx context.Context, env probe.Env) (map[string]string, error) {
	pkgs, err := collectors.CollectSBOM(ctx, env)
	if err != nil {
		return nil, err
	}
	versions := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		ver := p.Version
		if p.Epoch != "" {
			ver = p.Epoch + ":" + ver
		}
		if p.Release != "" && !strings.Contains(ver, "-") {
			ver = ver + "-" + p.Release
		}
		versions[p.Name] = ver
	}
	return versions, nil
}

// CapturePrePatch records kernel, active services, and current installed package versions.
func (g *NativeSafeModeGuard) CapturePrePatch(ctx context.Context, planID string) (PrePatchSnapshot, error) {
	probeRes := probe.Run(g.Env)
	svcs := collectors.CollectServices(ctx, g.Env, probeRes.InitSystem)
	active := make([]string, 0, len(svcs))
	for _, s := range svcs {
		if s.State == "running" || s.State == "active" || s.State == "configured" {
			active = append(active, s.Name)
		}
	}
	versions, _ := collectPackageVersionMap(ctx, g.Env)
	if versions == nil {
		versions = map[string]string{}
	}
	return PrePatchSnapshot{
		PlanID:          planID,
		CapturedAt:      time.Now().UTC(),
		KernelVersion:   probeRes.KernelVersion,
		ActiveServices:  active,
		PackageVersions: versions,
	}, nil
}

// VerifyPostPatch evaluates critical services and Control Plane reachability against SafeModePolicy.
func (g *NativeSafeModeGuard) VerifyPostPatch(
	ctx context.Context,
	pre PrePatchSnapshot,
	policy SafeModePolicy,
) (HealthCheckResult, error) {
	probeRes := probe.Run(g.Env)
	svcs := collectors.CollectServices(ctx, g.Env, probeRes.InitSystem)
	activeAfter := make([]string, 0, len(svcs))
	for _, s := range svcs {
		if s.State == "running" || s.State == "active" || s.State == "configured" {
			activeAfter = append(activeAfter, s.Name)
		}
	}
	reachable := true
	if policy.VerifyControlPlaneReachability && g.ReachabilityCheck != nil {
		reachable = g.ReachabilityCheck(ctx)
	}
	return EvaluatePostPatchHealth(pre, activeAfter, reachable, policy), nil
}

func selectRollbackTargets(preVersions, currentVersions map[string]string) map[string]string {
	if len(currentVersions) == 0 {
		return preVersions
	}
	changed := make(map[string]string)
	for pkg, preVer := range preVersions {
		currVer, exists := currentVersions[pkg]
		if !exists || currVer != preVer {
			changed[pkg] = preVer
		}
	}
	return changed
}

// Rollback restores ONLY packages whose installed versions changed since CapturePrePatch.
func (g *NativeSafeModeGuard) Rollback(ctx context.Context, pre PrePatchSnapshot) error {
	if len(pre.PackageVersions) == 0 {
		return nil
	}
	pm, binPath := DetectPackageManager(g.Env)
	if pm == PackageManagerUnknown {
		return errors.New("no supported package manager detected for rollback")
	}
	currentVersions, sbomErr := collectPackageVersionMap(ctx, g.Env)
	var targets map[string]string
	if sbomErr != nil {
		targets = pre.PackageVersions
	} else {
		targets = selectRollbackTargets(pre.PackageVersions, currentVersions)
	}
	if len(targets) == 0 {
		return nil
	}
	runner := g.Run
	if runner == nil {
		runner = DefaultCommandRunner
	}
	specs, err := buildRollbackSpecs(pm, targets)
	if err != nil {
		return err
	}
	args, extraEnv := buildRollbackArgs(pm, specs)
	out, err := runner(ctx, extraEnv, binPath, args...)
	if err != nil {
		return fmt.Errorf("%s rollback failed: %w (%s)", pm, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func buildRollbackSpecs(pm PackageManager, versions map[string]string) ([]string, error) {
	names := make([]string, 0, len(versions))
	for pkg := range versions {
		names = append(names, pkg)
	}
	sort.Strings(names)
	specs := make([]string, 0, len(names))
	for _, pkg := range names {
		ver := versions[pkg]
		if !validPackageNameRe.MatchString(pkg) || !validVersionRe.MatchString(ver) {
			return nil, fmt.Errorf("invalid rollback package specification %q=%q", pkg, ver)
		}
		if pm == PackageManagerDNF || pm == PackageManagerYUM {
			specs = append(specs, pkg+"-"+ver)
		} else {
			specs = append(specs, pkg+"="+ver)
		}
	}
	return specs, nil
}

func buildRollbackArgs(pm PackageManager, specs []string) ([]string, []string) {
	switch pm {
	case PackageManagerAPT:
		args := append([]string{"-y", "--allow-downgrades", "install", "--"}, specs...)
		return args, []string{"DEBIAN_FRONTEND=noninteractive"}
	case PackageManagerDNF, PackageManagerYUM:
		args := append([]string{"-y", "downgrade", "--"}, specs...)
		return args, nil
	case PackageManagerAPK:
		args := append([]string{"add", "--"}, specs...)
		return args, nil
	default:
		return nil, nil
	}
}

// NewNativeExecutor wires all native Linux Phase 3 patching components with AllowMutation defaulting to false.
func NewNativeExecutor(env probe.Env, allowMutation bool, reachability func(ctx context.Context) bool) *Executor {
	return &Executor{
		Verifier:      &NativeRepoVerifier{Env: env},
		Runner:        &NativeDryRunner{Env: env},
		Applier:       &NativePackageApplier{Env: env},
		Guard:         &NativeSafeModeGuard{Env: env, ReachabilityCheck: reachability},
		AllowMutation: allowMutation,
	}
}
