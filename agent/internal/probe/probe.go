package probe

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// CapabilityItem describes whether a host inspection feature is supported or degraded.
type CapabilityItem struct {
	Status       string `json:"status"`
	Binary       string `json:"binary,omitempty"`
	Reason       string `json:"reason,omitempty"`
	FallbackUsed bool   `json:"fallback_used"`
}

// ProbeResult captures OS identity, init system, architecture, and detected capabilities.
type ProbeResult struct {
	Hostname      string                    `json:"-"`
	MachineIDHash string                    `json:"-"`
	OSFamily      string                    `json:"os_family"`
	OSName        string                    `json:"os_name"`
	OSVersion     string                    `json:"os_version"`
	KernelVersion string                    `json:"kernel_version"`
	Arch          string                    `json:"arch"`
	InitSystem    string                    `json:"init_system"`
	Capabilities  map[string]CapabilityItem `json:"capabilities"`
}

// Env abstracts host filesystem root and binary lookup for deterministic testing.
type Env struct {
	RootDir  string
	LookPath func(file string) (string, error)
	Hostname func() (string, error)
	Arch     string
}

// DefaultEnv returns an Env pointing at the live Linux host filesystem.
func DefaultEnv() Env {
	return Env{
		RootDir:  "/",
		LookPath: exec.LookPath,
		Hostname: os.Hostname,
		Arch:     runtime.GOARCH,
	}
}

func (e Env) join(rel string) string {
	cleaned := strings.TrimPrefix(rel, "/")
	if e.RootDir == "" || e.RootDir == "/" {
		return "/" + cleaned
	}
	return filepath.Join(e.RootDir, cleaned)
}

func (e Env) pathExists(rel string) bool {
	_, err := os.Stat(e.join(rel))
	return err == nil
}

func (e Env) readTrimmed(rel string) string {
	data, err := os.ReadFile(e.join(rel))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (e Env) hasBinary(name string) (string, bool) {
	if e.LookPath == nil {
		return "", false
	}
	p, err := e.LookPath(name)
	if err != nil {
		return "", false
	}
	return p, true
}

// Run executes the Capability Probe without failing on missing modern binaries.
func Run(env Env) ProbeResult {
	if env.RootDir == "" {
		env.RootDir = "/"
	}
	if env.LookPath == nil {
		env.LookPath = exec.LookPath
	}
	if env.Hostname == nil {
		env.Hostname = os.Hostname
	}
	if env.Arch == "" {
		env.Arch = runtime.GOARCH
	}

	hostname, err := env.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "unknown-host"
	}
	osFamily, osName, osVersion := detectOS(env)
	kernel := env.readTrimmed("/proc/sys/kernel/osrelease")
	if kernel == "" {
		kernel = "unknown"
	}
	initSystem := detectInitSystem(env)
	machineHash := computeMachineIDHash(env, hostname)
	arch := normalizeArch(env.Arch)

	caps := map[string]CapabilityItem{
		"network_inspector":  probeNetworkInspector(env),
		"firewall_inspector": probeFirewallInspector(env),
		"systemd_security":   probeSystemdSecurity(env, initSystem),
		"mac_framework":      probeMACFramework(env),
		"package_manager":    probePackageManager(env),
	}

	return ProbeResult{
		Hostname:      hostname,
		MachineIDHash: machineHash,
		OSFamily:      osFamily,
		OSName:        osName,
		OSVersion:     osVersion,
		KernelVersion: kernel,
		Arch:          arch,
		InitSystem:    initSystem,
		Capabilities:  caps,
	}
}

func normalizeArch(goarch string) string {
	switch goarch {
	case "amd64", "arm64", "386":
		return goarch
	default:
		return "amd64"
	}
}

func computeMachineIDHash(env Env, fallbackHostname string) string {
	raw := env.readTrimmed("/etc/machine-id")
	if raw == "" {
		raw = env.readTrimmed("/var/lib/dbus/machine-id")
	}
	if raw == "" {
		raw = "hostgrid-fallback:" + fallbackHostname
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func detectOS(env Env) (string, string, string) {
	if content := env.readTrimmed("/etc/os-release"); content != "" {
		kv := parseOSRelease(content)
		family := normalizeOSFamily(kv["ID"], kv["ID_LIKE"])
		name := kv["NAME"]
		if name == "" {
			name = kv["PRETTY_NAME"]
		}
		if name == "" {
			name = "Linux"
		}
		ver := kv["VERSION_ID"]
		if ver == "" {
			ver = "unknown"
		}
		return family, name, ver
	}
	if debVer := env.readTrimmed("/etc/debian_version"); debVer != "" {
		return "debian", "Debian GNU/Linux", strings.Split(debVer, ".")[0]
	}
	if rh := env.readTrimmed("/etc/redhat-release"); rh != "" {
		lower := strings.ToLower(rh)
		family := "rhel"
		if strings.Contains(lower, "centos") {
			family = "centos"
		}
		return family, rh, extractFirstVersion(rh)
	}
	if alp := env.readTrimmed("/etc/alpine-release"); alp != "" {
		return "alpine", "Alpine Linux", alp
	}
	return "other", "Unknown Linux", "unknown"
}

func parseOSRelease(content string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		out[k] = v
	}
	return out
}

func normalizeOSFamily(id, idLike string) string {
	combined := strings.ToLower(strings.TrimSpace(id))
	switch combined {
	case "debian", "ubuntu", "centos", "rhel", "alpine":
		return combined
	case "sles", "opensuse", "opensuse-leap", "opensuse-tumbleweed":
		return "suse"
	case "rocky", "almalinux", "ol", "fedora":
		return "rhel"
	}
	like := strings.ToLower(idLike)
	switch {
	case strings.Contains(like, "ubuntu"):
		return "ubuntu"
	case strings.Contains(like, "debian"):
		return "debian"
	case strings.Contains(like, "rhel"), strings.Contains(like, "centos"):
		return "rhel"
	case strings.Contains(like, "suse"):
		return "suse"
	default:
		return "other"
	}
}

func extractFirstVersion(text string) string {
	for _, field := range strings.Fields(text) {
		if len(field) > 0 && field[0] >= '0' && field[0] <= '9' {
			return field
		}
	}
	return "unknown"
}

func detectInitSystem(env Env) string {
	if env.pathExists("/run/systemd/system") {
		return "systemd"
	}
	if env.pathExists("/run/openrc") {
		return "openrc"
	}
	if env.pathExists("/sbin/initctl") {
		return "upstart"
	}
	if env.pathExists("/etc/init.d") {
		return "sysvinit"
	}
	return "unknown"
}

func probeNetworkInspector(env Env) CapabilityItem {
	if _, ok := env.hasBinary("ss"); ok {
		return CapabilityItem{Status: "supported", Binary: "ss", FallbackUsed: false}
	}
	if _, ok := env.hasBinary("netstat"); ok {
		return CapabilityItem{Status: "supported", Binary: "netstat", FallbackUsed: true}
	}
	if env.pathExists("/proc/net/tcp") {
		return CapabilityItem{Status: "supported", Binary: "/proc/net/tcp", FallbackUsed: true}
	}
	return CapabilityItem{
		Status:       "not_supported_on_os",
		Reason:       "no_ss_netstat_or_proc_net_tcp",
		FallbackUsed: false,
	}
}

func probeFirewallInspector(env Env) CapabilityItem {
	if _, ok := env.hasBinary("nft"); ok {
		return CapabilityItem{Status: "supported", Binary: "nft", FallbackUsed: false}
	}
	if _, ok := env.hasBinary("iptables"); ok {
		return CapabilityItem{Status: "supported", Binary: "iptables", FallbackUsed: true}
	}
	return CapabilityItem{
		Status:       "not_supported_on_os",
		Reason:       "no_nftables_or_iptables_detected",
		FallbackUsed: false,
	}
}

func probeSystemdSecurity(env Env, initSystem string) CapabilityItem {
	if initSystem != "systemd" {
		return CapabilityItem{
			Status:       "not_supported_on_os",
			Reason:       "init_system_is_" + initSystem,
			FallbackUsed: false,
		}
	}
	if _, ok := env.hasBinary("systemctl"); ok {
		return CapabilityItem{Status: "supported", Binary: "systemctl", FallbackUsed: false}
	}
	return CapabilityItem{
		Status:       "not_supported_on_os",
		Reason:       "systemctl_binary_missing",
		FallbackUsed: false,
	}
}

func probeMACFramework(env Env) CapabilityItem {
	if _, ok := env.hasBinary("aa-status"); ok {
		return CapabilityItem{Status: "supported", Binary: "aa-status", FallbackUsed: false}
	}
	if _, ok := env.hasBinary("getenforce"); ok {
		return CapabilityItem{Status: "supported", Binary: "getenforce", FallbackUsed: false}
	}
	return CapabilityItem{
		Status:       "not_supported_on_os",
		Reason:       "no_selinux_or_apparmor_detected",
		FallbackUsed: false,
	}
}

func probePackageManager(env Env) CapabilityItem {
	if env.pathExists("/var/lib/dpkg/status") {
		return CapabilityItem{Status: "supported", Binary: "/var/lib/dpkg/status", FallbackUsed: false}
	}
	if _, ok := env.hasBinary("rpm"); ok {
		return CapabilityItem{Status: "supported", Binary: "rpm", FallbackUsed: false}
	}
	if env.pathExists("/lib/apk/db/installed") {
		return CapabilityItem{Status: "supported", Binary: "/lib/apk/db/installed", FallbackUsed: false}
	}
	return CapabilityItem{
		Status:       "not_supported_on_os",
		Reason:       "no_supported_package_database",
		FallbackUsed: false,
	}
}
