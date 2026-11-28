package probe_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tecno-consultores/HostGrid/agent/internal/probe"
)

func TestProbeDebian8SysVinitFallback(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "etc/debian_version"), "8.11\n")
	mustWrite(t, filepath.Join(root, "etc/machine-id"), "deadbeef12345678\n")
	mustWrite(t, filepath.Join(root, "proc/sys/kernel/osrelease"), "3.16.0-11-amd64\n")
	mustMkdir(t, filepath.Join(root, "etc/init.d"))
	mustWrite(t, filepath.Join(root, "var/lib/dpkg/status"), "Package: bash\nStatus: install ok installed\nVersion: 4.3-11\n\n")

	env := probe.Env{
		RootDir: root,
		Arch:    "amd64",
		Hostname: func() (string, error) {
			return "srv-deb8-legacy", nil
		},
		LookPath: func(bin string) (string, error) {
			if bin == "netstat" || bin == "iptables" {
				return "/sbin/" + bin, nil
			}
			return "", errors.New("not found")
		},
	}

	res := probe.Run(env)
	if res.OSFamily != "debian" || res.OSVersion != "8" {
		t.Fatalf("unexpected OS detection: %s %s", res.OSFamily, res.OSVersion)
	}
	if res.InitSystem != "sysvinit" {
		t.Fatalf("expected sysvinit, got %s", res.InitSystem)
	}
	if res.Capabilities["systemd_security"].Status != "not_supported_on_os" {
		t.Fatalf("expected systemd_security not_supported_on_os, got %+v", res.Capabilities["systemd_security"])
	}
	if !res.Capabilities["network_inspector"].FallbackUsed || res.Capabilities["network_inspector"].Binary != "netstat" {
		t.Fatalf("expected netstat fallback, got %+v", res.Capabilities["network_inspector"])
	}
	if !res.Capabilities["firewall_inspector"].FallbackUsed || res.Capabilities["firewall_inspector"].Binary != "iptables" {
		t.Fatalf("expected iptables fallback, got %+v", res.Capabilities["firewall_inspector"])
	}
	if res.Capabilities["mac_framework"].Status != "not_supported_on_os" {
		t.Fatalf("expected mac_framework not_supported_on_os, got %+v", res.Capabilities["mac_framework"])
	}
	if len(res.MachineIDHash) != 64 {
		t.Fatalf("expected 64-char sha256 machine_id_hash, got %d", len(res.MachineIDHash))
	}
}

func TestProbeUbuntu22SystemdModern(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "etc/os-release"), "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"22.04\"\n")
	mustWrite(t, filepath.Join(root, "proc/sys/kernel/osrelease"), "5.15.0-119-generic\n")
	mustMkdir(t, filepath.Join(root, "run/systemd/system"))

	env := probe.Env{
		RootDir: root,
		Arch:    "arm64",
		Hostname: func() (string, error) {
			return "srv-ubu22", nil
		},
		LookPath: func(bin string) (string, error) {
			switch bin {
			case "ss", "nft", "systemctl", "aa-status":
				return "/usr/bin/" + bin, nil
			default:
				return "", errors.New("not found")
			}
		},
	}

	res := probe.Run(env)
	if res.OSFamily != "ubuntu" || res.OSVersion != "22.04" || res.Arch != "arm64" {
		t.Fatalf("unexpected ubuntu probe: %+v", res)
	}
	if res.InitSystem != "systemd" {
		t.Fatalf("expected systemd, got %s", res.InitSystem)
	}
	if res.Capabilities["systemd_security"].Status != "supported" {
		t.Fatalf("expected systemd_security supported, got %+v", res.Capabilities["systemd_security"])
	}
	if res.Capabilities["network_inspector"].Binary != "ss" || res.Capabilities["network_inspector"].FallbackUsed {
		t.Fatalf("expected modern ss inspector, got %+v", res.Capabilities["network_inspector"])
	}
	if res.Capabilities["mac_framework"].Binary != "aa-status" {
		t.Fatalf("expected AppArmor aa-status, got %+v", res.Capabilities["mac_framework"])
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	mustMkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}
