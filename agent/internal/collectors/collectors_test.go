package collectors_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tecno-consultores/HostGrid/agent/internal/collectors"
	"github.com/tecno-consultores/HostGrid/agent/internal/probe"
)

const realDpkgFixture = `Package: openssh-server
Status: install ok installed
Priority: optional
Section: net
Architecture: amd64
Source: openssh (1:8.9p1-3ubuntu0.6)
Version: 1:8.9p1-3ubuntu0.6
Description: secure shell (SSH) server
 extended description line

Package: removed-pkg
Status: deinstall ok config-files
Architecture: amd64
Version: 1.2.3-1

Package: libssl1.0.0
Status: install ok installed
Architecture: amd64
Source: openssl
Version: 1.0.1t-1+deb8u12
`

func TestParseDpkgStatusRealFixture(t *testing.T) {
	pkgs, err := collectors.ParseDpkgStatus(strings.NewReader(realDpkgFixture))
	if err != nil {
		t.Fatalf("ParseDpkgStatus error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 installed packages (excluding deinstalled), got %d", len(pkgs))
	}
	if pkgs[0].Name != "openssh-server" || pkgs[0].Epoch != "1" || pkgs[0].Version != "8.9p1-3ubuntu0.6" || pkgs[0].SourcePackage != "openssh" {
		t.Fatalf("unexpected first package: %+v", pkgs[0])
	}
	if pkgs[1].Name != "libssl1.0.0" || pkgs[1].Epoch != "" || pkgs[1].SourcePackage != "openssl" {
		t.Fatalf("unexpected second package: %+v", pkgs[1])
	}
}

func TestParseRPMAndApkFixtures(t *testing.T) {
	rpmRaw := "openssh-server\topenssh-8.7p1-38.el9.src.rpm\t(none)\t8.7p1\t38.el9\tx86_64\n" +
		"gpg-pubkey\t(none)\t(none)\t1234\t5678\t(none)\n" +
		"openssl-libs\topenssl-3.0.7-27.el9.src.rpm\t1\t3.0.7\t27.el9\tx86_64\n"
	rpmPkgs, err := collectors.ParseRPMOutput(strings.NewReader(rpmRaw))
	if err != nil {
		t.Fatalf("ParseRPMOutput error: %v", err)
	}
	if len(rpmPkgs) != 2 {
		t.Fatalf("expected 2 rpm packages, got %d", len(rpmPkgs))
	}
	if rpmPkgs[0].SourcePackage != "openssh" || rpmPkgs[1].Epoch != "1" {
		t.Fatalf("unexpected rpm parsing: %+v", rpmPkgs)
	}

	apkRaw := "P:busybox\nV:1.36.1-r29\nA:x86_64\no:busybox\n\nP:libcrypto3\nV:3.3.1-r3\nA:x86_64\no:openssl\n\n"
	apkPkgs, err := collectors.ParseApkInstalled(strings.NewReader(apkRaw))
	if err != nil {
		t.Fatalf("ParseApkInstalled error: %v", err)
	}
	if len(apkPkgs) != 2 || apkPkgs[1].SourcePackage != "openssl" {
		t.Fatalf("unexpected apk parsing: %+v", apkPkgs)
	}
}

func TestNetworkParsersSSNetstatAndProc(t *testing.T) {
	ssOut := `Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=412,fd=3))
tcp LISTEN 0 128 [::]:443 [::]:* users:(("nginx",pid=900,fd=6))
`
	ssSockets := collectors.ParseSSOutput(strings.NewReader(ssOut))
	if len(ssSockets) != 2 || ssSockets[0].Port != 22 || ssSockets[0].Process != "sshd" || ssSockets[1].LocalAddr != "::" {
		t.Fatalf("unexpected ss sockets: %+v", ssSockets)
	}

	netstatOut := `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name
tcp 0 0 0.0.0.0:23 0.0.0.0:* LISTEN 551/in.telnetd
tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 412/sshd: /usr/sbin/sshd -D
tcp6 0 0 :::5432 :::* LISTEN 710/postgres
`
	nsSockets := collectors.ParseNetstatOutput(strings.NewReader(netstatOut))
	if len(nsSockets) != 3 || nsSockets[0].Port != 23 || nsSockets[0].Process != "in.telnetd" || nsSockets[1].Process != "sshd" || nsSockets[1].PID == nil || *nsSockets[1].PID != 412 {
		t.Fatalf("unexpected netstat sockets: %+v", nsSockets)
	}

	procOut := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 00000000 100 0 0 10 0
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   100        0 12346 1 00000000 100 0 0 10 0
   2: 0100007F:9999 0100007F:0016 01 00000000:00000000 00:00000000 00000000   100        0 12347 1 00000000 100 0 0 10 0
`
	procSockets := collectors.ParseProcNetTCP(strings.NewReader(procOut), "tcp")
	if len(procSockets) != 2 {
		t.Fatalf("expected 2 LISTEN sockets, got %d", len(procSockets))
	}
	if procSockets[0].LocalAddr != "0.0.0.0" || procSockets[0].Port != 22 {
		t.Fatalf("unexpected first proc socket: %+v", procSockets[0])
	}
	if procSockets[1].LocalAddr != "127.0.0.1" || procSockets[1].Port != 5432 {
		t.Fatalf("unexpected second proc socket: %+v", procSockets[1])
	}
}

func TestCollectSysctlAndRepos(t *testing.T) {
	root := t.TempDir()
	mustCreate := func(rel, content string) {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustCreate("proc/sys/net/ipv4/ip_forward", "0\n")
	mustCreate("proc/sys/kernel/kptr_restrict", "2\n")
	mustCreate("etc/apt/sources.list", "# comment\ndeb http://mirror.internal/debian bookworm main\n")

	env := probe.Env{RootDir: root}
	sysctl := collectors.CollectSysctl(env)
	if sysctl["net.ipv4.ip_forward"] != "0" || sysctl["kernel.kptr_restrict"] != "2" {
		t.Fatalf("unexpected sysctl: %+v", sysctl)
	}
	repos := collectors.CollectRepos(env)
	if len(repos.ConfiguredSources) != 1 {
		t.Fatalf("expected 1 repo source, got %+v", repos)
	}
}

func TestCollectReposDeb822Sources(t *testing.T) {
	root := t.TempDir()
	deb822Content := `# Modern Ubuntu 24.04 / Debian 12 DEB822 sources file
# URIs: http://commented.invalid/ubuntu
Types: deb
URIs: https://mirror.internal/ubuntu/
Suites: noble noble-updates
Components: main restricted universe
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 .
 mQINBF...
 -----END PGP PUBLIC KEY BLOCK-----

Types: deb
URIs:
 https://security.internal/ubuntu/
 http://fallback.internal/ubuntu-security/
Suites: noble-security
Components: main
Enabled: yes

Types: deb
URIs: http://disabled-after.invalid/ubuntu/
Suites: noble-proposed
Components: main
Enabled: no

Types: deb
Enabled: false
URIs: http://disabled-before.invalid/ubuntu/
Suites: noble-backports
Components: main
`
	sourcesPath := filepath.Join(root, "etc/apt/sources.list.d/ubuntu.sources")
	if err := os.MkdirAll(filepath.Dir(sourcesPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcesPath, []byte(deb822Content), 0o600); err != nil {
		t.Fatal(err)
	}

	repos := collectors.CollectRepos(probe.Env{RootDir: root})
	if repos.CheckDetail != "configured_sources_detected_offline" {
		t.Fatalf("expected configured_sources_detected_offline, got %q", repos.CheckDetail)
	}
	expected := []string{
		"https://mirror.internal/ubuntu/",
		"https://security.internal/ubuntu/",
		"http://fallback.internal/ubuntu-security/",
	}
	if len(repos.ConfiguredSources) != len(expected) {
		t.Fatalf("expected %d DEB822 sources, got %d: %+v", len(expected), len(repos.ConfiguredSources), repos.ConfiguredSources)
	}
	for i, want := range expected {
		if repos.ConfiguredSources[i] != want {
			t.Fatalf("source[%d]: want %q, got %q", i, want, repos.ConfiguredSources[i])
		}
	}

	// Verify all-disabled .sources reports no repositories configured.
	disabledRoot := t.TempDir()
	disabledPath := filepath.Join(disabledRoot, "etc/apt/sources.list.d/disabled.sources")
	if err := os.MkdirAll(filepath.Dir(disabledPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(disabledPath, []byte("Types: deb\nURIs: https://off.internal/debian\nSuites: bookworm\nEnabled: no\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	disabledRepos := collectors.CollectRepos(probe.Env{RootDir: disabledRoot})
	if disabledRepos.AccessOK == nil || *disabledRepos.AccessOK != false || disabledRepos.CheckDetail != "no_repositories_configured" {
		t.Fatalf("expected no_repositories_configured for all-disabled .sources, got %+v", disabledRepos)
	}
}

func TestParseDeb822SourcesEdgeCases(t *testing.T) {
	// UTF-8 BOM + CRLF + lone '.' continuation marker + folded Enabled: no + >64KB line before final stanza.
	hugeLine := "X-Padding: " + strings.Repeat("A", 70*1024)
	content := "\xef\xbb\xbfURIs:\r\n" +
		" https://bom-mirror.internal/debian/\r\n" +
		" .\r\n" +
		" https://bom-second.internal/debian/\r\n" +
		"Suites: trixie\r\n" +
		"Components: main\r\n" +
		"\r\n" +
		"Types: deb\r\n" +
		"URIs: https://folded-disabled.invalid/debian/\r\n" +
		"Suites: trixie-proposed\r\n" +
		"Enabled:\r\n" +
		" no\r\n" +
		"\r\n" +
		hugeLine + "\r\n" +
		"Types: deb\r\n" +
		"URIs: https://after-huge-line.internal/debian/\r\n" +
		"Suites: trixie-security\r\n" +
		"Enabled: no\r\n" +
		"Enabled: yes"

	got := collectors.ParseDeb822Sources(strings.NewReader(content))
	want := []string{
		"https://bom-mirror.internal/debian/",
		"https://bom-second.internal/debian/",
		"https://after-huge-line.internal/debian/",
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d URIs, got %d: %+v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("uri[%d]: want %q, got %q", i, want[i], got[i])
		}
	}

	// Verify hidden dotfiles in sources.list.d are ignored while .list + .sources combine cleanly.
	root := t.TempDir()
	aptDir := filepath.Join(root, "etc/apt/sources.list.d")
	if err := os.MkdirAll(aptDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aptDir, ".hidden.sources"), []byte("Types: deb\nURIs: https://hidden.invalid/apt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aptDir, "01-legacy.list"), []byte("deb https://legacy.internal/debian bookworm main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aptDir, "02-modern.sources"), []byte("Types: deb\nURIs: https://modern.internal/debian\nSuites: bookworm\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	combined := collectors.CollectRepos(probe.Env{RootDir: root})
	if len(combined.ConfiguredSources) != 2 {
		t.Fatalf("expected 2 combined sources (ignoring dotfile), got %+v", combined.ConfiguredSources)
	}
}
