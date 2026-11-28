package collectors

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tecno-consultores/HostGrid/agent/internal/probe"
)

// ServiceItem matches SPEC.md section 4.5 service inventory schema.
type ServiceItem struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	InitSystem string `json:"init_system"`
}

// ReposPayload matches SPEC.md section 4.5 repository status schema.
type ReposPayload struct {
	AccessOK          *bool    `json:"access_ok"`
	ConfiguredSources []string `json:"configured_sources"`
	CheckDetail       string   `json:"check_detail"`
}

var sysctlKeys = []string{
	"net.ipv4.ip_forward",
	"kernel.kptr_restrict",
	"kernel.randomize_va_space",
	"net.ipv4.conf.all.rp_filter",
	"net.ipv4.tcp_syncookies",
	"fs.protected_symlinks",
	"fs.protected_hardlinks",
}

// CollectServices enumerates active services adapting to systemd or SysVinit.
func CollectServices(ctx context.Context, env probe.Env, initSystem string) []ServiceItem {
	if env.RootDir == "" {
		env.RootDir = "/"
	}
	if initSystem == "systemd" && env.LookPath != nil {
		if scBin, err := env.LookPath("systemctl"); err == nil {
			cmd := exec.CommandContext(
				ctx,
				scBin,
				"list-units",
				"--type=service",
				"--state=running",
				"--no-pager",
				"--no-legend",
			)
			if out, runErr := cmd.Output(); runErr == nil {
				return parseSystemctlUnits(out)
			}
		}
	}

	initDir := filepath.Join(env.RootDir, "etc/init.d")
	entries, err := os.ReadDir(initDir)
	if err != nil {
		return []ServiceItem{}
	}
	services := []ServiceItem{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") || name == "README" {
			continue
		}
		services = append(services, ServiceItem{
			Name:       name,
			State:      "configured",
			InitSystem: initSystem,
		})
	}
	return services
}

func parseSystemctlUnits(out []byte) []ServiceItem {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	items := []ServiceItem{}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		items = append(items, ServiceItem{
			Name:       strings.TrimSuffix(fields[0], ".service"),
			State:      fields[3],
			InitSystem: "systemd",
		})
	}
	return items
}

// CollectSysctl reads selected hardening parameters directly from /proc/sys.
func CollectSysctl(env probe.Env) map[string]string {
	if env.RootDir == "" {
		env.RootDir = "/"
	}
	values := make(map[string]string)
	for _, key := range sysctlKeys {
		relPath := filepath.Join("proc/sys", strings.ReplaceAll(key, ".", "/"))
		raw, err := os.ReadFile(filepath.Join(env.RootDir, relPath))
		if err != nil {
			continue
		}
		values[key] = strings.TrimSpace(string(raw))
	}
	return values
}

// CollectRepos inspects configured APT/YUM/APK repository files without mutating host state.
func CollectRepos(env probe.Env) ReposPayload {
	if env.RootDir == "" {
		env.RootDir = "/"
	}
	sources := []string{}
	sources = append(sources, readNonCommentLines(filepath.Join(env.RootDir, "etc/apt/sources.list"))...)

	aptDir := filepath.Join(env.RootDir, "etc/apt/sources.list.d")
	if entries, err := os.ReadDir(aptDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			fullPath := filepath.Join(aptDir, e.Name())
			switch {
			case strings.HasSuffix(e.Name(), ".list"):
				sources = append(sources, readNonCommentLines(fullPath)...)
			case strings.HasSuffix(e.Name(), ".sources"):
				sources = append(sources, readDeb822SourcesFile(fullPath)...)
			}
		}
	}

	yumDir := filepath.Join(env.RootDir, "etc/yum.repos.d")
	if entries, err := os.ReadDir(yumDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".repo") {
				for _, line := range readNonCommentLines(filepath.Join(yumDir, e.Name())) {
					if strings.HasPrefix(line, "baseurl=") || strings.HasPrefix(line, "mirrorlist=") {
						sources = append(sources, line)
					}
				}
			}
		}
	}

	sources = append(sources, readNonCommentLines(filepath.Join(env.RootDir, "etc/apk/repositories"))...)
	if len(sources) == 0 {
		ok := false
		return ReposPayload{
			AccessOK:          &ok,
			ConfiguredSources: []string{},
			CheckDetail:       "no_repositories_configured",
		}
	}
	return ReposPayload{
		AccessOK:          nil,
		ConfiguredSources: sources,
		CheckDetail:       "configured_sources_detected_offline",
	}
}

func readNonCommentLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines
}

const maxRepoFileBytes = 4 << 20 // 4 MiB safety cap per repo config file

func readDeb822SourcesFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return ParseDeb822Sources(io.LimitReader(f, maxRepoFileBytes))
}

func appendDeb822URIs(dst []string, raw string) []string {
	for _, field := range strings.Fields(raw) {
		if field == "." {
			continue
		}
		dst = append(dst, field)
	}
	return dst
}

func applyDeb822Enabled(val string, disabled *bool) {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "no", "false", "0", "off", "disable", "without":
		*disabled = true
	case "yes", "true", "1", "on", "enable", "with":
		*disabled = false
	}
}

// ParseDeb822Sources extracts enabled repository URIs from a DEB822 APT .sources stream.
// Stanzas marked with Enabled: no/false/0/off are skipped, including folded continuation values.
func ParseDeb822Sources(r io.Reader) []string {
	var result []string
	var stanzaURIs []string
	disabled := false
	activeField := ""

	flush := func() {
		if !disabled && len(stanzaURIs) > 0 {
			result = append(result, stanzaURIs...)
		}
		stanzaURIs = nil
		disabled = false
		activeField = ""
	}

	reader := bufio.NewReader(r)
	firstLine := true
	for {
		raw, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			break
		}
		if err == io.EOF && raw == "" {
			break
		}
		raw = strings.TrimRight(raw, "\r\n")
		if firstLine {
			raw = strings.TrimPrefix(raw, "\xef\xbb\xbf")
			firstLine = false
		}

		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			flush()
		} else if !strings.HasPrefix(trimmed, "#") {
			if raw[0] == ' ' || raw[0] == '\t' {
				switch activeField {
				case "uris":
					stanzaURIs = appendDeb822URIs(stanzaURIs, trimmed)
				case "enabled":
					applyDeb822Enabled(trimmed, &disabled)
				}
			} else {
				activeField = ""
				if key, val, ok := strings.Cut(raw, ":"); ok {
					key = strings.ToLower(strings.TrimSpace(key))
					val = strings.TrimSpace(val)
					switch key {
					case "uris":
						activeField = "uris"
						if val != "" {
							stanzaURIs = appendDeb822URIs(stanzaURIs, val)
						}
					case "enabled":
						activeField = "enabled"
						if val != "" {
							applyDeb822Enabled(val, &disabled)
						}
					}
				}
			}
		}

		if err == io.EOF {
			break
		}
	}
	flush()
	return result
}
