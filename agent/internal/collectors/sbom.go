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

// PackageItem matches SPEC.md section 4.5 package inventory schema.
type PackageItem struct {
	PackageManager string `json:"package_manager"`
	Name           string `json:"name"`
	SourcePackage  string `json:"source_package,omitempty"`
	Epoch          string `json:"epoch"`
	Version        string `json:"version"`
	Release        string `json:"release"`
	Arch           string `json:"arch"`
}

// CollectSBOM extracts installed packages from dpkg, rpm, or apk without running package managers mutatively.
func CollectSBOM(ctx context.Context, env probe.Env) ([]PackageItem, error) {
	if env.RootDir == "" {
		env.RootDir = "/"
	}
	dpkgPath := filepath.Join(env.RootDir, "var/lib/dpkg/status")
	if f, err := os.Open(dpkgPath); err == nil {
		defer f.Close()
		return ParseDpkgStatus(f)
	}

	if env.LookPath != nil {
		if rpmBin, err := env.LookPath("rpm"); err == nil {
			return collectRPM(ctx, rpmBin)
		}
	}

	apkPath := filepath.Join(env.RootDir, "lib/apk/db/installed")
	if f, err := os.Open(apkPath); err == nil {
		defer f.Close()
		return ParseApkInstalled(f)
	}
	return []PackageItem{}, nil
}

// ParseDpkgStatus parses /var/lib/dpkg/status stanzas and keeps only installed packages.
func ParseDpkgStatus(r io.Reader) ([]PackageItem, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var packages []PackageItem
	stanza := make(map[string]string)

	flush := func() {
		if len(stanza) == 0 {
			return
		}
		if stanza["Status"] == "install ok installed" && stanza["Package"] != "" && stanza["Version"] != "" {
			epoch, version := splitEpoch(stanza["Version"])
			srcPkg := parseDpkgSource(stanza["Source"])
			if srcPkg == "" {
				srcPkg = stanza["Package"]
			}
			arch := stanza["Architecture"]
			if arch == "" {
				arch = "unknown"
			}
			packages = append(packages, PackageItem{
				PackageManager: "dpkg",
				Name:           stanza["Package"],
				SourcePackage:  srcPkg,
				Epoch:          epoch,
				Version:        version,
				Release:        "",
				Arch:           arch,
			})
		}
		stanza = make(map[string]string)
	}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		stanza[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	flush()
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return packages, nil
}

func splitEpoch(rawVersion string) (string, string) {
	if idx := strings.IndexByte(rawVersion, ':'); idx > 0 {
		candidate := rawVersion[:idx]
		allDigits := true
		for i := 0; i < len(candidate); i++ {
			if candidate[i] < '0' || candidate[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return candidate, rawVersion[idx+1:]
		}
	}
	return "", rawVersion
}

func parseDpkgSource(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func collectRPM(ctx context.Context, rpmBin string) ([]PackageItem, error) {
	// Explicit argument slice — never invoke a shell.
	cmd := exec.CommandContext(
		ctx,
		rpmBin,
		"-qa",
		"--qf",
		"%{NAME}\t%{SOURCERPM}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n",
	)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return ParseRPMOutput(bytes.NewReader(out))
}

// ParseRPMOutput parses tab-delimited rpm -qa --qf output.
func ParseRPMOutput(r io.Reader) ([]PackageItem, error) {
	scanner := bufio.NewScanner(r)
	var packages []PackageItem
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 6 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		if name == "" || name == "gpg-pubkey" {
			continue
		}
		srcPkg := cleanSourceRPM(fields[1], name)
		epoch := strings.TrimSpace(fields[2])
		if epoch == "(none)" {
			epoch = ""
		}
		version := strings.TrimSpace(fields[3])
		release := strings.TrimSpace(fields[4])
		arch := strings.TrimSpace(fields[5])
		if arch == "(none)" || arch == "" {
			arch = "unknown"
		}
		packages = append(packages, PackageItem{
			PackageManager: "rpm",
			Name:           name,
			SourcePackage:  srcPkg,
			Epoch:          epoch,
			Version:        version,
			Release:        release,
			Arch:           arch,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return packages, nil
}

func cleanSourceRPM(srcRPM, fallbackName string) string {
	trimmed := strings.TrimSpace(srcRPM)
	if trimmed == "" || trimmed == "(none)" {
		return fallbackName
	}
	trimmed = strings.TrimSuffix(trimmed, ".src.rpm")
	parts := strings.Split(trimmed, "-")
	if len(parts) >= 3 {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return fallbackName
}

// ParseApkInstalled parses Alpine Linux /lib/apk/db/installed records.
func ParseApkInstalled(r io.Reader) ([]PackageItem, error) {
	scanner := bufio.NewScanner(r)
	var packages []PackageItem
	cur := PackageItem{PackageManager: "apk", Arch: "unknown"}

	flush := func() {
		if cur.Name != "" && cur.Version != "" {
			if cur.SourcePackage == "" {
				cur.SourcePackage = cur.Name
			}
			packages = append(packages, cur)
		}
		cur = PackageItem{PackageManager: "apk", Arch: "unknown"}
	}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		val := strings.TrimSpace(line[2:])
		switch line[0] {
		case 'P':
			cur.Name = val
		case 'V':
			cur.Version = val
		case 'A':
			cur.Arch = val
		case 'o':
			cur.SourcePackage = val
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return packages, nil
}
