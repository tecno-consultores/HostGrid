package tools

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// ToolManifest matches SPEC.md section 4.4 portable tool bundle manifest.
type ToolManifest struct {
	ToolName              string `json:"tool_name"`
	Version               string `json:"version"`
	Arch                  string `json:"arch"`
	Filename              string `json:"filename"`
	SHA256                string `json:"sha256"`
	SizeBytes             int64  `json:"size_bytes"`
	ManifestCanonicalJSON string `json:"manifest_canonical_json"`
	SignatureB64          string `json:"signature_b64"`
	DownloadURL           string `json:"download_url"`
}

// LynisPayload matches SPEC.md section 4.5 Lynis report section.
type LynisPayload struct {
	Executed     bool   `json:"executed"`
	LynisVersion string `json:"lynis_version,omitempty"`
	ReportDat    string `json:"report_dat"`
}

var safeSegRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

const (
	MaxToolArchiveBytes      int64 = 50 * 1024 * 1024
	MaxToolUncompressedBytes int64 = 100 * 1024 * 1024
	integrityMarkerFile            = ".hostgrid-sha256"
)

// VerifyManifestSignature verifies Ed25519 signature over manifest_canonical_json using the pinned pubkey.
func VerifyManifestSignature(manifest ToolManifest, pinnedPubKeyB64 string) error {
	pubRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pinnedPubKeyB64))
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return errors.New("invalid pinned Ed25519 public key")
	}
	sigRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(manifest.SignatureB64))
	if err != nil || len(sigRaw) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), []byte(manifest.ManifestCanonicalJSON), sigRaw) {
		return errors.New("Ed25519 manifest signature verification failed")
	}

	var parsed struct {
		ToolName  string `json:"tool_name"`
		Version   string `json:"version"`
		Arch      string `json:"arch"`
		Filename  string `json:"filename"`
		SHA256    string `json:"sha256"`
		SizeBytes int64  `json:"size_bytes"`
	}
	if err := json.Unmarshal([]byte(manifest.ManifestCanonicalJSON), &parsed); err != nil {
		return fmt.Errorf("parse signed canonical manifest: %w", err)
	}
	if parsed.ToolName != manifest.ToolName ||
		parsed.Version != manifest.Version ||
		parsed.SHA256 != manifest.SHA256 ||
		parsed.SizeBytes != manifest.SizeBytes {
		return errors.New("manifest fields do not match signed canonical JSON")
	}
	return nil
}

func validateManifestBounds(manifest ToolManifest, pinnedPubKeyB64 string) error {
	if err := VerifyManifestSignature(manifest, pinnedPubKeyB64); err != nil {
		return err
	}
	if !safeSegRe.MatchString(manifest.ToolName) || !safeSegRe.MatchString(manifest.Version) ||
		strings.Contains(manifest.ToolName, "..") || strings.Contains(manifest.Version, "..") {
		return errors.New("unsafe tool name or version")
	}
	if manifest.SizeBytes <= 0 || manifest.SizeBytes > MaxToolArchiveBytes {
		return fmt.Errorf("archive size %d out of permitted bounds", manifest.SizeBytes)
	}
	return nil
}

// ResolveCachedBundle verifies the manifest Ed25519 signature first, then checks if a matching
// integrity-verified local installation already exists under toolsBaseDir/tool/version.
func ResolveCachedBundle(
	manifest ToolManifest,
	pinnedPubKeyB64 string,
	toolsBaseDir string,
) (string, bool, error) {
	if err := validateManifestBounds(manifest, pinnedPubKeyB64); err != nil {
		return "", false, err
	}
	finalDir := filepath.Join(toolsBaseDir, manifest.ToolName, manifest.Version)
	markerBytes, err := os.ReadFile(filepath.Join(finalDir, integrityMarkerFile))
	if err != nil {
		return "", false, nil
	}
	if !strings.EqualFold(strings.TrimSpace(string(markerBytes)), strings.TrimSpace(manifest.SHA256)) {
		return "", false, nil
	}
	if info, err := os.Stat(filepath.Join(finalDir, manifest.ToolName)); err != nil || info.IsDir() {
		return "", false, nil
	}
	return finalDir, true, nil
}

// InstallVerifiedBundle validates signature, SHA-256, and safely extracts tarball into toolsDir/tool/version.
func InstallVerifiedBundle(
	manifest ToolManifest,
	pinnedPubKeyB64 string,
	tarballReader io.Reader,
	toolsBaseDir string,
) (string, error) {
	if cachedDir, ok, err := ResolveCachedBundle(manifest, pinnedPubKeyB64, toolsBaseDir); err != nil {
		return "", err
	} else if ok {
		return cachedDir, nil
	}

	toolRoot := filepath.Join(toolsBaseDir, manifest.ToolName)
	if err := os.MkdirAll(toolRoot, 0o700); err != nil {
		return "", fmt.Errorf("create tools root: %w", err)
	}
	finalDir := filepath.Join(toolRoot, manifest.Version)

	tmpArchive, err := os.CreateTemp(toolRoot, ".download-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("create temp archive: %w", err)
	}
	tmpArchivePath := tmpArchive.Name()
	defer os.Remove(tmpArchivePath)

	hasher := sha256.New()
	limited := io.LimitReader(tarballReader, MaxToolArchiveBytes+1)
	written, err := io.Copy(io.MultiWriter(tmpArchive, hasher), limited)
	_ = tmpArchive.Close()
	if err != nil {
		return "", fmt.Errorf("stream tool archive: %w", err)
	}
	if written != manifest.SizeBytes {
		return "", fmt.Errorf("downloaded byte count %d does not match manifest %d", written, manifest.SizeBytes)
	}
	gotHash := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(gotHash, manifest.SHA256) {
		return "", fmt.Errorf("SHA-256 mismatch: expected %s, got %s", manifest.SHA256, gotHash)
	}

	stagingDir, err := os.MkdirTemp(toolRoot, ".extract-*")
	if err != nil {
		return "", fmt.Errorf("create staging dir: %w", err)
	}
	cleanupStaging := true
	defer func() {
		if cleanupStaging {
			_ = os.RemoveAll(stagingDir)
		}
	}()
	if err := os.Chmod(stagingDir, 0o700); err != nil {
		return "", err
	}

	if err := safeExtractTarGz(tmpArchivePath, stagingDir); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(stagingDir, integrityMarkerFile), []byte(strings.ToLower(gotHash)+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write integrity marker: %w", err)
	}
	if _, statErr := os.Stat(finalDir); statErr == nil {
		// Replace stale/unverified previous install atomically.
		staleDir := finalDir + ".stale"
		_ = os.RemoveAll(staleDir)
		if err := os.Rename(finalDir, staleDir); err != nil {
			return "", fmt.Errorf("move stale install: %w", err)
		}
		if err := os.Rename(stagingDir, finalDir); err != nil {
			_ = os.Rename(staleDir, finalDir)
			return "", fmt.Errorf("atomic install rename: %w", err)
		}
		_ = os.RemoveAll(staleDir)
	} else if err := os.Rename(stagingDir, finalDir); err != nil {
		return "", fmt.Errorf("atomic install rename: %w", err)
	}
	cleanupStaging = false
	return finalDir, nil
}

func safeExtractTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer gzr.Close()

	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gzr)
	var totalBytes int64

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		cleanRel, err := validateTarEntryPath(hdr.Name)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(absDest, cleanRel)
		if !strings.HasPrefix(targetPath, absDest+string(os.PathSeparator)) && targetPath != absDest {
			return fmt.Errorf("zip-slip blocked for entry %q", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
				return err
			}
			mode := os.FileMode(hdr.Mode) & 0o700
			if mode == 0 {
				mode = 0o600
			}
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			_ = outFile.Chmod(mode)
			remaining := MaxToolUncompressedBytes - totalBytes
			n, copyErr := io.Copy(outFile, io.LimitReader(tr, remaining+1))
			closeErr := outFile.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			totalBytes += n
			if totalBytes > MaxToolUncompressedBytes {
				return errors.New("tool archive exceeded uncompressed byte ceiling")
			}
		default:
			return fmt.Errorf("disallowed tar entry type %d for %q", hdr.Typeflag, hdr.Name)
		}
	}
	return nil
}

func validateTarEntryPath(raw string) (string, error) {
	if strings.HasPrefix(raw, "/") || strings.Contains(raw, "\\") {
		return "", fmt.Errorf("disallowed absolute or backslash path %q", raw)
	}
	cleaned := filepath.Clean(raw)
	if cleaned == "." {
		return ".", nil
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path traversal blocked: %q", raw)
	}
	return cleaned, nil
}

// FindLatestInstalledTool locates the most recently modified verified tool directory under toolsBaseDir/toolName.
func FindLatestInstalledTool(toolsBaseDir, toolName string) string {
	if strings.TrimSpace(toolsBaseDir) == "" || !safeSegRe.MatchString(toolName) {
		return ""
	}
	toolRoot := filepath.Join(toolsBaseDir, toolName)
	currentDir := filepath.Join(toolRoot, "current")
	if info, err := os.Stat(filepath.Join(currentDir, toolName)); err == nil && !info.IsDir() {
		return currentDir
	}
	entries, err := os.ReadDir(toolRoot)
	if err != nil {
		return ""
	}
	var bestDir string
	var bestMod int64
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		dir := filepath.Join(toolRoot, entry.Name())
		if _, err := os.Stat(filepath.Join(dir, integrityMarkerFile)); err != nil {
			continue
		}
		binInfo, err := os.Stat(filepath.Join(dir, toolName))
		if err != nil || binInfo.IsDir() {
			continue
		}
		mod := binInfo.ModTime().UnixNano()
		if bestDir == "" || mod >= bestMod {
			bestDir = dir
			bestMod = mod
		}
	}
	return bestDir
}

// RunIsolatedLynis executes a verified portable Lynis directory using explicit args (never sh -c).
func RunIsolatedLynis(ctx context.Context, lynisDir string) (LynisPayload, error) {
	if strings.TrimSpace(lynisDir) == "" {
		return LynisPayload{Executed: false}, nil
	}
	absDir, err := filepath.Abs(lynisDir)
	if err != nil {
		return LynisPayload{Executed: false}, err
	}
	lynisBin := filepath.Join(absDir, "lynis")
	info, err := os.Stat(lynisBin)
	if err != nil || info.IsDir() {
		return LynisPayload{Executed: false}, fmt.Errorf("portable lynis binary not found at %s", lynisBin)
	}

	tmpDir, err := os.MkdirTemp("", "hostgrid-lynis-*")
	if err != nil {
		return LynisPayload{Executed: false}, err
	}
	defer os.RemoveAll(tmpDir)
	_ = os.Chmod(tmpDir, 0o700)

	reportFile := filepath.Join(tmpDir, "lynis-report.dat")
	logFile := filepath.Join(tmpDir, "lynis.log")

	cmd := exec.CommandContext(
		ctx,
		lynisBin,
		"audit",
		"system",
		"--quick",
		"--no-colors",
		"--quiet",
		"--report-file",
		reportFile,
		"--logfile",
		logFile,
	)
	cmd.Dir = absDir
	// Lynis may exit non-zero on audit warnings; inspect reportFile directly.
	runErr := cmd.Run()
	rawReport, readErr := os.ReadFile(reportFile)
	if readErr != nil {
		return LynisPayload{Executed: false}, fmt.Errorf("lynis execution failed (%v) and report unreadable (%w)", runErr, readErr)
	}
	reportStr := string(rawReport)
	return LynisPayload{
		Executed:     true,
		LynisVersion: extractLynisVersion(reportStr),
		ReportDat:    reportStr,
	}, nil
}

func extractLynisVersion(reportDat string) string {
	for _, line := range strings.Split(reportDat, "\n") {
		if strings.HasPrefix(line, "lynis_version=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "lynis_version="))
		}
	}
	return ""
}
