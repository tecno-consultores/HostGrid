package transport

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// BundleManifestFile matches SPEC.md section 5.1 file integrity entry.
type BundleManifestFile struct {
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// BundleManifest matches SPEC.md section 5.1 manifest.json schema.
type BundleManifest struct {
	BundleFormatVersion string                        `json:"bundle_format_version"`
	BundleID            string                        `json:"bundle_id"`
	CreatedAt           string                        `json:"created_at"`
	Hostname            string                        `json:"hostname"`
	MachineIDHash       string                        `json:"machine_id_hash"`
	AgentVersion        string                        `json:"agent_version"`
	SignatureMode       string                        `json:"signature_mode"`
	Files               map[string]BundleManifestFile `json:"files"`
}

// ExportOptions controls cryptographic signing of an air-gapped .bundle export.
type ExportOptions struct {
	AgentCredential string
	Ed25519PrivKey  ed25519.PrivateKey
}

// ExportOfflineBundle creates a SPEC.md section 5.1 compliant tar.gz .bundle file.
func ExportOfflineBundle(outputPath string, snap SnapshotPayload, opts ExportOptions) (string, error) {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}

	snapCopy := snap
	snapCopy.ConnectivityMode = "airgapped"
	lynisDat := snapCopy.Lynis.ReportDat
	if lynisDat != "" {
		// Store Lynis report as dedicated verified archive entry per SPEC.md 5.1.
		snapCopy.Lynis.ReportDat = ""
	}

	snapBytes, err := json.MarshalIndent(snapCopy, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal snapshot.json: %w", err)
	}

	filesMeta := map[string]BundleManifestFile{
		"snapshot.json": {
			SHA256:    sha256HexBytes(snapBytes),
			SizeBytes: int64(len(snapBytes)),
		},
	}
	archiveEntries := []struct {
		name string
		data []byte
	}{
		{name: "snapshot.json", data: snapBytes},
	}

	if lynisDat != "" {
		lynisBytes := []byte(lynisDat)
		filesMeta["lynis-report.dat"] = BundleManifestFile{
			SHA256:    sha256HexBytes(lynisBytes),
			SizeBytes: int64(len(lynisBytes)),
		}
		archiveEntries = append(archiveEntries, struct {
			name string
			data []byte
		}{name: "lynis-report.dat", data: lynisBytes})
	}

	sigMode := "sha256_integrity_only"
	if len(opts.Ed25519PrivKey) == ed25519.PrivateKeySize {
		sigMode = "ed25519"
	} else if opts.AgentCredential != "" {
		sigMode = "hmac_host"
	}

	manifest := BundleManifest{
		BundleFormatVersion: "1.0",
		BundleID:            newUUIDv4(),
		CreatedAt:           time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Hostname:            snapCopy.Hostname,
		MachineIDHash:       snapCopy.MachineIDHash,
		AgentVersion:        snapCopy.AgentVersion,
		SignatureMode:       sigMode,
		Files:               filesMeta,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("marshal manifest.json: %w", err)
	}

	sigBytes := computeBundleSignature(manifestBytes, sigMode, opts)

	finalEntries := append(
		[]struct {
			name string
			data []byte
		}{
			{name: "manifest.json", data: manifestBytes},
			{name: "manifest.sig", data: sigBytes},
		},
		archiveEntries...,
	)

	outFile, err := os.CreateTemp(filepath.Dir(outputPath), ".hostgrid-bundle-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create bundle file: %w", err)
	}
	tmpPath := outFile.Name()
	if err := outFile.Chmod(0o600); err != nil {
		_ = outFile.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("chmod bundle temp file: %w", err)
	}
	hasher := sha256.New()
	gzw := gzip.NewWriter(outFile)
	tw := tar.NewWriter(gzw)

	for _, entry := range finalEntries {
		hdr := &tar.Header{
			Name:     entry.name,
			Mode:     0o600,
			Uid:      0,
			Gid:      0,
			Uname:    "root",
			Gname:    "root",
			Size:     int64(len(entry.data)),
			Typeflag: tar.TypeReg,
			ModTime:  time.Now().UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = outFile.Close()
			_ = os.Remove(tmpPath)
			return "", err
		}
		if _, err := tw.Write(entry.data); err != nil {
			_ = outFile.Close()
			_ = os.Remove(tmpPath)
			return "", err
		}
	}
	if err := tw.Close(); err != nil {
		_ = outFile.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := gzw.Close(); err != nil {
		_ = outFile.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := outFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}

	rawBundle, err := os.ReadFile(tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	_, _ = hasher.Write(rawBundle)
	if err := os.Rename(tmpPath, outputPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func computeBundleSignature(manifestBytes []byte, sigMode string, opts ExportOptions) []byte {
	switch sigMode {
	case "ed25519":
		sig := ed25519.Sign(opts.Ed25519PrivKey, manifestBytes)
		return []byte(base64.StdEncoding.EncodeToString(sig))
	case "hmac_host":
		// Derive key from SHA-256 hex of agent credential matching server's stored credential_hash.
		credHash := sha256HexBytes([]byte(opts.AgentCredential))
		mac := hmac.New(sha256.New, []byte(credHash))
		_, _ = mac.Write(manifestBytes)
		return []byte(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	default:
		return []byte("sha256_integrity_only")
	}
}

func sha256HexBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func newUUIDv4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16],
	)
}
