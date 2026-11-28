package tools_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tecno-consultores/HostGrid/agent/internal/tools"
)

func buildTestTarGz(t *testing.T, entries map[string]struct {
	content  string
	typeflag byte
	mode     int64
}) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	for name, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o700
		}
		hdr := &tar.Header{
			Name:     name,
			Typeflag: tf,
			Mode:     mode,
			Size:     int64(len(e.content)),
		}
		if tf == tar.TypeSymlink {
			hdr.Linkname = "/etc/passwd"
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if tf == tar.TypeReg {
			if _, err := tw.Write([]byte(e.content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = tw.Close()
	_ = gzw.Close()
	return buf.Bytes()
}

func makeSignedManifest(t *testing.T, priv ed25519.PrivateKey, archive []byte) tools.ToolManifest {
	t.Helper()
	sum := sha256.Sum256(archive)
	hashHex := hex.EncodeToString(sum[:])
	canonicalMap := map[string]any{
		"arch":       "noarch",
		"filename":   "lynis-3.1.4-portable.tar.gz",
		"sha256":     hashHex,
		"size_bytes": len(archive),
		"tool_name":  "lynis",
		"version":    "3.1.4",
	}
	canonBytes, err := json.Marshal(canonicalMap)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, canonBytes)
	return tools.ToolManifest{
		ToolName:              "lynis",
		Version:               "3.1.4",
		Arch:                  "noarch",
		Filename:              "lynis-3.1.4-portable.tar.gz",
		SHA256:                hashHex,
		SizeBytes:             int64(len(archive)),
		ManifestCanonicalJSON: string(canonBytes),
		SignatureB64:          base64.StdEncoding.EncodeToString(sig),
		DownloadURL:           "/api/v1/bundles/lynis/3.1.4/download",
	}
}

func TestInstallVerifiedBundleAndRunIsolatedLynis(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	fakeLynisScript := "#!/bin/sh\n" +
		"REPORT=\"\"\n" +
		"while [ \"$#\" -gt 0 ]; do\n" +
		"  if [ \"$1\" = \"--report-file\" ]; then shift; REPORT=\"$1\"; fi\n" +
		"  shift\n" +
		"done\n" +
		"printf 'lynis_version=3.1.4\\nhardening_index=75\\n' > \"$REPORT\"\n"

	archive := buildTestTarGz(t, map[string]struct {
		content  string
		typeflag byte
		mode     int64
	}{
		"lynis": {content: fakeLynisScript, mode: 0o700},
	})
	manifest := makeSignedManifest(t, priv, archive)

	toolsDir := t.TempDir()
	installedDir, err := tools.InstallVerifiedBundle(manifest, pubB64, bytes.NewReader(archive), toolsDir)
	if err != nil {
		t.Fatalf("InstallVerifiedBundle failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installedDir, "lynis")); err != nil {
		t.Fatalf("expected installed lynis binary: %v", err)
	}

	// Verified cache hit should succeed without re-downloading
	cachedDir, hit, err := tools.ResolveCachedBundle(manifest, pubB64, toolsDir)
	if err != nil || !hit || cachedDir != installedDir {
		t.Fatalf("expected verified cache hit, got dir=%q hit=%v err=%v", cachedDir, hit, err)
	}

	// Tampered integrity marker must invalidate cache and reinstall cleanly
	if err := os.WriteFile(filepath.Join(installedDir, ".hostgrid-sha256"), []byte("0000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, hitAfterTamper, err := tools.ResolveCachedBundle(manifest, pubB64, toolsDir); err != nil || hitAfterTamper {
		t.Fatalf("expected cache miss on tampered marker, got hit=%v err=%v", hitAfterTamper, err)
	}
	if _, err := tools.InstallVerifiedBundle(manifest, pubB64, bytes.NewReader(archive), toolsDir); err != nil {
		t.Fatalf("expected clean reinstall over stale dir, got %v", err)
	}
	if found := tools.FindLatestInstalledTool(toolsDir, "lynis"); found != installedDir {
		t.Fatalf("expected FindLatestInstalledTool=%q, got %q", installedDir, found)
	}

	payload, err := tools.RunIsolatedLynis(context.Background(), installedDir)
	if err != nil {
		t.Fatalf("RunIsolatedLynis failed: %v", err)
	}
	if !payload.Executed || payload.LynisVersion != "3.1.4" || !strings.Contains(payload.ReportDat, "hardening_index=75") {
		t.Fatalf("unexpected lynis payload: %+v", payload)
	}
}

func TestInstallVerifiedBundleRejectsTamperAndZipSlip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	goodArchive := buildTestTarGz(t, map[string]struct {
		content  string
		typeflag byte
		mode     int64
	}{"lynis": {content: "ok"}})
	manifest := makeSignedManifest(t, priv, goodArchive)

	tampered := append([]byte{}, goodArchive...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := tools.InstallVerifiedBundle(manifest, pubB64, bytes.NewReader(tampered), t.TempDir()); err == nil {
		t.Fatal("expected SHA-256 tamper error, got nil")
	}

	badSigManifest := manifest
	badSigManifest.SignatureB64 = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, err := tools.InstallVerifiedBundle(badSigManifest, pubB64, bytes.NewReader(goodArchive), t.TempDir()); err == nil {
		t.Fatal("expected Ed25519 signature error, got nil")
	}

	slipArchive := buildTestTarGz(t, map[string]struct {
		content  string
		typeflag byte
		mode     int64
	}{"../../etc/evil": {content: "pwn"}})
	slipManifest := makeSignedManifest(t, priv, slipArchive)
	if _, err := tools.InstallVerifiedBundle(slipManifest, pubB64, bytes.NewReader(slipArchive), t.TempDir()); err == nil {
		t.Fatal("expected zip-slip rejection, got nil")
	}

	symArchive := buildTestTarGz(t, map[string]struct {
		content  string
		typeflag byte
		mode     int64
	}{"evil-link": {typeflag: tar.TypeSymlink}})
	symManifest := makeSignedManifest(t, priv, symArchive)
	if _, err := tools.InstallVerifiedBundle(symManifest, pubB64, bytes.NewReader(symArchive), t.TempDir()); err == nil {
		t.Fatal("expected symlink rejection, got nil")
	}
}
