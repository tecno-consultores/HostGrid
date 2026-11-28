package transport_test

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/tecno-consultores/HostGrid/agent/internal/probe"
	"github.com/tecno-consultores/HostGrid/agent/internal/tools"
	"github.com/tecno-consultores/HostGrid/agent/internal/transport"
)

func TestExportOfflineBundleEd25519AndHMAC(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	snap := transport.SnapshotPayload{
		Hostname:         "srv-airgap-01",
		MachineIDHash:    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		Environment:      "prod",
		CollectedAt:      "2026-11-19T23:10:00.000Z",
		AgentVersion:     "0.1.0",
		ConnectivityMode: "airgapped",
		Probe: probe.ProbeResult{
			OSFamily:      "debian",
			OSName:        "Debian GNU/Linux",
			OSVersion:     "12",
			KernelVersion: "6.1.0-26-amd64",
			Arch:          "amd64",
			InitSystem:    "systemd",
			Capabilities:  map[string]probe.CapabilityItem{},
		},
		Lynis: tools.LynisPayload{
			Executed:     true,
			LynisVersion: "3.1.4",
			ReportDat:    "lynis_version=3.1.4\nhardening_index=77\n",
		},
	}

	outPath := filepath.Join(t.TempDir(), "host.bundle")
	digest, err := transport.ExportOfflineBundle(outPath, snap, transport.ExportOptions{
		Ed25519PrivKey: priv,
	})
	if err != nil {
		t.Fatalf("ExportOfflineBundle failed: %v", err)
	}
	if len(digest) != 64 {
		t.Fatalf("expected 64-char sha256 digest, got %q", digest)
	}

	entries := readTarEntries(t, outPath)
	for _, required := range []string{"manifest.json", "manifest.sig", "snapshot.json", "lynis-report.dat"} {
		if _, ok := entries[required]; !ok {
			t.Fatalf("missing required bundle entry %s", required)
		}
	}

	var manifest transport.BundleManifest
	if err := json.Unmarshal(entries["manifest.json"], &manifest); err != nil {
		t.Fatalf("invalid manifest.json: %v", err)
	}
	if manifest.SignatureMode != "ed25519" {
		t.Fatalf("expected ed25519 signature_mode, got %s", manifest.SignatureMode)
	}
	sigRaw, err := base64.StdEncoding.DecodeString(string(entries["manifest.sig"]))
	if err != nil {
		t.Fatalf("decode manifest.sig: %v", err)
	}
	if !ed25519.Verify(pub, entries["manifest.json"], sigRaw) {
		t.Fatal("ed25519 signature on manifest.json did not verify")
	}

	hmacOut := filepath.Join(t.TempDir(), "host-hmac.bundle")
	if _, err := transport.ExportOfflineBundle(hmacOut, snap, transport.ExportOptions{
		AgentCredential: "hg_agent_test_credential_value",
	}); err != nil {
		t.Fatalf("ExportOfflineBundle HMAC failed: %v", err)
	}
	hmacEntries := readTarEntries(t, hmacOut)
	var hmacManifest transport.BundleManifest
	_ = json.Unmarshal(hmacEntries["manifest.json"], &hmacManifest)
	if hmacManifest.SignatureMode != "hmac_host" {
		t.Fatalf("expected hmac_host signature_mode, got %s", hmacManifest.SignatureMode)
	}
}

func TestClientRejectsNonHTTPSRemote(t *testing.T) {
	if _, err := transport.NewClient(transport.ClientOptions{
		ServerURL:    "http://controlplane.internal:8000",
		AgentVersion: "0.1.0",
	}); err == nil {
		t.Fatal("expected error for non-HTTPS remote URL")
	}
	client, err := transport.NewClient(transport.ClientOptions{
		ServerURL:    "http://127.0.0.1:8000",
		AgentVersion: "0.1.0",
	})
	if err != nil {
		t.Fatalf("expected loopback HTTP allowed for local dev, got %v", err)
	}
	if _, err := transport.NewClient(transport.ClientOptions{
		ServerURL:      "https://controlplane.internal:8443",
		AgentVersion:   "0.1.0",
		ClientCertPath: "/tmp/only-cert.pem",
	}); err == nil {
		t.Fatal("expected error when client cert is given without client key")
	}
	if _, err := client.DownloadToolStream(context.Background(), "https://evil.example/payload"); err == nil {
		t.Fatal("expected error for disallowed tool bundle download path")
	}
	if _, err := client.DownloadToolStream(context.Background(), "/api/v1/bundles/../../etc/passwd"); err == nil {
		t.Fatal("expected error for path traversal in tool bundle download path")
	}
}

func readTarEntries(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	out := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = data
	}
	return out
}
