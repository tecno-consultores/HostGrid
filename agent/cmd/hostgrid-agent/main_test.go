package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tecno-consultores/HostGrid/agent/internal/config"
	"github.com/tecno-consultores/HostGrid/agent/internal/transport"
)

func TestCLIEnrollAndScanWithProxyEndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	caPEM, serverCert := generateSelfSignedLoopbackTLS(t)
	caPath := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	var enrollHits atomic.Int32
	var snapshotHits atomic.Int32
	var receivedAuth atomic.Value
	cpSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/enrollments/register":
			enrollHits.Add(1)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(transport.EnrollResponse{
				HostID:               "550e8400-e29b-41d4-a716-446655440001",
				AgentCredential:      "hg_agent_cli_proxy_secret",
				BundleSigningPubKey:  "",
				HeartbeatIntervalSec: 120,
				ScanIntervalSec:      600,
			})
		case "/api/v1/snapshots":
			snapshotHits.Add(1)
			receivedAuth.Store(r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	cpSrv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
	}
	cpSrv.StartTLS()
	defer cpSrv.Close()

	var connectTunnels atomic.Int32
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		connectTunnels.Add(1)
		destConn, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			destConn.Close()
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			destConn.Close()
			return
		}
		_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go func() {
			defer destConn.Close()
			defer clientConn.Close()
			_, _ = io.Copy(destConn, clientConn)
		}()
		go func() {
			defer destConn.Close()
			defer clientConn.Close()
			_, _ = io.Copy(clientConn, destConn)
		}()
	}))
	defer proxySrv.Close()

	cfgPath := filepath.Join(tmpDir, "etc", "agent.json")
	if err := runEnroll([]string{
		"--server", cpSrv.URL,
		"--token", "hg_enroll_cli_test",
		"--config", cfgPath,
		"--mode", "relay",
		"--env", "dmz",
		"--ca-cert", caPath,
		"--proxy", "  " + proxySrv.URL + "  ",
	}); err != nil {
		t.Fatalf("runEnroll with --proxy failed: %v", err)
	}

	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("stat persisted config: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected 0600 config permissions, got %#o", perm)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load persisted config: %v", err)
	}
	if cfg.ProxyURL != proxySrv.URL || cfg.ConnectivityMode != "relay" || cfg.Environment != "dmz" {
		t.Fatalf("unexpected persisted config: %+v", cfg)
	}
	if enrollHits.Load() != 1 || connectTunnels.Load() != 1 {
		t.Fatalf("expected 1 enroll via 1 CONNECT tunnel, got enroll=%d tunnels=%d", enrollHits.Load(), connectTunnels.Load())
	}

	if err := runScan([]string{"--config", cfgPath, "--skip-lynis"}); err != nil {
		t.Fatalf("runScan reusing persisted proxy_url failed: %v", err)
	}
	if snapshotHits.Load() != 1 {
		t.Fatalf("expected 1 snapshot upload, got %d", snapshotHits.Load())
	}
	if connectTunnels.Load() != 2 {
		t.Fatalf("expected second CONNECT tunnel for scan, got %d", connectTunnels.Load())
	}
	if auth, _ := receivedAuth.Load().(string); auth != "Bearer hg_agent_cli_proxy_secret" {
		t.Fatalf("unexpected Authorization header: %q", auth)
	}
}

func TestCLIEnrollRejectsInvalidProxyWithoutPersistingConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "agent.json")
	const secret = "DoNotLeakProxyCreds"
	err := runEnroll([]string{
		"--server", "https://control.internal:8443",
		"--token", "hg_enroll_test",
		"--config", cfgPath,
		"--proxy", "socks5://user:" + secret + "@relay.dmz:1080",
	})
	if err == nil {
		t.Fatal("expected error for invalid --proxy scheme")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked proxy credentials: %v", err)
	}
	if _, statErr := os.Stat(cfgPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected config file not to be created on failed enroll, statErr=%v", statErr)
	}
}

func generateSelfSignedLoopbackTLS(t *testing.T) ([]byte, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, cert
}
