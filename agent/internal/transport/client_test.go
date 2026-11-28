package transport_test

import (
	"context"
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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tecno-consultores/HostGrid/agent/internal/transport"
)

func TestNewClientUsesEnvironmentProxyByDefault(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "https://env-relay.dmz:8443")
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("NO_PROXY", "bypass.internal")

	client, err := transport.NewClient(transport.ClientOptions{
		ServerURL:    "https://control.internal:8443",
		AgentVersion: "0.1.0",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	tr, ok := client.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.HTTPClient.Transport)
	}
	if tr.Proxy == nil {
		t.Fatal("expected Proxy function to be configured by default")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("expected TLS 1.3 minimum version")
	}
	if tr.TLSHandshakeTimeout <= 0 || tr.IdleConnTimeout <= 0 {
		t.Fatalf("expected hardened cloned transport timeouts, got TLSHandshakeTimeout=%v IdleConnTimeout=%v", tr.TLSHandshakeTimeout, tr.IdleConnTimeout)
	}

	req, err := http.NewRequest(http.MethodPost, "https://control.internal:8443/api/v1/snapshots", nil)
	if err != nil {
		t.Fatal(err)
	}
	gotProxy, err := tr.Proxy(req)
	if err != nil {
		t.Fatalf("tr.Proxy failed: %v", err)
	}
	if gotProxy == nil || gotProxy.String() != "https://env-relay.dmz:8443" {
		t.Fatalf("expected env proxy https://env-relay.dmz:8443, got %v", gotProxy)
	}

	bypassReq, err := http.NewRequest(http.MethodGet, "https://bypass.internal:8443/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	bypassProxy, err := tr.Proxy(bypassReq)
	if err != nil {
		t.Fatalf("tr.Proxy bypass failed: %v", err)
	}
	if bypassProxy != nil {
		t.Fatalf("expected nil proxy for NO_PROXY host, got %v", bypassProxy)
	}
}

func TestNewClientExplicitProxyURLOverridesEnvAndRoutesTraffic(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "https://ignored-env-proxy.internal:9999")

	for _, proxyRaw := range []string{
		"http://relay.dmz:3128",
		"https://relay.dmz:8443",
		"https://relay.dmz:8443/",
		"http://[::1]:3128",
	} {
		client, err := transport.NewClient(transport.ClientOptions{
			ServerURL:    "https://control.internal:8443",
			AgentVersion: "0.1.0",
			ProxyURL:     "  " + proxyRaw + "  ",
		})
		if err != nil {
			t.Fatalf("NewClient(%q) failed: %v", proxyRaw, err)
		}
		tr := client.HTTPClient.Transport.(*http.Transport)
		req, _ := http.NewRequest(http.MethodGet, "https://control.internal:8443/api/v1/bundles/lynis/latest/manifest", nil)
		gotProxy, err := tr.Proxy(req)
		if err != nil {
			t.Fatalf("tr.Proxy failed for %q: %v", proxyRaw, err)
		}
		if gotProxy == nil || gotProxy.String() != proxyRaw {
			t.Fatalf("expected explicit proxy %q, got %v", proxyRaw, gotProxy)
		}
	}

	// End-to-end check: verify HTTP requests are actually forwarded through the configured proxy server.
	var proxiedTarget string
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxiedTarget = r.URL.String()
		w.WriteHeader(http.StatusOK)
	}))
	defer proxySrv.Close()

	client, err := transport.NewClient(transport.ClientOptions{
		ServerURL:    "http://127.0.0.1:19999",
		Credential:   "hg_agent_test_cred",
		AgentVersion: "0.1.0",
		ProxyURL:     proxySrv.URL,
	})
	if err != nil {
		t.Fatalf("NewClient with local proxy failed: %v", err)
	}
	if err := client.Heartbeat(context.Background(), "host-123", transport.HeartbeatRequest{
		AgentVersion: "0.1.0",
		UptimeSec:    42,
	}); err != nil {
		t.Fatalf("Heartbeat via proxy failed: %v", err)
	}
	expectedURL, _ := url.Parse("http://127.0.0.1:19999/api/v1/agents/host-123/heartbeat")
	if proxiedTarget != expectedURL.String() {
		t.Fatalf("expected proxy to receive %q, got %q", expectedURL.String(), proxiedTarget)
	}
}

func TestNewClientTLS13MTLSOverHTTPConnectProxy(t *testing.T) {
	pkiDir := t.TempDir()
	caPEM, serverCert, clientCertPath, clientKeyPath := generateTestMTLSBundle(t, pkiDir)
	caPath := filepath.Join(pkiDir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to load test CA pool")
	}

	var sawClientCN atomic.Value
	cpSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "tls 1.3 mTLS required", http.StatusForbidden)
			return
		}
		sawClientCN.Store(r.TLS.PeerCertificates[0].Subject.CommonName)
		if r.URL.Path == "/api/v1/enrollments/register" {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(transport.EnrollResponse{
				HostID:               "550e8400-e29b-41d4-a716-446655440000",
				AgentCredential:      "hg_agent_cred_mtls",
				BundleSigningPubKey:  "dGVzdC1wdWJrZXk=",
				HeartbeatIntervalSec: 300,
				ScanIntervalSec:      3600,
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	cpSrv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	cpSrv.StartTLS()
	defer cpSrv.Close()

	var connectCount atomic.Int32
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		connectCount.Add(1)
		destConn, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			destConn.Close()
			http.Error(w, "hijacking not supported", http.StatusInternalServerError)
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

	client, err := transport.NewClient(transport.ClientOptions{
		ServerURL:      cpSrv.URL,
		AgentVersion:   "0.1.0",
		CACertPath:     caPath,
		ClientCertPath: clientCertPath,
		ClientKeyPath:  clientKeyPath,
		ProxyURL:       proxySrv.URL,
	})
	if err != nil {
		t.Fatalf("NewClient for mTLS CONNECT proxy failed: %v", err)
	}

	resp, err := client.Enroll(context.Background(), transport.EnrollRequest{
		EnrollmentToken: "hg_enroll_test",
		Hostname:        "srv-dmz-01",
	})
	if err != nil {
		t.Fatalf("Enroll via TLS 1.3 mTLS CONNECT proxy failed: %v", err)
	}
	if resp.HostID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("unexpected EnrollResponse: %+v", resp)
	}
	if connectCount.Load() != 1 {
		t.Fatalf("expected exactly 1 CONNECT tunnel through proxy, got %d", connectCount.Load())
	}
	if gotCN, _ := sawClientCN.Load().(string); gotCN != "hostgrid-test-agent" {
		t.Fatalf("expected server to verify mTLS CN hostgrid-test-agent, got %q", gotCN)
	}
}

func TestNewClientRejectsInvalidProxyURLsWithoutLeakingCredentials(t *testing.T) {
	const secret = "SuperSecretProxyPass99"
	invalidProxies := []string{
		"socks5://user:" + secret + "@relay.dmz:1080",
		"ftp://relay.dmz:21",
		"file:///etc/passwd",
		"relay.dmz:3128",
		"user:" + secret + "@relay.dmz:3128",
		"http://",
		"https://",
		"http://user:" + secret + "@:3128",
		"http://user:" + secret + "@[::1",
		"http://relay.dmz:0",
		"http://relay.dmz:65536",
		"http://relay.dmz:99999",
		"https://relay.dmz:8443/subpath",
		"https://relay.dmz:8443?foo=bar",
		"https://relay.dmz:8443#frag",
		"http:opaque.relay.dmz:3128",
		"http://user:" + secret + "@relay.dmz:3128/\n",
		"http://user:" + secret + "@relay.dmz:3128/foo\r\nX-Injected: 1",
	}

	for _, badProxy := range invalidProxies {
		_, err := transport.NewClient(transport.ClientOptions{
			ServerURL:    "https://control.internal:8443",
			AgentVersion: "0.1.0",
			ProxyURL:     badProxy,
		})
		if err == nil {
			t.Errorf("expected error for invalid ProxyURL %q, got nil", badProxy)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error for invalid ProxyURL leaked proxy credentials: %v", err)
		}
	}
}

func generateTestMTLSBundle(t *testing.T, dir string) ([]byte, tls.Certificate, string, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "HostGrid Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatal(err)
	}
	srvCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}

	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "hostgrid-test-agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, &cliKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cliKeyDER, err := x509.MarshalECPrivateKey(cliKey)
	if err != nil {
		t.Fatal(err)
	}

	cliCertPath := filepath.Join(dir, "client.crt")
	cliKeyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(cliCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cliDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cliKeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: cliKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return caPEM, srvCert, cliCertPath, cliKeyPath
}
