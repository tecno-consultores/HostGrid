package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateTestPKI(t *testing.T, dir string) (caPEMPath, srvCertPath, srvKeyPath, cliCertPath, cliKeyPath string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "HostGrid Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
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
	caPEMPath = filepath.Join(dir, "ca.pem")
	writePEM(t, caPEMPath, "CERTIFICATE", caDER)

	issue := func(prefix string, serial int64, extUsage x509.ExtKeyUsage) (string, string) {
		key, kErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if kErr != nil {
			t.Fatal(kErr)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: prefix},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{extUsage},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
			DNSNames:     []string{"localhost"},
		}
		der, cErr := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if cErr != nil {
			t.Fatal(cErr)
		}
		keyDER, mErr := x509.MarshalECPrivateKey(key)
		if mErr != nil {
			t.Fatal(mErr)
		}
		cPath := filepath.Join(dir, prefix+".crt")
		kPath := filepath.Join(dir, prefix+".key")
		writePEM(t, cPath, "CERTIFICATE", der)
		writePEM(t, kPath, "EC PRIVATE KEY", keyDER)
		return cPath, kPath
	}

	srvCertPath, srvKeyPath = issue("server", 2, x509.ExtKeyUsageServerAuth)
	cliCertPath, cliKeyPath = issue("client", 3, x509.ExtKeyUsageClientAuth)
	return caPEMPath, srvCertPath, srvKeyPath, cliCertPath, cliKeyPath
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBuildServerRejectsMisconfiguredTLSAndMTLS(t *testing.T) {
	if _, _, err := buildServer(relayConfig{
		upstreamURL: "https://127.0.0.1:8443",
		tlsCert:     "/tmp/cert.pem",
	}); err == nil {
		t.Fatal("expected error when --tls-cert is set without --tls-key")
	}

	if _, _, err := buildServer(relayConfig{
		upstreamURL: "https://127.0.0.1:8443",
		clientCA:    "/tmp/ca.pem",
	}); err == nil {
		t.Fatal("expected error when --client-ca is set without TLS cert/key")
	}
}

func TestRelayTLS13AndMTLSEndToEndAndHealthcheck(t *testing.T) {
	pkiDir := t.TempDir()
	caPEM, srvCert, srvKey, cliCert, cliKey := generateTestPKI(t, pkiDir)

	// TLS 1.3 upstream mock Control Plane
	upCert, err := tls.LoadX509KeyPair(srvCert, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agents/550e8400-e29b-41d4-a716-446655440001/patch-jobs" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
			return
		}
		http.NotFound(w, r)
	}))
	upstream.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{upCert},
	}
	upstream.StartTLS()
	defer upstream.Close()

	srv, useTLS, err := buildServer(relayConfig{
		listenAddr:  "127.0.0.1:0",
		upstreamURL: upstream.URL,
		cacheDir:    t.TempDir(),
		tlsCert:     srvCert,
		tlsKey:      srvKey,
		clientCA:    caPEM,
		upstreamCA:  caPEM,
	})
	if err != nil || !useTLS {
		t.Fatalf("expected valid TLS 1.3 mTLS server, got useTLS=%v err=%v", useTLS, err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, srv.TLSConfig)
	srvCertPair, err := tls.LoadX509KeyPair(srvCert, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	srv.TLSConfig.Certificates = []tls.Certificate{srvCertPair}
	go func() {
		_ = srv.Serve(tlsLn)
	}()
	defer srv.Close()

	relayURL := "https://" + ln.Addr().String()
	caBytes, err := os.ReadFile(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caBytes)
	clientPair, err := tls.LoadX509KeyPair(cliCert, cliKey)
	if err != nil {
		t.Fatal(err)
	}

	// 1. TLS 1.2 client MUST be rejected
	tls12Client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MaxVersion:   tls.VersionTLS12,
				RootCAs:      caPool,
				Certificates: []tls.Certificate{clientPair},
			},
		},
	}
	if _, err := tls12Client.Get(relayURL + "/healthz"); err == nil {
		t.Fatal("expected TLS 1.2 connection to be rejected by TLS 1.3 relay")
	}

	// 2. TLS 1.3 client WITHOUT client certificate MUST be rejected by mTLS
	noCertClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    caPool,
			},
		},
	}
	if _, err := noCertClient.Get(relayURL + "/healthz"); err == nil {
		t.Fatal("expected missing mTLS client cert to be rejected")
	}

	// 3. TLS 1.3 client WITH valid mTLS cert succeeds and forwards to TLS 1.3 upstream
	mtlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
				RootCAs:      caPool,
				Certificates: []tls.Certificate{clientPair},
			},
		},
	}
	resp, err := mtlsClient.Get(relayURL + "/api/v1/agents/550e8400-e29b-41d4-a716-446655440001/patch-jobs")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 over TLS 1.3 mTLS, got resp=%+v err=%v", resp, err)
	}
	_ = resp.Body.Close()

	// 4. Built-in healthcheck subcommand works over TLS 1.3 + mTLS and fails closed on partial client cert
	if err := runHealthcheck([]string{
		"--url", relayURL + "/healthz",
		"--ca-cert", caPEM,
		"--client-cert", cliCert,
		"--client-key", "",
	}); err == nil {
		t.Fatal("expected healthcheck to fail closed when --client-cert is provided without --client-key")
	}
	if err := runHealthcheck([]string{
		"--url", relayURL + "/healthz",
		"--ca-cert", caPEM,
		"--client-cert", cliCert,
		"--client-key", cliKey,
	}); err != nil {
		t.Fatalf("expected TLS 1.3 mTLS healthcheck to pass, got %v", err)
	}
}
