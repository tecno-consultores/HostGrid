package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tecno-consultores/HostGrid/relay/internal/relay"
)

var version = "0.1.0"

type relayConfig struct {
	listenAddr         string
	upstreamURL        string
	cacheDir           string
	tlsCert            string
	tlsKey             string
	clientCA           string
	upstreamCA         string
	upstreamClientCert string
	upstreamClientKey  string
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func buildServer(cfg relayConfig) (*http.Server, bool, error) {
	if (cfg.tlsCert == "") != (cfg.tlsKey == "") {
		return nil, false, errors.New("both --tls-cert and --tls-key must be provided together")
	}
	if cfg.clientCA != "" && cfg.tlsCert == "" {
		return nil, false, errors.New("--client-ca requires --tls-cert and --tls-key to enforce mTLS")
	}

	handler, err := relay.NewHandler(relay.Options{
		UpstreamURL:    cfg.upstreamURL,
		CacheDir:       cfg.cacheDir,
		CACertPath:     cfg.upstreamCA,
		ClientCertPath: cfg.upstreamClientCert,
		ClientKeyPath:  cfg.upstreamClientKey,
	})
	if err != nil {
		return nil, false, err
	}

	srv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	useTLS := cfg.tlsCert != "" && cfg.tlsKey != ""
	if useTLS {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
		if cfg.clientCA != "" {
			pemBytes, readErr := os.ReadFile(cfg.clientCA)
			if readErr != nil {
				return nil, false, fmt.Errorf("read client CA: %w", readErr)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pemBytes) {
				return nil, false, errors.New("failed to parse client CA PEM")
			}
			tlsCfg.ClientCAs = pool
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
		srv.TLSConfig = tlsCfg
	}
	return srv, useTLS, nil
}

func resolveHealthcheckURL(listenAddr string, useTLS bool) string {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" {
		return scheme + "://127.0.0.1:8443/healthz"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s://%s/healthz", scheme, net.JoinHostPort(host, port))
}

func runHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	defaultTLS := os.Getenv("HOSTGRID_RELAY_TLS_CERT") != ""
	defaultURL := resolveHealthcheckURL(envOrDefault("HOSTGRID_RELAY_LISTEN", ":8443"), defaultTLS)
	targetURL := fs.String("url", envOrDefault("HOSTGRID_RELAY_HEALTH_URL", defaultURL), "Local /healthz URL")
	caCert := fs.String("ca-cert", envOrDefault("HOSTGRID_RELAY_HEALTH_CA", os.Getenv("HOSTGRID_RELAY_TLS_CERT")), "CA or server cert PEM for local TLS healthcheck")
	clientCert := fs.String("client-cert", os.Getenv("HOSTGRID_RELAY_HEALTH_CLIENT_CERT"), "Optional mTLS client cert for healthcheck")
	clientKey := fs.String("client-key", os.Getenv("HOSTGRID_RELAY_HEALTH_CLIENT_KEY"), "Optional mTLS client key for healthcheck")
	if err := fs.Parse(args); err != nil {
		return err
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if *caCert != "" {
		pemBytes, err := os.ReadFile(*caCert)
		if err != nil {
			return fmt.Errorf("read healthcheck CA PEM: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return errors.New("failed to parse healthcheck CA PEM")
		}
		tlsCfg.RootCAs = pool
	}
	if (*clientCert == "") != (*clientKey == "") {
		return errors.New("both --client-cert and --client-key must be provided together")
	}
	if *clientCert != "" && *clientKey != "" {
		cert, err := tls.LoadX509KeyPair(*clientCert, *clientKey)
		if err != nil {
			return fmt.Errorf("load healthcheck client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	client := &http.Client{
		Timeout:   4 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	resp, err := client.Get(*targetURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("hostgrid-relay %s\n", version)
			return
		case "healthcheck":
			if err := runHealthcheck(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "hostgrid-relay healthcheck error: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	cfg := relayConfig{}
	flag.StringVar(&cfg.listenAddr, "listen", envOrDefault("HOSTGRID_RELAY_LISTEN", ":8443"), "Listen address")
	flag.StringVar(&cfg.upstreamURL, "upstream", envOrDefault("HOSTGRID_RELAY_UPSTREAM", ""), "Control Plane HTTPS URL")
	flag.StringVar(&cfg.cacheDir, "cache-dir", envOrDefault("HOSTGRID_RELAY_CACHE_DIR", "/var/cache/hostgrid-relay"), "Signed bundle cache directory")
	flag.StringVar(&cfg.tlsCert, "tls-cert", envOrDefault("HOSTGRID_RELAY_TLS_CERT", ""), "Optional inbound TLS 1.3 certificate PEM")
	flag.StringVar(&cfg.tlsKey, "tls-key", envOrDefault("HOSTGRID_RELAY_TLS_KEY", ""), "Optional inbound TLS 1.3 private key PEM")
	flag.StringVar(&cfg.clientCA, "client-ca", envOrDefault("HOSTGRID_RELAY_CLIENT_CA", ""), "Optional CA PEM to enforce agent mTLS")
	flag.StringVar(&cfg.upstreamCA, "upstream-ca", envOrDefault("HOSTGRID_RELAY_UPSTREAM_CA", ""), "Optional custom CA PEM for upstream Control Plane")
	flag.StringVar(&cfg.upstreamClientCert, "upstream-client-cert", envOrDefault("HOSTGRID_RELAY_UPSTREAM_CLIENT_CERT", ""), "Optional mTLS client cert for upstream")
	flag.StringVar(&cfg.upstreamClientKey, "upstream-client-key", envOrDefault("HOSTGRID_RELAY_UPSTREAM_CLIENT_KEY", ""), "Optional mTLS client key for upstream")
	flag.Parse()

	cfg.listenAddr = strings.TrimSpace(cfg.listenAddr)
	srv, useTLS, err := buildServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostgrid-relay config error: %v\n", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		fmt.Printf("hostgrid-relay %s listening on %s -> %s (tls=%v)\n", version, cfg.listenAddr, cfg.upstreamURL, useTLS)
		if useTLS {
			errCh <- srv.ListenAndServeTLS(cfg.tlsCert, cfg.tlsKey)
		} else {
			errCh <- srv.ListenAndServe()
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	case srvErr := <-errCh:
		if srvErr != nil && srvErr != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "hostgrid-relay serve error: %v\n", srvErr)
			os.Exit(1)
		}
	}
}
