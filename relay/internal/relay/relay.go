// Package relay implements the HostGrid DMZ Relay Node (ARCHITECTURE.md section 3.2).
// It forwards strictly allow-listed agent protocol requests to the Control Plane without mutating
// payloads and caches signed tool bundles (manifests + tarballs) while NEVER holding any Ed25519
// private signing key.
package relay

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultMaxForwardBytes caps forwarded agent request bodies (32 MiB).
	DefaultMaxForwardBytes int64 = 32 * 1024 * 1024
	// DefaultMaxBundleBytes caps cached tool bundle downloads (50 MiB).
	DefaultMaxBundleBytes int64 = 50 * 1024 * 1024
	// DefaultAuthCacheTTL caps how long an upstream-verified Bearer token hash remains cached for bundle HITs.
	DefaultAuthCacheTTL = 5 * time.Minute
	maxAuthCacheEntries = 4096
)

var (
	toolNameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	toolVersionRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}$`)
	toolArchRe    = regexp.MustCompile(`^(noarch|amd64|arm64|386)$`)
	hostIDRe      = regexp.MustCompile(`^[0-9a-fA-F-]{36}$`)
	sha256HexRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Options configures the DMZ Relay reverse proxy and bundle cache.
// Notice there is intentionally NO signing key field: the Relay never possesses Ed25519 private keys.
type Options struct {
	UpstreamURL    string
	CacheDir       string
	CACertPath     string
	ClientCertPath string
	ClientKeyPath  string
	Timeout        time.Duration
	MaxForwardSize int64
	MaxBundleSize  int64
	AuthCacheTTL   time.Duration
}

// Handler implements http.Handler for the HostGrid DMZ Relay Node.
type Handler struct {
	upstream       *url.URL
	client         *http.Client
	cacheDir       string
	maxForwardSize int64
	maxBundleSize  int64
	authCacheTTL   time.Duration
	mu             sync.RWMutex
	authMu         sync.RWMutex
	authCache      map[string]time.Time
}

// NewHandler constructs a hardened DMZ Relay HTTP handler enforcing TLS 1.3 upstream.
func NewHandler(opts Options) (*Handler, error) {
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, errors.New("upstream URL is required")
	}
	parsed, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil || parsed.Host == "" {
		return nil, errors.New("invalid upstream URL")
	}
	if parsed.Scheme != "https" && !isLoopbackHost(parsed.Hostname()) {
		return nil, errors.New("HTTPS is mandatory for non-loopback Control Plane upstream URLs")
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	if opts.CACertPath != "" {
		pemBytes, readErr := os.ReadFile(opts.CACertPath)
		if readErr != nil {
			return nil, fmt.Errorf("read upstream CA cert: %w", readErr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("failed to parse upstream CA PEM")
		}
		tlsCfg.RootCAs = pool
	}
	if (opts.ClientCertPath == "") != (opts.ClientKeyPath == "") {
		return nil, errors.New("both upstream client cert and key are required for mTLS")
	}
	if opts.ClientCertPath != "" {
		cert, certErr := tls.LoadX509KeyPair(opts.ClientCertPath, opts.ClientKeyPath)
		if certErr != nil {
			return nil, fmt.Errorf("load upstream mTLS keypair: %w", certErr)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	cacheDir := opts.CacheDir
	if cacheDir != "" {
		if mkErr := os.MkdirAll(cacheDir, 0o700); mkErr != nil {
			return nil, fmt.Errorf("create relay cache dir: %w", mkErr)
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	maxFwd := opts.MaxForwardSize
	if maxFwd <= 0 {
		maxFwd = DefaultMaxForwardBytes
	}
	maxBundle := opts.MaxBundleSize
	if maxBundle <= 0 {
		maxBundle = DefaultMaxBundleBytes
	}
	authTTL := opts.AuthCacheTTL
	if authTTL <= 0 {
		authTTL = DefaultAuthCacheTTL
	}

	var tr *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok && base != nil {
		tr = base.Clone()
	} else {
		tr = &http.Transport{}
	}
	tr.TLSClientConfig = tlsCfg

	return &Handler{
		upstream: parsed,
		client: &http.Client{
			Timeout:   timeout,
			Transport: tr,
		},
		cacheDir:       cacheDir,
		maxForwardSize: maxFwd,
		maxBundleSize:  maxBundle,
		authCacheTTL:   authTTL,
		authCache:      make(map[string]time.Time),
	}, nil
}

func isLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func hasUnsafePath(p string) bool {
	if strings.Contains(p, "..") || strings.Contains(p, "//") || strings.Contains(p, `\`) {
		return true
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return true
		}
	}
	return false
}

func extractBearerToken(headerVal string) (string, bool) {
	if !strings.HasPrefix(headerVal, "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(headerVal, "Bearer "))
	if tok == "" {
		return "", false
	}
	return tok, true
}

func authTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (h *Handler) isAuthVerified(token string) bool {
	key := authTokenHash(token)
	now := time.Now()
	h.authMu.RLock()
	exp, ok := h.authCache[key]
	h.authMu.RUnlock()
	if !ok {
		return false
	}
	if now.After(exp) {
		h.authMu.Lock()
		delete(h.authCache, key)
		h.authMu.Unlock()
		return false
	}
	return true
}

func (h *Handler) markAuthVerified(token string) {
	key := authTokenHash(token)
	now := time.Now()
	h.authMu.Lock()
	defer h.authMu.Unlock()
	if len(h.authCache) >= maxAuthCacheEntries {
		for k, exp := range h.authCache {
			if now.After(exp) {
				delete(h.authCache, k)
			}
		}
		if len(h.authCache) >= maxAuthCacheEntries {
			h.authCache = make(map[string]time.Time)
		}
	}
	h.authCache[key] = now.Add(h.authCacheTTL)
}

func (h *Handler) revokeAuth(token string) {
	key := authTokenHash(token)
	h.authMu.Lock()
	delete(h.authCache, key)
	h.authMu.Unlock()
}

// ServeHTTP enforces strict agent-only route allow-listing, bundle caching, and transparent forwarding.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if hasUnsafePath(r.URL.Path) || hasUnsafePath(r.URL.RawPath) {
		writeProblem(w, http.StatusForbidden, "Forbidden", "Path traversal or malformed path is not allowed.")
		return
	}

	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","role":"relay"}`))
		return
	}

	if tool, ver, action, ok := parseBundleRoute(r.URL.Path); ok && r.Method == http.MethodGet {
		h.handleBundleRequest(w, r, tool, ver, action)
		return
	}

	if isAllowedForwardRoute(r.Method, r.URL.Path) {
		h.forwardRequest(w, r)
		return
	}

	writeProblem(
		w,
		http.StatusForbidden,
		"Forbidden",
		"Endpoint is not permitted on DMZ Relay (agent protocol endpoints only).",
	)
}

func parseBundleRoute(path string) (tool, version, action string, ok bool) {
	trimmed := strings.TrimPrefix(path, "/api/v1/bundles/")
	if trimmed == path {
		return "", "", "", false
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 {
		return "", "", "", false
	}
	tool, version, action = parts[0], parts[1], parts[2]
	if !toolNameRe.MatchString(tool) || !toolVersionRe.MatchString(version) {
		return "", "", "", false
	}
	if action != "manifest" && action != "download" {
		return "", "", "", false
	}
	return tool, version, action, true
}

func isAllowedForwardRoute(method, path string) bool {
	if method == http.MethodPost && (path == "/api/v1/enrollments/register" || path == "/api/v1/snapshots") {
		return true
	}
	trimmed := strings.TrimPrefix(path, "/api/v1/agents/")
	if trimmed == path {
		return false
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 || !hostIDRe.MatchString(parts[0]) {
		return false
	}
	if len(parts) == 2 && method == http.MethodPost && parts[1] == "heartbeat" {
		return true
	}
	if len(parts) == 2 && method == http.MethodGet && parts[1] == "patch-jobs" {
		return true
	}
	if len(parts) == 4 && method == http.MethodPost && parts[1] == "patch-jobs" && hostIDRe.MatchString(parts[2]) && parts[3] == "result" {
		return true
	}
	return false
}

func (h *Handler) handleBundleRequest(w http.ResponseWriter, r *http.Request, tool, version, action string) {
	token, hasToken := extractBearerToken(r.Header.Get("Authorization"))
	if !hasToken {
		writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Missing or empty agent Bearer token.")
		return
	}

	archParams := r.URL.Query()["arch"]
	if len(archParams) > 1 {
		writeProblem(w, http.StatusBadRequest, "Bad Request", "Duplicate arch query parameters are not permitted.")
		return
	}
	arch := ""
	if len(archParams) == 1 {
		arch = strings.TrimSpace(archParams[0])
	}
	if arch != "" && !toolArchRe.MatchString(arch) {
		writeProblem(w, http.StatusBadRequest, "Bad Request", "Invalid arch query parameter.")
		return
	}

	cacheable := h.cacheDir != "" && version != "latest"
	cacheKey := fmt.Sprintf("%s__%s.%s", tool, version, action)
	if arch != "" {
		cacheKey = fmt.Sprintf("%s__%s__%s.%s", tool, version, arch, action)
	}
	cachePath := filepath.Join(h.cacheDir, cacheKey)
	shaPath := cachePath + ".sha256"

	// Only serve cached bundles to callers whose Bearer token was recently verified by the Control Plane.
	if cacheable && h.isAuthVerified(token) {
		if data, digest, hit := h.readCachedBundle(cachePath, shaPath); hit {
			h.writeBundleResponse(w, action, data, digest, "HIT")
			return
		}
	}

	upstreamTarget := h.upstream.String() + r.URL.Path
	if arch != "" {
		upstreamTarget += "?arch=" + url.QueryEscape(arch)
	}
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstreamTarget, nil)
	if err != nil {
		writeProblem(w, http.StatusBadGateway, "Bad Gateway", "Failed to build upstream bundle request.")
		return
	}
	copyAgentHeaders(upReq.Header, r.Header)

	resp, err := h.client.Do(upReq)
	if err != nil {
		writeProblem(w, http.StatusBadGateway, "Bad Gateway", "Upstream Control Plane unreachable.")
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, h.maxBundleSize+1))
	if err != nil {
		writeProblem(w, http.StatusBadGateway, "Bad Gateway", "Failed reading upstream bundle stream.")
		return
	}
	if int64(len(body)) > h.maxBundleSize {
		writeProblem(w, http.StatusBadGateway, "Bad Gateway", "Upstream bundle exceeds relay size limit.")
		return
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			h.revokeAuth(token)
		}
		copyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		return
	}

	h.markAuthVerified(token)

	expectedSHA := strings.ToLower(strings.TrimSpace(resp.Header.Get("X-HostGrid-SHA256")))
	sum := sha256.Sum256(body)
	actualSHA := hex.EncodeToString(sum[:])

	if action == "download" && expectedSHA != "" {
		if !sha256HexRe.MatchString(expectedSHA) || expectedSHA != actualSHA {
			writeProblem(w, http.StatusBadGateway, "Integrity Error", "Upstream bundle SHA-256 mismatch.")
			return
		}
	}

	if cacheable {
		_ = h.writeCachedBundle(cachePath, shaPath, body, actualSHA)
	}
	h.writeBundleResponse(w, action, body, actualSHA, "MISS")
}

func (h *Handler) readCachedBundle(cachePath, shaPath string) ([]byte, string, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, "", false
	}
	digestBytes, err := os.ReadFile(shaPath)
	if err != nil {
		return nil, "", false
	}
	expected := strings.TrimSpace(string(digestBytes))
	sum := sha256.Sum256(data)
	if !sha256HexRe.MatchString(expected) || hex.EncodeToString(sum[:]) != expected {
		return nil, "", false
	}
	return data, expected, true
}

func writeAtomicFile(dir, destPath string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".relay-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, destPath); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func (h *Handler) writeCachedBundle(cachePath, shaPath string, data []byte, digest string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if err := writeAtomicFile(h.cacheDir, cachePath, data); err != nil {
		return err
	}
	return writeAtomicFile(h.cacheDir, shaPath, []byte(digest+"\n"))
}

func (h *Handler) writeBundleResponse(w http.ResponseWriter, action string, data []byte, digest, cacheStatus string) {
	w.Header().Set("X-HostGrid-Relay-Cache", cacheStatus)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if action == "manifest" {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("X-HostGrid-SHA256", digest)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *Handler) forwardRequest(w http.ResponseWriter, r *http.Request) {
	var bodyReader io.Reader
	if r.Body != nil {
		defer r.Body.Close()
		payload, err := io.ReadAll(io.LimitReader(r.Body, h.maxForwardSize+1))
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "Bad Request", "Failed reading request payload.")
			return
		}
		if int64(len(payload)) > h.maxForwardSize {
			writeProblem(w, http.StatusRequestEntityTooLarge, "Payload Too Large", "Request exceeds relay forward limit.")
			return
		}
		if len(payload) > 0 {
			bodyReader = bytes.NewReader(payload)
		}
	}

	target := h.upstream.String() + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, target, bodyReader)
	if err != nil {
		writeProblem(w, http.StatusBadGateway, "Bad Gateway", "Failed building upstream request.")
		return
	}
	copyAgentHeaders(upReq.Header, r.Header)
	if ct := r.Header.Get("Content-Type"); ct != "" {
		upReq.Header.Set("Content-Type", ct)
	}

	resp, err := h.client.Do(upReq)
	if err != nil {
		writeProblem(w, http.StatusBadGateway, "Bad Gateway", "Upstream Control Plane unreachable.")
		return
	}
	defer resp.Body.Close()

	if tok, ok := extractBearerToken(r.Header.Get("Authorization")); ok {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			h.markAuthVerified(tok)
		} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			h.revokeAuth(tok)
		}
	}

	copyResponseHeaders(w.Header(), resp.Header)
	w.Header().Set("X-HostGrid-Relay", "1")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, h.maxForwardSize))
}

func copyAgentHeaders(dst, src http.Header) {
	for _, key := range []string{"Authorization", "Idempotency-Key", "User-Agent", "X-HostGrid-Protocol-Version"} {
		if val := src.Get(key); val != "" {
			dst.Set(key, val)
		}
	}
}

func copyResponseHeaders(dst, src http.Header) {
	for _, key := range []string{"Content-Type", "X-HostGrid-SHA256", "Content-Disposition"} {
		if val := src.Get(key); val != "" {
			dst.Set(key, val)
		}
	}
}

func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "urn:hostgrid:error:relay",
		"title":  title,
		"status": status,
		"detail": detail,
	})
}
