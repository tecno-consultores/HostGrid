package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tecno-consultores/HostGrid/agent/internal/collectors"
	"github.com/tecno-consultores/HostGrid/agent/internal/probe"
	"github.com/tecno-consultores/HostGrid/agent/internal/tools"
)

// SnapshotPayload matches SPEC.md section 4.5 snapshot ingestion payload.
type SnapshotPayload struct {
	HostID           string                    `json:"host_id,omitempty"`
	Hostname         string                    `json:"hostname,omitempty"`
	MachineIDHash    string                    `json:"machine_id_hash,omitempty"`
	Environment      string                    `json:"environment,omitempty"`
	CollectedAt      string                    `json:"collected_at"`
	AgentVersion     string                    `json:"agent_version"`
	ConnectivityMode string                    `json:"connectivity_mode"`
	Probe            probe.ProbeResult         `json:"probe"`
	Packages         []collectors.PackageItem  `json:"packages"`
	Network          collectors.NetworkPayload `json:"network"`
	Services         []collectors.ServiceItem  `json:"services"`
	Sysctl           map[string]string         `json:"sysctl"`
	Repos            collectors.ReposPayload   `json:"repos"`
	Lynis            tools.LynisPayload        `json:"lynis"`
}

// EnrollRequest matches SPEC.md section 4.2.
type EnrollRequest struct {
	EnrollmentToken  string `json:"enrollment_token"`
	Hostname         string `json:"hostname"`
	MachineIDHash    string `json:"machine_id_hash"`
	OSFamily         string `json:"os_family"`
	OSName           string `json:"os_name"`
	OSVersion        string `json:"os_version"`
	KernelVersion    string `json:"kernel_version"`
	Arch             string `json:"arch"`
	InitSystem       string `json:"init_system"`
	ConnectivityMode string `json:"connectivity_mode"`
	Environment      string `json:"environment,omitempty"`
}

// EnrollResponse matches SPEC.md section 4.2.
type EnrollResponse struct {
	HostID               string `json:"host_id"`
	AgentCredential      string `json:"agent_credential"`
	BundleSigningPubKey  string `json:"bundle_signing_pubkey_b64"`
	HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
	ScanIntervalSec      int    `json:"scan_interval_sec"`
}

// HeartbeatRequest matches SPEC.md section 4.3.
type HeartbeatRequest struct {
	AgentVersion string `json:"agent_version"`
	LynisVersion string `json:"lynis_version,omitempty"`
	UptimeSec    int64  `json:"uptime_sec"`
	LastScanAt   string `json:"last_scan_at,omitempty"`
	RepoAccessOK *bool  `json:"repo_access_ok,omitempty"`
}

// PatchJob represents a pull-based dry-run or wave apply job returned by the Control Plane (Phase 3).
type PatchJob struct {
	PlanID            string   `json:"plan_id"`
	Title             string   `json:"title"`
	Mode              string   `json:"mode"`
	WaveNumber        *int     `json:"wave_number,omitempty"`
	Packages          []string `json:"packages"`
	SafeModeEnabled   bool     `json:"safe_mode_enabled"`
	RollbackOnFailure bool     `json:"rollback_on_failure"`
}

// PatchJobResult reports an agent's dry-run or Safe Mode wave execution outcome back to the Control Plane.
type PatchJobResult struct {
	Mode                string   `json:"mode"`
	Status              string   `json:"status"`
	Succeeded           bool     `json:"succeeded"`
	RepoVerified        bool     `json:"repo_verified"`
	PlannedChangesCount int      `json:"planned_changes_count"`
	HealthyAfterPatch   *bool    `json:"healthy_after_patch,omitempty"`
	RolledBack          bool     `json:"rolled_back"`
	Detail              string   `json:"detail,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
}

// Client performs outbound-only pull HTTPS/TLS 1.3 communication with the Control Plane or Relay.
type Client struct {
	BaseURL      string
	Credential   string
	AgentVersion string
	HTTPClient   *http.Client
}

// ClientOptions configures TLS 1.3, custom CA pinning, optional mTLS client certs, and proxy/relay routing.
type ClientOptions struct {
	ServerURL      string
	Credential     string
	AgentVersion   string
	CACertPath     string
	ClientCertPath string
	ClientKeyPath  string
	ProxyURL       string
	Timeout        time.Duration
}

// NewClient constructs a hardened outbound-only HTTP/HTTPS client enforcing TLS 1.3.
func NewClient(opts ClientOptions) (*Client, error) {
	if hasASCIIControlChar(opts.ServerURL) {
		return nil, errors.New("invalid server URL: control characters are not allowed")
	}
	parsedURL, err := url.Parse(strings.TrimRight(opts.ServerURL, "/"))
	if err != nil || parsedURL.Host == "" {
		return nil, errors.New("invalid server URL")
	}
	if parsedURL.Scheme != "https" && !isLoopbackHost(parsedURL.Hostname()) {
		return nil, errors.New("HTTPS is mandatory for non-loopback control plane URLs")
	}

	proxyFunc := http.ProxyFromEnvironment
	if opts.ProxyURL != "" {
		if hasASCIIControlChar(opts.ProxyURL) {
			return nil, errors.New("invalid proxy URL: control characters are not allowed")
		}
		if trimmedProxy := strings.Trim(opts.ProxyURL, " "); trimmedProxy != "" {
			parsedProxy, proxyErr := parseProxyURL(trimmedProxy)
			if proxyErr != nil {
				return nil, proxyErr
			}
			proxyFunc = http.ProxyURL(parsedProxy)
		}
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	if opts.CACertPath != "" {
		pemBytes, readErr := os.ReadFile(opts.CACertPath)
		if readErr != nil {
			return nil, fmt.Errorf("read CA cert: %w", readErr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("failed to parse CA certificate PEM")
		}
		tlsCfg.RootCAs = pool
	}
	if (opts.ClientCertPath == "") != (opts.ClientKeyPath == "") {
		return nil, errors.New("both client certificate and private key must be specified for mTLS")
	}
	if opts.ClientCertPath != "" && opts.ClientKeyPath != "" {
		cert, certErr := tls.LoadX509KeyPair(opts.ClientCertPath, opts.ClientKeyPath)
		if certErr != nil {
			return nil, fmt.Errorf("load mTLS client certificate: %w", certErr)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	var tr *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok && base != nil {
		tr = base.Clone()
	} else {
		tr = &http.Transport{}
	}
	tr.Proxy = proxyFunc
	tr.TLSClientConfig = tlsCfg

	return &Client{
		BaseURL:      strings.TrimRight(opts.ServerURL, "/"),
		Credential:   opts.Credential,
		AgentVersion: opts.AgentVersion,
		HTTPClient: &http.Client{
			Timeout:   timeout,
			Transport: tr,
		},
	}, nil
}

func hasASCIIControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func parseProxyURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid proxy URL: malformed URL syntax")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("unsupported proxy URL scheme (must be http or https)")
	}
	if parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return nil, errors.New("invalid proxy URL: host is required")
	}
	if portStr := parsed.Port(); portStr != "" {
		port, portErr := strconv.Atoi(portStr)
		if portErr != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid proxy URL: port must be between 1 and 65535")
		}
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid proxy URL: path, query, and fragment are not supported")
	}
	return parsed, nil
}

func isLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func (c *Client) doJSON(
	ctx context.Context,
	method, path string,
	reqBody any,
	respBody any,
	withAuth bool,
	idempotencyKey string,
) error {
	var bodyReader io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "hostgrid-agent/"+c.AgentVersion)
	req.Header.Set("X-HostGrid-Protocol-Version", "1")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if withAuth && c.Credential != "" {
		req.Header.Set("Authorization", "Bearer "+c.Credential)
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errPayload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(errPayload)))
	}
	if respBody != nil {
		return json.NewDecoder(resp.Body).Decode(respBody)
	}
	return nil
}

// Enroll registers the agent using a one-time enrollment token.
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	var out EnrollResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/enrollments/register", req, &out, false, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// Heartbeat reports agent liveness to the Control Plane.
func (c *Client) Heartbeat(ctx context.Context, hostID string, req HeartbeatRequest) error {
	return c.doJSON(ctx, http.MethodPost, "/api/v1/agents/"+url.PathEscape(hostID)+"/heartbeat", req, nil, true, "")
}

// FetchPatchJobs pulls pending governed dry-run or active-wave apply jobs for this host.
func (c *Client) FetchPatchJobs(ctx context.Context, hostID string) ([]PatchJob, error) {
	var jobs []PatchJob
	path := "/api/v1/agents/" + url.PathEscape(hostID) + "/patch-jobs"
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &jobs, true, ""); err != nil {
		return nil, err
	}
	return jobs, nil
}

// ReportPatchJobResult posts a dry-run or wave execution outcome back to the Control Plane.
func (c *Client) ReportPatchJobResult(ctx context.Context, hostID, planID string, res PatchJobResult) error {
	path := "/api/v1/agents/" + url.PathEscape(hostID) + "/patch-jobs/" + url.PathEscape(planID) + "/result"
	return c.doJSON(ctx, http.MethodPost, path, res, nil, true, "")
}

// SendSnapshot pushes a collected snapshot to /api/v1/snapshots with an Idempotency-Key header.
func (c *Client) SendSnapshot(ctx context.Context, snap SnapshotPayload) error {
	return c.doJSON(ctx, http.MethodPost, "/api/v1/snapshots", snap, nil, true, newUUIDv4())
}

// FetchToolManifest retrieves a signed tool bundle manifest (e.g., lynis/latest).
func (c *Client) FetchToolManifest(ctx context.Context, tool, version string) (*tools.ToolManifest, error) {
	var out tools.ToolManifest
	path := fmt.Sprintf("/api/v1/bundles/%s/%s/manifest", url.PathEscape(tool), url.PathEscape(version))
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &out, true, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// DownloadToolStream opens an authenticated stream for downloading a tool tarball.
func (c *Client) DownloadToolStream(ctx context.Context, downloadPath string) (io.ReadCloser, error) {
	if !strings.HasPrefix(downloadPath, "/api/v1/bundles/") ||
		strings.Contains(downloadPath, "..") ||
		strings.Contains(downloadPath, "://") {
		return nil, fmt.Errorf("disallowed tool bundle download path %q", downloadPath)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+downloadPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "hostgrid-agent/"+c.AgentVersion)
	req.Header.Set("X-HostGrid-Protocol-Version", "1")
	if c.Credential != "" {
		req.Header.Set("Authorization", "Bearer "+c.Credential)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("bundle download failed with HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}
