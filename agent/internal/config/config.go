package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// AgentConfig holds persisted agent identity and server connection settings.
type AgentConfig struct {
	ServerURL            string `json:"server_url"`
	HostID               string `json:"host_id"`
	AgentCredential      string `json:"agent_credential"`
	BundleSigningPubKey  string `json:"bundle_signing_pubkey_b64"`
	ConnectivityMode     string `json:"connectivity_mode"`
	Environment          string `json:"environment"`
	CACertPath           string `json:"ca_cert_path,omitempty"`
	ClientCertPath       string `json:"client_cert_path,omitempty"`
	ClientKeyPath        string `json:"client_key_path,omitempty"`
	ProxyURL             string `json:"proxy_url,omitempty"`
	ToolsDir             string `json:"tools_dir"`
	HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
	ScanIntervalSec      int    `json:"scan_interval_sec"`
}

const (
	DefaultConfigPath = "/etc/hostgrid/agent.json"
	DefaultToolsDir   = "/opt/hostgrid/tools"
)

// Load reads and parses AgentConfig from disk.
func Load(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg AgentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.ToolsDir == "" {
		cfg.ToolsDir = DefaultToolsDir
	}
	if cfg.HeartbeatIntervalSec <= 0 {
		cfg.HeartbeatIntervalSec = 300
	}
	if cfg.ScanIntervalSec <= 0 {
		cfg.ScanIntervalSec = 3600
	}
	if cfg.ConnectivityMode == "" {
		cfg.ConnectivityMode = "lan"
	}
	if cfg.Environment == "" {
		cfg.Environment = "prod"
	}
	return &cfg, nil
}

// Save writes AgentConfig atomically with strict 0600 permissions.
func Save(path string, cfg *AgentConfig) error {
	if cfg == nil {
		return errors.New("config cannot be nil")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory %s: %w", dir, err)
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	raw = append(raw, '\n')

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return fmt.Errorf("write temp config %s: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod config %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename config %s: %w", path, err)
	}
	return nil
}
