package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tecno-consultores/HostGrid/agent/internal/config"
)

func TestSaveAndLoadConfigEnforces0600Permissions(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "etc", "agent.json")
	input := &config.AgentConfig{
		ServerURL:           "https://control.internal:8443",
		HostID:              "550e8400-e29b-41d4-a716-446655440000",
		AgentCredential:     "hg_agent_test_cred_value",
		BundleSigningPubKey: "dGVzdC1wdWJrZXk=",
		ProxyURL:            "https://relay.dmz:8443",
	}
	if err := config.Save(cfgPath, input); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected file mode 0600, got %#o", perm)
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.HostID != input.HostID ||
		loaded.ToolsDir != config.DefaultToolsDir ||
		loaded.HeartbeatIntervalSec != 300 ||
		loaded.ProxyURL != input.ProxyURL {
		t.Fatalf("unexpected loaded config: %+v", loaded)
	}

	if err := config.Save(cfgPath, nil); err == nil {
		t.Fatal("expected error saving nil config")
	}
}
