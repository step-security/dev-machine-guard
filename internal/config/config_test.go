package config

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestIsEnterpriseMode_Placeholder(t *testing.T) {
	APIKey = "{{API_KEY}}"
	if IsEnterpriseMode() {
		t.Error("placeholder should not be enterprise mode")
	}
}

func TestIsEnterpriseMode_Empty(t *testing.T) {
	APIKey = ""
	if IsEnterpriseMode() {
		t.Error("empty should not be enterprise mode")
	}
}

func TestIsEnterpriseMode_Valid(t *testing.T) {
	APIKey = "sk-test-123456"
	defer func() { APIKey = "{{API_KEY}}" }()
	if !IsEnterpriseMode() {
		t.Error("valid API key should be enterprise mode")
	}
}

func TestIsPlaceholder(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"{{API_KEY}}", true},
		{"{{CUSTOMER_ID}}", true},
		{"real-value", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isPlaceholder(tt.input); got != tt.want {
			t.Errorf("isPlaceholder(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestSaveAndLoad(t *testing.T) {
	// Drives the actual save()/Load() round-trip by pointing $HOME at a
	// temp dir, so LegacyDir() / ConfigFilePath() resolve into the test
	// sandbox. Verifies the on-disk JSON layout matches the in-memory
	// package vars after a Load, plus omitempty behaviour for absent
	// fields. Avoids machine-wide / elevation paths — those are covered
	// in config_nonint_test.go's Windows-specific tests.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	// On Windows, os.UserHomeDir() also checks USERPROFILE; keep them in
	// sync so the test runs cross-platform.
	t.Setenv("USERPROFILE", tmpHome)

	want := &ConfigFile{
		CustomerID:         "test-customer",
		APIEndpoint:        "https://api.example.com",
		APIKey:             "sk-test-key",
		ScanFrequencyHours: "4",
		SearchDirs:         []string{"/tmp", "/opt/code"},
		InstallDir:         "/opt/stepsecurity",
	}
	if err := save(want); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := ConfigFilePath(); got != filepath.Join(tmpHome, ".stepsecurity", "config.json") {
		t.Errorf("ConfigFilePath = %q, want under %s", got, tmpHome)
	}

	// Reset package-level vars to placeholders so Load actually populates
	// them (Load is intentionally idempotent — only sets unset values).
	prev := struct {
		CustomerID, APIKey, InstallDir string
		SearchDirs                     []string
	}{CustomerID, APIKey, InstallDir, SearchDirs}
	CustomerID = "{{CUSTOMER_ID}}"
	APIKey = "{{API_KEY}}"
	InstallDir = ""
	SearchDirs = nil
	t.Cleanup(func() {
		CustomerID = prev.CustomerID
		APIKey = prev.APIKey
		InstallDir = prev.InstallDir
		SearchDirs = prev.SearchDirs
	})

	Load()

	if CustomerID != "test-customer" {
		t.Errorf("CustomerID after Load = %q, want test-customer", CustomerID)
	}
	if APIKey != "sk-test-key" {
		t.Errorf("APIKey after Load = %q, want sk-test-key", APIKey)
	}
	if InstallDir != "/opt/stepsecurity" {
		t.Errorf("InstallDir after Load = %q, want /opt/stepsecurity", InstallDir)
	}
	if len(SearchDirs) != 2 || SearchDirs[0] != "/tmp" || SearchDirs[1] != "/opt/code" {
		t.Errorf("SearchDirs after Load = %v, want [/tmp /opt/code]", SearchDirs)
	}
}

func TestConfigFile_JSON(t *testing.T) {
	cfg := ConfigFile{
		CustomerID: "cust-123",
		APIKey:     "key-456",
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	if parsed["customer_id"] != "cust-123" {
		t.Error("customer_id not serialized correctly")
	}
	// Empty fields should be omitted
	if _, ok := parsed["api_endpoint"]; ok {
		t.Error("empty api_endpoint should be omitted")
	}
}

func TestConfigFile_InstallDir_JSONRoundTrip(t *testing.T) {
	in := ConfigFile{InstallDir: "/opt/stepsecurity"}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"install_dir":"/opt/stepsecurity"`)) {
		t.Errorf("install_dir not serialized: %s", data)
	}

	var out ConfigFile
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.InstallDir != "/opt/stepsecurity" {
		t.Errorf("InstallDir round-trip = %q, want /opt/stepsecurity", out.InstallDir)
	}

	// Empty InstallDir is omitted from JSON (omitempty).
	empty := ConfigFile{}
	data, err = json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("install_dir")) {
		t.Errorf("empty install_dir should be omitted: %s", data)
	}
}
