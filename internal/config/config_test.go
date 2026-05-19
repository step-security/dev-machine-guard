package config

import (
	"bytes"
	"encoding/json"
	"os"
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
	// Use a temp directory
	tmpDir := t.TempDir()
	origConfigDir := configDir
	// Override configDir for test
	tmpConfigPath := filepath.Join(tmpDir, "config.json")

	cfg := &ConfigFile{
		CustomerID:         "test-customer",
		APIEndpoint:        "https://api.example.com",
		APIKey:             "sk-test-key",
		ScanFrequencyHours: "4",
		SearchDirs:         []string{"/tmp", "/opt/code"},
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpConfigPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// Read it back
	readData, err := os.ReadFile(tmpConfigPath)
	if err != nil {
		t.Fatal(err)
	}

	var loaded ConfigFile
	if err := json.Unmarshal(readData, &loaded); err != nil {
		t.Fatal(err)
	}

	if loaded.CustomerID != "test-customer" {
		t.Errorf("customer_id: expected test-customer, got %s", loaded.CustomerID)
	}
	if loaded.APIKey != "sk-test-key" {
		t.Errorf("api_key: expected sk-test-key, got %s", loaded.APIKey)
	}
	if len(loaded.SearchDirs) != 2 {
		t.Errorf("search_dirs: expected 2 dirs, got %d", len(loaded.SearchDirs))
	}

	_ = origConfigDir
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

func TestConfigFile_LogFile_JSONRoundTrip(t *testing.T) {
	in := ConfigFile{LogFile: "/var/log/dmg.log"}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"log_file":"/var/log/dmg.log"`)) {
		t.Errorf("log_file not serialized: %s", data)
	}

	var out ConfigFile
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.LogFile != "/var/log/dmg.log" {
		t.Errorf("LogFile round-trip = %q, want /var/log/dmg.log", out.LogFile)
	}

	// Empty LogFile is omitted from JSON (omitempty).
	empty := ConfigFile{}
	data, err = json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("log_file")) {
		t.Errorf("empty log_file should be omitted: %s", data)
	}
}
