package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withHome redirects HOME (and USERPROFILE on Windows) so save/load operate
// on a clean per-test directory. readConfigDir / writeConfigDir fall back
// to userConfigDir when no machine-wide config exists, which is exactly
// the path this exercises on non-root test runs.
func withHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir) // Windows
	return dir
}

func TestRunConfigureNonInteractive_RequiresAPIKey(t *testing.T) {
	withHome(t)
	err := RunConfigureNonInteractive(NonInteractiveOptions{
		CustomerID:  "cust-1",
		APIEndpoint: "https://api.example.com",
	})
	if err == nil || !strings.Contains(err.Error(), "api_key is required") {
		t.Fatalf("expected api_key required error, got %v", err)
	}
}

func TestRunConfigureNonInteractive_RequiresCustomerID(t *testing.T) {
	withHome(t)
	err := RunConfigureNonInteractive(NonInteractiveOptions{
		APIKey:      "sk-1",
		APIEndpoint: "https://api.example.com",
	})
	if err == nil || !strings.Contains(err.Error(), "customer_id is required") {
		t.Fatalf("expected customer_id required error, got %v", err)
	}
}

func TestRunConfigureNonInteractive_RequiresAPIEndpoint(t *testing.T) {
	withHome(t)
	err := RunConfigureNonInteractive(NonInteractiveOptions{
		APIKey:     "sk-1",
		CustomerID: "cust-1",
	})
	if err == nil || !strings.Contains(err.Error(), "api_endpoint is required") {
		t.Fatalf("expected api_endpoint required error, got %v", err)
	}
}

func TestRunConfigureNonInteractive_Inline(t *testing.T) {
	withHome(t)
	err := RunConfigureNonInteractive(NonInteractiveOptions{
		CustomerID:    "cust-1",
		APIEndpoint:   "https://api.example.com",
		APIKey:        "sk-abcdef",
		ScanFrequency: "6",
		SearchDirs:    []string{"/opt", "/usr/local"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg := loadExisting()
	if cfg.CustomerID != "cust-1" {
		t.Errorf("CustomerID: got %q", cfg.CustomerID)
	}
	if cfg.APIKey != "sk-abcdef" {
		t.Errorf("APIKey: got %q", cfg.APIKey)
	}
	if cfg.ScanFrequencyHours != "6" {
		t.Errorf("ScanFrequencyHours: got %q", cfg.ScanFrequencyHours)
	}
	if len(cfg.SearchDirs) != 2 || cfg.SearchDirs[0] != "/opt" {
		t.Errorf("SearchDirs: got %v", cfg.SearchDirs)
	}
}

func TestRunConfigureNonInteractive_FromFile(t *testing.T) {
	withHome(t)
	src := &ConfigFile{
		CustomerID:         "from-file-cust",
		APIEndpoint:        "https://from-file.example.com",
		APIKey:             "sk-from-file",
		ScanFrequencyHours: "12",
		SearchDirs:         []string{"/from-file"},
	}
	srcPath := filepath.Join(t.TempDir(), "bootstrap.json")
	data, _ := json.Marshal(src)
	if err := os.WriteFile(srcPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	err := RunConfigureNonInteractive(NonInteractiveOptions{FromFile: srcPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg := loadExisting()
	if cfg.CustomerID != "from-file-cust" || cfg.APIKey != "sk-from-file" {
		t.Errorf("from-file values not applied: %+v", cfg)
	}
}

func TestRunConfigureNonInteractive_InlineOverridesFromFile(t *testing.T) {
	withHome(t)
	src := &ConfigFile{
		CustomerID:  "from-file-cust",
		APIEndpoint: "https://from-file.example.com",
		APIKey:      "sk-old",
	}
	srcPath := filepath.Join(t.TempDir(), "bootstrap.json")
	data, _ := json.Marshal(src)
	if err := os.WriteFile(srcPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// Inline --api-key should win over the file's value (this is how
	// customers inject per-tenant keys without committing them).
	err := RunConfigureNonInteractive(NonInteractiveOptions{
		FromFile: srcPath,
		APIKey:   "sk-inline-wins",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg := loadExisting()
	if cfg.APIKey != "sk-inline-wins" {
		t.Errorf("inline APIKey should override file: got %q", cfg.APIKey)
	}
	if cfg.CustomerID != "from-file-cust" {
		t.Errorf("non-overridden file value lost: got %q", cfg.CustomerID)
	}
}

func TestNonInteractiveOptions_HasAny(t *testing.T) {
	if (NonInteractiveOptions{}).HasAny() {
		t.Error("empty opts should not report HasAny")
	}
	if !(NonInteractiveOptions{APIKey: "x"}).HasAny() {
		t.Error("APIKey alone should be enough")
	}
	if !(NonInteractiveOptions{FromFile: "p"}).HasAny() {
		t.Error("FromFile alone should be enough")
	}
}
