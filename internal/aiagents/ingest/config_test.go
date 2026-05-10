package ingest

import (
	"testing"

	"github.com/step-security/dev-machine-guard/internal/config"
)

// withConfig stages the DMG config globals for one test case and restores
// them on cleanup. The DMG config package is package-level mutable, so
// tests must restore-on-exit to stay independent.
func withConfig(t *testing.T, customerID, apiEndpoint, apiKey string) {
	t.Helper()
	prevCustomer, prevEndpoint, prevKey := config.CustomerID, config.APIEndpoint, config.APIKey
	t.Cleanup(func() {
		config.CustomerID = prevCustomer
		config.APIEndpoint = prevEndpoint
		config.APIKey = prevKey
	})
	config.CustomerID = customerID
	config.APIEndpoint = apiEndpoint
	config.APIKey = apiKey
}

func TestSnapshot_AllValid(t *testing.T) {
	withConfig(t, "cust-123", "https://api.stepsecurity.io", "sk_live_abc")

	cfg, ok := Snapshot()
	if !ok {
		t.Fatal("expected ok=true with all three fields populated")
	}
	if cfg.CustomerID != "cust-123" || cfg.APIEndpoint != "https://api.stepsecurity.io" || cfg.APIKey != "sk_live_abc" {
		t.Errorf("unexpected snapshot: %+v", cfg)
	}
}

func TestSnapshot_RejectsPlaceholders(t *testing.T) {
	cases := []struct {
		name, customer, endpoint, key string
	}{
		{"placeholder customer", "{{CUSTOMER_ID}}", "https://api.example.com", "sk_live_abc"},
		{"placeholder endpoint", "cust-123", "{{API_ENDPOINT}}", "sk_live_abc"},
		{"placeholder key", "cust-123", "https://api.example.com", "{{API_KEY}}"},
		{"all placeholders", "{{CUSTOMER_ID}}", "{{API_ENDPOINT}}", "{{API_KEY}}"},
		{"partial placeholder", "cust-123", "https://api.{{HOST}}.io", "sk_live_abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withConfig(t, tc.customer, tc.endpoint, tc.key)
			if _, ok := Snapshot(); ok {
				t.Errorf("expected ok=false on placeholder, got true")
			}
		})
	}
}

func TestSnapshot_RejectsEmpty(t *testing.T) {
	cases := []struct {
		name, customer, endpoint, key string
	}{
		{"empty customer", "", "https://api.example.com", "sk_live_abc"},
		{"empty endpoint", "cust-123", "", "sk_live_abc"},
		{"empty key", "cust-123", "https://api.example.com", ""},
		{"all empty", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withConfig(t, tc.customer, tc.endpoint, tc.key)
			if _, ok := Snapshot(); ok {
				t.Errorf("expected ok=false on empty field, got true")
			}
		})
	}
}

func TestSnapshot_RejectsWhitespaceOnly(t *testing.T) {
	withConfig(t, "   ", "\t\n", "  ")
	if _, ok := Snapshot(); ok {
		t.Error("expected ok=false on whitespace-only fields")
	}
}

func TestSnapshot_TrimsSurroundingWhitespace(t *testing.T) {
	withConfig(t, "  cust-123  ", "\thttps://api.example.com\n", " sk_live_abc ")
	cfg, ok := Snapshot()
	if !ok {
		t.Fatal("expected ok=true after trimming")
	}
	if cfg.CustomerID != "cust-123" || cfg.APIEndpoint != "https://api.example.com" || cfg.APIKey != "sk_live_abc" {
		t.Errorf("expected trimmed values, got %+v", cfg)
	}
}

func TestSnapshot_AcceptsSingleBrace(t *testing.T) {
	// The placeholder marker is `{{` (double brace) per the build-time
	// substitution scheme. A single `{` is a legitimate URL/token char
	// (e.g., a query template var) and must NOT trip the gate.
	withConfig(t, "cust-{abc}", "https://api.example.com/v1?ctx={ts}", "sk_live_abc")
	cfg, ok := Snapshot()
	if !ok {
		t.Fatal("expected ok=true; single-brace inputs should pass the placeholder gate")
	}
	if cfg.CustomerID != "cust-{abc}" {
		t.Errorf("single-brace value mutated: %q", cfg.CustomerID)
	}
}

func TestSnapshot_PopulatesEvenWhenInvalid(t *testing.T) {
	// Diagnostics need access to whatever the user did configure, even when
	// the gate refuses. Confirm Config is not zero-valued on the false path.
	withConfig(t, "cust-123", "", "sk_live_abc")
	cfg, ok := Snapshot()
	if ok {
		t.Fatal("expected ok=false (empty endpoint)")
	}
	if cfg.CustomerID != "cust-123" || cfg.APIKey != "sk_live_abc" {
		t.Errorf("expected populated diagnostic snapshot, got %+v", cfg)
	}
}

func TestSnapshot_EnvOverridesConfigFile(t *testing.T) {
	// The on-disk config has stale/MDM-restored values; env vars must
	// win at hook-invocation time so a developer can redirect uploads
	// without rewriting the file.
	withConfig(t, "file-cust", "https://file.example.com", "sk_file")
	t.Setenv(envCustomerID, "env-cust")
	t.Setenv(envAPIEndpoint, "https://env.example.com")
	t.Setenv(envAPIKey, "sk_env")

	cfg, ok := Snapshot()
	if !ok {
		t.Fatal("expected ok=true with env overrides set")
	}
	if cfg.CustomerID != "env-cust" || cfg.APIEndpoint != "https://env.example.com" || cfg.APIKey != "sk_env" {
		t.Errorf("env overrides not applied: %+v", cfg)
	}
}

func TestSnapshot_EnvOverridesAreIndependent(t *testing.T) {
	// Each env var is independently optional. With only DMG_API_ENDPOINT
	// set, customer_id and api_key must still come from the config file.
	withConfig(t, "file-cust", "https://file.example.com", "sk_file")
	t.Setenv(envAPIEndpoint, "https://env.example.com")

	cfg, ok := Snapshot()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if cfg.CustomerID != "file-cust" {
		t.Errorf("CustomerID should fall back to config: got %q", cfg.CustomerID)
	}
	if cfg.APIEndpoint != "https://env.example.com" {
		t.Errorf("APIEndpoint should come from env: got %q", cfg.APIEndpoint)
	}
	if cfg.APIKey != "sk_file" {
		t.Errorf("APIKey should fall back to config: got %q", cfg.APIKey)
	}
}

func TestSnapshot_EmptyEnvFallsBackToConfig(t *testing.T) {
	// `export DMG_API_ENDPOINT=` (empty) is a common mistake; treat it
	// as "not set" so we don't stealth-disable uploads.
	withConfig(t, "file-cust", "https://file.example.com", "sk_file")
	t.Setenv(envAPIEndpoint, "")

	cfg, ok := Snapshot()
	if !ok {
		t.Fatal("expected ok=true; empty env should fall back, not break gate")
	}
	if cfg.APIEndpoint != "https://file.example.com" {
		t.Errorf("expected fallback to config value, got %q", cfg.APIEndpoint)
	}
}

func TestSnapshot_EnvOverridesPlaceholderConfig(t *testing.T) {
	// Build-time placeholders normally fail the gate; env vars rescue
	// the install, which is exactly the local-dev scenario.
	withConfig(t, "{{CUSTOMER_ID}}", "{{API_ENDPOINT}}", "{{API_KEY}}")
	t.Setenv(envCustomerID, "env-cust")
	t.Setenv(envAPIEndpoint, "https://env.example.com")
	t.Setenv(envAPIKey, "sk_env")

	cfg, ok := Snapshot()
	if !ok {
		t.Fatal("expected ok=true; env vars should rescue placeholder config")
	}
	if cfg.CustomerID != "env-cust" || cfg.APIEndpoint != "https://env.example.com" || cfg.APIKey != "sk_env" {
		t.Errorf("env override over placeholders failed: %+v", cfg)
	}
}
