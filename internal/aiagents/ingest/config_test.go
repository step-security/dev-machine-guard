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
