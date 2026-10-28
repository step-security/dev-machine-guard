package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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
		DeviceID:           "custom-from-file",
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
	if cfg.DeviceID != "custom-from-file" {
		t.Fatalf("DeviceID = %q", cfg.DeviceID)
	}
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

// SCCM e2e B1: an MSI upgrade's --from-file must merge into the machine
// config, not replace it: an AUTOUPDATE=0 opt-out and unknown keys the
// bootstrap file doesn't mention survive, while keys it does carry
// (credential rotation) win.
func TestRunConfigureNonInteractive_FromFileMerges(t *testing.T) {
	optOut := false
	withHome(t)
	if err := RunConfigureNonInteractive(NonInteractiveOptions{
		CustomerID: "cust", APIEndpoint: "https://old.example.com", APIKey: "sk-old",
		AutoUpdate: &optOut,
	}); err != nil {
		t.Fatal(err)
	}
	path := ConfigFilePath()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["future_key"] = map[string]any{"x": 1.0}
	raw, _ = json.Marshal(m)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	srcPath := filepath.Join(t.TempDir(), "bootstrap.json")
	if err := os.WriteFile(srcPath, []byte(`{"customer_id":"cust","api_endpoint":"https://new.example.com","api_key":"sk-rotated"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RunConfigureNonInteractive(NonInteractiveOptions{FromFile: srcPath}); err != nil {
		t.Fatal(err)
	}
	cfg := loadExisting()
	if cfg.AutoUpdate == nil || *cfg.AutoUpdate {
		t.Fatalf("auto_update opt-out lost: %v", cfg.AutoUpdate)
	}
	if cfg.APIKey != "sk-rotated" || cfg.APIEndpoint != "https://new.example.com" {
		t.Fatalf("bootstrap file keys not applied: %+v", cfg)
	}
	raw, _ = os.ReadFile(path)
	if !strings.Contains(string(raw), `"future_key"`) {
		t.Fatalf("unknown key dropped:\n%s", raw)
	}
}

// Every config.json setting must be settable non-interactively. A new
// ConfigFile field fails here until NonInteractiveOptions grows a matching
// field (and, per AGENTS.md §13, a `configure` CLI flag).
func TestNonInteractiveOptions_CoverEveryConfigKey(t *testing.T) {
	aliases := map[string]string{"ScanFrequencyHours": "ScanFrequency"}
	opts := reflect.TypeOf(NonInteractiveOptions{})
	cf := reflect.TypeOf(ConfigFile{})
	for i := range cf.NumField() {
		f := cf.Field(i)
		if !f.IsExported() {
			continue
		}
		name := f.Name
		if a, ok := aliases[name]; ok {
			name = a
		}
		if _, ok := opts.FieldByName(name); !ok {
			t.Errorf("config key %s (ConfigFile.%s) has no NonInteractiveOptions.%s", f.Tag.Get("json"), f.Name, name)
		}
	}
}

// Every NonInteractiveOptions field must reach config.json: fill them all
// and check no ConfigFile key is left empty.
func TestRunConfigureNonInteractive_AppliesEveryOption(t *testing.T) {
	withHome(t)
	var opts NonInteractiveOptions
	v := reflect.ValueOf(&opts).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		name := v.Type().Field(i).Name
		switch f.Kind() {
		case reflect.String:
			f.SetString("value-" + name)
		case reflect.Slice:
			f.Set(reflect.ValueOf([]string{"/dir-" + name}))
		case reflect.Pointer:
			p := reflect.New(f.Type().Elem())
			switch p.Elem().Kind() {
			case reflect.Bool:
				p.Elem().SetBool(true)
			case reflect.Int:
				p.Elem().SetInt(7)
			}
			f.Set(p)
		default:
			t.Fatalf("unhandled option kind %s for %s", f.Kind(), name)
		}
	}
	opts.FromFile = ""
	if err := RunConfigureNonInteractive(opts); err != nil {
		t.Fatal(err)
	}

	got := reflect.ValueOf(*loadExisting())
	for i := range got.NumField() {
		f := got.Type().Field(i)
		if f.IsExported() && got.Field(i).IsZero() {
			t.Errorf("option for %s was not persisted", f.Tag.Get("json"))
		}
	}
}

func TestRunConfigureNonInteractive_DefaultsStoredAsOmitted(t *testing.T) {
	withHome(t)
	base := NonInteractiveOptions{CustomerID: "c", APIEndpoint: "https://e", APIKey: "k"}
	base.ColorMode, base.OutputFormat = "never", "json"
	if err := RunConfigureNonInteractive(base); err != nil {
		t.Fatal(err)
	}
	base.ColorMode, base.OutputFormat = "auto", "pretty"
	if err := RunConfigureNonInteractive(base); err != nil {
		t.Fatal(err)
	}
	cfg := loadExisting()
	if cfg.ColorMode != "" || cfg.OutputFormat != "" {
		t.Errorf("defaults not cleared: color=%q format=%q", cfg.ColorMode, cfg.OutputFormat)
	}
}
