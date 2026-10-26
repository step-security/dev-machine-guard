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

func TestRunConfigureNonInteractive_DeviceIDAndRetireFlags(t *testing.T) {
	withHome(t)
	retire := true
	err := RunConfigureNonInteractive(NonInteractiveOptions{
		CustomerID:        "cust-1",
		APIEndpoint:       "https://api.example.com",
		APIKey:            "sk-abcdef",
		DeviceID:          " {hostname}-{user} ",
		RetireOnUninstall: &retire,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg := loadExisting()
	if cfg.DeviceID != "{hostname}-{user}" {
		t.Errorf("DeviceID: got %q", cfg.DeviceID)
	}
	if cfg.RetireOnUninstall == nil || !*cfg.RetireOnUninstall {
		t.Errorf("RetireOnUninstall: got %v", cfg.RetireOnUninstall)
	}
	raw, _ := os.ReadFile(filepath.Join(withHomeDir(t), ".stepsecurity", "config.json"))
	for _, want := range []string{`"device_id": "{hostname}-{user}"`, `"retire_on_uninstall": true`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("config.json missing %s:\n%s", want, raw)
		}
	}

	// Omitted = unchanged; "-" clears the template; false drops the retire key.
	off := false
	if err := RunConfigureNonInteractive(NonInteractiveOptions{APIKey: "sk-2", RetireOnUninstall: &off}); err != nil {
		t.Fatalf("second configure: %v", err)
	}
	cfg = loadExisting()
	if cfg.DeviceID != "{hostname}-{user}" {
		t.Errorf("omitted --device-id must keep the template, got %q", cfg.DeviceID)
	}
	if cfg.RetireOnUninstall != nil {
		t.Errorf("retire_on_uninstall=false must be omitted from the file, got %v", *cfg.RetireOnUninstall)
	}
	if err := RunConfigureNonInteractive(NonInteractiveOptions{DeviceID: "-"}); err != nil {
		t.Fatalf("third configure: %v", err)
	}
	if cfg = loadExisting(); cfg.DeviceID != "" {
		t.Errorf("\"-\" must clear the template, got %q", cfg.DeviceID)
	}
}

// withHomeDir returns the HOME withHome set (HOME is read back rather than
// threaded through so the helper's signature stays the same).
func withHomeDir(t *testing.T) string {
	t.Helper()
	return os.Getenv("HOME")
}

func TestHasAny_DeviceIDAndRetire(t *testing.T) {
	if (NonInteractiveOptions{}).HasAny() {
		t.Fatal("empty options report HasAny")
	}
	if !(NonInteractiveOptions{DeviceID: "x"}).HasAny() {
		t.Fatal("DeviceID alone must count as an inline value")
	}
	v := false
	if !(NonInteractiveOptions{RetireOnUninstall: &v}).HasAny() {
		t.Fatal("RetireOnUninstall alone must count as an inline value")
	}
}

func TestLoad_DeviceIDAndRetireOnUninstall(t *testing.T) {
	dir := withHome(t)
	cfgDir := filepath.Join(dir, ".stepsecurity")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	content := `{"customer_id":"c","api_endpoint":"https://e","api_key":"k","device_id":" {hostname}-{user} ","retire_on_uninstall":true}`
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	prevID, prevRetire := DeviceID, RetireOnUninstall
	prevCust, prevEnd, prevKey := CustomerID, APIEndpoint, APIKey
	DeviceID, RetireOnUninstall = "", false
	t.Cleanup(func() {
		DeviceID, RetireOnUninstall = prevID, prevRetire
		CustomerID, APIEndpoint, APIKey = prevCust, prevEnd, prevKey
	})
	Load()
	if DeviceID != "{hostname}-{user}" {
		t.Fatalf("DeviceID = %q", DeviceID)
	}
	if !RetireOnUninstall {
		t.Fatal("RetireOnUninstall not applied")
	}
	// An already-set (build-time) template wins over the file.
	DeviceID = "pinned"
	Load()
	if DeviceID != "pinned" {
		t.Fatalf("Load overrode an in-memory template: %q", DeviceID)
	}
}

func TestShowConfigure_PrintsDeviceIdentity(t *testing.T) {
	withHome(t)
	retire := true
	if err := RunConfigureNonInteractive(NonInteractiveOptions{
		CustomerID: "c", APIEndpoint: "https://e", APIKey: "sk-abcdef",
		DeviceID: "{hostname}", RetireOnUninstall: &retire,
	}); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() { ShowConfigure("avd-host-07 (source: config)") })
	for _, want := range []string{
		"Device ID:               {hostname}",
		"resolves now to:       avd-host-07 (source: config)",
		"Retire On Uninstall:     true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("configure show missing %q:\n%s", want, out)
		}
	}
	out = captureStdout(t, func() { ShowConfigure("") })
	if strings.Contains(out, "resolves now to") {
		t.Errorf("empty resolved line must be omitted:\n%s", out)
	}
	if err := RunConfigureNonInteractive(NonInteractiveOptions{DeviceID: "-"}); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() { ShowConfigure("") })
	if !strings.Contains(out, "auto (per-user on multi-session hosts, hardware serial elsewhere)") {
		t.Errorf("default identity label missing:\n%s", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- b.String()
	}()
	fn()
	os.Stdout = prev
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
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
