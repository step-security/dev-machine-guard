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
	// Elevated on Windows, save() writes the machine-wide config; never
	// clobber a real install's.
	if !strings.HasPrefix(WriteConfigFilePath(), dir) {
		t.Skip("config writes outside the temp HOME (elevated Windows)")
	}
	return dir
}

func TestRunConfigureNonInteractive_RequiresAPIKey(t *testing.T) {
	withHome(t)
	err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{
		"customer_id":  "cust-1",
		"api_endpoint": "https://api.example.com",
	}})
	if err == nil || !strings.Contains(err.Error(), "api_key is required") {
		t.Fatalf("expected api_key required error, got %v", err)
	}
}

func TestRunConfigureNonInteractive_RequiresCustomerID(t *testing.T) {
	withHome(t)
	err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{
		"api_key":      "sk-1",
		"api_endpoint": "https://api.example.com",
	}})
	if err == nil || !strings.Contains(err.Error(), "customer_id is required") {
		t.Fatalf("expected customer_id required error, got %v", err)
	}
}

func TestRunConfigureNonInteractive_RequiresAPIEndpoint(t *testing.T) {
	withHome(t)
	err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{
		"api_key":     "sk-1",
		"customer_id": "cust-1",
	}})
	if err == nil || !strings.Contains(err.Error(), "api_endpoint is required") {
		t.Fatalf("expected api_endpoint required error, got %v", err)
	}
}

func TestRunConfigureNonInteractive_Inline(t *testing.T) {
	withHome(t)
	err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{
		"customer_id":          "cust-1",
		"api_endpoint":         "https://api.example.com",
		"api_key":              "sk-abcdef",
		"scan_frequency_hours": "6",
		"search_dirs":          []string{"/opt", "/usr/local"},
	}})
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
		Values:   map[string]any{"api_key": "sk-inline-wins"},
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
	if !(NonInteractiveOptions{Values: map[string]any{"api_key": "x"}}).HasAny() {
		t.Error("one value alone should be enough")
	}
	if !(NonInteractiveOptions{FromFile: "p"}).HasAny() {
		t.Error("FromFile alone should be enough")
	}
}

func TestRunConfigureNonInteractive_DeviceIDAndRetireFlags(t *testing.T) {
	withHome(t)
	err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{
		"customer_id":         "cust-1",
		"api_endpoint":        "https://api.example.com",
		"api_key":             "sk-abcdef",
		"device_id":           " {hostname}-vdi ",
		"retire_on_uninstall": true,
	}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg := loadExisting()
	if cfg.DeviceID != "{hostname}-vdi" {
		t.Errorf("DeviceID: got %q", cfg.DeviceID)
	}
	if cfg.RetireOnUninstall == nil || !*cfg.RetireOnUninstall {
		t.Errorf("RetireOnUninstall: got %v", cfg.RetireOnUninstall)
	}
	raw, _ := os.ReadFile(filepath.Join(withHomeDir(t), ".stepsecurity", "config.json"))
	for _, want := range []string{`"device_id": "{hostname}-vdi"`, `"retire_on_uninstall": true`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("config.json missing %s:\n%s", want, raw)
		}
	}

	// Omitted = unchanged; false (saved as null by the flag) drops the retire
	// key; "-" clears the template (an explicit empty id is rejected).
	if err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{"api_key": "sk-2", "retire_on_uninstall": nil}}); err != nil {
		t.Fatalf("second configure: %v", err)
	}
	cfg = loadExisting()
	if cfg.DeviceID != "{hostname}-vdi" {
		t.Errorf("omitted --device-id must keep the template, got %q", cfg.DeviceID)
	}
	if cfg.RetireOnUninstall != nil {
		t.Errorf("retire_on_uninstall=false must be omitted from the file, got %v", *cfg.RetireOnUninstall)
	}
	if err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{"device_id": ""}}); err == nil {
		t.Error("an explicit empty device_id must be rejected")
	}
	if err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{"device_id": "-"}}); err != nil {
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

func TestValidDeviceTag(t *testing.T) {
	cases := []struct {
		tag  string
		want bool
	}{
		{"avd-pool-eu", true},
		{"pool_1.b:c/d", true},
		{"a", true},
		{strings.Repeat("x", 64), true},
		{"", false},
		{strings.Repeat("x", 65), false},
		{"avd pool", false},
		{"pool#1", false},
		{"caf\u00e9", false},
	}
	for _, tc := range cases {
		if got := ValidDeviceTag(tc.tag); got != tc.want {
			t.Errorf("ValidDeviceTag(%q) = %v, want %v", tc.tag, got, tc.want)
		}
	}
}

func TestRunConfigureNonInteractive_DeviceTag(t *testing.T) {
	withHome(t)
	if err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{
		"customer_id": "cust-1", "api_endpoint": "https://api.example.com", "api_key": "sk-abcdef",
		"device_tag": " avd-pool-eu ",
	}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg := loadExisting()
	if cfg.DeviceTag != "avd-pool-eu" {
		t.Errorf("DeviceTag: got %q", cfg.DeviceTag)
	}
	raw, _ := os.ReadFile(filepath.Join(withHomeDir(t), ".stepsecurity", "config.json"))
	if !strings.Contains(string(raw), `"device_tag": "avd-pool-eu"`) {
		t.Errorf("config.json missing device_tag:\n%s", raw)
	}
	// Omitted = unchanged.
	if err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{"api_key": "sk-2"}}); err != nil {
		t.Fatalf("second configure: %v", err)
	}
	if cfg = loadExisting(); cfg.DeviceTag != "avd-pool-eu" {
		t.Errorf("omitted --device-tag must keep the tag, got %q", cfg.DeviceTag)
	}
	// Invalid = rejected, file untouched.
	if err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{"device_tag": "avd pool"}}); err == nil {
		t.Error("a tag with a space must be rejected")
	}
	if cfg = loadExisting(); cfg.DeviceTag != "avd-pool-eu" {
		t.Errorf("a rejected tag must not change the file, got %q", cfg.DeviceTag)
	}
	// "" (what "-" saves) clears.
	if err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{"device_tag": ""}}); err != nil {
		t.Fatalf("third configure: %v", err)
	}
	if cfg = loadExisting(); cfg.DeviceTag != "" {
		t.Errorf("an empty device_tag must clear the tag, got %q", cfg.DeviceTag)
	}
}

func TestLoad_DeviceTag(t *testing.T) {
	dir := withHome(t)
	cfgDir := filepath.Join(dir, ".stepsecurity")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(tag string) {
		t.Helper()
		content := `{"customer_id":"c","api_endpoint":"https://e","api_key":"k","device_tag":"` + tag + `"}`
		if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prevTag, prevCust, prevEnd, prevKey := DeviceTag, CustomerID, APIEndpoint, APIKey
	t.Cleanup(func() { DeviceTag, CustomerID, APIEndpoint, APIKey = prevTag, prevCust, prevEnd, prevKey })

	write(" avd-pool-eu ")
	DeviceTag = ""
	Load()
	if DeviceTag != "avd-pool-eu" {
		t.Fatalf("DeviceTag = %q, want avd-pool-eu", DeviceTag)
	}
	// An invalid value in the file is ignored, never fatal.
	write("avd pool")
	DeviceTag = ""
	Load()
	if DeviceTag != "" {
		t.Fatalf("an invalid device_tag must be ignored, got %q", DeviceTag)
	}
}

func TestLoad_DeviceIDAndRetireOnUninstall(t *testing.T) {
	dir := withHome(t)
	cfgDir := filepath.Join(dir, ".stepsecurity")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	content := `{"customer_id":"c","api_endpoint":"https://e","api_key":"k","device_id":" {hostname}-vdi ","retire_on_uninstall":true}`
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
	if DeviceID != "{hostname}-vdi" {
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
	if err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{
		"customer_id": "c", "api_endpoint": "https://e", "api_key": "sk-abcdef",
		"device_id": "{hostname}", "retire_on_uninstall": true,
	}}); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() { ShowConfigure("avd-host-07 (source: config)", "") })
	for _, want := range []string{
		"Device ID:               {hostname}",
		"resolves now to:       avd-host-07 (source: config)",
		"Multi-User Detection:    edition (default",
		"Retire On Uninstall:     true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("configure show missing %q:\n%s", want, out)
		}
	}
	out = captureStdout(t, func() { ShowConfigure("", "") })
	if strings.Contains(out, "resolves now to") {
		t.Errorf("empty resolved line must be omitted:\n%s", out)
	}
	if err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{"device_id": "-"}}); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() { ShowConfigure("", "") })
	if !strings.Contains(out, "Device ID:               hardware serial (default)") {
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
	if err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{
		"customer_id": "cust", "api_endpoint": "https://old.example.com", "api_key": "sk-old",
		"auto_update": optOut,
	}}); err != nil {
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

// Flag values merge key by key: "" clears a string setting (how the CLI
// stores the "auto"/"pretty" defaults), keys not passed are kept.
func TestRunConfigureNonInteractive_ValuesMerge(t *testing.T) {
	withHome(t)
	creds := map[string]any{"customer_id": "c", "api_endpoint": "https://e", "api_key": "k"}
	with := func(kv map[string]any) NonInteractiveOptions {
		m := map[string]any{}
		for k, v := range creds {
			m[k] = v
		}
		for k, v := range kv {
			m[k] = v
		}
		return NonInteractiveOptions{Values: m}
	}
	if err := RunConfigureNonInteractive(with(map[string]any{
		"color_mode": "never", "output_format": "json", "update_lag_behind": 3, "enable_brew_scan": false,
	})); err != nil {
		t.Fatal(err)
	}
	if err := RunConfigureNonInteractive(with(map[string]any{"color_mode": "", "output_format": ""})); err != nil {
		t.Fatal(err)
	}
	cfg := loadExisting()
	if cfg.ColorMode != "" || cfg.OutputFormat != "" {
		t.Errorf("defaults not cleared: color=%q format=%q", cfg.ColorMode, cfg.OutputFormat)
	}
	if cfg.UpdateLagBehind != 3 || cfg.EnableBrewScan == nil || *cfg.EnableBrewScan {
		t.Errorf("unpassed keys not kept: lag=%d brew=%v", cfg.UpdateLagBehind, cfg.EnableBrewScan)
	}
}

// A community install (no credentials) can change preferences without
// prompts; anything touching credentials, a --from-file, or a bare
// --non-interactive (an MSI with empty credential properties) still needs
// all three.
func TestRunConfigureNonInteractive_CredentialsRequirement(t *testing.T) {
	tests := []struct {
		name    string
		opts    NonInteractiveOptions
		wantErr string
	}{
		{"preferences only", NonInteractiveOptions{Values: map[string]any{"color_mode": "never", "enable_brew_scan": false}}, ""},
		{"bare non-interactive", NonInteractiveOptions{}, "api_key is required"},
		{"partial credentials", NonInteractiveOptions{Values: map[string]any{"customer_id": "c", "color_mode": "never"}}, "api_key is required"},
		{"env api key only", NonInteractiveOptions{Values: map[string]any{"api_key": "k"}}, "customer_id is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withHome(t)
			err := RunConfigureNonInteractive(tc.opts)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if cfg := loadExisting(); cfg.ColorMode != "never" || cfg.EnableBrewScan == nil || *cfg.EnableBrewScan {
					t.Errorf("preferences not saved: %+v", cfg)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// multi_user_detection: loaded when valid, shown by configure show, and an
// invalid value falls back to the default rather than stopping a scan.
func TestMultiUserDetection_LoadShowAndValidate(t *testing.T) {
	withHome(t)
	prev := MultiUserDetection
	t.Cleanup(func() { MultiUserDetection = prev })
	for _, tc := range []struct{ in, mode string }{
		{"", MultiUserDetectionEdition}, {"USERS", MultiUserDetectionUsers}, {"off", MultiUserDetectionOff}, {"sometimes", MultiUserDetectionEdition},
	} {
		MultiUserDetection = tc.in
		if got := MultiUserDetectionMode(); got != tc.mode {
			t.Errorf("MultiUserDetectionMode(%q) = %q, want %q", tc.in, got, tc.mode)
		}
	}
	if ValidMultiUserDetection("sometimes") || !ValidMultiUserDetection("Users") {
		t.Error("ValidMultiUserDetection accepts edition, users and off only")
	}
	MultiUserDetection = ""
	if err := RunConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{
		"customer_id": "c", "api_endpoint": "https://e", "api_key": "sk-abcdef", "multi_user_detection": "users",
	}}); err != nil {
		t.Fatal(err)
	}
	Load()
	if MultiUserDetection != MultiUserDetectionUsers {
		t.Fatalf("Load must apply a valid multi_user_detection, got %q", MultiUserDetection)
	}
	out := captureStdout(t, func() { ShowConfigure("", "") })
	if !strings.Contains(out, "Multi-User Detection:    users (") {
		t.Errorf("configure show must print the mode:\n%s", out)
	}
}

// PowerShell 5.1's Set-Content/Out-File -Encoding UTF8 writes a byte-order
// mark; a bootstrap.json written that way must still configure the agent.
func TestRunConfigureNonInteractive_FromFileWithBOM(t *testing.T) {
	withHome(t)
	srcPath := filepath.Join(t.TempDir(), "bootstrap.json")
	body := []byte("\xef\xbb\xbf" + `{"customer_id":"bom-cust","api_endpoint":"https://bom.example.com","api_key":"sk-bom","scan_frequency_hours":"6"}`)
	if err := os.WriteFile(srcPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := RunConfigureNonInteractive(NonInteractiveOptions{FromFile: srcPath}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg := loadExisting()
	if cfg.CustomerID != "bom-cust" || cfg.APIKey != "sk-bom" || cfg.ScanFrequencyHours != "6" {
		t.Errorf("from-file values not applied through the BOM: %+v", cfg)
	}
}
