package config

import (
	"os"
	"path/filepath"
	"testing"
)

// setExecutablePath points the resolution seam at a fake binary path and
// restores the real os.Executable on cleanup.
func setExecutablePath(t *testing.T, exe string) {
	t.Helper()
	orig := executablePath
	executablePath = func() (string, error) { return exe, nil }
	t.Cleanup(func() { executablePath = orig })
}

const agentConfigJSON = `{"customer_id":"acme","api_endpoint":"https://agent.example.io","api_key":"sk-test"}`

// stageInstallTree builds <root>/bin/<binary> with an agent config.json at
// <root>, the loader layout, and returns the root and the fake binary path.
func stageInstallTree(t *testing.T) (root, exe string) {
	t.Helper()
	root = t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(agentConfigJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(binDir, "stepsecurity-dev-machine-guard")
}

// sameDir compares a resolved directory with an expected one, tolerating
// the symlinked temp roots macOS hands out (/var -> /private/var).
func sameDir(got, want string) bool {
	if got == want {
		return true
	}
	if r, err := filepath.EvalSymlinks(want); err == nil && got == r {
		return true
	}
	return false
}

// noMachineConfig skips a test when a Windows machine-wide config exists on
// the host: that location legitimately outranks every per-user lookup.
func noMachineConfig(t *testing.T) {
	t.Helper()
	if mcd := machineConfigDir(); mcd != "" {
		if _, err := os.Stat(filepath.Join(mcd, "config.json")); err == nil {
			t.Skip("machine-wide config present on this host")
		}
	}
}

func TestReadConfigDir_LegacyFileWinsOverInstallTree(t *testing.T) {
	noMachineConfig(t)
	home := withHome(t)
	legacy := filepath.Join(home, ".stepsecurity")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "config.json"), []byte(agentConfigJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	_, exe := stageInstallTree(t)
	setExecutablePath(t, exe)

	if got := readConfigDir(); got != legacy {
		t.Errorf("readConfigDir() = %q, want the legacy dir %q (a stale install-tree copy must never shadow it)", got, legacy)
	}
	if got := writeConfigDir(); got != legacy && !isElevated() {
		t.Errorf("writeConfigDir() = %q, want the legacy dir %q", got, legacy)
	}
}

// lookupAllowed skips a positive install-tree test where the lookup is
// disabled on purpose (an elevated Windows run).
func lookupAllowed(t *testing.T) {
	t.Helper()
	if !installTreeLookupAllowed() {
		t.Skip("install-tree lookup is disabled in this context (elevated Windows)")
	}
}

func TestReadConfigDir_InstallTreeParentOfBinWhenNoLegacyFile(t *testing.T) {
	noMachineConfig(t)
	lookupAllowed(t)
	withHome(t)
	root, exe := stageInstallTree(t)
	setExecutablePath(t, exe)

	if got := readConfigDir(); !sameDir(got, root) {
		t.Errorf("readConfigDir() = %q, want install root %q", got, root)
	}
	if isElevated() {
		return // root never trusts a non-root-owned temp file; covered by the trust table test
	}
	if got := writeConfigDir(); !sameDir(got, root) {
		t.Errorf("writeConfigDir() = %q, want install root %q (write where we read)", got, root)
	}
}

func TestReadConfigDir_ConfigBesideBinary(t *testing.T) {
	noMachineConfig(t)
	lookupAllowed(t)
	withHome(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(agentConfigJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	setExecutablePath(t, filepath.Join(dir, "stepsecurity-dev-machine-guard"))

	if got := readConfigDir(); !sameDir(got, dir) {
		t.Errorf("readConfigDir() = %q, want binary dir %q", got, dir)
	}
}

func TestReadConfigDir_ParentOnlyForBinDir(t *testing.T) {
	noMachineConfig(t)
	home := withHome(t)
	// A binary in ~/Downloads must not adopt a config.json sitting in ~.
	downloads := filepath.Join(home, "Downloads")
	if err := os.MkdirAll(downloads, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "config.json"), []byte(agentConfigJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	setExecutablePath(t, filepath.Join(downloads, "stepsecurity-dev-machine-guard"))

	if got, want := readConfigDir(), filepath.Join(home, ".stepsecurity"); got != want {
		t.Errorf("readConfigDir() = %q, want %q (parent lookup is for bin/ layouts only)", got, want)
	}
}

func TestIsAgentConfigFile_RejectsForeignAndUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name string
		path string
		want bool
	}{
		// Accepted even when elevated: as root the temp file is root-owned
		// 0600, and on Windows the elevation rule lives in
		// installTreeLookupAllowed, not here.
		{"agent config", write("ours.json", agentConfigJSON), true},
		{"api_key only (another tool's file)", write("other.json", `{"api_key":"abc"}`), false},
		{"customer_id without endpoint", write("half.json", `{"customer_id":"acme"}`), false},
		{"empty values", write("empty.json", `{"customer_id":" ","api_endpoint":""}`), false},
		{"not JSON", write("garbage.json", "not json"), false},
		{"missing", filepath.Join(dir, "missing.json"), false},
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(filepath.Join(dir, "ours.json"), link); err == nil {
		cases = append(cases, struct {
			name string
			path string
			want bool
		}{"symlink to an agent config", link, false})
	}
	for _, tc := range cases {
		if _, got := isAgentConfigFile(tc.path); got != tc.want {
			t.Errorf("isAgentConfigFile(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The bytes loaded are the bytes the lookup validated on one open descriptor:
// a symlink swapped in after the first lookup is rejected at the next one,
// and the config falls back to the (empty) per-user location.
func TestReadExisting_RejectsASwappedSymlink(t *testing.T) {
	noMachineConfig(t)
	lookupAllowed(t)
	withHome(t)
	root, exe := stageInstallTree(t)
	setExecutablePath(t, exe)
	path := ConfigFilePath()
	if !sameDir(filepath.Dir(path), root) {
		t.Fatalf("ConfigFilePath() = %q, want the install root", path)
	}
	cfg, err := readExisting()
	if err != nil || cfg.CustomerID != "acme" {
		t.Fatalf("first read = %+v, %v; want the install-tree config", cfg, err)
	}
	// Swap the validated file for a symlink to a planted one.
	planted := filepath.Join(t.TempDir(), "planted.json")
	if err := os.WriteFile(planted, []byte(`{"customer_id":"evil","api_endpoint":"https://evil.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(planted, path); err != nil {
		t.Skip("symlinks not available")
	}
	cfg, err = readExisting()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CustomerID != "" {
		t.Errorf("customer_id = %q, want no config at all (a symlinked config.json is never followed)", cfg.CustomerID)
	}
}

// A legacy config that cannot be checked for a reason other than absence
// keeps precedence, so the error surfaces instead of a stale fallback.
func TestReadConfigDir_LegacyStatErrorKeepsLegacyPath(t *testing.T) {
	noMachineConfig(t)
	if isElevated() {
		t.Skip("root bypasses directory permissions")
	}
	home := withHome(t)
	legacy := filepath.Join(home, ".stepsecurity")
	if err := os.MkdirAll(legacy, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(legacy, 0o700) })
	_, exe := stageInstallTree(t)
	setExecutablePath(t, exe)
	if got := readConfigDir(); got != legacy {
		t.Errorf("readConfigDir() = %q, want the legacy dir %q despite the permission error", got, legacy)
	}
	if got := writeConfigDir(); got != legacy {
		t.Errorf("writeConfigDir() = %q, want the legacy dir %q", got, legacy)
	}
}

func TestInstallTreeConfigDir_ExecutableErrorIsEmpty(t *testing.T) {
	orig := executablePath
	executablePath = func() (string, error) { return "", os.ErrNotExist }
	t.Cleanup(func() { executablePath = orig })

	if got := installTreeConfigDir(); got != "" {
		t.Errorf("installTreeConfigDir() = %q, want empty on executable error", got)
	}
}

func TestConfigFilePath_OverrideStillWins(t *testing.T) {
	noMachineConfig(t)
	withHome(t)
	_, exe := stageInstallTree(t)
	setExecutablePath(t, exe)
	override := filepath.Join(t.TempDir(), "wsl-host-config.json")
	SetFileOverride(override)
	t.Cleanup(func() { SetFileOverride("") })

	if got := ConfigFilePath(); got != override {
		t.Errorf("ConfigFilePath() = %q, want the --config override %q", got, override)
	}
}
