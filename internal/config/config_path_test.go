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

// stageInstallTree builds <root>/bin/<binary> with config.json at <root> —
// the loader layout — and returns the root and the fake binary path.
func stageInstallTree(t *testing.T) (root, exe string) {
	t.Helper()
	root = t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(binDir, "stepsecurity-dev-machine-guard")
}

func TestReadConfigDir_PrefersInstallTreeParentOfBin(t *testing.T) {
	root, exe := stageInstallTree(t)
	setExecutablePath(t, exe)

	got := readConfigDir()
	// t.TempDir on macOS hands out /var/... which is a symlink to
	// /private/var; EvalSymlinks in the resolver canonicalises, so compare
	// canonical forms.
	want, _ := filepath.EvalSymlinks(root)
	if want == "" {
		want = root
	}
	if got != want && got != root {
		t.Errorf("readConfigDir() = %q, want install root %q", got, root)
	}
}

func TestReadConfigDir_PrefersConfigBesideBinary(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "stepsecurity-dev-machine-guard")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	setExecutablePath(t, exe)

	got := readConfigDir()
	want, _ := filepath.EvalSymlinks(dir)
	if want == "" {
		want = dir
	}
	if got != want && got != dir {
		t.Errorf("readConfigDir() = %q, want binary dir %q", got, dir)
	}
}

func TestReadConfigDir_FallsBackToUserDirWithoutInstallTreeConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	// Fake binary in a tree with NO config.json anywhere near it.
	setExecutablePath(t, filepath.Join(t.TempDir(), "bin", "stepsecurity-dev-machine-guard"))

	// Mirror the documented chain: a machine-wide config (Windows hosts
	// with a real ProgramData install) may legitimately win before the
	// legacy per-user fallback.
	want := filepath.Join(home, ".stepsecurity")
	if mcd := machineConfigDir(); mcd != "" {
		if _, err := os.Stat(filepath.Join(mcd, "config.json")); err == nil {
			want = mcd
		}
	}
	if got := readConfigDir(); got != want {
		t.Errorf("readConfigDir() = %q, want %q", got, want)
	}
}

func TestWriteConfigDir_FollowsInstallTreeConfig(t *testing.T) {
	root, exe := stageInstallTree(t)
	setExecutablePath(t, exe)

	got := writeConfigDir()
	want, _ := filepath.EvalSymlinks(root)
	if want == "" {
		want = root
	}
	if got != want && got != root {
		t.Errorf("writeConfigDir() = %q, want install root %q (write where we read)", got, root)
	}
}

func TestWriteConfigDir_FallsBackWithoutInstallTreeConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	setExecutablePath(t, filepath.Join(t.TempDir(), "bin", "stepsecurity-dev-machine-guard"))

	// Mirror the documented chain: elevated runs (Windows CI runners run
	// as admin) write machine-wide; everything else writes the legacy
	// per-user dir.
	want := filepath.Join(home, ".stepsecurity")
	if isElevated() {
		if mcd := machineConfigDir(); mcd != "" {
			want = mcd
		}
	}
	if got := writeConfigDir(); got != want {
		t.Errorf("writeConfigDir() = %q, want %q", got, want)
	}
}

func TestExeAdjacentConfigDir_ExecutableErrorIsEmpty(t *testing.T) {
	orig := executablePath
	executablePath = func() (string, error) { return "", os.ErrNotExist }
	t.Cleanup(func() { executablePath = orig })

	if got := exeAdjacentConfigDir(); got != "" {
		t.Errorf("exeAdjacentConfigDir() = %q, want empty on executable error", got)
	}
}
