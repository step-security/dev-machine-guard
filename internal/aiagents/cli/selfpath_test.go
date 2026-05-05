package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolve_ReturnsAbsoluteExistingPath(t *testing.T) {
	got, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("Resolve returned non-absolute path: %q", got)
	}
	if _, err := os.Stat(got); err != nil {
		t.Errorf("Resolve returned non-existent path %q: %v", got, err)
	}
}

func TestResolveFrom_PassesNonSymlinkThrough(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "binary")
	if err := os.WriteFile(real, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := resolveFrom(real)
	if err != nil {
		t.Fatal(err)
	}
	// EvalSymlinks may canonicalize the temp dir prefix (e.g., /var → /private/var on macOS).
	// Compare the canonicalized expectation, not the raw input.
	want, _ := filepath.EvalSymlinks(real)
	if got != want {
		t.Errorf("resolveFrom non-symlink: got %q, want %q", got, want)
	}
}

// Mirrors the brew-style layout: a `bin/` symlink points at the actual
// binary in `Cellar/`. Resolve must record the Cellar path so the hook
// command survives a `brew upgrade` that re-points the symlink.
func TestResolveFrom_FollowsSymlinkToTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}

	dir := t.TempDir()
	cellar := filepath.Join(dir, "Cellar", "stepsecurity-dev-machine-guard", "1.11.0")
	if err := os.MkdirAll(cellar, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(cellar, "stepsecurity-dev-machine-guard")
	if err := os.WriteFile(real, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(binDir, "stepsecurity-dev-machine-guard")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	got, err := resolveFrom(link)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(real)
	if got != want {
		t.Errorf("resolveFrom symlink: got %q, want %q", got, want)
	}
}

func TestResolveFrom_BrokenSymlinkErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}

	dir := t.TempDir()
	link := filepath.Join(dir, "broken")
	if err := os.Symlink(filepath.Join(dir, "nope"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveFrom(link); err == nil {
		t.Error("expected error on broken symlink — recording an unresolved path defeats the canonicalization")
	}
}

func TestResolveFrom_NonExistentPathErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := resolveFrom(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Error("expected error on non-existent path")
	}
}

// On Windows the resolved binary path keeps its `.exe` suffix; the hook
// command we write into agent settings must invoke `dmg.exe`, not `dmg`.
// On Unix the suffix is just an opaque part of the basename, so the same
// expectation holds.
func TestResolveFrom_PreservesExeSuffix(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "stepsecurity-dev-machine-guard.exe")
	if err := os.WriteFile(real, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := resolveFrom(real)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(got) != ".exe" {
		t.Errorf("resolveFrom dropped .exe suffix: got %q", got)
	}
}
