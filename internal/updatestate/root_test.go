package updatestate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func touch(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

func trustRoots(t *testing.T) {
	t.Helper()
	checkRoot = func(string) error { return nil }
	t.Cleanup(func() { checkRoot = checkRootProtected })
}

// Copilot 4356483380: the updater derives its install root from its own
// path (any MSI INSTALLFOLDER), by the same rule as the bootstrap.
func TestResolveInstallRoot_CustomRoot(t *testing.T) {
	trustRoots(t)
	root := filepath.Join(t.TempDir(), "D", "Apps", "StepSecurity")
	touch(t, filepath.Join(root, BootstrapFile))
	v := Version{1, 20, 0}
	for _, exe := range []string{
		filepath.Join(root, "versions", "1.20.0", AgentFile),
		filepath.Join(root, "seed", "1.20.0", AgentFile),
		filepath.Join(root, BootstrapFile),
	} {
		got, err := ResolveInstallRoot(exe)
		if err != nil || got != root {
			t.Fatalf("ResolveInstallRoot(%s) = %q, %v; want %q", exe, got, err, root)
		}
	}
	l, err := ResolveLayout(filepath.Join(root, "versions", "1.20.0", AgentFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{l.StateFile(), l.LockFile(), l.LogFile(), l.VersionDir(v), l.SeedDir(v), filepath.Join(l.StateDir(), "device-id")} {
		if rel, err := filepath.Rel(root, p); err != nil || rel == "" || rel[0] == '.' {
			t.Errorf("%s is not under the custom root %s", p, root)
		}
	}
}

func TestResolveInstallRoot_NoBootstrapRefused(t *testing.T) {
	trustRoots(t)
	root := filepath.Join(t.TempDir(), "StepSecurity")
	exe := filepath.Join(root, "versions", "1.20.0", AgentFile)
	touch(t, exe)
	if _, err := ResolveInstallRoot(exe); !errors.Is(err, ErrUnsafeRoot) {
		t.Fatalf("no bootstrap: err = %v, want ErrUnsafeRoot", err)
	}
}

// A root the current (unprivileged) user owns is user-writable: refused.
func TestResolveInstallRoot_UserWritableRootRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running privileged: a temp root isn't user-writable for this check")
	}
	root := filepath.Join(t.TempDir(), "StepSecurity")
	touch(t, filepath.Join(root, BootstrapFile))
	if _, err := ResolveInstallRoot(filepath.Join(root, "versions", "1.20.0", AgentFile)); !errors.Is(err, ErrUnsafeRoot) {
		t.Fatalf("user-writable root: err = %v, want ErrUnsafeRoot", err)
	}
}
