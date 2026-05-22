package telemetry

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/launchd"
	"github.com/step-security/dev-machine-guard/internal/systemd"
)

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "marker")
	if err := os.WriteFile(present, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"existing file", present, true},
		{"missing file", filepath.Join(dir, "nope"), false},
		{"empty path", "", false},
		{"directory", dir, false}, // dirs intentionally don't count as installs
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fileExists(tc.path); got != tc.want {
				t.Fatalf("fileExists(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestDetectInvocationMethod_HostMachine exercises the detector against the
// real machine. The result is whatever the current dev box reports; we can
// only assert the value is one of the two valid wire-format strings.
func TestDetectInvocationMethod_HostMachine(t *testing.T) {
	got := DetectInvocationMethod()
	if got != InvocationInstall && got != InvocationOneTime {
		t.Fatalf("DetectInvocationMethod returned %q, want %q or %q",
			got, InvocationInstall, InvocationOneTime)
	}
}

// TestDetectInvocationMethod_RespondsToFilesystem covers the darwin/linux
// path that stats a scheduler artifact. On Windows the check shells out to
// schtasks, which we can't safely stub without an executor seam — skip there.
//
// Sandboxes HOME (Unix) and USERPROFILE (Windows-safe no-op on Unix) under
// t.TempDir() so launchd.UserPlistPath / systemd.TimerUnitPath compute paths
// that live entirely inside the temp tree. Without this the test would write
// markers (and MkdirAll-created parent dirs) into the developer's real
// ~/Library/LaunchAgents or ~/.config/systemd/user — leaving stray files
// behind on CI and risking a tiny TOCTOU window against a real install.
func TestDetectInvocationMethod_RespondsToFilesystem(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows uses schtasks /query, not filesystem")
	}

	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome) // no-op on Unix but cheap and keeps the seam consistent

	// Resolve the platform's expected artifact path AFTER the env override
	// so os.UserHomeDir() returns tempHome.
	var path string
	switch runtime.GOOS {
	case "darwin":
		path = launchd.UserPlistPath()
	case "linux":
		path = systemd.TimerUnitPath()
	default:
		t.Skipf("no scheduler artifact path on %s", runtime.GOOS)
	}
	if path == "" {
		t.Skip("could not resolve scheduler artifact path on this host")
	}
	if !strings.HasPrefix(path, tempHome) {
		t.Fatalf("resolved path %q escaped tempHome %q — env sandbox is not effective", path, tempHome)
	}

	// Fresh temp home — detector starts at one_time, flips to install when
	// the marker appears, flips back when it's removed.
	if got := DetectInvocationMethod(); got != InvocationOneTime {
		t.Fatalf("on clean temp home, detector returned %q, want %q",
			got, InvocationOneTime)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("prepare scheduler artifact dir: %v", err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write fake scheduler artifact: %v", err)
	}
	// No explicit cleanup: everything lives under t.TempDir() and is
	// removed by the testing framework when the test ends.

	if got := DetectInvocationMethod(); got != InvocationInstall {
		t.Fatalf("after creating %q, detector returned %q, want %q",
			path, got, InvocationInstall)
	}

	// Remove the marker mid-test and re-check — confirms detection is not
	// cached and reflects current filesystem state.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove fake artifact: %v", err)
	}

	if got := DetectInvocationMethod(); got != InvocationOneTime {
		t.Fatalf("after removing %q, detector returned %q, want %q",
			path, got, InvocationOneTime)
	}
}
