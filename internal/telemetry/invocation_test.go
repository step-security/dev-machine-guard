package telemetry

import (
	"os"
	"path/filepath"
	"runtime"
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
func TestDetectInvocationMethod_RespondsToFilesystem(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows uses schtasks /query, not filesystem")
	}

	// Resolve the platform's expected artifact path.
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

	// We don't want to clobber a real installation. If the artifact already
	// exists, just confirm the detector agrees and bail; otherwise create a
	// fake marker, assert detection flips, then clean up.
	if _, err := os.Stat(path); err == nil {
		if got := DetectInvocationMethod(); got != InvocationInstall {
			t.Fatalf("artifact %q exists but detector returned %q", path, got)
		}
		return
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Skipf("cannot prepare scheduler artifact dir for test: %v", err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Skipf("cannot write fake scheduler artifact: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })

	if got := DetectInvocationMethod(); got != InvocationInstall {
		t.Fatalf("after creating %q, detector returned %q, want %q",
			path, got, InvocationInstall)
	}

	// Remove the marker mid-test and re-check — confirms detection is not
	// cached and reflects current filesystem state.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove fake artifact: %v", err)
	}
	// Avoid double-remove in cleanup.
	t.Cleanup(func() {})

	if got := DetectInvocationMethod(); got != InvocationOneTime {
		t.Fatalf("after removing %q, detector returned %q, want %q",
			path, got, InvocationOneTime)
	}
}
