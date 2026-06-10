package launcher

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// resolvableTarget picks a binary we know is on PATH for the host running
// the test, so the exec.LookPath inside ResolveTarget actually succeeds.
// macOS CI doesn't have powershell.exe; Windows local devs don't have
// /bin/sh. Pick per-OS so the cross-platform tests stay honest about
// covering the resolve path end-to-end rather than just the argv parsing.
func resolvableTarget(t *testing.T) (basename, wantSuffix string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		// cmd.exe ships on every Windows host the test would ever run on.
		return "cmd.exe", "cmd.exe"
	}
	return "sh", "/sh"
}

func TestResolveTarget_ExecMode_ForwardsArgs(t *testing.T) {
	basename, wantSuffix := resolvableTarget(t)
	target, args, err := ResolveTarget([]string{"--exec", basename, "-c", "echo hi"})
	if err != nil {
		t.Fatalf("ResolveTarget returned error: %v", err)
	}
	if !strings.HasSuffix(target, wantSuffix) {
		t.Errorf("target = %q, want suffix %q", target, wantSuffix)
	}
	if len(args) != 2 || args[0] != "-c" || args[1] != "echo hi" {
		t.Errorf("args = %v, want [-c, \"echo hi\"]", args)
	}
}

// --exec with no further args is the misuse case: a customer-supplied
// task definition that includes the flag but no target. Must error
// rather than fall through to the default agent-sibling path — that
// would silently swallow a malformed task action.
func TestResolveTarget_ExecMode_MissingTarget(t *testing.T) {
	_, _, err := ResolveTarget([]string{"--exec"})
	if err == nil {
		t.Fatal("expected error for --exec with no target, got nil")
	}
	if !strings.Contains(err.Error(), ExecFlag) {
		t.Errorf("error %q does not mention %q", err, ExecFlag)
	}
}

// An --exec target that doesn't resolve through LookPath must produce a
// distinct error rather than silently exiting (which Task Scheduler
// would record as a generic non-zero exit, indistinguishable from a
// transient failure). exec.LookPath is wrapped, so the inner error is
// preserved via errors.Is for diagnostic chains.
func TestResolveTarget_ExecMode_TargetNotFound(t *testing.T) {
	bogus := "this-binary-definitely-does-not-exist-on-PATH-xyzzy.exe"
	_, _, err := ResolveTarget([]string{"--exec", bogus})
	if err == nil {
		t.Fatalf("expected error resolving %q, got nil", bogus)
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("expected error chain to include exec.ErrNotFound, got %v", err)
	}
}

// --exec with no further child args means "spawn target with empty argv"
// — useful for the trivial case (launcher.exe --exec foo.exe) where the
// child doesn't need flags. Forwards an empty slice, not a nil slice
// (callers passing this directly into exec.Command must get a usable
// value).
func TestResolveTarget_ExecMode_NoChildArgs(t *testing.T) {
	basename, _ := resolvableTarget(t)
	_, args, err := ResolveTarget([]string{"--exec", basename})
	if err != nil {
		t.Fatalf("ResolveTarget returned error: %v", err)
	}
	if args == nil {
		t.Error("args is nil; expected empty (but non-nil) slice")
	}
	if len(args) != 0 {
		t.Errorf("args = %v, want []", args)
	}
}

// Default mode (no --exec) computes the sibling agent path relative to
// os.Executable(). During `go test` os.Executable() returns the compiled
// test binary, so we can stage a fake agent next to it and assert
// ResolveTarget picks it up. This is the lever the MSI install relies
// on — the launcher's directory dictates where the agent comes from.
func TestResolveTarget_DefaultMode_FindsSibling(t *testing.T) {
	exePath, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable not available on this platform: %v", err)
	}
	siblingDir := filepath.Dir(exePath)
	siblingPath := filepath.Join(siblingDir, AgentBinary)

	// Don't clobber a real agent that might be sitting next to the test
	// binary in a developer's checkout. Three cases to handle correctly:
	//
	//   - File doesn't exist (ErrNotExist) — seed the fake, delete on
	//     cleanup. Normal CI path.
	//   - File exists and is readable — capture bytes + mode, seed the
	//     fake, restore both on cleanup.
	//   - File exists but can't be read (permission, locked) — we'd
	//     destroy the developer's checkout if we overwrote it. Skip
	//     the test instead.
	prev, readErr := os.ReadFile(siblingPath)
	var prevMode os.FileMode = 0o644
	if readErr == nil {
		// Capture the original mode so the file is restored byte-for-
		// byte AND mode-for-mode. Without this, a real Authenticode-
		// signed .exe with the executable bit set on POSIX (rare on
		// CI but possible in a dual-platform checkout) would come back
		// non-executable.
		if info, statErr := os.Stat(siblingPath); statErr == nil {
			prevMode = info.Mode().Perm()
		}
	} else if !errors.Is(readErr, fs.ErrNotExist) {
		t.Skipf("cannot read existing sibling %q without risking developer state: %v", siblingPath, readErr)
	}

	if err := os.WriteFile(siblingPath, []byte("fake-agent"), 0o644); err != nil {
		t.Fatalf("seeding fake agent at %q: %v", siblingPath, err)
	}
	t.Cleanup(func() {
		if readErr == nil {
			// Restore both bytes and mode.
			_ = os.WriteFile(siblingPath, prev, prevMode)
		} else {
			// Original was absent; remove our seed.
			_ = os.Remove(siblingPath)
		}
	})

	target, args, err := ResolveTarget([]string{"send-telemetry", "--install-dir=C:\\fake"})
	if err != nil {
		t.Fatalf("ResolveTarget returned error: %v", err)
	}
	if target != siblingPath {
		t.Errorf("target = %q, want %q", target, siblingPath)
	}
	if len(args) != 2 || args[0] != "send-telemetry" || args[1] != "--install-dir=C:\\fake" {
		t.Errorf("args = %v, did not pass through unchanged", args)
	}
}

// When the sibling agent isn't on disk, ResolveTarget must return an
// error rather than a non-existent path. The launcher exit-1's on this;
// surfacing it as an explicit error here means callers (and tests) can
// distinguish "no agent installed" from other failure modes.
func TestResolveTarget_DefaultMode_NoSibling(t *testing.T) {
	exePath, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable not available on this platform: %v", err)
	}
	siblingPath := filepath.Join(filepath.Dir(exePath), AgentBinary)
	if _, statErr := os.Stat(siblingPath); statErr == nil {
		// A real or stale sibling agent is in the way of this assertion.
		// Move it aside for the test and restore on cleanup so we don't
		// leave a half-broken dev checkout behind.
		shadow := siblingPath + ".test-shadow"
		if renameErr := os.Rename(siblingPath, shadow); renameErr != nil {
			t.Skipf("could not move existing sibling agent %q out of the way: %v", siblingPath, renameErr)
		}
		t.Cleanup(func() { _ = os.Rename(shadow, siblingPath) })
	}

	_, _, err = ResolveTarget(nil)
	if err == nil {
		t.Fatal("expected error when sibling agent is absent, got nil")
	}
}
