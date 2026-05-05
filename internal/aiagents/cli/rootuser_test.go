package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// withMockUser sets the Mock executor's CurrentUser/LoggedInUser pair.
// Mock returns CurrentUser from LoggedInUser, so a single setter chain
// covers both.
//
// Note: Mock's CurrentUser only carries Username + HomeDir — UID/GID are
// not part of the public Mock API, so ResolveTargetUser's strconv.Atoi
// will yield 0 on the empty string. Tests that need a specific UID
// drive the chown branch directly with TargetUser literals (see
// TestChownToTarget_AsFakeRootSucceedsForOwnUID).
func withMockUser(m *executor.Mock, username, home string) {
	m.SetUsername(username)
	m.SetHomeDir(home)
}

func TestResolveTargetUser_NonRoot_ReturnsCallingUser(t *testing.T) {
	m := executor.NewMock()
	m.SetIsRoot(false)
	withMockUser(m, "alice", "/Users/alice")

	var stderr bytes.Buffer
	got, ok := ResolveTargetUser(m, &stderr)
	if !ok {
		t.Fatal("expected ok=true for non-root caller")
	}
	if got.User.Username != "alice" {
		t.Errorf("Username = %q, want alice", got.User.Username)
	}
	if got.HomeDir != "/Users/alice" {
		t.Errorf("HomeDir = %q, want /Users/alice", got.HomeDir)
	}
	if stderr.Len() != 0 {
		t.Errorf("expected silent stderr on success, got %q", stderr.String())
	}
}

func TestResolveTargetUser_RootWithConsoleUser_ReturnsConsoleUser(t *testing.T) {
	tmp := withErrorLog(t)

	m := executor.NewMock()
	m.SetIsRoot(true)
	withMockUser(m, "alice", "/Users/alice")

	var stderr bytes.Buffer
	got, ok := ResolveTargetUser(m, &stderr)
	if !ok {
		t.Fatal("expected ok=true when console user resolves to non-root")
	}
	if got.User.Username != "alice" {
		t.Errorf("Username = %q, want alice", got.User.Username)
	}

	// Errors log must not be touched on the success path.
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("expected errors log not created on success, got err=%v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("expected silent stderr on success, got %q", stderr.String())
	}
}

func TestResolveTargetUser_RootNoConsoleUser_BailsWithLog(t *testing.T) {
	logPath := withErrorLog(t)

	m := executor.NewMock()
	m.SetIsRoot(true)
	// Mock.LoggedInUser falls back to CurrentUser which returns whatever
	// SetUsername staged. "root" simulates the executor failing to
	// resolve a console user under root.
	withMockUser(m, "root", "/var/root")

	var stderr bytes.Buffer
	_, ok := ResolveTargetUser(m, &stderr)
	if ok {
		t.Fatal("expected ok=false when running as root with no console user")
	}

	if !strings.Contains(stderr.String(), "running as root with no console user") {
		t.Errorf("stderr missing the expected one-line note: %q", stderr.String())
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("expected errors log written: %v", err)
	}
	var entry ErrorEntry
	if err := json.Unmarshal(bytes.TrimRight(data, "\n"), &entry); err != nil {
		t.Fatalf("unmarshal: %v (data=%q)", err, string(data))
	}
	if entry.Stage != "install" || entry.Code != "no_console_user" {
		t.Errorf("unexpected error entry: %+v", entry)
	}
}

func TestResolveTargetUser_RootEmptyUsername_AlsoBails(t *testing.T) {
	withErrorLog(t) // capture log writes to temp

	m := executor.NewMock()
	m.SetIsRoot(true)
	withMockUser(m, "", "")

	var stderr bytes.Buffer
	_, ok := ResolveTargetUser(m, &stderr)
	if ok {
		t.Fatal("expected ok=false for empty username under root")
	}
	if !strings.Contains(stderr.String(), "no console user") {
		t.Errorf("stderr missing the bail note: %q", stderr.String())
	}
}

// ChownToTarget is a no-op when the caller is not root, because chowning
// a file to a different UID requires CAP_CHOWN. Verify the early exit.
func TestChownToTarget_NoOpWhenNotRoot(t *testing.T) {
	withErrorLog(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := executor.NewMock()
	m.SetIsRoot(false)

	// Use a bogus UID/GID — if we accidentally tried to chown, this would fail.
	ChownToTarget(m, []string{path}, TargetUser{UID: 9999, GID: 9999})

	// File still exists and is readable.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file vanished after no-op chown: %v", err)
	}
}

func TestChownToTarget_SkipsEmptyPaths(t *testing.T) {
	withErrorLog(t)

	m := executor.NewMock()
	m.SetIsRoot(false) // no-op anyway, but proves the empty-string skip doesn't error

	ChownToTarget(m, []string{"", "", ""}, TargetUser{})
	// Reaching this line without a panic is the assertion.
}

// On Unix as a non-root user, chowning a file to YOUR OWN UID is a no-op
// that succeeds. Use a "fake-root" mock that claims IsRoot=true to drive
// the chown branch, with the calling user's real UID/GID as the target —
// that's the only chown that won't fail under a non-privileged test.
func TestChownToTarget_AsFakeRootSucceedsForOwnUID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chown semantics differ on Windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid := atoi(me.Uid)
	gid := atoi(me.Gid)

	withErrorLog(t)

	m := executor.NewMock()
	m.SetIsRoot(true) // drive the chown branch

	ChownToTarget(m, []string{path}, TargetUser{UID: uid, GID: gid})

	// File should still exist with the same owner.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file unexpectedly missing: %v", err)
	}
}

// Failed chowns (e.g., bogus UID) must be logged but not abort the loop.
func TestChownToTarget_FailureLogsButContinues(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chown semantics differ on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("running as actual root; chown to UID 1 would succeed and not exercise the error branch")
	}

	logPath := withErrorLog(t)

	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	m := executor.NewMock()
	m.SetIsRoot(true)

	// Bogus UID — chown fails for non-privileged caller despite IsRoot=true.
	ChownToTarget(m, []string{a, b}, TargetUser{UID: 1, GID: 1})

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("expected errors log to capture failures: %v", err)
	}
	// Two failed chowns → two log lines.
	if lines := strings.Count(strings.TrimRight(string(data), "\n"), "\n"); lines != 1 {
		// strings.Count of "\n" with one newline-stripped → 1 if there are 2 lines
		t.Errorf("expected 2 log entries, got data=%q", string(data))
	}
	if !strings.Contains(string(data), "chown_failed") {
		t.Errorf("expected chown_failed code in log, got %q", string(data))
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
