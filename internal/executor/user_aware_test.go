package executor

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestNewUserAwareExecutor_Wrapping pins the wrapping decision. The fix dropped
// the old `!inner.IsRoot()` gate so the wrapper also applies under a LaunchAgent
// (the agent running as the user, not root). launchd strips PATH in both modes,
// so brew/pip3/npm must run through the user's rc-sourced login shell either
// way — the non-root row is the regression this change fixes.
func TestNewUserAwareExecutor_Wrapping(t *testing.T) {
	tests := []struct {
		name     string
		goos     string
		isRoot   bool
		username string
		wantWrap bool
	}{
		{"non-root macOS with user (LaunchAgent regression)", "darwin", false, "alice", true},
		{"root macOS with user (LaunchDaemon)", "darwin", true, "alice", true},
		{"non-root linux with user", "linux", false, "alice", true},
		{"empty username → passthrough", "darwin", false, "", false},
		{"windows → passthrough", "windows", false, "alice", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := NewMock()
			mock.SetGOOS(tc.goos)
			mock.SetIsRoot(tc.isRoot)

			got := NewUserAwareExecutor(mock, tc.username)
			_, wrapped := got.(*UserAwareExecutor)
			if wrapped != tc.wantWrap {
				t.Errorf("NewUserAwareExecutor wrapped=%v, want %v", wrapped, tc.wantWrap)
			}
		})
	}
}

// TestUserAwareExecutor_RunDelegatesNonRoot confirms a wrapped Run is routed
// through the inner RunAsUser (which the Mock dispatches as `bash -c`) even when
// not root — i.e. the command actually reaches the user's shell, where PATH is
// resolved, rather than a bare exec.
func TestUserAwareExecutor_RunDelegatesNonRoot(t *testing.T) {
	mock := NewMock()
	mock.SetGOOS("darwin")
	mock.SetIsRoot(false) // LaunchAgent: running as the user, not root
	// Args are individually shell-quoted before being joined into the RunAsUser
	// command string, so the stub is keyed on the quoted form.
	mock.SetCommand("/opt/homebrew/bin/brew\n", "", 0, "bash", "-c", "'which' 'brew'")

	exec := NewUserAwareExecutor(mock, "alice")
	stdout, _, code, err := exec.Run(context.Background(), "which", "brew")
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if got := strings.TrimSpace(stdout); got != "/opt/homebrew/bin/brew" {
		t.Errorf("stdout = %q, want /opt/homebrew/bin/brew (Run should delegate to RunAsUser)", got)
	}
}

// TestUserAwareExecutor_RunQuotesArgsWithSpaces is the regression for the
// argv-splitting bug: now that the wrapper applies on the non-root LaunchAgent
// path, Run must shell-quote each token so an argument containing spaces
// survives as a single argv entry. Models the real LM Studio version probe
// (FrameworkDetector → readPlistVersion → PlistBuddy) where both the "-c"
// expression and the ".app" path contain spaces. The stub matches only if the
// command string is correctly quoted.
func TestUserAwareExecutor_RunQuotesArgsWithSpaces(t *testing.T) {
	mock := NewMock()
	mock.SetGOOS("darwin")
	mock.SetIsRoot(false)
	want := `'/usr/libexec/PlistBuddy' '-c' 'Print :CFBundleShortVersionString' '/Applications/LM Studio.app/Contents/Info.plist'`
	mock.SetCommand("0.3.45\n", "", 0, "bash", "-c", want)

	exec := NewUserAwareExecutor(mock, "alice")
	stdout, _, code, err := exec.Run(
		context.Background(),
		"/usr/libexec/PlistBuddy",
		"-c", "Print :CFBundleShortVersionString",
		"/Applications/LM Studio.app/Contents/Info.plist",
	)
	if err != nil {
		t.Fatalf("Run returned error — args likely not quoted, so the shell split the path/expression: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if strings.TrimSpace(stdout) != "0.3.45" {
		t.Errorf("stdout = %q, want 0.3.45", stdout)
	}
}

// TestUserAwareExecutor_RunInDirQuotesDirAndArgs verifies RunInDir quotes the
// working directory too — a project under a path with spaces ("My Projects")
// must cd correctly before the command runs.
func TestUserAwareExecutor_RunInDirQuotesDirAndArgs(t *testing.T) {
	mock := NewMock()
	mock.SetGOOS("darwin")
	mock.SetIsRoot(false)
	want := `cd '/Users/alice/My Projects/app' && 'npm' 'ls' '--json'`
	mock.SetCommand(`{"ok":true}`, "", 0, "bash", "-c", want)

	exec := NewUserAwareExecutor(mock, "alice")
	stdout, _, code, err := exec.RunInDir(context.Background(), "/Users/alice/My Projects/app", 10*time.Second, "npm", "ls", "--json")
	if err != nil {
		t.Fatalf("RunInDir returned error — dir/args likely not quoted: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if strings.TrimSpace(stdout) != `{"ok":true}` {
		t.Errorf("stdout = %q, want {\"ok\":true}", stdout)
	}
}
