package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReal_GuardedFiles(t *testing.T) {
	// CI's Windows TEMP can use an 8.3 alias; verified opens use the full path.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"small": "ok", "large": "oversize", "blocked": "no"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, exec := range []Executor{NewReal(), NewUserAwareExecutor(NewReal(), "test-user")} {
		guarded := exec.GuardedFiles([]string{root}, func(p string) string {
			if filepath.Base(p) == "blocked" {
				return "test_refusal"
			}
			return ""
		}, 4)
		if data, err := guarded.ReadFile(filepath.Join(root, "small")); err != nil || string(data) != "ok" {
			t.Fatalf("guarded read = %q, %v", data, err)
		}
		for _, name := range []string{"large", "blocked"} {
			if data, err := guarded.ReadFile(filepath.Join(root, name)); err == nil || len(data) != 0 {
				t.Errorf("%s: expected refusal without contents, got %q, %v", name, data, err)
			}
		}
		if info, err := guarded.Stat(filepath.Join(root, "small")); err != nil || info.Size() != 2 {
			t.Fatalf("guarded stat = %v, %v", info, err)
		}
		entries, err := guarded.ReadDir(root)
		if err != nil || len(entries) != 3 || entries[0].Name() != "blocked" || entries[2].Name() != "small" {
			t.Fatalf("guarded directory ordering = %v, %v", entries, err)
		}
	}
}

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

type userContextExecutor struct {
	Executor
	runAsUser func(context.Context, string, string) (string, error)
}

func (e *userContextExecutor) RunAsUser(ctx context.Context, username, command string) (string, error) {
	return e.runAsUser(ctx, username, command)
}

func TestUserAwareExecutor_GetenvUsesAllowlistedUserSnapshot(t *testing.T) {
	service := NewMock()
	service.SetGOOS("linux")
	service.SetEnv("XDG_CONFIG_HOME", "/service/xdg")
	inner := &userContextExecutor{
		Executor: service,
		runAsUser: func(_ context.Context, _, command string) (string, error) {
			if !strings.Contains(command, "XDG_CONFIG_HOME") || !strings.Contains(command, "UV_INDEX_URL") ||
				!strings.Contains(command, "GOPROXY") || !strings.Contains(command, "GOENV") || !strings.Contains(command, "GOAUTH") {
				t.Fatalf("environment snapshot command = %q", command)
			}
			return "XDG_CONFIG_HOME=/home/alice/.xdg\x00PIP_EXTRA_INDEX_URL=https://pip-extra.example/simple\x00UV_INDEX_URL=https://user.example/simple\x00UV_NO_INDEX=true\x00GOPROXY=https://proxy.example/go\x00GOENV=off\x00GOAUTH=netrc\x00", nil
		},
	}
	exec := NewUserAwareExecutor(inner, "alice")
	if got := exec.Getenv("XDG_CONFIG_HOME"); got != "/home/alice/.xdg" {
		t.Fatalf("XDG_CONFIG_HOME = %q, want resolved user value", got)
	}
	if got := exec.Getenv("PIP_EXTRA_INDEX_URL"); got != "https://pip-extra.example/simple" {
		t.Fatalf("PIP_EXTRA_INDEX_URL = %q, want resolved user value", got)
	}
	if got := exec.Getenv("UV_INDEX_URL"); got != "https://user.example/simple" {
		t.Fatalf("UV_INDEX_URL = %q, want resolved user value", got)
	}
	if got := exec.Getenv("UV_NO_INDEX"); got != "true" {
		t.Fatalf("UV_NO_INDEX = %q, want resolved user value", got)
	}
	if got := exec.Getenv("GOPROXY"); got != "https://proxy.example/go" {
		t.Fatalf("GOPROXY = %q, want resolved user value", got)
	}
	if got := exec.Getenv("GOENV"); got != "off" {
		t.Fatalf("GOENV = %q, want resolved user value", got)
	}
	if got := exec.Getenv("GOAUTH"); got != "netrc" {
		t.Fatalf("GOAUTH = %q, want resolved user value", got)
	}
}

func TestUserAwareExecutor_ReportsEnvironmentInspectionFailure(t *testing.T) {
	service := NewMock()
	service.SetGOOS("linux")
	inner := &userContextExecutor{
		Executor: service,
		runAsUser: func(context.Context, string, string) (string, error) {
			return "", context.DeadlineExceeded
		},
	}
	exec := NewUserAwareExecutor(inner, "alice")
	if got := exec.Getenv("PIP_CONFIG_FILE"); got != "" {
		t.Fatalf("PIP_CONFIG_FILE = %q, want empty after failed inspection", got)
	}
	if err := UserEnvironmentError(exec); err == nil {
		t.Fatal("UserEnvironmentError() = nil, want inspection failure")
	}
}

func TestUserAwareExecutor_LookPathUsesCallerContext(t *testing.T) {
	service := NewMock()
	service.SetGOOS("linux")
	calls := 0
	inner := &userContextExecutor{
		Executor: service,
		runAsUser: func(ctx context.Context, _, _ string) (string, error) {
			calls++
			if ctx.Err() != context.Canceled {
				t.Fatalf("RunAsUser context error = %v, want canceled", ctx.Err())
			}
			return "", ctx.Err()
		},
	}
	exec := NewUserAwareExecutor(inner, "alice")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LookPathWithContext(ctx, exec, "pip"); err == nil {
		t.Fatal("LookPathWithContext() error = nil, want cancellation")
	}
	if calls != 0 {
		t.Fatalf("RunAsUser calls = %d, want 0 after caller cancellation", calls)
	}
}

func TestUserAwareExecutor_LookPathHasDeadline(t *testing.T) {
	service := NewMock()
	service.SetGOOS("linux")
	inner := &userContextExecutor{
		Executor: service,
		runAsUser: func(ctx context.Context, _, _ string) (string, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("LookPath RunAsUser context has no deadline")
			}
			return "/usr/bin/uv", nil
		},
	}
	exec := NewUserAwareExecutor(inner, "alice")
	if _, err := exec.LookPath("uv"); err != nil {
		t.Fatal(err)
	}
}
