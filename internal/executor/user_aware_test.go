package executor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
		runAsUser: func(ctx context.Context, _, command string) (string, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("LookPath RunAsUser context has no deadline")
			}
			// Fail the one-time $PATH fetch so LookPath exercises the
			// `which` fallback; both RunAsUser paths must carry a deadline.
			if strings.Contains(command, "$PATH") {
				return "", errMockPathFetch
			}
			return "/usr/bin/uv", nil
		},
	}
	exec := NewUserAwareExecutor(inner, "alice")
	if _, err := exec.LookPath("uv"); err != nil {
		t.Fatal(err)
	}
}

func TestUserAwareExecutor_CopilotRootsUseScannedUser(t *testing.T) {
	service := NewMock()
	service.SetGOOS("linux")
	keys := []string{"COPILOT_HOME", "COPILOT_CACHE_HOME", "XDG_CACHE_HOME", "LOCALAPPDATA", "VSCODE_AGENT_PLUGINS", "VSCODE_PORTABLE"}
	for _, key := range keys {
		service.SetEnv(key, "/daemon/"+key)
	}
	calls := 0
	inner := &userContextExecutor{Executor: service, runAsUser: func(_ context.Context, user, command string) (string, error) {
		calls++
		if user != "alice" {
			t.Fatalf("wrong user: %s", user)
		}
		var entries []string
		for _, key := range keys {
			if !strings.Contains(command, key) {
				t.Fatalf("missing selected key: %s", key)
			}
			entries = append(entries, key+"=/home/alice/"+key)
		}
		return strings.Join(entries, "\x00") + "\x00", nil
	}}
	scanned := NewUserAwareExecutor(inner, "alice")
	for _, key := range keys {
		if got := scanned.Getenv(key); got != "/home/alice/"+key {
			t.Fatalf("%s used daemon environment: %s", key, got)
		}
	}
	if calls != 1 {
		t.Fatalf("environment probed %d times", calls)
	}
}

// LookPath resolves against ONE login-shell $PATH fetch with stat-based
// candidate walks, not a `which` login shell per tool: each of those
// re-sourced rc files where zsh compinit's "insecure directories" prompt hung.
func TestUserAwareExecutor_LookPathNativePATH(t *testing.T) {
	skipOnWindowsHost(t)
	mock := NewMock()
	mock.SetCommand("/fake/bin:/other/bin", "", 0, "bash", "-c", `printf '%s' "$PATH"`)
	mock.SetExecutable("/other/bin/claude")
	e := NewUserAwareExecutor(mock, "someuser")

	got, err := e.LookPath("claude")
	if err != nil {
		t.Fatalf("LookPath(claude) error: %v", err)
	}
	if got != "/other/bin/claude" {
		t.Errorf("LookPath(claude) = %q, want /other/bin/claude", got)
	}
	if _, err := e.LookPath("missing-tool"); err == nil {
		t.Error("LookPath(missing-tool) = nil error, want not-found")
	}
}

// A non-executable file on PATH must not resolve (exec.LookPath semantics).
func TestUserAwareExecutor_LookPathSkipsNonExecutable(t *testing.T) {
	skipOnWindowsHost(t)
	mock := NewMock()
	mock.SetCommand("/fake/bin", "", 0, "bash", "-c", `printf '%s' "$PATH"`)
	mock.SetFileMtime("/fake/bin/readme", 100) // exists, default mode 0644
	e := NewUserAwareExecutor(mock, "someuser")

	if _, err := e.LookPath("readme"); err == nil {
		t.Error("LookPath(readme) resolved a non-executable file")
	}
}

// A failed $PATH fetch degrades to the per-tool `which` probe.
func TestUserAwareExecutor_LookPathFallsBackToWhich(t *testing.T) {
	skipOnWindowsHost(t)
	mock := NewMock()
	mock.SetCommandError(errMockPathFetch, "bash", "-c", `printf '%s' "$PATH"`)
	mock.SetCommand("/usr/local/bin/claude\n", "", 0, "bash", "-c", "which 'claude'")
	e := NewUserAwareExecutor(mock, "someuser")

	got, err := e.LookPath("claude")
	if err != nil {
		t.Fatalf("LookPath fallback error: %v", err)
	}
	if got != "/usr/local/bin/claude" {
		t.Errorf("LookPath fallback = %q, want /usr/local/bin/claude", got)
	}
}

// A caller that gives up mid-fetch must not pin the fallback for the process.
func TestUserAwareExecutor_PATHFetchRetriedAfterCallerCancel(t *testing.T) {
	skipOnWindowsHost(t)
	service := NewMock()
	service.SetExecutable("/fake/bin/uv")
	ctx, cancel := context.WithCancel(context.Background())
	inner := &userContextExecutor{
		Executor: service,
		runAsUser: func(callCtx context.Context, _, command string) (string, error) {
			if ctx.Err() == nil {
				cancel() // caller gives up while the fetch is in flight
				return "", context.Canceled
			}
			if strings.Contains(command, "$PATH") {
				return "/fake/bin", nil
			}
			return "", errMockPathFetch
		},
	}
	e := NewUserAwareExecutor(inner, "someuser")
	_, _ = LookPathWithContext(ctx, e, "uv")

	if got, err := e.LookPath("uv"); err != nil || got != "/fake/bin/uv" {
		t.Errorf("LookPath(uv) = %q, %v; want /fake/bin/uv", got, err)
	}
}

// Path-containing names (e.g. app-bundle binaries) are checked as-is, not
// joined onto PATH entries.
func TestUserAwareExecutor_LookPathAbsoluteName(t *testing.T) {
	skipOnWindowsHost(t)
	mock := NewMock()
	mock.SetCommand("/fake/bin", "", 0, "bash", "-c", `printf '%s' "$PATH"`)
	mock.SetExecutable("/opt/homebrew/opt/ampcode/bin/amp")
	e := NewUserAwareExecutor(mock, "someuser")

	got, err := e.LookPath("/opt/homebrew/opt/ampcode/bin/amp")
	if err != nil || got != "/opt/homebrew/opt/ampcode/bin/amp" {
		t.Errorf("LookPath(abs) = %q, %v; want /opt/homebrew/opt/ampcode/bin/amp", got, err)
	}
	if _, err := e.LookPath("/opt/missing/amp"); err == nil {
		t.Error("LookPath(missing abs) = nil error, want not-found")
	}
}

type blockingStatExecutor struct {
	*Mock
	release chan struct{}
}

func (e *blockingStatExecutor) Stat(path string) (os.FileInfo, error) {
	<-e.release
	return e.Mock.Stat(path)
}

// A PATH entry on a hung mount must not hold LookPath past the caller's ctx.
func TestUserAwareExecutor_LookPathStatBoundedByContext(t *testing.T) {
	skipOnWindowsHost(t)
	mock := NewMock()
	mock.SetCommand("/nfs/bin", "", 0, "bash", "-c", `printf '%s' "$PATH"`)
	inner := &blockingStatExecutor{Mock: mock, release: make(chan struct{})}
	defer close(inner.release)
	e := NewUserAwareExecutor(inner, "someuser")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := LookPathWithContext(ctx, e, "uv"); err == nil {
		t.Fatal("LookPathWithContext() error = nil, want deadline")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("LookPathWithContext took %s with a hung Stat", elapsed)
	}
}

var errMockPathFetch = fmt.Errorf("mock: PATH fetch failed")

// The user-aware PATH lookup only exists for Unix targets (on Windows
// NewUserAwareExecutor returns the inner executor) and uses host path rules.
func skipOnWindowsHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("user-aware PATH lookup is Unix-only")
	}
}
