package executor

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"
)

// UserAwareExecutor wraps an Executor and delegates LookPath/Run/RunWithTimeout/
// RunInDir to the logged-in user's login shell (with rc files sourced for a full
// PATH). This ensures commands like "brew list", "pip3 list", "npm --version"
// execute in the user's context with their real PATH — whether the agent runs
// as root (sudo to the user) or as the user itself under a LaunchAgent. launchd
// strips PATH in both cases, so package managers installed via nvm/fnm/homebrew
// aren't found by a bare exec.
//
// All other Executor methods are forwarded unchanged.
type UserAwareExecutor struct {
	inner    Executor
	username string // logged-in user to delegate to; empty = no delegation
}

// NewUserAwareExecutor returns a wrapped executor that runs commands through the
// given user's login shell (rc files sourced for a full PATH) on Unix, in both
// deployment modes:
//   - root (LaunchDaemon / MDM "Run Script"): RunAsUser sudo's to the user.
//   - non-root (LaunchAgent's periodic fire): RunAsUser runs as the current user.
//
// launchd hands both a stripped PATH, so package managers (brew/pip3/npm via
// nvm/fnm/homebrew/npm-global) need the user's rc-sourced shell to be resolved.
// Passes through to the inner executor unchanged when username is empty or on Windows.
func NewUserAwareExecutor(inner Executor, username string) Executor {
	if username == "" || inner.GOOS() == "windows" {
		return inner // no wrapping needed
	}
	return &UserAwareExecutor{inner: inner, username: username}
}

// posixShellQuote wraps s in single quotes so it survives the shell's word-
// splitting and globbing when embedded in a command string for RunAsUser,
// escaping any embedded single quote (POSIX close-quote, escaped quote, reopen). Every command name, argument and
// path handed to RunAsUser must be quoted — otherwise an argument containing
// spaces (a "/Applications/LM Studio.app/..." path, a multi-word PlistBuddy
// "-c" expression) is split into multiple argv entries and the command fails.
// UserAwareExecutor never wraps on Windows (NewUserAwareExecutor passes through
// there), so POSIX single-quote quoting is sufficient.
func posixShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (e *UserAwareExecutor) Run(ctx context.Context, name string, args ...string) (string, string, int, error) {
	cmd := posixShellQuote(name)
	for _, a := range args {
		cmd += " " + posixShellQuote(a)
	}
	stdout, err := e.inner.RunAsUser(ctx, e.username, cmd)
	if err != nil {
		exitCode := 1
		_, _ = fmt.Sscanf(err.Error(), "command exited with code %d", &exitCode)
		return stdout, err.Error(), exitCode, err
	}
	return stdout, "", 0, nil
}

func (e *UserAwareExecutor) RunWithTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stdout, stderr, code, err := e.Run(ctx, name, args...)
	if ctx.Err() == context.DeadlineExceeded {
		return stdout, stderr, 124, fmt.Errorf("command timed out after %s", timeout)
	}
	return stdout, stderr, code, err
}

func (e *UserAwareExecutor) RunInDir(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// For user-aware execution, use cd + command via RunAsUser. Quote the dir,
	// command and every arg so paths with spaces (e.g. "/Users/me/My App")
	// survive the shell's word-splitting as single argv entries.
	cmd := "cd " + posixShellQuote(dir) + " && " + posixShellQuote(name)
	for _, a := range args {
		cmd += " " + posixShellQuote(a)
	}
	stdout, err := e.inner.RunAsUser(ctx, e.username, cmd)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return stdout, "", 124, fmt.Errorf("command timed out after %s", timeout)
		}
		return stdout, err.Error(), 1, err
	}
	return stdout, "", 0, nil
}

func (e *UserAwareExecutor) RunAsUser(ctx context.Context, username, command string) (string, error) {
	return e.inner.RunAsUser(ctx, username, command)
}

func (e *UserAwareExecutor) LookPath(name string) (string, error) {
	stdout, err := e.inner.RunAsUser(context.Background(), e.username, "which "+posixShellQuote(name))
	path := strings.TrimSpace(stdout)
	if err != nil || path == "" || !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("%s not found in user PATH", name)
	}
	return path, nil
}

// --- Pass-through methods ---

func (e *UserAwareExecutor) FileExists(path string) bool          { return e.inner.FileExists(path) }
func (e *UserAwareExecutor) DirExists(path string) bool           { return e.inner.DirExists(path) }
func (e *UserAwareExecutor) ReadFile(path string) ([]byte, error) { return e.inner.ReadFile(path) }
func (e *UserAwareExecutor) ReadDir(path string) ([]os.DirEntry, error) {
	return e.inner.ReadDir(path)
}
func (e *UserAwareExecutor) Stat(path string) (os.FileInfo, error) { return e.inner.Stat(path) }
func (e *UserAwareExecutor) Hostname() (string, error)             { return e.inner.Hostname() }
func (e *UserAwareExecutor) Getenv(key string) string              { return e.inner.Getenv(key) }
func (e *UserAwareExecutor) IsRoot() bool                          { return e.inner.IsRoot() }
func (e *UserAwareExecutor) CurrentUser() (*user.User, error)      { return e.inner.CurrentUser() }
func (e *UserAwareExecutor) HomeDir(username string) (string, error) {
	return e.inner.HomeDir(username)
}
func (e *UserAwareExecutor) Glob(pattern string) ([]string, error) { return e.inner.Glob(pattern) }
func (e *UserAwareExecutor) EvalSymlinks(path string) (string, error) {
	return e.inner.EvalSymlinks(path)
}
func (e *UserAwareExecutor) LoggedInUser() (*user.User, error) { return e.inner.LoggedInUser() }
func (e *UserAwareExecutor) GOOS() string                      { return e.inner.GOOS() }
func (e *UserAwareExecutor) IsAppleCLTStub(ctx context.Context, binPath string) bool {
	return e.inner.IsAppleCLTStub(ctx, binPath)
}
func (e *UserAwareExecutor) DiskCapacityBytes(path string) uint64 {
	return e.inner.DiskCapacityBytes(path)
}
