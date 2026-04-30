package executor

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"
)

// UserAwareExecutor wraps an Executor and delegates LookPath and RunWithTimeout
// to the logged-in user when the process is running as root. This ensures that
// commands like "brew list", "pip3 list", "npm --version" etc. execute in the
// correct user context, since many tools refuse to run as root or return
// different results for different users.
//
// All other Executor methods are forwarded unchanged.
type UserAwareExecutor struct {
	inner    Executor
	username string // logged-in user to delegate to; empty = no delegation
}

// NewUserAwareExecutor returns a wrapped executor that delegates command execution
// to the given user when running as root on Unix. If username is empty or the
// process is not root, all calls pass through to the inner executor unchanged.
func NewUserAwareExecutor(inner Executor, username string) Executor {
	if username == "" || !inner.IsRoot() || inner.GOOS() == "windows" {
		return inner // no wrapping needed
	}
	return &UserAwareExecutor{inner: inner, username: username}
}

func (e *UserAwareExecutor) Run(ctx context.Context, name string, args ...string) (string, string, int, error) {
	cmd := name
	for _, a := range args {
		cmd += " " + a
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
	// For user-aware execution, use cd + command via RunAsUser
	cmd := "cd " + dir + " && " + name
	for _, a := range args {
		cmd += " " + a
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
	stdout, err := e.inner.RunAsUser(context.Background(), e.username, "which "+name)
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
func (e *UserAwareExecutor) LoggedInUser() (*user.User, error)     { return e.inner.LoggedInUser() }
func (e *UserAwareExecutor) GOOS() string                          { return e.inner.GOOS() }
