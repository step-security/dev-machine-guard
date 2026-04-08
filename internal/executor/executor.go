package executor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"time"
)

// Executor defines the interface for all OS interactions.
// Every detector depends on this interface, enabling full unit-test coverage via mocks.
type Executor interface {
	// Run executes a command and returns stdout, stderr, and exit code.
	Run(ctx context.Context, name string, args ...string) (stdout, stderr string, exitCode int, err error)
	// RunWithTimeout executes a command with a timeout.
	RunWithTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) (stdout, stderr string, exitCode int, err error)
	// RunAsUser runs a shell command as a specific user (for root -> user delegation).
	RunAsUser(ctx context.Context, username, command string) (string, error)
	// LookPath searches for an executable in PATH.
	LookPath(name string) (string, error)
	// FileExists checks if a file exists and is not a directory.
	FileExists(path string) bool
	// DirExists checks if a directory exists.
	DirExists(path string) bool
	// ReadFile reads a file's contents.
	ReadFile(path string) ([]byte, error)
	// ReadDir lists directory entries.
	ReadDir(path string) ([]os.DirEntry, error)
	// Stat returns file info.
	Stat(path string) (os.FileInfo, error)
	// Hostname returns the system hostname.
	Hostname() (string, error)
	// Getenv reads an environment variable.
	Getenv(key string) string
	// IsRoot returns true if the process is running as root.
	IsRoot() bool
	// CurrentUser returns the current OS user.
	CurrentUser() (*user.User, error)
	// HomeDir returns the home directory for a given username.
	HomeDir(username string) (string, error)
	// Glob returns filenames matching a pattern.
	Glob(pattern string) ([]string, error)
	// GOOS returns the runtime operating system.
	GOOS() string
}

// Real implements Executor using actual OS calls.
type Real struct{}

func NewReal() *Real { return &Real{} }

func (r *Real) Run(ctx context.Context, name string, args ...string) (string, string, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return stdout.String(), stderr.String(), -1, err
		}
	}
	return stdout.String(), stderr.String(), exitCode, nil
}

func (r *Real) RunWithTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stdout, stderr, code, err := r.Run(ctx, name, args...)
	if ctx.Err() == context.DeadlineExceeded {
		return stdout, stderr, 124, fmt.Errorf("command timed out after %s", timeout)
	}
	return stdout, stderr, code, err
}

func (r *Real) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (r *Real) FileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func (r *Real) DirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func (r *Real) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (r *Real) ReadDir(path string) ([]os.DirEntry, error) {
	return os.ReadDir(path)
}

func (r *Real) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

func (r *Real) Hostname() (string, error) {
	return os.Hostname()
}

func (r *Real) Getenv(key string) string {
	return os.Getenv(key)
}

func (r *Real) CurrentUser() (*user.User, error) {
	return user.Current()
}

func (r *Real) HomeDir(username string) (string, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

func (r *Real) Glob(pattern string) ([]string, error) {
	return filepath.Glob(pattern)
}

func (r *Real) GOOS() string {
	return runtime.GOOS
}
