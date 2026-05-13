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
	"strings"
	"sync"
	"time"
)

// Executor defines the interface for all OS interactions.
// Every detector depends on this interface, enabling full unit-test coverage via mocks.
type Executor interface {
	// Run executes a command and returns stdout, stderr, and exit code.
	Run(ctx context.Context, name string, args ...string) (stdout, stderr string, exitCode int, err error)
	// RunWithTimeout executes a command with a timeout.
	RunWithTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) (stdout, stderr string, exitCode int, err error)
	// RunInDir executes a command with a working directory and timeout.
	// Avoids shell quoting issues with cd on Windows.
	RunInDir(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) (stdout, stderr string, exitCode int, err error)
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
	// EvalSymlinks resolves symbolic links in a path. Returns the resolved
	// canonical path. If the path is not a symlink, returns it unchanged.
	EvalSymlinks(path string) (string, error)
	// LoggedInUser returns the actual logged-in console user.
	// When running as root on macOS (e.g., via LaunchDaemon), this detects the
	// real console user via /dev/console rather than returning root.
	// Falls back to CurrentUser() when not root or on non-macOS platforms.
	LoggedInUser() (*user.User, error)
	// GOOS returns the runtime operating system.
	GOOS() string
	// IsAppleCLTStub reports whether binPath is an Apple Command Line Tools
	// shim (under /usr/bin/) that would trigger the macOS "install developer
	// tools" GUI prompt when invoked. Returns false on non-darwin systems, for
	// paths outside /usr/bin/, or when CLT is installed. Detectors must guard
	// every Run/RunWithTimeout on /usr/bin/-resolved binaries with this check
	// to avoid disrupting end users on machines without CLT installed.
	IsAppleCLTStub(ctx context.Context, binPath string) bool
}

// Real implements Executor using actual OS calls.
type Real struct {
	cltOnce    sync.Once
	cltPresent bool
}

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

func (r *Real) RunInDir(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
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
	if ctx.Err() == context.DeadlineExceeded {
		return stdout.String(), stderr.String(), 124, fmt.Errorf("command timed out after %s", timeout)
	}
	return stdout.String(), stderr.String(), exitCode, nil
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

func (r *Real) EvalSymlinks(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}

func (r *Real) LoggedInUser() (*user.User, error) {
	if runtime.GOOS != "darwin" || !r.IsRoot() {
		return r.CurrentUser()
	}

	// On macOS running as root, detect the console user.
	// This mirrors the bash script's get_logged_in_user_info() which uses
	// stat -f%Su /dev/console to find who is actually logged in.
	ctx := context.Background()
	stdout, _, _, err := r.Run(ctx, "stat", "-f%Su", "/dev/console")
	if err != nil {
		return r.CurrentUser()
	}

	username := strings.TrimSpace(stdout)
	if username == "" || username == "root" || username == "_windowserver" {
		return r.CurrentUser()
	}

	u, err := user.Lookup(username)
	if err != nil {
		return r.CurrentUser()
	}

	return u, nil
}

func (r *Real) GOOS() string {
	return runtime.GOOS
}

// appleCLTStubBinaries is the explicit set of /usr/bin/ paths that Apple
// ships as Command Line Tools shims. Invoking any of these on a Mac without
// CLT installed pops a GUI install prompt. A "/usr/bin/" prefix check alone
// would over-match: /usr/bin/ssh, /usr/bin/ls, /usr/bin/env etc. are base
// system binaries that work fine without CLT.
//
// Extend this set when introducing a detector that invokes another /usr/bin/
// binary Apple wraps as a CLT shim (common examples: git, make, clang,
// clang++, cc, c++, gcc, g++, swift, swiftc, gdb, lldb).
var appleCLTStubBinaries = map[string]struct{}{
	"/usr/bin/python3": {},
	"/usr/bin/pip3":    {},
}

// IsAppleCLTStub reports whether binPath is an Apple Command Line Tools shim
// that would trigger the macOS "install developer tools" GUI prompt when
// invoked. Returns true iff:
//  1. GOOS is darwin,
//  2. binPath is a known Apple CLT shim (see appleCLTStubBinaries), AND
//  3. Xcode Command Line Tools are not installed (`xcode-select -p` fails).
//
// The CLT-presence result is cached per Real instance via sync.Once. The
// probe deliberately uses context.Background() (with its own 5 s timeout)
// rather than the caller-provided ctx: sync.Once consumes the slot on the
// first call, so a caller arriving with a canceled or near-deadline ctx
// could otherwise poison the cache with cltPresent=false and make every
// subsequent check treat real binaries as stubs. The caller's ctx is
// retained in the signature for symmetry with the Executor interface.
//
// `xcode-select -p` itself does NOT trigger the install prompt — it just
// prints the developer-dir path or exits non-zero when CLT is absent.
func (r *Real) IsAppleCLTStub(_ context.Context, binPath string) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	if _, ok := appleCLTStubBinaries[binPath]; !ok {
		return false
	}
	r.cltOnce.Do(func() {
		probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(probeCtx, "xcode-select", "-p")
		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		err := cmd.Run()
		r.cltPresent = err == nil && strings.TrimSpace(stdout.String()) != ""
	})
	return !r.cltPresent
}
