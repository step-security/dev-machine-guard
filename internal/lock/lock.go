package lock

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/paths"
)

// Lock represents an acquired instance lock.
type Lock struct {
	path string
}

// lockFileName is the PID file's basename. When a per-user device identity is
// in force (paths.UserScope non-empty) the scope is suffixed, so two users'
// concurrent sessions on one machine — two devices — never contend for one
// lock; with a shared identity the name, and the directory, are unchanged.
func lockFileName() string {
	if scope := paths.UserScope(); scope != "" {
		return "stepsecurity-dev-machine-guard-" + scope + ".lock"
	}
	return "stepsecurity-dev-machine-guard.lock"
}

// Acquire obtains an exclusive instance lock using atomic file creation.
// Returns error if another instance is running.
func Acquire(_ executor.Executor) (*Lock, error) {
	lockFilePath := lockPath()
	// Check for existing lock file
	if data, err := os.ReadFile(lockFilePath); err == nil {
		pidStr := strings.TrimSpace(string(data))
		if pid, err := strconv.Atoi(pidStr); err == nil && pid > 0 {
			if isProcessAlive(pid) {
				return nil, fmt.Errorf("another instance is already running (PID %d)", pid)
			}
		}
		// Stale lock — remove before attempting atomic create
		_ = os.Remove(lockFilePath)
	}

	// Atomic create: O_CREATE|O_EXCL fails if file already exists,
	// preventing two processes from both creating the lock.
	f, err := os.OpenFile(lockFilePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			// Another process created the lock between our check and create
			return nil, fmt.Errorf("another instance is already running (lock file created concurrently)")
		}
		return nil, fmt.Errorf("creating lock file: %w", err)
	}

	_, err = fmt.Fprintf(f, "%d", os.Getpid())
	_ = f.Close()
	if err != nil {
		_ = os.Remove(lockFilePath)
		return nil, fmt.Errorf("writing PID to lock file: %w", err)
	}

	return &Lock{path: lockFilePath}, nil
}

// Release removes the lock file.
func (l *Lock) Release() {
	if l != nil && l.path != "" {
		_ = os.Remove(l.path)
	}
}
