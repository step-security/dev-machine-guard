package lock

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// Lock represents an acquired instance lock.
type Lock struct {
	path string
}

// Acquire obtains an exclusive instance lock using atomic file creation.
// Returns error if another instance is running.
func Acquire(_ executor.Executor) (*Lock, error) {
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

