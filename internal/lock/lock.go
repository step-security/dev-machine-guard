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

// Holder peeks at the lock without acquiring or mutating it: it reports the
// recorded PID and whether that process is alive. (0, false) means no live
// holder — absent file, unparsable content, or a stale PID. The run gate uses
// this to back off QUIETLY when a scan is already running (hourly MDM
// wakeups overlapping a 1-2h scan), instead of reaching Acquire's contention
// path, which reports a failed run to the backend. TOCTOU is fine here:
// Acquire's O_CREATE|O_EXCL remains the authoritative guard for the race
// window, and a racer just keeps today's behavior.
func Holder() (pid int, alive bool) {
	data, err := os.ReadFile(lockFilePath)
	if err != nil {
		return 0, false
	}
	pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	if !isProcessAlive(pid) {
		return 0, false
	}
	return pid, true
}
