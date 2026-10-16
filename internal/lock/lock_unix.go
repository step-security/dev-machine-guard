//go:build !windows

package lock

import (
	"errors"
	"syscall"
)

var lockFilePath = "/tmp/stepsecurity-dev-machine-guard.lock"

// isProcessAlive checks if a process with the given PID exists.
// Returns true if the process is alive (signal 0 succeeds or returns EPERM).
func isProcessAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true // process exists and we can signal it
	}
	// EPERM means the process exists but we don't have permission to signal it
	if errors.Is(err, syscall.EPERM) {
		return true
	}
	return false // ESRCH or other error — process doesn't exist
}
