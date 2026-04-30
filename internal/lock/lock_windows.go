//go:build windows

package lock

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

var lockFilePath = filepath.Join(os.TempDir(), "stepsecurity-dev-machine-guard.lock")

// isProcessAlive checks if a process with the given PID exists by attempting
// to open a handle to it. This avoids shelling out to tasklist.
// Access-denied means the process exists but is owned by another user/session.
func isProcessAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		// ERROR_ACCESS_DENIED means the process exists but we can't open it
		return err == windows.ERROR_ACCESS_DENIED
	}
	_ = windows.CloseHandle(h)
	return true
}
