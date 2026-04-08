//go:build windows

package lock

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var lockFilePath = filepath.Join(os.TempDir(), "stepsecurity-dev-machine-guard.lock")

// isProcessAlive checks if a process with the given PID exists using tasklist.
func isProcessAlive(pid int) bool {
	cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return !strings.Contains(string(output), "No tasks")
}
