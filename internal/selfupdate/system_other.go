//go:build !windows

package selfupdate

import (
	"os/exec"

	"golang.org/x/sys/unix"
)

func prepareSmoke(*exec.Cmd) {}

func runSmokeCmd(cmd *exec.Cmd) error { return cmd.Run() }

// EnsureConfigACL is Windows-only; elsewhere config.json keeps its mode.
func EnsureConfigACL(string) (bool, error) { return false, nil }

// SetRunningVersion is Windows-only (HKLM RunningVersion).
func SetRunningVersion(string) error { return nil }

// FreeBytes reports the bytes available to this process on path's volume.
func FreeBytes(path string) (uint64, error) {
	var s unix.Statfs_t
	if err := unix.Statfs(path, &s); err != nil {
		return 0, err
	}
	return uint64(s.Bavail) * uint64(s.Bsize), nil // #nosec G115 -- statfs sizes are non-negative
}

// InstallerBusy is Windows-only.
func InstallerBusy() bool { return false }
