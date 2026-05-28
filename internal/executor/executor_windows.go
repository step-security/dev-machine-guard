//go:build windows

package executor

import (
	"context"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
)

// setupKillgroupOnCancel is a no-op on Windows for now. The Unix equivalent
// uses Setpgid + kill(-pgid) to kill grandchildren on ctx cancel. The
// Windows analogue (JobObject + CREATE_BREAKAWAY_FROM_JOB) is a larger
// change and is tracked separately — Windows hosts are less exposed to the
// unreaped-helper hang because most scanned binaries are not Electron apps
// invoked under launchd.
func setupKillgroupOnCancel(cmd *exec.Cmd) {}

func (r *Real) IsRoot() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func (r *Real) RunAsUser(ctx context.Context, _ string, command string) (string, error) {
	stdout, _, _, err := r.Run(ctx, "cmd", "/c", command)
	return strings.TrimSpace(stdout), err
}

func (r *Real) DiskCapacityBytes(path string) uint64 {
	if path == "" {
		return 0
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0
	}
	var freeBytesAvail, totalBytes, totalFreeBytes uint64
	if err := windows.GetDiskFreeSpaceEx(pathPtr, &freeBytesAvail, &totalBytes, &totalFreeBytes); err != nil {
		return 0
	}
	return totalBytes
}
