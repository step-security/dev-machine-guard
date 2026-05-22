//go:build windows

package winproc

import (
	"os/exec"
	"syscall"
)

// CREATE_NO_WINDOW. Spelled out so callers don't drag in
// golang.org/x/sys/windows for one constant.
const createNoWindow uint32 = 0x08000000

// HideWindow tells the child not to allocate a console. Safe to call
// twice or on a cmd whose SysProcAttr is already set: HideWindow is
// merged, not overwritten, and CREATE_NO_WINDOW is OR'd into
// CreationFlags. Without this, every powershell/cmd/.cmd subprocess
// Go spawns under Task Scheduler flashes a console window.
func HideWindow(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= createNoWindow
}
