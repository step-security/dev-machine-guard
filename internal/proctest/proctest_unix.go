//go:build !windows

package proctest

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// killTreeOnCancel starts cmd in its own process group and kills the group
// on cancel, so grandchildren go too.
func killTreeOnCancel(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error {
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		} else if err != nil {
			return err
		}
		return nil
	}
}

// killTree kills pid and the process group it leads, if any. A group id
// equal to pid can only be pid's own group while pid is alive.
func killTree(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

// watchParent calls onExit once this process is reparented: its parent
// exited.
func watchParent(onExit func()) {
	ppid := os.Getppid()
	if ppid == 1 {
		onExit()
		return
	}
	go func() {
		for {
			time.Sleep(200 * time.Millisecond)
			if os.Getppid() != ppid {
				onExit()
				return
			}
		}
	}()
}

// WaitGone reports whether pid (not a child of this process) exits within d.
func WaitGone(pid int, d time.Duration) bool {
	for end := time.Now().Add(d); ; time.Sleep(50 * time.Millisecond) {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return true
		}
		if time.Now().After(end) {
			return false
		}
	}
}
