//go:build windows

// Command stepsecurity-dev-machine-guard-task is a GUI-subsystem
// launcher that invokes the console-subsystem agent under
// CREATE_NO_WINDOW. Built with `-ldflags "-H windowsgui"`.
//
// Why a separate binary: Windows allocates a console for any
// console-subsystem process whose parent has none. Task Scheduler
// under /ru INTERACTIVE is such a parent, so the agent itself would
// always flash a window. The only fully-reliable suppression is for
// the parent CreateProcess call to pass CREATE_NO_WINDOW, and the
// only way to be that parent without flashing our own console is to
// be GUI-subsystem. The agent stays console-subsystem so interactive
// CLI use (install, configure, manual scans) still works normally.
//
// Layout: both binaries sit in the same directory. The scheduled task
// points at this launcher; arguments forward unchanged.
//
// Lifecycle: the agent is assigned to a Job Object with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE so it dies when the launcher
// does — including under Stop-ScheduledTask, which only terminates
// the registered action's PID.
package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	createNoWindow uint32 = 0x08000000
	agentBinary           = "stepsecurity-dev-machine-guard.exe"
)

func main() {
	os.Exit(run())
}

func run() int {
	me, err := os.Executable()
	if err != nil {
		return 1
	}
	agent := filepath.Join(filepath.Dir(me), agentBinary)
	if _, err := os.Stat(agent); err != nil {
		return 1
	}

	cmd := exec.Command(agent, os.Args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}

	if err := cmd.Start(); err != nil {
		return 1
	}

	// Best-effort: bind the agent to a kill-on-close job. The job
	// handle stays open in this process; the kernel closes it on our
	// exit, which fires the kill. Failure here only weakens lifecycle
	// (orphan possible on forced termination), not the scan itself.
	if job, jerr := newKillOnCloseJob(); jerr == nil {
		if h, oerr := windows.OpenProcess(
			windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
			false,
			uint32(cmd.Process.Pid),
		); oerr == nil {
			_ = windows.AssignProcessToJobObject(job, h)
			_ = windows.CloseHandle(h)
		}
	}

	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		return 1
	}
	return 0
}

func newKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}
