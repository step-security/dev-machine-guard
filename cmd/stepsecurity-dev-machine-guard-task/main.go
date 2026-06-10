//go:build windows

// Command stepsecurity-dev-machine-guard-task is a GUI-subsystem
// launcher that invokes a console-subsystem child under
// CREATE_NO_WINDOW. Built with `-ldflags "-H windowsgui"`.
//
// Why a separate binary: Windows allocates a console for any
// console-subsystem process whose parent has none. Task Scheduler under
// /ru INTERACTIVE is such a parent, so a console-subsystem child
// invoked directly would always flash a window. The only fully reliable
// suppression is for the parent CreateProcess call to pass
// CREATE_NO_WINDOW, and the only way to be that parent without flashing
// our own console is to be GUI-subsystem.
//
// Two operating modes (target-resolution lives in internal/launcher so
// it can be unit-tested cross-platform):
//
//   - Default. Invoked without --exec, the launcher spawns its sibling
//     stepsecurity-dev-machine-guard.exe and forwards argv unchanged.
//     This is what the MSI install layout's scheduled-task action uses.
//
//   - --exec mode. Invoked as `task.exe --exec <exe> [args...]`, the
//     launcher spawns <exe> (exec.LookPath resolved) with the remaining
//     args. Used by the PowerShell loader's scheduled task to wrap
//     `powershell.exe -File loader.ps1 send-telemetry` in the same
//     no-console envelope the MSI flow uses for the agent.
//
// The agent (and any --exec target) stays console-subsystem so
// interactive CLI use continues to work normally.
//
// Lifecycle: the child is assigned to a Job Object with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE so it dies when the launcher does
// — including under Stop-ScheduledTask, which only terminates the
// registered action's PID.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/step-security/dev-machine-guard/internal/launcher"
	"golang.org/x/sys/windows"
)

const createNoWindow uint32 = 0x08000000

func main() {
	os.Exit(run(os.Args[1:]))
}

// run is split out so the entrypoint stays one line. argv is the slice
// after the program name (os.Args[1:] in main); accepting it explicitly
// keeps the windows-only test path open if we add one later.
func run(argv []string) int {
	target, childArgs, err := launcher.ResolveTarget(argv)
	if err != nil {
		// Two distinct failure shapes, matched to the legacy contract:
		//
		//   - Default mode (no --exec): the launcher silently exits 1.
		//     This preserves byte-for-byte compatibility with MSI installs
		//     that the pre-1.11.5 launcher served. Task Scheduler records
		//     "LastTaskResult=1" — same value MSI deployments have always
		//     observed when the sibling agent is absent. A behavioral
		//     change here would shift downstream dashboards/alerts that
		//     key on the result code.
		//
		//   - --exec mode: the caller asked for a feature; surface the
		//     concrete misuse (missing target, unresolved PATH, etc.) on
		//     stderr with a distinct exit code so dispatch failures are
		//     diagnosable.
		if len(argv) > 0 && argv[0] == launcher.ExecFlag {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		return 1
	}

	cmd := exec.Command(target, childArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}

	if err := cmd.Start(); err != nil {
		return 1
	}

	// Best-effort: bind the child to a kill-on-close job. The job
	// handle stays open in this process; the kernel closes it on our
	// exit, which fires the kill. Failure here only weakens lifecycle
	// (orphan possible on forced termination), not the work the child
	// was started to do.
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
