//go:build windows

package launcher

import (
	"fmt"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/step-security/dev-machine-guard/internal/winproc"
)

// CreateNoWindow is CREATE_NO_WINDOW: the console-subsystem child gets no
// console, so nothing flashes under the INTERACTIVE scan task.
const CreateNoWindow uint32 = 0x08000000

// SpawnHidden starts the child under CREATE_NO_WINDOW inside a kill-on-close
// job (joined before the child runs; if it can't be, nothing runs), so the child's whole tree dies with this process (Stop-ScheduledTask
// and the task's ExecutionTimeLimit only terminate the action's PID) and a
// deadline terminates the whole tree, nested launcher job included.
func SpawnHidden(path string, args, env []string, deadline time.Duration, onStart func()) SpawnResult {
	cmd := exec.Command(path, args...) // #nosec G204 -- the bootstrap launches its own resolved version binaries
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: CreateNoWindow}
	job, err := newJob()
	if err != nil {
		return SpawnResult{Err: fmt.Errorf("kill-on-close job: %w", err)}
	}
	defer func() { _ = windows.CloseHandle(job) }()
	if err := winproc.StartInJob(cmd, job); err != nil {
		return SpawnResult{Err: err}
	}
	if onStart != nil {
		onStart()
	}
	return waitWithDeadline(cmd, deadline, func() {
		if windows.TerminateJobObject(job, uint32(ExitKilled)) != nil {
			_ = cmd.Process.Kill()
		}
	})
}

// newJob is NewKillOnCloseJob; tests replace it.
var newJob = NewKillOnCloseJob

// NewKillOnCloseJob creates a job whose processes die when its last handle
// closes. BREAKAWAY_OK lets the agent's CREATE_BREAKAWAY_FROM_JOB spawns
// (WSL guest scans) outlive the run instead of being killed.
func NewKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK,
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

// AssignToJob puts the process pid into job.
func AssignToJob(job windows.Handle, pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid)) // #nosec G115 -- pid from os.Process
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	return windows.AssignProcessToJobObject(job, h)
}
