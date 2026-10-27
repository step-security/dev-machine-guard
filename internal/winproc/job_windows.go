//go:build windows

package winproc

import (
	"fmt"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

var procNtResumeProcess = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")

// StartInJob starts cmd suspended, assigns it to job, then resumes it, so
// nothing the child spawns can escape the job. If the child can't be put in
// the job it is terminated and reaped and an error returned: no child ever
// runs uncontained.
func StartInJob(cmd *exec.Cmd, job windows.Handle) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	if err := cmd.Start(); err != nil {
		return err
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_SUSPEND_RESUME, false, uint32(cmd.Process.Pid)) // #nosec G115 -- a live pid
	if err == nil {
		err = windows.AssignProcessToJobObject(job, h)
		if err == nil {
			if status, _, _ := procNtResumeProcess.Call(uintptr(h)); status != 0 {
				err = fmt.Errorf("resume: NTSTATUS 0x%x", status)
			}
		}
		_ = windows.CloseHandle(h)
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("job setup: %w", err)
	}
	return nil
}
