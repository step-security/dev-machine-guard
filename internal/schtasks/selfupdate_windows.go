//go:build windows

package schtasks

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
	"github.com/step-security/dev-machine-guard/internal/winproc"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// instanceMutex is the scan singleton (internal/lock).
var instanceMutex = `Global\StepSecurityDevMachineGuard`

// stopDMGProcessesPlatform waits up to wait for a running scan to release the
// instance mutex, then terminates every process (other than this one) whose
// image lives under root: launchers, agents and bootstraps from versions\,
// seed\ or the root itself. Fixes the files-in-use reboot of M-18.
func stopDMGProcessesPlatform(root string, wait time.Duration, log *progress.Logger) error {
	if waitForInstanceMutex(wait) {
		log.Debug("instance mutex free; no scan running")
	} else {
		log.Warn("a scan still holds the instance mutex after %s; terminating DMG processes", wait)
	}
	return terminateUnder(root, log)
}

// waitForInstanceMutex reports whether the mutex is absent or was acquired
// (and released) within wait. Ownership is per thread, so the wait and the
// release run on one locked OS thread.
func waitForInstanceMutex(wait time.Duration) bool {
	res := make(chan bool, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread exits with the goroutine
		name, _ := windows.UTF16PtrFromString(instanceMutex)
		h, err := windows.OpenMutex(windows.SYNCHRONIZE|windows.MUTEX_MODIFY_STATE, false, name)
		if err != nil {
			res <- errors.Is(err, windows.ERROR_FILE_NOT_FOUND)
			return
		}
		defer func() { _ = windows.CloseHandle(h) }()
		ev, _ := windows.WaitForSingleObject(h, uint32(wait/time.Millisecond)) // #nosec G115 -- bounded constant
		if ev == windows.WAIT_OBJECT_0 || ev == windows.WAIT_ABANDONED {
			_ = windows.ReleaseMutex(h)
			res <- true
			return
		}
		res <- false
	}()
	return <-res
}

// terminateUnder stops every DMG process under root, then waits (bounded)
// until no process holds an MSI-owned file, since a terminated process can
// keep its image held for a while (D29). This process's own image (the
// uninstall action runs the seed agent) can't be waited for and is skipped.
func terminateUnder(root string, log *progress.Logger) error {
	stopped, err := winproc.StopUnder(root)
	for _, img := range stopped {
		log.Progress("Stopped running DMG process %s", img)
	}
	self, _ := os.Executable()
	var files []string
	for _, f := range (updatestate.Layout{InstallRoot: root}).MSIOwnedFiles() {
		if !strings.EqualFold(filepath.Clean(f), filepath.Clean(self)) {
			files = append(files, f)
		}
	}
	if held := winproc.WaitReleased(files, releaseWait, 50*time.Millisecond); len(held) > 0 {
		log.Warn("still held after %s: %s", releaseWait, strings.Join(held, ", "))
	}
	return err
}

// releaseWait bounds the wait for MSI-owned files to be released.
const releaseWait = 30 * time.Second

func stopProcess(h windows.Handle) error { return winproc.StopProcess(h) }

// deleteRunningVersionPlatform removes HKLM\Software\StepSecurity\RunningVersion
// (updater-owned). AgentVersion is MSI-owned and left to the MSI.
func deleteRunningVersionPlatform() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\StepSecurity`, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	defer k.Close()
	if err := k.DeleteValue("RunningVersion"); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}
