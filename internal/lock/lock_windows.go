//go:build windows

package lock

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var mutexName = "StepSecurityDevMachineGuard"

func setLockTarget(name string) (old string) { old, mutexName = mutexName, name; return old }

func lockTarget() string { return mutexName }

// mutexSDDL lets any account (Everyone) wait on and release the mutex, so
// SYSTEM, admin and user runs exclude each other; SYSTEM and Administrators
// keep full control.
const mutexSDDL = "D:(A;;0x100001;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)"

// mutexAccess is what we need: SYNCHRONIZE to wait, MUTEX_MODIFY_STATE to release.
const mutexAccess = windows.SYNCHRONIZE | windows.MUTEX_MODIFY_STATE

// acquire owns the mutex on a dedicated OS thread: mutex ownership is
// per-thread, and goroutines migrate, so the wait and ReleaseMutex must both
// run on the same locked thread.
func acquire() (func(), error) {
	res := make(chan error, 1)
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		// Never unlocked: the thread exits with this goroutine.
		runtime.LockOSThread()
		defer close(done)
		h, err := openMutex()
		if err != nil {
			res <- err
			return
		}
		defer func() { _ = windows.CloseHandle(h) }()
		ev, err := windows.WaitForSingleObject(h, 0)
		switch {
		case ev == windows.WAIT_OBJECT_0, ev == windows.WAIT_ABANDONED:
			// Abandoned = previous holder died; we own it now.
		case ev == uint32(windows.WAIT_TIMEOUT):
			res <- fmt.Errorf("%w (mutex %s)", ErrHeld, mutexName)
			return
		default:
			res <- fmt.Errorf("waiting on mutex %s: %w", mutexName, err)
			return
		}
		res <- nil
		<-release
		_ = windows.ReleaseMutex(h)
	}()
	if err := <-res; err != nil {
		return nil, err
	}
	return func() {
		close(release)
		<-done
	}, nil
}

// openMutex creates or opens the machine-wide mutex, falling back to the
// session-local namespace when Global\ is unavailable.
func openMutex() (windows.Handle, error) {
	sd, err := windows.SecurityDescriptorFromString(mutexSDDL)
	if err != nil {
		return 0, fmt.Errorf("building mutex security descriptor: %w", err)
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))

	h, gErr := createMutex(sa, `Global\`+mutexName)
	if gErr == nil {
		return h, nil
	}
	h, lErr := createMutex(sa, `Local\`+mutexName)
	if lErr != nil {
		return 0, fmt.Errorf("creating mutex (Global: %v): %w", gErr, lErr)
	}
	fmt.Fprintf(os.Stderr, "[warn] instance lock: Global mutex unavailable (%v); using session-local mutex\n", gErr)
	return h, nil
}

func createMutex(sa *windows.SecurityAttributes, name string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateMutexEx(sa, p, 0, mutexAccess)
	if h != 0 && (err == nil || errors.Is(err, windows.ERROR_ALREADY_EXISTS)) {
		return h, nil
	}
	if err == nil {
		err = errors.New("CreateMutexEx returned no handle")
	}
	return 0, err
}
