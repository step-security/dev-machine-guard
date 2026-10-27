//go:build windows

package winproc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileHeld reports whether something holds path: it can't be opened for
// exclusive write access (a running or still-mapped image, or an open
// handle). A missing file is not held.
func fileHeld(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
	}
	_ = windows.CloseHandle(h)
	return false
}

// StopUnder terminates every process (other than this one) whose image
// lives under root and waits up to 5 s for each to exit. It returns the
// images it stopped. Callers then WaitReleased the files they need.
func StopUnder(root string) ([]string, error) {
	prefix := strings.ToLower(filepath.Clean(root)) + `\`
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("process snapshot: %w", err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	self := uint32(os.Getpid()) // #nosec G115 -- a pid fits in uint32
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var stopped []string
	var errs []error
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if pe.ProcessID == self || pe.ProcessID == 0 {
			continue
		}
		h, oerr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pe.ProcessID)
		if oerr != nil {
			continue
		}
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n := uint32(len(buf))
		if qerr := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); qerr == nil {
			img := windows.UTF16ToString(buf[:n])
			if strings.HasPrefix(strings.ToLower(img), prefix) {
				if serr := StopProcess(h); serr != nil {
					errs = append(errs, fmt.Errorf("terminating %s (pid %d): %w", img, pe.ProcessID, serr))
				} else {
					stopped = append(stopped, img)
				}
			}
		}
		_ = windows.CloseHandle(h)
	}
	return stopped, errors.Join(errs...)
}

// StopProcess terminates the process and waits up to 5 s for it to exit.
// A process already exiting (e.g. killed by its kill-on-close job) rejects
// TerminateProcess with ACCESS_DENIED; what counts is that it is gone.
func StopProcess(h windows.Handle) error {
	terr := windows.TerminateProcess(h, 1)
	if ev, _ := windows.WaitForSingleObject(h, 5000); ev == windows.WAIT_OBJECT_0 {
		return nil
	}
	if terr != nil {
		return terr
	}
	return errors.New("still running 5 s after TerminateProcess")
}
