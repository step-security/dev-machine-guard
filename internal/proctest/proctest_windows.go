//go:build windows

package proctest

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// killTreeOnCancel keeps exec's default cancel (kill the child); helpers
// it started exit through Guard's parent watch.
func killTreeOnCancel(*exec.Cmd) {}

func killTree(pid int) {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid)) // #nosec G115 -- pid from a process snapshot
	if err != nil {
		return
	}
	_ = windows.TerminateProcess(h, 1)
	_ = windows.CloseHandle(h)
}

// watchParent calls onExit once the parent process exits. A parent that
// can't be opened for another reason (access) is not watched.
func watchParent(onExit func()) {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(os.Getppid())) // #nosec G115 -- parent pid
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			onExit() // already gone
		}
		return
	}
	go func() {
		if ev, _ := windows.WaitForSingleObject(h, windows.INFINITE); ev == windows.WAIT_OBJECT_0 {
			onExit()
		}
	}()
}

// WaitGone reports whether pid exits within d.
func WaitGone(pid int, d time.Duration) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid)) // #nosec G115 -- test pid
	if err != nil {
		return true
	}
	defer func() { _ = windows.CloseHandle(h) }()
	ev, _ := windows.WaitForSingleObject(h, uint32(d.Milliseconds())) // #nosec G115 -- short test wait
	return ev == windows.WAIT_OBJECT_0
}

func children() ([]int, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	self := uint32(os.Getpid()) // #nosec G115 -- pid
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []int
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		// A console app can own its conhost.exe; that is not a test's child.
		if pe.ParentProcessID == self && pe.ProcessID != self && !strings.EqualFold(windows.UTF16ToString(pe.ExeFile[:]), "conhost.exe") {
			out = append(out, int(pe.ProcessID))
		}
	}
	return out, nil
}
