//go:build windows

package executor

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// createBreakawayFromJob lets a child escape the parent's job object. Not in
// syscall/x-sys, so it is spelled out here (winbase.h).
const createBreakawayFromJob = 0x01000000

// detachAttrs returns creation flags for a spawn that must outlive this
// process, most-isolated first.
//
// The child gets its own hidden console (CREATE_NO_WINDOW), not none: a
// console app started with DETACHED_PROCESS, as wsl.exe was, allocates a
// fresh visible console when it needs one, so every WSL guest scan opened a
// terminal window on the user's desktop. CREATE_NO_WINDOW is ignored when
// combined with DETACHED_PROCESS, so the two must not be mixed. A console of
// its own still keeps the child independent of ours.
//
// Breakaway is insurance rather than a fix for a measured bug. os/exec puts
// the child in the parent's job object, a job with KILL_ON_JOB_CLOSE would
// take the child with it, and WSL tears a distro down shortly after its last
// Windows-side client exits — so a killed relay means a scan that reported
// "launched" and then quietly never happened. Breakaway fails outright when
// the job forbids it, so the caller retries with the second form; a child
// that shares the job is still better than none.
func detachAttrs() []*syscall.SysProcAttr {
	const flags = syscall.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW
	return []*syscall.SysProcAttr{
		{HideWindow: true, CreationFlags: flags | createBreakawayFromJob},
		{HideWindow: true, CreationFlags: flags},
	}
}
