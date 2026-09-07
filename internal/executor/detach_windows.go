//go:build windows

package executor

import "syscall"

// createBreakawayFromJob lets a child escape the parent's job object. Not in
// syscall/x-sys, so it is spelled out here (winbase.h).
const createBreakawayFromJob = 0x01000000

// detachedProcess detaches the child from the parent's console.
const detachedProcess = 0x00000008

// detachAttrs returns creation flags for a spawn that must outlive this
// process, most-isolated first.
//
// Honest status: a plain spawn was NOT observed to fail. Triggering a distro
// scan works identically with and without these flags when the agent runs in a
// live logon session, so this is insurance rather than a fix for a measured
// bug.
//
// It is kept because the failure it guards against is silent and the property
// is load-bearing: os/exec puts the child in the parent's job object, a job
// with KILL_ON_JOB_CLOSE would take the child with it, and WSL tears a distro
// down shortly after its last Windows-side client exits — so a killed relay
// means a scan that reported "launched" and then quietly never happened. The
// case that would expose it (a guest scan outlasting the host run) has not been
// reproduced on the test box, where guest scans finish in ~2s.
//
// Breakaway fails outright when the job forbids it, so the caller retries with
// the second (flags-only) form; a detached child that shares the job is still
// better than none.
func detachAttrs() []*syscall.SysProcAttr {
	return []*syscall.SysProcAttr{
		{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess | createBreakawayFromJob},
		{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess},
	}
}
