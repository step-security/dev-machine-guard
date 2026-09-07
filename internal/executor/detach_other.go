//go:build !windows

package executor

import "syscall"

// detachAttrs puts the child in its own session so it is not killed with the
// parent's process group. Only Windows needs the job-object dance; this exists
// so StartDetached has one shape on every platform.
func detachAttrs() []*syscall.SysProcAttr {
	return []*syscall.SysProcAttr{{Setsid: true}}
}
