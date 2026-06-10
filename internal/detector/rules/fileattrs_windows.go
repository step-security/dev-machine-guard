//go:build windows

package rules

import (
	"os"
	"syscall"
)

// statTimes returns the creation time from the Windows file attributes. There
// is no ctime (inode-change time) concept on Windows, so changed is 0.
func statTimes(info os.FileInfo) (createdAt, changedAt int64) {
	st, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return 0, 0
	}
	return st.CreationTime.Nanoseconds() / 1e9, 0
}
