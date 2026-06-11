//go:build linux

package rules

import (
	"os"
	"syscall"
)

// statTimes returns ctime from the Linux stat structure. Linux's
// syscall.Stat_t exposes no birth time (that requires statx), so created is 0.
func statTimes(info os.FileInfo) (createdAt, changedAt int64) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0
	}
	return 0, int64(st.Ctim.Sec)
}
