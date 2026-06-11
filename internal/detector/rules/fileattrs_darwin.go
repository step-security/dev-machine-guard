//go:build darwin

package rules

import (
	"os"
	"syscall"
)

// statTimes returns birth time and ctime from the macOS stat structure.
func statTimes(info os.FileInfo) (createdAt, changedAt int64) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0
	}
	return int64(st.Birthtimespec.Sec), int64(st.Ctimespec.Sec)
}
