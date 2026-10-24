//go:build windows

package awakeclock

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procQueryUnbiasedInterruptTime = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryUnbiasedInterruptTime")

// Awake is QueryUnbiasedInterruptTime (100 ns units since boot, excluding
// sleep and hibernation). Go's own monotonic clock on Windows includes
// sleep, so it can't be used for watchdog deadlines.
func (systemClock) Awake() time.Duration {
	var t uint64
	if r, _, _ := procQueryUnbiasedInterruptTime.Call(uintptr(unsafe.Pointer(&t))); r == 0 {
		return time.Duration(time.Now().UnixNano()) // unavailable: fall back to wall time
	}
	return time.Duration(t) * 100 // #nosec G115 -- interrupt time fits int64 ns for centuries
}
