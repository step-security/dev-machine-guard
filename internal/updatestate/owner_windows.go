//go:build windows

package updatestate

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

const stillActive = 259 // STILL_ACTIVE

// processStartTime is the creation time of pid.
func processStartTime(pid int) (time.Time, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)) // #nosec G115 -- a pid
	if err != nil {
		return time.Time{}, false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) != nil {
		return time.Time{}, false
	}
	return time.Unix(0, created.Nanoseconds()).UTC(), true
}

// processLiveness: gone (or exited, or the PID reused by a process with
// another creation time) is dead; a process we may not query is unknown.
func processLiveness(pid int, created time.Time) liveness {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)) // #nosec G115 -- a pid
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return ownerDead
	}
	if err != nil {
		return ownerUnknown
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var code uint32
	if windows.GetExitCodeProcess(h, &code) == nil && code != stillActive {
		return ownerDead
	}
	if !created.IsZero() {
		var c, e, k, u windows.Filetime
		if windows.GetProcessTimes(h, &c, &e, &k, &u) == nil && !time.Unix(0, c.Nanoseconds()).Equal(created) {
			return ownerDead // PID reused
		}
	}
	return ownerAlive
}
