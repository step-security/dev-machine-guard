//go:build !windows

package updatestate

import (
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// processStartTime is not available portably off Windows; liveness then
// rests on the PID alone.
func processStartTime(int) (time.Time, bool) { return time.Time{}, false }

func processLiveness(pid int, _ time.Time) liveness {
	switch err := unix.Kill(pid, 0); {
	case err == nil, errors.Is(err, unix.EPERM):
		return ownerAlive
	case errors.Is(err, unix.ESRCH):
		return ownerDead
	}
	return ownerUnknown
}
