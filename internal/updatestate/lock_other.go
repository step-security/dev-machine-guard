//go:build !windows

package updatestate

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockFile(f *os.File) error {
	fd := f.Fd()
	// POSIX descriptors fit in a signed 32-bit int; reject anything else
	// before converting os.File's platform-neutral uintptr.
	if fd > 1<<31-1 {
		return os.ErrInvalid
	}
	return unix.Flock(int(fd), unix.LOCK_EX|unix.LOCK_NB)
}

func isLockHeld(err error) bool { return errors.Is(err, unix.EWOULDBLOCK) }
