//go:build !windows

package config

import (
	"errors"
	"math"
	"os"

	"golang.org/x/sys/unix"
)

func tryConfigLock(f *os.File) (bool, error) {
	fd := f.Fd()
	if fd > uintptr(math.MaxInt) {
		return false, unix.EBADF
	}
	err := unix.Flock(int(fd), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return false, nil
	}
	return err == nil, err
}
func replaceConfig(from, to string) error { return os.Rename(from, to) }
