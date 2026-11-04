//go:build !windows

package lock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// defaultLockFilePath deliberately differs from the legacy PID file
// (stepsecurity-dev-machine-guard.lock) so leftovers from old versions are
// ignored.
const defaultLockFilePath = "/tmp/stepsecurity-dev-machine-guard.flock"

// lockFileMode lets root- and user-context runs open each other's file; flock
// only needs a read-only descriptor.
const lockFileMode = 0o644

var lockFilePath = defaultLockFilePath

func setLockTarget(p string) (old string) { old, lockFilePath = lockFilePath, p; return old }

func lockTarget() string { return lockFilePath }

func acquire() (func(), error) {
	f, err := openLockFile(lockFilePath)
	if err != nil {
		return nil, err
	}
	// #nosec G115 -- f.Fd() is a live descriptor; narrowing to int cannot overflow.
	fd := int(f.Fd())
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w (flock %s)", ErrHeld, lockFilePath)
		}
		return nil, fmt.Errorf("flock %s: %w", lockFilePath, err)
	}
	// The file is never unlinked: removing it would let a later run lock a
	// fresh inode while another still holds the old one.
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// openLockFile opens the lock file read-only without following symlinks. An
// existing file is opened without O_CREAT so Linux protected_regular doesn't
// refuse root opening a user-created file in sticky /tmp. O_NONBLOCK keeps a
// planted FIFO from blocking the open.
func openLockFile(path string) (*os.File, error) {
	const flags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
	for range 2 {
		fd, err := syscall.Open(path, flags, 0)
		if errors.Is(err, syscall.ENOENT) {
			fd, err = syscall.Open(path, flags|syscall.O_CREAT|syscall.O_EXCL, lockFileMode)
			if errors.Is(err, syscall.EEXIST) {
				continue // lost a create race; open the winner's file
			}
		}
		if err != nil {
			return nil, fmt.Errorf("opening lock file %s: %w", path, err)
		}
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			_ = syscall.Close(fd)
			return nil, fmt.Errorf("stat lock file %s: %w", path, err)
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			_ = syscall.Close(fd)
			return nil, fmt.Errorf("lock file %s is not a regular file", path)
		}
		// Undo umask, and widen a restrictive file we own. Fails harmlessly
		// on another account's file.
		_ = syscall.Fchmod(fd, lockFileMode)
		// #nosec G115 -- fd is a valid, non-negative descriptor from Open.
		return os.NewFile(uintptr(fd), path), nil
	}
	return nil, fmt.Errorf("opening lock file %s: repeatedly created and removed", path)
}
