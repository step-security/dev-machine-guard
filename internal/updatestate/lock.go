package updatestate

import (
	"errors"
	"os"
)

// ErrLocked means another process holds the update lock.
var ErrLocked = errors.New("updatestate: update lock held by another process")

// Lock is an OS-owned exclusive lock that the kernel releases when the
// holder dies. The lock file is never removed: every contender must lock the
// same file.
type Lock struct{ f *os.File }

// AcquireLock takes the lock without blocking; it returns ErrLocked when
// another process holds it.
func AcquireLock(path string) (*Lock, error) {
	// #nosec G304 -- fixed lock path inside the protected state directory.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		if isLockHeld(err) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return &Lock{f: f}, nil
}

// Release drops the lock. It is safe to call more than once.
func (l *Lock) Release() {
	if l != nil && l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
}
