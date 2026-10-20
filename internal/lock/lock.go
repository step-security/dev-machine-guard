// Package lock provides the single-instance lock for agent runs. It is an OS
// lock (flock on Unix, a named mutex on Windows) rather than a PID file, so the
// kernel drops it on any exit — os.Exit, signal, SIGKILL, crash — and no stale
// or forged file can block later runs.
package lock

import (
	"errors"
	"sync"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// ErrHeld means another instance holds the lock.
var ErrHeld = errors.New("another instance is already running")

// Lock represents an acquired instance lock.
type Lock struct {
	once    sync.Once
	release func()
}

// Acquire takes the instance lock without blocking. It returns an error
// wrapping ErrHeld when another instance (any account) holds it.
func Acquire(_ executor.Executor) (*Lock, error) {
	release, err := acquire()
	if err != nil {
		return nil, err
	}
	return &Lock{release: release}, nil
}

// SetTargetForTest points the lock at another file (Unix) or mutex name
// (Windows) and returns a func restoring the previous one. Tests only.
func SetTargetForTest(target string) (restore func()) {
	old := setLockTarget(target)
	return func() { setLockTarget(old) }
}

// Release drops the lock. Safe to call more than once.
func (l *Lock) Release() {
	if l == nil || l.release == nil {
		return
	}
	l.once.Do(l.release)
}
