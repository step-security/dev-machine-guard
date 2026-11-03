// Package lock provides the single-instance lock for agent runs. It is an OS
// lock (flock on Unix, a named mutex on Windows) rather than a PID file, so the
// kernel drops it on any exit — os.Exit, signal, SIGKILL, crash — and no stale
// or forged file can block later runs.
package lock

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/paths"
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
	// Under a per-user device identity (paths.UserScope non-empty) each
	// logged-in user is a separate device, so each gets its own lock target
	// and two sessions' scans never exclude each other. With a shared identity
	// the target is unchanged and overlapping runs still serialise.
	if scope := paths.UserScope(); scope != "" {
		if t := lockTarget(); t != scopedTarget(t, scope) {
			setLockTarget(scopedTarget(t, scope))
		}
	}
	release, err := acquire()
	if err != nil {
		return nil, err
	}
	return &Lock{release: release}, nil
}

// AcquireMachineWide takes the shared, unscoped instance lock that scans
// under the machine identity hold, without blocking, independently of the
// per-user lock the caller may already own. The identity switch uses it to
// make sure no scan still reporting under the previous identity is running
// before that identity's row is retired.
func AcquireMachineWide() (*Lock, error) {
	old := setLockTarget(unscopedTarget(lockTarget(), paths.UserScope()))
	release, err := acquire()
	setLockTarget(old)
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

// unscopedTarget undoes scopedTarget: the shared target a scoped one came from.
func unscopedTarget(target, scope string) string {
	if scope == "" {
		return target
	}
	ext := filepath.Ext(target)
	stem := strings.TrimSuffix(target, ext)
	return strings.TrimSuffix(stem, "-"+scope) + ext
}

// scopedTarget suffixes a lock target (a file path on Unix, a mutex name on
// Windows) with the per-user state scope, keeping any file extension:
// /tmp/x.flock + "dev1" -> /tmp/x-dev1.flock; "Name" + "dev1" -> "Name-dev1".
// An empty scope or an already-suffixed target is returned unchanged.
func scopedTarget(base, scope string) string {
	if scope == "" {
		return base
	}
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if strings.HasSuffix(stem, "-"+scope) {
		return base
	}
	return stem + "-" + scope + ext
}
