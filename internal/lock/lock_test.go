package lock

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// withTempLockPath redirects the package-level lock path to a tempdir so
// tests never touch the real /tmp lock of a concurrently-running agent.
func withTempLockPath(t *testing.T) string {
	t.Helper()
	prev := lockFilePath
	lockFilePath = filepath.Join(t.TempDir(), "test.lock")
	t.Cleanup(func() { lockFilePath = prev })
	return lockFilePath
}

func TestHolderAbsentFile(t *testing.T) {
	withTempLockPath(t)
	if pid, alive := Holder(); alive || pid != 0 {
		t.Fatalf("Holder() = (%d, %v), want (0, false) with no lock file", pid, alive)
	}
}

func TestHolderLivePID(t *testing.T) {
	path := withTempLockPath(t)
	// Our own PID is guaranteed alive.
	if err := os.WriteFile(path, fmt.Appendf(nil, "%d", os.Getpid()), 0o600); err != nil {
		t.Fatal(err)
	}
	pid, alive := Holder()
	if !alive || pid != os.Getpid() {
		t.Fatalf("Holder() = (%d, %v), want (%d, true)", pid, alive, os.Getpid())
	}
}

func TestHolderStalePID(t *testing.T) {
	path := withTempLockPath(t)
	// A PID far beyond any real pid space reads as dead on every platform.
	if err := os.WriteFile(path, []byte("1073741824"), 0o600); err != nil {
		t.Fatal(err)
	}
	if pid, alive := Holder(); alive || pid != 0 {
		t.Fatalf("Holder() = (%d, %v), want (0, false) for a stale PID", pid, alive)
	}
}

func TestHolderGarbageContent(t *testing.T) {
	path := withTempLockPath(t)
	if err := os.WriteFile(path, []byte("not-a-pid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if pid, alive := Holder(); alive || pid != 0 {
		t.Fatalf("Holder() = (%d, %v), want (0, false) for garbage content", pid, alive)
	}
}

// TestHolderReflectsAcquireRelease pins the peek to the real lock lifecycle:
// alive while held (it is this process), gone after Release, and Holder
// itself never mutates the file.
func TestHolderReflectsAcquireRelease(t *testing.T) {
	withTempLockPath(t)

	lk, err := Acquire(nil)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	pid, alive := Holder()
	if !alive || pid != os.Getpid() {
		t.Fatalf("Holder() during hold = (%d, %v), want (%d, true)", pid, alive, os.Getpid())
	}
	// Peeking must not release or corrupt the lock.
	if _, err := Acquire(nil); err == nil {
		t.Fatal("second Acquire must fail while the lock is held")
	}

	lk.Release()
	if pid, alive := Holder(); alive || pid != 0 {
		t.Fatalf("Holder() after Release = (%d, %v), want (0, false)", pid, alive)
	}
}
