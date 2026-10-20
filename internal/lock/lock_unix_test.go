//go:build !windows

package lock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testLockTarget(t *testing.T) string {
	return filepath.Join(t.TempDir(), "dmg.flock")
}

func TestDefaultPathIsNotLegacyPIDFile(t *testing.T) {
	if !strings.HasSuffix(defaultLockFilePath, ".flock") {
		t.Fatalf("lock path %q must not reuse the legacy PID-file name", defaultLockFilePath)
	}
}

func TestLegacyPIDFileDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	// PID 1 is always alive: the old implementation treated this as held forever.
	if err := os.WriteFile(filepath.Join(dir, "stepsecurity-dev-machine-guard.lock"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	setLockTarget(filepath.Join(dir, "stepsecurity-dev-machine-guard.flock"))
	lk, err := Acquire(nil)
	if err != nil {
		t.Fatalf("Acquire with legacy PID file present: %v", err)
	}
	lk.Release()
}

func TestPreexistingRestrictiveFileSameUser(t *testing.T) {
	target := testLockTarget(t)
	if err := os.WriteFile(target, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	setLockTarget(target)
	lk, err := Acquire(nil)
	if err != nil {
		t.Fatalf("Acquire on pre-existing 0600 file: %v", err)
	}
	defer lk.Release()
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != lockFileMode {
		t.Fatalf("mode = %o, want %o (other accounts must be able to open it)", got, lockFileMode)
	}
}

func TestCreatedFileIsWorldReadable(t *testing.T) {
	target := testLockTarget(t)
	setLockTarget(target)
	lk, err := Acquire(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Release()
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != lockFileMode {
		t.Fatalf("mode = %o, want %o regardless of umask", got, lockFileMode)
	}
}

func TestReleaseKeepsFile(t *testing.T) {
	target := testLockTarget(t)
	setLockTarget(target)
	lk, err := Acquire(nil)
	if err != nil {
		t.Fatal(err)
	}
	lk.Release()
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("lock file must persist after Release: %v", err)
	}
}

func TestSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "dmg.flock")
	if err := os.Symlink(victim, target); err != nil {
		t.Fatal(err)
	}
	setLockTarget(target)
	if lk, err := Acquire(nil); err == nil {
		lk.Release()
		t.Fatal("Acquire followed a symlink")
	} else if errors.Is(err, ErrHeld) {
		t.Fatalf("symlink reported as contention: %v", err)
	}
}

func TestFIFORefused(t *testing.T) {
	target := testLockTarget(t)
	if err := syscall.Mkfifo(target, 0o644); err != nil {
		t.Fatal(err)
	}
	setLockTarget(target)
	done := make(chan error, 1)
	go func() {
		lk, err := Acquire(nil)
		if err == nil {
			lk.Release()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || errors.Is(err, ErrHeld) {
			t.Fatalf("Acquire on FIFO: err=%v, want non-contention error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Acquire blocked on a FIFO")
	}
}
