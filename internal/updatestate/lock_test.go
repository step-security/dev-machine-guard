package updatestate

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

func TestLockExclusiveNonBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.lock")
	a, err := AcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("second AcquireLock = %v, want ErrLocked", err)
	}
	a.Release()
	a.Release()
	b, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("AcquireLock after Release: %v", err)
	}
	b.Release()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("lock file must persist: %v", err)
	}
	if _, err := AcquireLock(filepath.Join(t.TempDir(), "missing", "update.lock")); err == nil || errors.Is(err, ErrLocked) {
		t.Fatalf("AcquireLock in a missing dir = %v", err)
	}
}

func TestLockHelper(t *testing.T) {
	path := os.Getenv("UPDATESTATE_LOCK_PATH")
	if path == "" {
		t.Skip("helper")
	}
	proctest.Guard()
	if _, err := AcquireLock(path); err != nil {
		os.Exit(90)
	}
	os.Stdout.WriteString("locked\n")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	os.Exit(137) // die holding the lock, no Release
}

func TestLockReleasedOnProcessDeath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.lock")
	cmd := proctest.Command(t, os.Args[0], "-test.run=^TestLockHelper$")
	cmd.Env = append(cmd.Env, "UPDATESTATE_LOCK_PATH="+path)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if line, _ := bufio.NewReader(out).ReadString('\n'); line != "locked\n" {
		t.Fatalf("helper said %q", line)
	}
	if _, err := AcquireLock(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("lock held by another process: %v, want ErrLocked", err)
	}
	_ = in.Close()
	_ = cmd.Wait()
	l, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("lock not released by process death: %v", err)
	}
	l.Release()
}
