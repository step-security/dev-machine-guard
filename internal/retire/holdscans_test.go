package retire

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/lock"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// testLockTarget is a lock target valid on the host OS: a file for flock, a
// mutex name on Windows (a path is not a valid kernel object name there).
func testLockTarget(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("StepSecurityDMGRetireTest-%d", time.Now().UnixNano())
	}
	return filepath.Join(t.TempDir(), "instance.flock")
}

func TestHoldScans_HoldsIdleHostAndGivesUpWhileAScanRuns(t *testing.T) {
	t.Cleanup(lock.SetTargetForTest(testLockTarget(t)))
	orig := scanHoldPoll
	scanHoldPoll = time.Millisecond
	t.Cleanup(func() { scanHoldPoll = orig })
	log := progress.NewNoop()

	release, idle := holdScans(context.Background(), []string{"dev1"}, log)
	if !idle {
		t.Fatal("idle host reported as scanning")
	}
	if _, err := lock.AcquireAll([]string{"dev1"}); !errors.Is(err, lock.ErrHeld) {
		t.Errorf("locks are not held while the retire runs: err=%v", err)
	}
	release()

	scan, err := lock.AcquireSibling("dev1") // dev1's scan is mid-flight
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, idle := holdScans(ctx, []string{"dev1"}, log); idle {
		t.Fatal("reported idle while dev1's scan held its lock")
	}
	scan.Release()

	release, idle = holdScans(context.Background(), []string{"dev1"}, log)
	if !idle {
		t.Fatal("host still reported as scanning after the scan released its lock")
	}
	release()
}

func TestStateScopes_ListsPerSessionStateDirs(t *testing.T) {
	root := t.TempDir()
	t.Setenv(paths.HomeEnvVar, root)
	for _, d := range []string{"dev2-aaaaaaaaaaaa", "dev1-bbbbbbbbbbbb"} {
		if err := os.MkdirAll(filepath.Join(root, "users", d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "users", "stray.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	scopes, complete := stateScopes()
	got := strings.Join(scopes, ",")
	if !complete || !strings.Contains(got, "dev1-bbbbbbbbbbbb") || !strings.Contains(got, "dev2-aaaaaaaaaaaa") || strings.Contains(got, "stray") {
		t.Errorf("stateScopes() = %q (complete %v), want the two user dirs and no files", got, complete)
	}
}

// More session directories than can be held at once (a user-creatable tree)
// means the set cannot be inspected: HoldScans reports the host as not idle
// without taking a lock.
func TestHoldScans_SkipsWhenTheScopeSetIsUnbounded(t *testing.T) {
	root := t.TempDir()
	t.Setenv(paths.HomeEnvVar, root)
	for i := range maxScanHoldScopes + 1 {
		if err := os.MkdirAll(filepath.Join(root, "users", fmt.Sprintf("u%03d-aaaaaaaaaaaa", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, complete := stateScopes(); complete {
		t.Fatal("stateScopes() reported a complete listing past the bound")
	}
	t.Cleanup(lock.SetTargetForTest(testLockTarget(t)))
	if _, idle := HoldScans(context.Background(), progress.NewNoop()); idle {
		t.Fatal("HoldScans reported idle without being able to inspect every scope")
	}
}

// A lock that cannot be inspected at all (here: its file cannot be created)
// is not evidence that the host is idle; the retire does not proceed.
func TestHoldScans_UninspectableLockIsNotIdle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows lock is a named mutex; there is no path to make unopenable")
	}
	t.Cleanup(lock.SetTargetForTest(filepath.Join(t.TempDir(), "missing-dir", "instance.flock")))
	orig := scanHoldPoll
	scanHoldPoll = time.Millisecond
	t.Cleanup(func() { scanHoldPoll = orig })
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, idle := holdScans(ctx, []string{"dev1"}, progress.NewNoop()); idle {
		t.Fatal("an uninspectable lock was taken as proof that no scan runs")
	}
}
